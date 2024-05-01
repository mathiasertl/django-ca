"""HSM backend for keys."""

import asyncio
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict
from python_x509_pkcs11 import PKCS11Session, get_keytypes_enum
from python_x509_pkcs11.privatekeys import (
    PKCS11ECPrivateKey,
    PKCS11ED448PrivateKey,
    PKCS11ED25519PrivateKey,
    PKCS11RSAPrivateKey,
)

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    CertificateIssuerPublicKeyTypes,
)

from django.core.management import CommandError

from django_ca.key_backends.base import KeyBackend
from django_ca.typehints import AllowedHashTypes, ArgumentGroup, ParsableKeyType
from django_ca.utils import get_cert_builder

if TYPE_CHECKING:
    from django_ca.models import CertificateAuthority

PrivateKeyTypes = Union[
    PKCS11RSAPrivateKey, PKCS11ED25519PrivateKey, PKCS11ED448PrivateKey, PKCS11ECPrivateKey
]
KeyType = Literal["RSA", "EC", "Ed25519", "Ed448"]
KeySize = Literal[2048, 4096]
EllipticCurves = Literal["secp256r1", "secp384r1", "secp521r1"]


async def _create_key_pair(key_label: str, hsm_key_type: str) -> tuple[str, bytes]:
    """Creates the new keypair in async way."""
    key_type = get_keytypes_enum(hsm_key_type)
    public_key, identifier = await PKCS11Session().create_keypair(key_label, key_type=key_type)
    return public_key, identifier


# TODO: This should be part of the library itself.
def get_private_key(key_label: str, hsm_key_type: str) -> PrivateKeyTypes:
    """Returns a private key of the given type."""
    if hsm_key_type in ["rsa_2048", "rsa_4096"]:
        return PKCS11RSAPrivateKey(key_label, hsm_key_type)
    elif hsm_key_type == "ed25519":
        return PKCS11ED25519PrivateKey(key_label)
    elif hsm_key_type == "ed448":
        return PKCS11ED448PrivateKey(key_label)
    elif hsm_key_type in ["secp256r1", "secp384r1", "secp521r1"]:
        return PKCS11ECPrivateKey(key_label, hsm_key_type)
    raise ValueError("Unknown HSM key type.")


def get_signing_algo(ca: "CertificateAuthority") -> Optional[AllowedHashTypes]:
    """Get the right algorithm for signing a certificate."""
    # FIXME: We should deal with algorithm in a better way.
    key_type = ca.key_backend_options["key_type"]
    key_size = ca.key_backend_options["key_size"]
    if key_type == "RSA" and key_size == 2048:
        return hashes.SHA256()
    elif key_type == "RSA" and key_size == 4096:
        return hashes.SHA512()
    else:
        return None


def get_hsm_key_type(
    key_type: KeyType, key_size: Optional[KeySize], elliptic_curve: Optional[EllipticCurves]
) -> str:
    """Get the HSM version of the key type (encoding key size and elliptic curve)."""
    if key_type == "RSA":
        if key_size is None:
            raise ValueError("Key size missing for RSA key.")
        return f"rsa_{key_size}"
    elif key_type == "EC":
        if elliptic_curve is None:
            raise ValueError("Elliptic curve missing for EC key.")
        return elliptic_curve
    else:
        return key_type.lower()


class CreatePrivateKeyOptions(BaseModel):
    """Options for initializing private keys."""

    # NOTE: we set frozen here to prevent accidental coding mistakes. Models should be immutable.
    model_config = ConfigDict(arbitrary_types_allowed=True)

    key_type: KeyType
    key_size: Optional[KeySize]
    elliptic_curve: Optional[EllipticCurves]
    key_label: str


class StorePrivateKeyOptions(BaseModel):
    """Options for storing a private key."""

    # NOTE: we set frozen here to prevent accidental coding mistakes. Models should be immutable.
    model_config = ConfigDict(frozen=True)

    key_label: str


class UsePrivateKeyOptions(BaseModel):
    """Options for using the private key."""

    model_config = ConfigDict(frozen=True)


class HSMBackend(KeyBackend[CreatePrivateKeyOptions, StorePrivateKeyOptions, UsePrivateKeyOptions]):
    """The HSM backend that uses PKCS111.

    .. tab:: Python

       .. literalinclude:: /include/config/settings_default_ca_key_backends.py
          :language: python

    .. tab:: YAML

       .. literalinclude:: /include/config/settings_default_ca_key_backends.yaml
          :language: YAML

    .. seealso::

       * `STORAGES setting <https://docs.djangoproject.com/en/5.0/ref/settings/#std-setting-STORAGES>`_
       * `Django file storage API <https://docs.djangoproject.com/en/5.0/ref/files/storage/>`_
    """

    name = "hsm"
    title = "Store private keys using HSM"
    description = "Use a HSM for private key storage."
    use_model = UsePrivateKeyOptions

    default_key_size: KeySize = 4096
    default_elliptic_curve: EllipticCurves = "secp521r1"

    supported_key_types: tuple[KeyType, ...] = ("RSA", "EC", "Ed25519", "Ed448")
    supported_elliptic_curves: tuple[EllipticCurves, ...] = ("secp256r1", "secp384r1", "secp521r1")

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, HSMBackend)

    def _add_key_label_argument(self, group: ArgumentGroup) -> None:
        group.add_argument(
            f"--{self.argparse_prefix}key-label",
            type=str,
            help="KEY_LABEL in HSM for CA.",
        )

    def add_create_private_key_arguments(self, group: ArgumentGroup) -> None:
        self._add_key_label_argument(group)

    def add_use_parent_private_key_arguments(self, group: ArgumentGroup) -> None:
        group.add_argument(
            f"--{self.argparse_prefix}parent-key-label",
            type=str,
            help="KEY_LABEL for the private key of the parent CA, if stored using the Django storage system.",
        )

    def add_store_private_key_arguments(self, group: ArgumentGroup) -> None:
        self._add_key_label_argument(group)

    def add_use_private_key_arguments(self, group: ArgumentGroup) -> None:
        self._add_key_label_argument(group)

    def get_create_private_key_options(
        self,
        key_type: ParsableKeyType,
        key_size: Optional[int],
        elliptic_curve: Optional[EllipticCurves],  # type: ignore[override]
        options: dict[str, Any],
    ) -> CreatePrivateKeyOptions:
        if key_type == "RSA":
            if key_size is None:
                key_size = self.default_key_size
            elif key_size not in (2048, 4096):
                raise CommandError(f"{key_size}: Unsupported key size.")
        if key_type == "EC" and elliptic_curve is None:
            elliptic_curve = self.default_elliptic_curve

        key_label = options[f"{self.options_prefix}key_label"]
        return CreatePrivateKeyOptions(
            key_type=key_type, key_size=key_size, elliptic_curve=elliptic_curve, key_label=key_label
        )

    def get_store_private_key_options(self, options: dict[str, Any]) -> StorePrivateKeyOptions:
        return StorePrivateKeyOptions(
            key_label=options[f"{self.options_prefix}key_label"],
        )

    def get_use_private_key_options(
        self, ca: Optional["CertificateAuthority"], options: dict[str, Any]
    ) -> UsePrivateKeyOptions:
        return UsePrivateKeyOptions()

    def get_use_parent_private_key_options(
        self, ca: "CertificateAuthority", options: dict[str, Any]
    ) -> UsePrivateKeyOptions:
        return UsePrivateKeyOptions()

    def create_private_key(
        self,
        ca: "CertificateAuthority",
        key_type: KeyType,  # type: ignore[override]  # backend doesn't support DSA, key_type is more specific
        options: CreatePrivateKeyOptions,
    ) -> tuple[CertificateIssuerPublicKeyTypes, UsePrivateKeyOptions]:
        hsm_key_type = get_hsm_key_type(options.key_type, options.key_size, options.elliptic_curve)
        try:
            asyncio.run(_create_key_pair(key_label=options.key_label, hsm_key_type=hsm_key_type))
        except Exception as ex:
            raise ex

        # Update model instance
        ca.key_backend_options = options.model_dump(mode="json")

        key = get_private_key(key_label=options.key_label, hsm_key_type=hsm_key_type)
        return key.public_key(), UsePrivateKeyOptions()

    def store_private_key(
        self,
        ca: "CertificateAuthority",
        key: CertificateIssuerPrivateKeyTypes,
        options: StorePrivateKeyOptions,
    ) -> None:
        pass

    def get_key(
        self, ca: "CertificateAuthority", use_private_key_options: UsePrivateKeyOptions
    ) -> CertificateIssuerPrivateKeyTypes:
        """The CAs private key as private key."""
        key_label = ca.key_backend_options["key_label"]
        key_type = ca.key_backend_options["key_type"]
        key_size = ca.key_backend_options["key_size"]
        elliptic_curve = ca.key_backend_options["elliptic_curve"]

        hsm_key_type = get_hsm_key_type(key_type, key_size, elliptic_curve)
        return get_private_key(key_label, hsm_key_type)

    def is_usable(
        self, ca: "CertificateAuthority", use_private_key_options: Optional[UsePrivateKeyOptions] = None
    ) -> bool:
        # If key_backend_options is not set or path is not set, it is certainly unusable.
        if not ca.key_backend_options or not ca.key_backend_options.get("key_label"):
            return False
        if use_private_key_options is None:
            return True

        try:
            self.get_key(ca, use_private_key_options)
            return True
        except Exception:  # pylint: disable=broad-exception-caught  # want to always return bool
            return False

    def check_usable(self, ca: "CertificateAuthority", use_private_key_options: UsePrivateKeyOptions) -> None:
        """Check if the given CA is usable, raise ValueError if not.

        The `options` are the options returned by
        :py:func:`~django_ca.key_backends.base.KeyBackend.get_use_private_key_options`. It may be ``None`` in
        cases where key options cannot (yet) be loaded. If ``None``, the backend should return ``False`` if it
        knows for sure that it will not be usable, and ``True`` if usability cannot be determined.
        """
        if not ca.key_backend_options or not ca.key_backend_options.get("key_label"):
            raise ValueError(f"{ca.key_backend_options}: key_label not configured in database.")

        try:
            self.get_key(ca, use_private_key_options)
        except Exception as ex:
            raise ValueError(*ex.args) from ex

    def sign_certificate(
        self,
        ca: "CertificateAuthority",
        use_private_key_options: UsePrivateKeyOptions,
        public_key: CertificateIssuerPublicKeyTypes,
        serial: int,
        algorithm: Optional[AllowedHashTypes],
        issuer: x509.Name,
        subject: x509.Name,
        expires: datetime,
        extensions: list[x509.Extension[x509.ExtensionType]],
    ) -> x509.Certificate:
        builder = get_cert_builder(expires, serial=serial)
        builder = builder.public_key(public_key)
        builder = builder.issuer_name(issuer)
        builder = builder.subject_name(subject)
        for extension in extensions:
            builder = builder.add_extension(extension.value, critical=extension.critical)
        # We need the correct algorithm
        algorithm = get_signing_algo(ca)
        return builder.sign(private_key=self.get_key(ca, use_private_key_options), algorithm=algorithm)

    def sign_certificate_revocation_list(
        self,
        ca: "CertificateAuthority",
        use_private_key_options: UsePrivateKeyOptions,
        builder: x509.CertificateRevocationListBuilder,
        algorithm: Optional[AllowedHashTypes],
    ) -> x509.CertificateRevocationList:
        # We need the correct algorithm
        algorithm = get_signing_algo(ca)
        return builder.sign(private_key=self.get_key(ca, use_private_key_options), algorithm=algorithm)

    def get_ocsp_key_size(
        self, ca: "CertificateAuthority", use_private_key_options: UsePrivateKeyOptions
    ) -> int:
        """Get the default key size for OCSP keys. This is only called for RSA or DSA keys."""
        key = self.get_key(ca, use_private_key_options)
        if not isinstance(key, (rsa.RSAPrivateKey, dsa.DSAPrivateKey)):
            raise ValueError("This function should only be called with RSA/DSA CAs.")
        return key.key_size

    def get_ocsp_key_elliptic_curve(
        self, ca: "CertificateAuthority", use_private_key_options: UsePrivateKeyOptions
    ) -> ec.EllipticCurve:
        """Get the default elliptic curve for OCSP keys. This is only called for elliptic curve keys."""
        key = self.get_key(ca, use_private_key_options)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError("This function should only be called with EllipticCurve-based CAs.")
        return key.curve

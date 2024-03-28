"""HSM backend for keys."""

import typing
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    CertificateIssuerPublicKeyTypes,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    load_der_private_key,
    load_pem_private_key,
)
from python_x509_pkcs11.privatekeys import PKCS11RSAPrivateKey, PKCS11ECPrivateKey, PKCS11ED25519PrivateKey, PKCS11ED448PrivateKey
from python_x509_pkcs11 import KEYTYPES, get_keytypes_enum, PKCS11Session
import asyncio

from django.conf import settings

from django_ca import ca_settings, constants
from django_ca.key_backends.base import KeyBackend
from django_ca.management.actions import PasswordAction
from django_ca.management.base import add_elliptic_curve, add_key_size
from django_ca.pydantic.type_aliases import PrivateKeySize
from django_ca.typehints import AllowedHashTypes, ArgumentGroup, ParsableKeyType
from django_ca.utils import generate_private_key, get_cert_builder


if typing.TYPE_CHECKING:
    from django_ca.models import CertificateAuthority

ParsableHSMKeyType = typing.Literal["rsa_2048", "rsa_4096", "secp256r1", "ed25519", "ed448", "secp384r1", "secp521r1"]

# TODO: This should go to the library itself.
async def _create_key_pair(key_label:str, hsm_key_type: str):
    "Creates the new keypair in async way"
    k_type = get_keytypes_enum(hsm_key_type)
    public_key, identifier = await PKCS11Session().create_keypair(key_label, key_type=k_type)
    return public_key, identifier

# TODO: This should be part of the library itself.
def get_private_key(key_label:str, hsm_key_type: str):
    "Returns a private key of the given type."
    if hsm_key_type in ["rsa_2048", "rsa_4096"]:
        return PKCS11RSAPrivateKey(key_label, hsm_key_type)
    elif hsm_key_type == "ed25519":
        return PKCS11ED25519PrivateKey(key_label)
    elif hsm_key_type == "ed448":
        return PKCS11ED448PrivateKey(key_label)
    elif hsm_key_type in ["secp256r1", "secp384r1", "secp521r1"]:
        return PKCS11ECPrivateKey(key_label, hsm_key_type)

def get_signing_algo(ca: "CertificateAuthority") -> Optional[AllowedHashTypes]:
    "Get the right algorithm for signing a certificate."
    # FIXME: We should deal with algorithm in a better way.
    hsm_key_type = ca.key_backend_options["hsm_key_type"]
    if hsm_key_type == "rsa_2048":
        return hashes.SHA256()
    elif hsm_key_type == "rsa_4096":
        return hashes.SHA512()
    else:
        return None


class CreatePrivateKeyOptions(BaseModel):
    """Options for initializing private keys."""

    # NOTE: we set frozen here to prevent accidental coding mistakes. Models should be immutable.
    model_config = ConfigDict(arbitrary_types_allowed=True)

    hsm_key_type: ParsableHSMKeyType
    key_label: str


class StorePrivateKeyOptions(BaseModel):
    """Options for storing a private key."""

    # NOTE: we set frozen here to prevent accidental coding mistakes. Models should be immutable.
    model_config = ConfigDict(frozen=True)

    hsm_key_type: ParsableHSMKeyType
    key_label: str


class UsePrivateKeyOptions(BaseModel):
    """Options for using a private key."""

    # NOTE: we set frozen here to prevent accidental coding mistakes. Models should be immutable.
    model_config = ConfigDict(frozen=True)

    key_label: str



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
    description = (
        "Use a HSM for private key storage."
    )
    use_model = UsePrivateKeyOptions

    # Backend options
    storage_alias: str

    def __init__(self, alias: str, storage_alias: str) -> None:
        if storage_alias not in settings.STORAGES:
            raise ValueError(f"{alias}: {storage_alias}: Storage alias is not configured.")
        super().__init__(alias, storage_alias=storage_alias)

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, HSMBackend) and self.storage_alias == other.storage_alias

    def _add_key_label_argument(self, group: ArgumentGroup) -> None:
        group.add_argument(
            f"--{self.argparse_prefix}key_label",
            type=str,
            help="KEY_LABEL in HSM for CA.",
        )

    def _add_key_type_argument(self, group: ArgumentGroup) -> None:
        group.add_argument(
            f"--{self.argparse_prefix}hsm_key_type",
            type=str,
            default="ed25519",
            help="HSM Key type, default: %(default)s).",
        )

    def add_create_private_key_arguments(self, group: ArgumentGroup) -> None:
        self._add_key_type_argument(group)
        self._add_key_label_argument(group)

    def add_use_parent_private_key_arguments(self, group: ArgumentGroup) -> None:
        group.add_argument(
            f"--{self.argparse_prefix}parent_key_label",
            type=str,
            help="KEY_LABEL for the private key of the parent CA, if stored using the Django storage system.",
        )

    def add_store_private_key_arguments(self, group: ArgumentGroup) -> None:
        self._add_key_label_argument(group)
        self._add_key_type_argument(group)

    def add_use_private_key_arguments(self, group: ArgumentGroup) -> None:
        self._add_key_label_argument(group)

    def get_create_private_key_options(
        self,key_type: ParsableKeyType,  options: Dict[str, Any]
    ) -> CreatePrivateKeyOptions:
        return CreatePrivateKeyOptions(
            hsm_key_type=options[f"{self.options_prefix}hsm_key_type"],
            key_label=options[f"{self.options_prefix}key_label"],
        )

    def get_store_private_key_options(self, options: Dict[str, Any]) -> StorePrivateKeyOptions:
        return StorePrivateKeyOptions(
            hsm_key_type=options[f"{self.options_prefix}hsm_key_type"],
            key_label=options[f"{self.options_prefix}key_label"],
        )

    def get_use_private_key_options(
        self, ca: Optional["CertificateAuthority"], options: Dict[str, Any]
    ) -> UsePrivateKeyOptions:
        return UsePrivateKeyOptions.model_validate(
            {"key_label": options.get(f"{self.options_prefix}key_label")}, context={"ca": ca}
        )

    def get_use_parent_private_key_options(
        self, ca: "CertificateAuthority", options: Dict[str, Any]
    ) -> UsePrivateKeyOptions:
        return UsePrivateKeyOptions.model_validate(
            {"key_label": options[f"{self.options_prefix}parent_key_label"]}, context={"ca": ca}
        )


    def create_private_key(
        self, ca: "CertificateAuthority", key_type: ParsableKeyType, options: CreatePrivateKeyOptions
    ) -> Tuple[CertificateIssuerPublicKeyTypes, UsePrivateKeyOptions]:

        hsm_key_type = options.hsm_key_type
        try:
            asyncio.run(_create_key_pair(key_label=options.key_label, hsm_key_type=hsm_key_type))
        except Exception as e:
            raise  e

        # Update model instance
        ca.key_backend_options = {"key_label": options.key_label, "hsm_key_type": hsm_key_type}

        use_private_key_options = UsePrivateKeyOptions.model_validate(
            {"key_label": options.key_label}, context={"ca": ca}
        )

        key = get_private_key(key_label=options.key_label, hsm_key_type=hsm_key_type)
        return key.public_key(), use_private_key_options

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
        hsm_key_type = ca.key_backend_options["hsm_key_type"]
        key = get_private_key(key_label=key_label, hsm_key_type=hsm_key_type)

        return key

    def is_usable(
        self, ca: "CertificateAuthority", use_private_key_options: Optional[UsePrivateKeyOptions] = None
    ) -> bool:
        # If key_backend_options is not set or path is not set, it is certainly unusable.
        if not ca.key_backend_options or not ca.key_backend_options.get("key_label"):
            return False

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
        extensions: List[x509.Extension[x509.ExtensionType]],
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

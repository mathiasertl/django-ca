# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU General
# Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca. If not, see
# <http://www.gnu.org/licenses/>.

"""Key storage backend for hardware security modules (HSMs)."""

from collections.abc import Sequence
from datetime import datetime
from typing import TYPE_CHECKING, Any, Final, Optional

import pkcs11
from pkcs11 import Session
from pkcs11.util.ec import decode_ec_private_key, decode_ec_public_key
from pkcs11.util.rsa import decode_rsa_private_key, decode_rsa_public_key

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    CertificateIssuerPublicKeyTypes,
)

from django.core.management import CommandError

from django_ca import constants
from django_ca.conf import model_settings
from django_ca.key_backends import KeyBackend
from django_ca.key_backends.hsm.keys import (
    PKCS11Ed448PrivateKey,
    PKCS11Ed25519PrivateKey,
    PKCS11EllipticCurvePrivateKey,
    PKCS11PrivateKeyTypes,
    PKCS11RSAPrivateKey,
)
from django_ca.key_backends.hsm.mixins import HSMKeyBackendMixin
from django_ca.key_backends.hsm.models import (
    HSMCreatePrivateKeyOptions,
    HSMStorePrivateKeyOptions,
    HSMUsePrivateKeyOptions,
)
from django_ca.key_backends.hsm.typehints import SupportedKeyType
from django_ca.typehints import (
    AllowedHashTypes,
    ArgumentGroup,
    CertificateExtension,
    EllipticCurves,
    HashAlgorithms,
    ParsableKeyType,
)
from django_ca.utils import get_cert_builder, int_to_hex

if TYPE_CHECKING:
    from django_ca.models import CertificateAuthority


class HSMBackend(
    HSMKeyBackendMixin,
    KeyBackend[HSMCreatePrivateKeyOptions, HSMStorePrivateKeyOptions, HSMUsePrivateKeyOptions],
):
    """A key backend to create and use private keys in a hardware security module (HSM)."""

    name = "hsm"
    title = "Store private keys using a hardware security module (HSM)"
    description = (
        "The private key will be stored on the hardware security module (HSM). The HSM makes sure that the"
        "private key can never be recovered and thus compromised."
    )
    use_model = HSMUsePrivateKeyOptions

    supported_key_types: tuple[SupportedKeyType, ...] = ("RSA", "EC", "Ed25519", "Ed448")
    supported_hash_algorithms: tuple[HashAlgorithms, ...] = ("SHA-224", "SHA-256", "SHA-384", "SHA-512")
    supported_elliptic_curves: tuple[EllipticCurves, ...] = tuple(constants.ELLIPTIC_CURVE_TYPES)

    _required_key_backend_options: Final[tuple[str, str, str]] = ("key_label", "key_id", "key_type")

    def _add_key_label_argument(self, group: ArgumentGroup, prefix: str = "") -> None:
        group.add_argument(
            f"--{self.argparse_prefix}{prefix}key-label",
            type=str,
            metavar="LABEL",
            help="%(metavar)s to use for the private key in the HSM.",
        )

    def _add_pin_arguments(self, group: ArgumentGroup, prefix: str = "") -> None:
        group.add_argument(
            f"--{self.argparse_prefix}{prefix}so-pin",
            type=str,
            metavar="PIN",
            help="Security officer %(metavar)s to access the HSM.",
        )
        group.add_argument(
            f"--{self.argparse_prefix}{prefix}user-pin",
            type=str,
            metavar="PIN",
            help="User %(metavar)s to access the HSM.",
        )

    def _get_pins(self, options: dict[str, Any], prefix: str = "") -> tuple[Optional[str], Optional[str]]:
        options_prefix = f"{self.options_prefix}{prefix.replace('-', '_')}"
        argparse_prefix = f"{self.argparse_prefix}{prefix}"

        so_pin: Optional[str] = options.get(f"{options_prefix}so_pin")
        if so_pin is None:
            so_pin = self.so_pin
        elif so_pin == "":
            so_pin = None

        user_pin: Optional[str] = options.get(f"{options_prefix}user_pin")
        if user_pin is None:
            user_pin = self.user_pin
        elif user_pin == "":
            user_pin = None

        if so_pin is not None and user_pin is not None:
            raise CommandError(
                "Both SO pin and user pin configured. To override a pin from settings, pass "
                f'--{argparse_prefix}so-pin="" or --{argparse_prefix}user-pin="".'
            )

        return so_pin, user_pin

    def _get_private_key(self, ca: "CertificateAuthority", session: Session) -> PKCS11PrivateKeyTypes:
        key_id: str = ca.key_backend_options["key_id"]
        key_label: str = ca.key_backend_options["key_label"]
        key_type: SupportedKeyType = ca.key_backend_options["key_type"]

        if key_type == "RSA":
            return PKCS11RSAPrivateKey(session, key_id, key_label)
        if key_type == "Ed448":
            return PKCS11Ed448PrivateKey(session, key_id, key_label)
        if key_type == "Ed25519":
            return PKCS11Ed25519PrivateKey(session, key_id, key_label)
        if key_type == "EC":
            return PKCS11EllipticCurvePrivateKey(session, key_id, key_label)

        raise ValueError(f"{key_type}: Unsupported key type.")

    def add_create_private_key_arguments(self, group: ArgumentGroup) -> None:
        self._add_key_label_argument(group)
        self._add_pin_arguments(group)

    def add_use_parent_private_key_arguments(self, group: ArgumentGroup) -> None:
        self._add_pin_arguments(group, "parent-")

    def add_store_private_key_arguments(self, group: ArgumentGroup) -> None:
        self._add_key_label_argument(group)
        self._add_pin_arguments(group)

    def add_use_private_key_arguments(self, group: ArgumentGroup) -> None:
        self._add_pin_arguments(group)

    def get_create_private_key_options(
        self,
        key_type: ParsableKeyType,
        key_size: Optional[int],
        elliptic_curve: Optional[str],
        options: dict[str, Any],
    ) -> HSMCreatePrivateKeyOptions:
        key_label = options[f"{self.options_prefix}key_label"]
        if not key_label:
            raise CommandError(
                f"--{self.argparse_prefix}key-label is a required option for this key backend."
            )

        so_pin, user_pin = self._get_pins(options)

        if key_type == "EC" and elliptic_curve is None:
            # NOTE: Currently all curves supported by cryptography are also supported by this backend.
            #       If this changes, a check should be added here (if the default is not supported by the
            #       backend).
            elliptic_curve = model_settings.CA_DEFAULT_ELLIPTIC_CURVE.name

        return HSMCreatePrivateKeyOptions(
            key_label=key_label,
            key_type=key_type,
            key_size=key_size,
            elliptic_curve=elliptic_curve,
            so_pin=so_pin,
            user_pin=user_pin,
        )

    def get_use_parent_private_key_options(
        self, ca: "CertificateAuthority", options: dict[str, Any]
    ) -> HSMUsePrivateKeyOptions:
        so_pin, user_pin = self._get_pins(options, "parent-")
        return HSMUsePrivateKeyOptions.model_validate(
            {"so_pin": so_pin, "user_pin": user_pin}, context={"ca": ca, "backend": self}, strict=True
        )

    def get_use_private_key_options(
        self, ca: "CertificateAuthority", options: dict[str, Any]
    ) -> HSMUsePrivateKeyOptions:
        so_pin, user_pin = self._get_pins(options)
        return HSMUsePrivateKeyOptions.model_validate(
            {"so_pin": so_pin, "user_pin": user_pin}, context={"ca": ca, "backend": self}, strict=True
        )

    def get_store_private_key_options(self, options: dict[str, Any]) -> HSMStorePrivateKeyOptions:
        key_label = options[f"{self.options_prefix}key_label"]
        so_pin, user_pin = self._get_pins(options)
        return HSMStorePrivateKeyOptions.model_validate(
            {"key_label": key_label, "so_pin": so_pin, "user_pin": user_pin},
            context={"backend": self},
            strict=True,
        )

    def is_usable(
        self,
        ca: "CertificateAuthority",
        use_private_key_options: Optional[HSMUsePrivateKeyOptions] = None,
    ) -> bool:
        if not ca.key_backend_options or not isinstance(ca.key_backend_options, dict):
            return False
        for option in self._required_key_backend_options:
            if not ca.key_backend_options.get(option):
                return False
        if use_private_key_options is None:
            return True

        try:
            with self.session(
                so_pin=use_private_key_options.so_pin, user_pin=use_private_key_options.user_pin
            ) as session:
                self._get_private_key(ca, session)
            return True
        except Exception:  # pylint: disable=broad-exception-caught  # want to always return bool
            return False

    def check_usable(
        self, ca: "CertificateAuthority", use_private_key_options: HSMUsePrivateKeyOptions
    ) -> None:
        if not ca.key_backend_options or not isinstance(ca.key_backend_options, dict):
            raise ValueError("key backend options are not defined.")
        for option in self._required_key_backend_options:
            if not ca.key_backend_options.get(option):
                raise ValueError(f"{option}: Required key option is not defined.")

        with self.session(
            so_pin=use_private_key_options.so_pin, user_pin=use_private_key_options.user_pin
        ) as session:
            self._get_private_key(ca, session)

    def create_private_key(
        self,
        ca: "CertificateAuthority",
        key_type: SupportedKeyType,  # type: ignore[override]  # more specific here
        options: HSMCreatePrivateKeyOptions,
    ) -> tuple[CertificateIssuerPublicKeyTypes, HSMUsePrivateKeyOptions]:
        key_id = int_to_hex(x509.random_serial_number())
        key_label = options.key_label

        with self.session(so_pin=options.so_pin, user_pin=options.user_pin, rw=True) as session:
            private_key = self._create_private_key(
                session,
                key_id,
                key_label,
                key_type,
                key_size=options.key_size,
                elliptic_curve=options.elliptic_curve,
            )

            public_key = private_key.public_key()

        ca.key_backend_options = {"key_id": key_id, "key_label": key_label, "key_type": key_type}
        use_private_key_options = HSMUsePrivateKeyOptions.model_validate(
            {"so_pin": options.so_pin, "user_pin": options.user_pin}, context={"ca": ca, "backend": self}
        )

        return public_key, use_private_key_options

    def store_private_key(
        self,
        ca: "CertificateAuthority",
        key: CertificateIssuerPrivateKeyTypes,
        certificate: x509.Certificate,
        options: HSMStorePrivateKeyOptions,
    ) -> None:
        key_id = int_to_hex(x509.random_serial_number())
        public_key = certificate.public_key()

        if isinstance(key, rsa.RSAPrivateKey):
            key_type: SupportedKeyType = "RSA"
            key_der = key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
            key_attrs = decode_rsa_private_key(key_der)
            pub_der = public_key.public_bytes(
                serialization.Encoding.DER, format=serialization.PublicFormat.PKCS1
            )
            pub_attrs = decode_rsa_public_key(pub_der)
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            key_type = "EC"
            key_der = key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
            key_attrs = decode_ec_private_key(key_der)
            pub_der = public_key.public_bytes(
                serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            pub_attrs = decode_ec_public_key(pub_der)
        elif isinstance(key, (ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey)):
            raise ValueError("Import of Ed448/Ed25519 keys is not implemented.")
        else:
            raise ValueError(f"{key}: Importing a key of this type is not supported.")

        shared_attrs = {
            pkcs11.Attribute.TOKEN: True,
            pkcs11.Attribute.PRIVATE: True,
            pkcs11.Attribute.ID: key_id.encode(),
            pkcs11.Attribute.LABEL: options.key_label,
        }
        key_attrs.update(shared_attrs)
        pub_attrs.update(shared_attrs)

        with self.session(so_pin=options.so_pin, user_pin=options.user_pin, rw=True) as session:
            session.create_object(key_attrs)
            session.create_object(pub_attrs)

        ca.key_backend_options = {"key_id": key_id, "key_label": options.key_label, "key_type": key_type}

    def sign_certificate(
        self,
        ca: "CertificateAuthority",
        use_private_key_options: HSMUsePrivateKeyOptions,
        public_key: CertificateIssuerPublicKeyTypes,
        serial: int,
        algorithm: Optional[AllowedHashTypes],
        issuer: x509.Name,
        subject: x509.Name,
        not_after: datetime,
        extensions: Sequence[CertificateExtension],
    ) -> x509.Certificate:
        builder = get_cert_builder(not_after, serial=serial)
        builder = builder.public_key(public_key)
        builder = builder.issuer_name(issuer)
        builder = builder.subject_name(subject)
        for extension in extensions:
            builder = builder.add_extension(extension.value, critical=extension.critical)

        with self.session(
            so_pin=use_private_key_options.so_pin, user_pin=use_private_key_options.user_pin
        ) as session:
            private_key = self._get_private_key(ca, session)
            return builder.sign(private_key=private_key, algorithm=algorithm)

    def sign_certificate_revocation_list(
        self,
        ca: "CertificateAuthority",
        use_private_key_options: HSMUsePrivateKeyOptions,
        builder: x509.CertificateRevocationListBuilder,
        algorithm: Optional[AllowedHashTypes],
    ) -> x509.CertificateRevocationList:
        with self.session(
            so_pin=use_private_key_options.so_pin, user_pin=use_private_key_options.user_pin
        ) as session:
            private_key = self._get_private_key(ca, session)
            return builder.sign(private_key=private_key, algorithm=algorithm)

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

"""Storages."""

import typing
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic_core.core_schema import ValidationInfo

from cryptography import x509
from cryptography.hazmat.primitives import serialization
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

from django.conf import settings
from django.core.files.base import ContentFile
from django.core.files.storage import storages

from django_ca import constants
from django_ca.conf import model_settings
from django_ca.key_backends.base import CreatePrivateKeyOptionsBaseModel, KeyBackend
from django_ca.management.actions import PasswordAction
from django_ca.pydantic.type_aliases import Base64EncodedBytes, EllipticCurveTypeAlias
from django_ca.typehints import (
    AllowedHashTypes,
    ArgumentGroup,
    CertificateExtension,
    EllipticCurves,
    ParsableKeyType,
)
from django_ca.utils import generate_private_key, get_cert_builder

if typing.TYPE_CHECKING:
    from django_ca.models import CertificateAuthority


class StoragesCreatePrivateKeyOptions(CreatePrivateKeyOptionsBaseModel):
    """Options for initializing private keys."""

    # NOTE: we set frozen here to prevent accidental coding mistakes. Models should be immutable.
    model_config = ConfigDict(arbitrary_types_allowed=True)

    password: Optional[bytes]
    path: Path
    elliptic_curve: Optional[EllipticCurveTypeAlias] = None

    @model_validator(mode="after")
    def validate_elliptic_curve(self) -> "StoragesCreatePrivateKeyOptions":
        """Validate that the elliptic curve is not set for invalid key types."""
        if self.key_type == "EC" and self.elliptic_curve is None:
            self.elliptic_curve = model_settings.CA_DEFAULT_ELLIPTIC_CURVE
        elif self.key_type != "EC" and self.elliptic_curve is not None:
            raise ValueError(f"Elliptic curves are not supported for {self.key_type} keys.")
        return self


class StoragesStorePrivateKeyOptions(BaseModel):
    """Options for storing a private key."""

    # NOTE: we set frozen here to prevent accidental coding mistakes. Models should be immutable.
    model_config = ConfigDict(frozen=True)

    path: Path
    password: Optional[bytes]


class StoragesUsePrivateKeyOptions(BaseModel):
    """Options for using a private key."""

    # NOTE: we set frozen here to prevent accidental coding mistakes. Models should be immutable.
    model_config = ConfigDict(frozen=True)

    password: Optional[Base64EncodedBytes] = Field(default=None, validate_default=True)

    @field_validator("password", mode="after")
    @classmethod
    def load_default_password(cls, password: Optional[bytes], info: ValidationInfo) -> Optional[bytes]:
        """Validator to load the password from CA_PASSWORDS if not given."""
        if info.context and password is None:
            ca: CertificateAuthority = info.context.get("ca")
            if ca is not None:  # pragma: no branch  # ca is always set, this is just a precaution.
                if settings_password := model_settings.CA_PASSWORDS.get(ca.serial):
                    return settings_password

        return password


class StoragesBackend(
    KeyBackend[StoragesCreatePrivateKeyOptions, StoragesStorePrivateKeyOptions, StoragesUsePrivateKeyOptions]
):
    """The default storage backend that uses Django's file storage API."""

    name = "storages"
    title = "Store private keys using the Django file storage API"
    description = (
        "It is most commonly used to store private keys on the filesystem. Custom file storage backends can "
        "be used to store keys on other systems (e.g. a cloud storage system)."
    )
    use_model = StoragesUsePrivateKeyOptions

    supported_key_types: tuple[ParsableKeyType, ...] = constants.PARSABLE_KEY_TYPES
    supported_elliptic_curves: tuple[EllipticCurves, ...] = tuple(constants.ELLIPTIC_CURVE_TYPES)

    # Backend options
    storage_alias: str

    def __init__(self, alias: str, storage_alias: str) -> None:
        if storage_alias not in settings.STORAGES:
            raise ValueError(f"{alias}: {storage_alias}: Storage alias is not configured.")
        super().__init__(alias, storage_alias=storage_alias)

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, StoragesBackend) and self.storage_alias == other.storage_alias

    def _add_password_argument(self, group: ArgumentGroup) -> None:
        group.add_argument(
            f"--{self.argparse_prefix}password",
            nargs="?",
            action=PasswordAction,
            metavar="PASSWORD",
            prompt="Password for CA: ",
            help="Password for the private key of the CA, if stored using the Django storage system.",
        )

    def _add_path_argument(self, group: ArgumentGroup) -> None:
        group.add_argument(
            f"--{self.argparse_prefix}path",
            type=Path,
            default=Path("ca"),
            help="Path for storing the private key (in the storage backend, default: %(default)s).",
        )

    def add_create_private_key_arguments(self, group: ArgumentGroup) -> None:
        self._add_path_argument(group)
        group.add_argument(
            f"--{self.argparse_prefix}password",
            nargs="?",
            action=PasswordAction,
            help="Encrypt the private key with PASSWORD. If PASSWORD is not passed, you will be prompted. By "
            "default, the private key is not encrypted.",
        )

    def add_use_parent_private_key_arguments(self, group: ArgumentGroup) -> None:
        group.add_argument(
            f"--{self.argparse_prefix}parent-password",
            nargs="?",
            action=PasswordAction,
            metavar="PASSWORD",
            prompt="Password for parent CA: ",
            help="Password for the private key of the parent CA, if stored using the Django storage system.",
        )

    def add_store_private_key_arguments(self, group: ArgumentGroup) -> None:
        self._add_password_argument(group)
        self._add_path_argument(group)

    def add_use_private_key_arguments(self, group: ArgumentGroup) -> None:
        self._add_password_argument(group)

    def get_create_private_key_options(
        self,
        key_type: ParsableKeyType,
        key_size: Optional[int],
        elliptic_curve: Optional[EllipticCurves],  # type: ignore[override]
        options: dict[str, Any],
    ) -> StoragesCreatePrivateKeyOptions:
        return StoragesCreatePrivateKeyOptions(
            key_type=key_type,
            password=options[f"{self.options_prefix}password"],
            path=options[f"{self.options_prefix}path"],
            key_size=key_size,
            elliptic_curve=elliptic_curve,
        )

    def get_store_private_key_options(self, options: dict[str, Any]) -> StoragesStorePrivateKeyOptions:
        return StoragesStorePrivateKeyOptions(
            password=options[f"{self.options_prefix}password"], path=options[f"{self.options_prefix}path"]
        )

    def get_use_private_key_options(
        self, ca: "CertificateAuthority", options: dict[str, Any]
    ) -> StoragesUsePrivateKeyOptions:
        return StoragesUsePrivateKeyOptions.model_validate(
            {"password": options.get(f"{self.options_prefix}password")},
            context={"ca": ca, "backend": self},
            strict=True,
        )

    def get_use_parent_private_key_options(
        self, ca: "CertificateAuthority", options: dict[str, Any]
    ) -> StoragesUsePrivateKeyOptions:
        return StoragesUsePrivateKeyOptions.model_validate(
            {"password": options[f"{self.options_prefix}parent_password"]},
            context={"ca": ca, "backend": self},
        )

    def create_private_key(
        self,
        ca: "CertificateAuthority",
        key_type: ParsableKeyType,
        options: StoragesCreatePrivateKeyOptions,
    ) -> tuple[CertificateIssuerPublicKeyTypes, StoragesUsePrivateKeyOptions]:
        storage = storages[self.storage_alias]

        if options.password is None:
            encryption: serialization.KeySerializationEncryption = serialization.NoEncryption()
        else:
            encryption = serialization.BestAvailableEncryption(options.password)

        key = generate_private_key(options.key_size, key_type, options.elliptic_curve)

        der = key.private_bytes(
            encoding=Encoding.DER, format=PrivateFormat.PKCS8, encryption_algorithm=encryption
        )

        # write private key to file and update ourselves so that we are able to sign certificates
        safe_serial = ca.serial.replace(":", "")
        path = storage.save(str(options.path / f"{safe_serial}.key"), ContentFile(der))

        # Update model instance
        ca.key_backend_options = {"path": path}

        use_private_key_options = StoragesUsePrivateKeyOptions.model_validate(
            {"password": options.password}, context={"ca": ca, "backend": self}
        )

        return key.public_key(), use_private_key_options

    def store_private_key(
        self,
        ca: "CertificateAuthority",
        key: CertificateIssuerPrivateKeyTypes,
        certificate: x509.Certificate,
        options: StoragesStorePrivateKeyOptions,
    ) -> None:
        storage = storages[self.storage_alias]

        if options.password is None:
            encryption: serialization.KeySerializationEncryption = serialization.NoEncryption()
        else:
            encryption = serialization.BestAvailableEncryption(options.password)

        der = key.private_bytes(
            encoding=Encoding.DER, format=PrivateFormat.PKCS8, encryption_algorithm=encryption
        )

        safe_serial = ca.serial.replace(":", "")
        path = storage.save(str(options.path / f"{safe_serial}.key"), ContentFile(der))

        # Update model instance
        ca.key_backend_options = {"path": path}

    def get_key(
        self, ca: "CertificateAuthority", use_private_key_options: StoragesUsePrivateKeyOptions
    ) -> CertificateIssuerPrivateKeyTypes:
        """The CAs private key as private key."""
        storage = storages[self.storage_alias]
        path = ca.key_backend_options["path"]

        # Load encoded private key data from the filesystem
        stream = storage.open(path, mode="rb")
        try:
            key_data: bytes = stream.read()
        finally:
            stream.close()

        password = use_private_key_options.password

        try:
            key = typing.cast(  # type validated below
                CertificateIssuerPrivateKeyTypes, load_der_private_key(key_data, password)
            )
        except ValueError:
            try:
                key = typing.cast(  # type validated below
                    CertificateIssuerPrivateKeyTypes, load_pem_private_key(key_data, password)
                )
            except ValueError as ex2:
                # cryptography passes the OpenSSL error directly here and it is notoriously unstable.
                raise ValueError("Could not decrypt private key - bad password?") from ex2

        if not isinstance(key, constants.PRIVATE_KEY_TYPES):  # pragma: no cover
            raise ValueError("Private key of this type is not supported.")

        return key

    def is_usable(
        self,
        ca: "CertificateAuthority",
        use_private_key_options: Optional[StoragesUsePrivateKeyOptions] = None,
    ) -> bool:
        # If key_backend_options is not set or path is not set, it is certainly unusable.
        if not ca.key_backend_options or not ca.key_backend_options.get("path"):
            return False

        # If options are not passed, we return True if the file exists.
        if not use_private_key_options:
            return storages[self.storage_alias].exists(ca.key_backend_options["path"])

        try:
            self.get_key(ca, use_private_key_options)
            return True
        except Exception:  # pylint: disable=broad-exception-caught  # want to always return bool
            return False

    def check_usable(
        self, ca: "CertificateAuthority", use_private_key_options: StoragesUsePrivateKeyOptions
    ) -> None:
        """Check if the given CA is usable, raise ValueError if not.

        The `options` are the options returned by
        :py:func:`~django_ca.key_backends.base.KeyBackend.get_use_private_key_options`. It may be ``None`` in
        cases where key options cannot (yet) be loaded. If ``None``, the backend should return ``False`` if it
        knows for sure that it will not be usable, and ``True`` if usability cannot be determined.
        """
        if not ca.key_backend_options or not ca.key_backend_options.get("path"):
            raise ValueError(f"{ca.key_backend_options}: Path not configured in database.")

        try:
            self.get_key(ca, use_private_key_options)
        except FileNotFoundError as ex:
            storage = storages[self.storage_alias]
            try:
                path = storage.path(ca.key_backend_options["path"])
            except NotImplementedError:  # pragma: no cover
                # Backends that do not implement path() should raise NotImplementedError
                path = ca.key_backend_options["path"]

            raise ValueError(f"{path}: Private key file not found.") from ex
        except ValueError:
            raise
        except Exception as ex:
            raise ValueError(*ex.args) from ex

    def sign_certificate(
        self,
        ca: "CertificateAuthority",
        use_private_key_options: StoragesUsePrivateKeyOptions,
        public_key: CertificateIssuerPublicKeyTypes,
        serial: int,
        algorithm: Optional[AllowedHashTypes],
        issuer: x509.Name,
        subject: x509.Name,
        expires: datetime,
        extensions: Sequence[CertificateExtension],
    ) -> x509.Certificate:
        builder = get_cert_builder(expires, serial=serial)
        builder = builder.public_key(public_key)
        builder = builder.issuer_name(issuer)
        builder = builder.subject_name(subject)
        for extension in extensions:
            builder = builder.add_extension(extension.value, critical=extension.critical)
        return builder.sign(private_key=self.get_key(ca, use_private_key_options), algorithm=algorithm)

    def sign_certificate_revocation_list(
        self,
        ca: "CertificateAuthority",
        use_private_key_options: StoragesUsePrivateKeyOptions,
        builder: x509.CertificateRevocationListBuilder,
        algorithm: Optional[AllowedHashTypes],
    ) -> x509.CertificateRevocationList:
        return builder.sign(private_key=self.get_key(ca, use_private_key_options), algorithm=algorithm)

    def get_ocsp_key_size(
        self, ca: "CertificateAuthority", use_private_key_options: StoragesUsePrivateKeyOptions
    ) -> int:
        """Get the default key size for OCSP keys. This is only called for RSA or DSA keys."""
        key = self.get_key(ca, use_private_key_options)
        if not isinstance(key, (rsa.RSAPrivateKey, dsa.DSAPrivateKey)):
            raise ValueError("This function should only be called with RSA/DSA CAs.")
        return key.key_size

    def get_ocsp_key_elliptic_curve(
        self, ca: "CertificateAuthority", use_private_key_options: StoragesUsePrivateKeyOptions
    ) -> ec.EllipticCurve:
        """Get the default elliptic curve for OCSP keys. This is only called for elliptic curve keys."""
        key = self.get_key(ca, use_private_key_options)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError("This function should only be called with EllipticCurve-based CAs.")
        return key.curve

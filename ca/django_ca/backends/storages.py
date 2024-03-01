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
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import pydantic
from pydantic import ConfigDict

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
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

from django.core.files.base import ContentFile
from django.core.files.storage import storages

from django_ca import constants
from django_ca.backends.base import KeyBackend
from django_ca.management.actions import PasswordAction
from django_ca.management.base import add_elliptic_curve, add_key_size, add_password
from django_ca.typehints import AllowedHashTypes, ArgumentGroup, ParsableKeyType
from django_ca.utils import generate_private_key, get_cert_builder, read_file, validate_private_key_parameters

if typing.TYPE_CHECKING:
    from django_ca.models import CertificateAuthority


class CreatePrivateKeyOptions(pydantic.BaseModel):
    """Options for initializing private keys."""

    # NOTE: we set frozen here to prevent accidental coding mistakes. Models should be immutable.
    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    password: Optional[bytes]
    path: Path
    key_size: Optional[int] = None
    elliptic_curve: Optional[ec.EllipticCurve] = None


class LoadPrivateKeyOptions(pydantic.BaseModel):
    """Options for loading a private key."""

    # NOTE: we set frozen here to prevent accidental coding mistakes. Models should be immutable.
    model_config = ConfigDict(frozen=True)

    password: Optional[bytes]


class StoragesBackend(KeyBackend[CreatePrivateKeyOptions, LoadPrivateKeyOptions]):
    """A simple storage backend that does not yet do much."""

    name = "storages"
    title = "Store private keys using the Django file storage API"
    description = (
        "It is most commonly used to store private keys on the filesystem. Custom file storage backends can "
        "be used to store keys on other systems (e.g. a cloud storage system)."
    )
    load_model = LoadPrivateKeyOptions

    # Backend options
    storage_alias: str

    # cached variables
    _key: Optional[CertificateIssuerPrivateKeyTypes] = None

    def add_private_key_arguments(cls, group: ArgumentGroup) -> None:
        group.add_argument(
            "--path",
            type=Path,
            default=Path("ca"),
            help="Path where to store Certificate Authorities (within the configured storage backend).",
        )
        add_key_size(group)
        add_elliptic_curve(group)
        add_password(
            group,
            help_text="Encrypt the private key with PASSWORD. If PASSWORD is not passed, you will be "
            "prompted. By default, the private key is not encrypted.",
        )

    def add_parent_private_key_arguments(cls, group: ArgumentGroup) -> None:
        group.add_argument(
            "--parent-password",
            nargs="?",
            action=PasswordAction,
            metavar="PASSWORD",
            prompt="Password for parent CA: ",
            help="Password for the private key of the parent CA, if stored using the Django storage system.",
        )

    def get_create_private_key_options(
        self, key_type: ParsableKeyType, options: Dict[str, Any]
    ) -> CreatePrivateKeyOptions:
        key_size, elliptic_curve = validate_private_key_parameters(
            key_type, options["key_size"], options["elliptic_curve"]
        )
        return CreatePrivateKeyOptions(
            password=options["password"],
            path=options["path"],
            key_size=key_size,
            elliptic_curve=elliptic_curve,
        )

    def get_load_private_key_options(self, options: Dict[str, Any]) -> LoadPrivateKeyOptions:
        return LoadPrivateKeyOptions(password=options["password"])

    def get_load_parent_private_key_options(self, options: Dict[str, Any]) -> LoadPrivateKeyOptions:
        return LoadPrivateKeyOptions(password=options["parent_password"])

    def create_private_key(
        self, ca: "CertificateAuthority", key_type: ParsableKeyType, options: CreatePrivateKeyOptions
    ) -> CertificateIssuerPublicKeyTypes:
        storage = storages[self.storage_alias]

        if options.password is None:
            encryption: serialization.KeySerializationEncryption = serialization.NoEncryption()
        else:
            encryption = serialization.BestAvailableEncryption(options.password)

        self._key = generate_private_key(options.key_size, key_type, options.elliptic_curve)

        der = self._key.private_bytes(
            encoding=Encoding.DER, format=PrivateFormat.PKCS8, encryption_algorithm=encryption
        )

        # write private key to file and update ourselves so that we are able to sign certificates
        safe_serial = ca.serial.replace(":", "")
        path = storage.save(str(options.path / f"{safe_serial}.key"), ContentFile(der))

        # Update model instance
        ca.key_backend_options = {"path": path}

        return self._key.public_key()

    def get_key(
        self, ca: "CertificateAuthority", load_options: LoadPrivateKeyOptions
    ) -> CertificateIssuerPrivateKeyTypes:
        """The CAs private key as private key."""
        path = ca.key_backend_options["path"]
        key_data = read_file(path)
        password = load_options.password

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

    def is_usable(self, ca: "CertificateAuthority", options: LoadPrivateKeyOptions) -> bool:
        try:
            self.get_key(ca, options)
            return True
        except Exception:
            return False

    def sign_certificate(
        self,
        ca: "CertificateAuthority",
        load_options: LoadPrivateKeyOptions,
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
        return builder.sign(private_key=self.get_key(ca, load_options), algorithm=algorithm)

    def sign_certificate_revocation_list(
        self,
        ca: "CertificateAuthority",
        load_options: LoadPrivateKeyOptions,
        builder: x509.CertificateRevocationListBuilder,
        algorithm: Optional[AllowedHashTypes],
    ) -> x509.CertificateRevocationList:
        return builder.sign(private_key=self.get_key(ca, load_options), algorithm=algorithm)

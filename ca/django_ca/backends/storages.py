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

from ca import settings
from django_ca import ca_settings, constants
from django_ca.backends.base import KeyBackend
from django_ca.management.actions import PasswordAction
from django_ca.management.base import add_elliptic_curve, add_key_size, add_password
from django_ca.typehints import AllowedHashTypes, ArgumentGroup, ParsableKeyType
from django_ca.utils import (
    file_exists,
    generate_private_key,
    get_cert_builder,
    read_file,
    validate_private_key_parameters,
)


class StoragesBackend(KeyBackend):
    """A simple storage backend that does not yet do much."""

    name = "storages"
    title = "Store private keys using the Django file storage API"
    description = (
        "It is most commonly used to store private keys on the filesystem. Custom file storage backends can "
        "be used to store keys on other systems (e.g. a cloud storage system)."
    )

    # Common options
    alias: str
    path: Optional[str] = None  # not set when not yet initialized
    password: Optional[bytes]

    # Initialization options
    _base_path: Optional[Path]
    _key_type: Optional[ParsableKeyType]
    _key_size: Optional[int]
    _elliptic_curve: Optional[ec.EllipticCurve]

    # cached variables
    _key: Optional[CertificateIssuerPrivateKeyTypes] = None

    @classmethod
    def add_private_key_arguments(cls, group: ArgumentGroup) -> None:
        storage_aliases = tuple(key for key in settings.STORAGES if key not in ("default", "staticfiles"))
        group.add_argument(
            "--storage-alias",
            choices=storage_aliases,
            default=ca_settings.CA_DEFAULT_STORAGE_ALIAS,
            help="Storage alias identifying the storage configured in the STORAGES setting "
            "(default: %(default)s).",
        )
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

    @classmethod
    def add_parent_private_key_arguments(cls, group: ArgumentGroup) -> None:
        group.add_argument(
            "--parent-password",
            nargs="?",
            action=PasswordAction,
            metavar="PASSWORD",
            prompt="Password for parent CA: ",
            help="Password for the private key of the parent CA, if stored using the Django storage system.",
        )

    @classmethod
    def load_from_options(cls, key_type: ParsableKeyType, options: Dict[str, Any]) -> "StoragesBackend":
        key_size, elliptic_curve = validate_private_key_parameters(
            key_type, options["key_size"], options["elliptic_curve"]
        )
        return cls(
            alias=options["storage_alias"],
            password=options["password"],
            _base_path=options["path"],
            _key_type=key_type,
            _key_size=key_size,
            _elliptic_curve=elliptic_curve,
        )

    @classmethod
    def get_parent_backend_options(cls, options: Dict[str, Any]) -> Dict[str, Any]:
        return {"password": options["parent_password"]}

    @property
    def usable(self) -> bool:
        if self._key is not None:
            return True
        if not self.path:
            return False
        return file_exists(self.path)

    def initialize(self) -> CertificateIssuerPublicKeyTypes:
        if self._key_type is None or self.ca is None or self._base_path is None:
            raise ValueError("Backend is not initialized.")
        storage = storages[self.alias]

        if self.password is None:
            encryption: serialization.KeySerializationEncryption = serialization.NoEncryption()
        else:
            encryption = serialization.BestAvailableEncryption(self.password)

        self._key = generate_private_key(self._key_size, self._key_type, self._elliptic_curve)

        der = self._key.private_bytes(
            encoding=Encoding.DER, format=PrivateFormat.PKCS8, encryption_algorithm=encryption
        )

        # write private key to file and update ourselves so that we are able to sign certificates
        safe_serial = self.ca.serial.replace(":", "")
        path = storage.save(str(self._base_path / f"{safe_serial}.key"), ContentFile(der))
        self.path = path

        # Update model instance
        self.ca.key_backend_options = {"alias": self.alias, "path": path}

        return self._key.public_key()

    @property
    def key(self) -> CertificateIssuerPrivateKeyTypes:
        """The CAs private key as private key."""
        if self.path is None:
            raise ValueError("Backend not initialized.")

        if self._key is None:
            key_data = read_file(self.path)

            try:
                self._key = typing.cast(  # type validated below
                    CertificateIssuerPrivateKeyTypes, load_der_private_key(key_data, self.password)
                )
            except ValueError:
                try:
                    self._key = typing.cast(  # type validated below
                        CertificateIssuerPrivateKeyTypes, load_pem_private_key(key_data, self.password)
                    )
                except ValueError as ex2:
                    # cryptography passes the OpenSSL error directly here and it is notoriously unstable.
                    raise ValueError("Could not decrypt private key - bad password?") from ex2

        if not isinstance(self._key, constants.PRIVATE_KEY_TYPES):  # pragma: no cover
            raise ValueError("Private key of this type is not supported.")

        return self._key

    def sign_certificate(
        self,
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
        return builder.sign(private_key=self.key, algorithm=algorithm)

    def sign_certificate_revocation_list(
        self, builder: x509.CertificateRevocationListBuilder, algorithm: Optional[AllowedHashTypes]
    ) -> x509.CertificateRevocationList:
        return builder.sign(private_key=self.key, algorithm=algorithm)

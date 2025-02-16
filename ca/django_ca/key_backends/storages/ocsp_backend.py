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

"""OCSP key backend using the Django Storages system."""

import base64
import os

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives._serialization import Encoding, PrivateFormat
from cryptography.hazmat.primitives.asymmetric import ec

from django.conf import settings
from django.core.files.base import ContentFile
from django.core.files.storage import storages

from django_ca.conf import model_settings
from django_ca.key_backends.base import CryptographyOCSPKeyBackend
from django_ca.models import CertificateAuthority
from django_ca.typehints import ParsableKeyType
from django_ca.utils import generate_private_key, read_file


class StoragesOCSPBackend(CryptographyOCSPKeyBackend):
    """OCSP key backend storing files on the local file system."""

    # Backend options
    storage_alias: str
    path: str
    encrypt_private_key: bool

    def __init__(
        self, alias: str, storage_alias: str, path: str = "ocsp/", encrypt_private_key: bool = True
    ) -> None:
        if storage_alias not in settings.STORAGES:
            raise ValueError(f"{alias}: {storage_alias}: Storage alias is not configured.")
        if not path.endswith("/"):
            path += "/"
        super().__init__(
            alias, storage_alias=storage_alias, path=path, encrypt_private_key=encrypt_private_key
        )

    def create_private_key(
        self,
        ca: "CertificateAuthority",
        key_type: ParsableKeyType,
        key_size: int | None,
        elliptic_curve: ec.EllipticCurve | None,
    ) -> x509.CertificateSigningRequest:
        # Generate the private key.
        private_key = generate_private_key(key_size, key_type, elliptic_curve)

        if self.encrypt_private_key is True:
            random_password = os.urandom(32)
            encoded_password = base64.b64encode(random_password).decode()
            ca.ocsp_key_backend_options["private_key"]["password"] = encoded_password
            encryption: serialization.KeySerializationEncryption = serialization.BestAvailableEncryption(
                random_password
            )
        else:
            encryption = serialization.NoEncryption()

        # Serialize and store the key on the file system.
        private_der = private_key.private_bytes(
            encoding=Encoding.DER,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )
        storage = storages[model_settings.CA_DEFAULT_STORAGE_ALIAS]
        private_key_path = storage.save(f"{self.path}{ca.serial}.key", ContentFile(private_der))

        # Set private key path in model, so that it can be loaded later.
        ca.ocsp_key_backend_options["private_key"]["path"] = private_key_path

        # Generate the CSR to return to the caller.
        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([]))
        csr_algorithm = self.get_csr_algorithm(key_type)
        csr = csr_builder.sign(private_key, csr_algorithm)
        return csr

    def get_private_key_password(self, ca: "CertificateAuthority") -> bytes | None:
        if encoded_password := ca.ocsp_key_backend_options["private_key"].get("password"):
            return base64.b64decode(encoded_password)
        return None

    def load_private_key_data(self, ca: "CertificateAuthority") -> bytes:
        private_key_path = ca.ocsp_key_backend_options["private_key"]["path"]
        return read_file(private_key_path)

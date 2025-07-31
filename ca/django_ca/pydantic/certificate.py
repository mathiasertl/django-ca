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
from datetime import datetime
from functools import cached_property
from typing import Any, Literal

from pydantic import BaseModel, model_validator

from cryptography import x509
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from cryptography.hazmat.primitives.serialization import Encoding

from django_ca.constants import HASH_ALGORITHM_TYPES
from django_ca.models import X509CertMixin
from django_ca.pydantic import NameModel
from django_ca.pydantic.extensions import CertificateExtensionModel
from django_ca.pydantic.type_aliases import HashAlgorithmName, OIDType
from django_ca.typehints import HashAlgorithms, Self


class CertificateModel(BaseModel):
    serial_number: int
    version: Literal[x509.Version.v1.value, x509.Version.v3.value]
    not_valid_before: datetime
    not_valid_after: datetime
    issuer: NameModel
    subject: NameModel
    signature_hash_algorithm: HashAlgorithmName | None
    signature_algorithm_oid: OIDType
    public_key_algorithm_oid: OIDType
    # TODO
    # signature_algorithm_parameters
    extensions: list[CertificateExtensionModel]
    pem: str

    @model_validator(mode="before")
    @classmethod
    def model_validate(cls, obj: Any) -> Self:
        if isinstance(obj, X509CertMixin):
            obj = obj.pub.loaded

        if isinstance(obj, x509.Certificate):
            pem = obj.public_bytes(Encoding.PEM).decode("ascii")
            return CertificateModel(
                serial_number=obj.serial_number,
                version=obj.version.value,
                not_valid_before=obj.not_valid_before_utc,
                not_valid_after=obj.not_valid_after_utc,
                issuer=obj.issuer,
                subject=obj.subject,
                signature_hash_algorithm=obj.signature_hash_algorithm,
                signature_algorithm_oid=obj.signature_algorithm_oid,
                public_key_algorithm_oid=obj.public_key_algorithm_oid,
                extensions=obj.extensions,
                pem=pem,
            )
        return obj

    @cached_property
    def cryptography(self) -> x509.Certificate:
        return x509.load_pem_x509_certificate(self.pem.encode("ascii"))

    def fingerprint(self, algorithm: HashAlgorithms | HashAlgorithm) -> bytes:
        if isinstance(algorithm, str):
            algorithm = HASH_ALGORITHM_TYPES[algorithm]
        return self.cryptography.fingerprint(algorithm)

    def public_key(self):
        return self.cryptography.public_key()

    def public_bytes(self, encoding: str | Encoding):
        if isinstance(encoding, str):
            encoding = Encoding[encoding]
        return self.cryptography.public_bytes(encoding)

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

"""Module for Certifiate."""

from datetime import datetime
from functools import cached_property
from typing import Annotated, Any, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, model_validator
from pydantic_core.core_schema import ValidationInfo

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from cryptography.hazmat.primitives.serialization import Encoding

from django_ca.constants import HASH_ALGORITHM_NAMES, HASH_ALGORITHM_TYPES
from django_ca.models import Certificate, CertificateAuthority, X509CertMixin
from django_ca.pydantic import (
    AuthorityInformationAccessModel,
    CertificatePoliciesModel,
    CRLDistributionPointsModel,
    IssuerAlternativeNameModel,
    NameModel,
)
from django_ca.pydantic.base import CryptographyModel
from django_ca.pydantic.ec import ECDSAModel
from django_ca.pydantic.extensions import CertificateExtensionModel
from django_ca.pydantic.padding import AsymmetricPaddingTypes
from django_ca.pydantic.type_aliases import HashAlgorithmName, OIDType
from django_ca.typehints import HashAlgorithms


def version_validator(value: Any) -> Any:
    """Convert cryptography version into an integer."""
    if isinstance(value, x509.Version):
        return value.value
    return value


def ecdsa_validator(value: Any) -> Any:
    """Validator for ECDSA model type."""
    if isinstance(value, ec.ECDSA):
        return ECDSAModel.model_validate(value)
    return value


SignatureAlgorithmParameters = Annotated[
    AsymmetricPaddingTypes | ECDSAModel | None, BeforeValidator(ecdsa_validator)
]


class CertificateModel(CryptographyModel[x509.Certificate]):
    """Model for :class:`cg:~cryptography.x509.Certificate`."""

    serial_number: int
    version: Annotated[  # type: ignore[name-defined]  # false positive
        Literal[x509.Version.v1.value, x509.Version.v3.value],
        BeforeValidator(version_validator),
    ]
    not_valid_before: datetime
    not_valid_after: datetime
    issuer: NameModel
    subject: NameModel
    signature_hash_algorithm: HashAlgorithmName | None
    signature_algorithm_oid: OIDType
    public_key_algorithm_oid: OIDType
    signature_algorithm_parameters: SignatureAlgorithmParameters
    extensions: list[CertificateExtensionModel]
    pem: str

    @model_validator(mode="before")
    @classmethod
    def validate_cryptography(cls, obj: Any) -> Any:
        """Model validator to parse cryptography models."""
        if isinstance(obj, x509.Certificate):
            pem = obj.public_bytes(Encoding.PEM).decode("ascii")
            return {
                "serial_number": obj.serial_number,
                "version": obj.version.value,
                "not_valid_before": obj.not_valid_before_utc,
                "not_valid_after": obj.not_valid_after_utc,
                "issuer": obj.issuer,
                "subject": obj.subject,
                "signature_hash_algorithm": obj.signature_hash_algorithm,
                "signature_algorithm_oid": obj.signature_algorithm_oid,
                "public_key_algorithm_oid": obj.public_key_algorithm_oid,
                "signature_algorithm_parameters": obj.signature_algorithm_parameters,
                "extensions": obj.extensions,
                "pem": pem,
            }
        return obj

    @cached_property
    def cryptography(self) -> x509.Certificate:
        """Convert this model instance to a matching cryptography object."""
        return x509.load_pem_x509_certificate(self.pem.encode("ascii"))

    def fingerprint(self, algorithm: HashAlgorithms | HashAlgorithm) -> bytes:
        """See :class:`cg:~cryptography.x509.Certificate`."""
        if isinstance(algorithm, str):
            algorithm = HASH_ALGORITHM_TYPES[algorithm]()
        return self.cryptography.fingerprint(algorithm)

    def public_key(self) -> CertificatePublicKeyTypes:
        """See :class:`cg:~cryptography.x509.Certificate`."""
        return self.cryptography.public_key()

    def public_bytes(self, encoding: str | Encoding) -> bytes:
        """See :class:`cg:~cryptography.x509.Certificate`."""
        if isinstance(encoding, str):
            encoding = Encoding[encoding]
        return self.cryptography.public_bytes(encoding)


class WatcherModel(BaseModel):
    """Model for a Watcher as stored in the database."""

    model_config = ConfigDict(from_attributes=True)

    id: Any  # primary key can be any type when used as app
    name: str
    mail: str


class X509CertMixinModel(BaseModel):
    """Base model for certificates."""

    id: Any  # primary key can be any type when used as app
    created: datetime
    updated: datetime
    revoked: bool = False
    revoked_date: datetime | None
    revoked_reason: str
    compromised: datetime | None
    certificate: CertificateModel

    fingerprints: dict[HashAlgorithms, str]

    @classmethod
    def _from_model(cls, value: X509CertMixin, info: ValidationInfo) -> dict[str, Any]:
        algorithms = (hashes.SHA256(), hashes.SHA512())
        if isinstance(info.context, dict):
            algorithms = info.context.get("hash_algorithms", algorithms)
            if not isinstance(algorithms, tuple):
                raise ValueError("hash_algorithms must be a tuple of hash algorithms.")
            if not all(isinstance(algorithm, hashes.HashAlgorithm) for algorithm in algorithms):
                raise ValueError("hash_algorithms must be a tuple of hash algorithms.")

        fingerprints = {
            HASH_ALGORITHM_NAMES[type(algorithm)]: value.get_fingerprint(algorithm)
            for algorithm in algorithms
        }

        return {
            "id": value.pk,
            "created": value.created,
            "updated": value.updated,
            "revoked": value.revoked,
            "revoked_date": value.revoked_date,
            "revoked_reason": value.revoked_reason,
            "compromised": value.compromised,
            "certificate": value.pub.loaded,
            "fingerprints": fingerprints,
        }


class DjangoCertificateAuthorityModel(X509CertMixinModel):
    """Model for a Certificate Authority as stored in the database."""

    name: str
    enabled: bool
    parent: Any  # primary key can be any type when used as app
    key_backend_alias: str
    key_backend_options: dict[str, Any]
    sign_authority_information_access: AuthorityInformationAccessModel | None
    sign_certificate_policies: CertificatePoliciesModel | None
    sign_crl_distribution_points: CRLDistributionPointsModel | None
    sign_issuer_alternative_name: IssuerAlternativeNameModel | None
    caa_identity: str
    website: str
    terms_of_service: str
    ocsp_key_backend_alias: str
    ocsp_key_backend_options: dict[str, Any]
    ocsp_responder_key_validity: int
    ocsp_response_validity: int
    acme_enabled: bool
    acme_registration: bool
    acme_profile: str
    acme_requires_contact: bool
    api_enabled: bool

    @model_validator(mode="before")
    @classmethod
    def validate_django_model(cls, value: Any, info: ValidationInfo) -> Any:
        """Parse Django model values."""
        if isinstance(value, CertificateAuthority):
            if value.parent is None:
                parent = None
            else:
                parent = value.parent.id

            return {
                **cls._from_model(value, info=info),
                "name": value.name,
                "enabled": value.enabled,
                "parent": parent,
                "key_backend_alias": value.key_backend_alias,
                "key_backend_options": value.key_backend_options,
                "sign_authority_information_access": value.sign_authority_information_access,
                "sign_certificate_policies": value.sign_certificate_policies,
                "sign_crl_distribution_points": value.sign_crl_distribution_points,
                "sign_issuer_alternative_name": value.sign_issuer_alternative_name,
                "caa_identity": value.caa_identity,
                "website": value.website,
                "terms_of_service": value.terms_of_service,
                "ocsp_key_backend_alias": value.ocsp_key_backend_alias,
                "ocsp_key_backend_options": value.ocsp_key_backend_options,
                "ocsp_responder_key_validity": value.ocsp_responder_key_validity,
                "ocsp_response_validity": value.ocsp_response_validity,
                "acme_enabled": value.acme_enabled,
                "acme_registration": value.acme_registration,
                "acme_profile": value.acme_profile,
                "acme_requires_contact": value.acme_requires_contact,
                "api_enabled": value.api_enabled,
            }
        return value  # pragma: no cover


class DjangoCertificateModel(X509CertMixinModel):
    """Model for a Certificate as stored in the database."""

    watchers: list[WatcherModel]
    ca: Any
    csr: str | None
    profile: str
    autogenerated: bool

    @model_validator(mode="before")
    @classmethod
    def validate_django_model(cls, value: Any, info: ValidationInfo) -> Any:
        """Parse Django model values."""
        if isinstance(value, Certificate):
            if value.csr is None:
                csr: str | None = None
            elif isinstance(value.csr, x509.CertificateSigningRequest):
                # This happens with a model that was just created.
                csr = value.csr.public_bytes(Encoding.PEM).decode("ascii")
            else:
                csr = value.csr.pem

            return {
                **cls._from_model(value, info=info),
                "watchers": value.watchers.all(),
                "ca": value.ca.id,
                "csr": csr,
                "profile": value.profile,
                "autogenerated": value.autogenerated,
            }
        return value  # pragma: no cover

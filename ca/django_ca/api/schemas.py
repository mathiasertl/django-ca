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

"""Pydantic Schemas for the API."""

import abc
from datetime import datetime
from typing import List, Optional, Union

from ninja import Field, ModelSchema, Schema

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from django_ca import ca_settings, constants
from django_ca.constants import ReasonFlags
from django_ca.models import Certificate, CertificateAuthority, X509CertMixin

DATETIME_EXAMPLE = "2023-07-30T10:06:35Z"


class AuthorityInformationAccessValueSchema(Schema):
    """Schema for the Authority Information Access extension value."""

    issuers: Optional[List[str]] = Field(example=["URI:https://example.com/issuer"])
    ocsp: Optional[List[str]] = Field(example=["URI:https://example.com/ocsp"])


class AuthorityInformationAccessSchema(Schema):
    """Schema for the Authority Information Access extension."""

    critical: bool = constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.AUTHORITY_INFORMATION_ACCESS]
    value: AuthorityInformationAccessValueSchema


class NoticeReferenceSchema(Schema):
    """Schema for a Notice Reference."""

    organization: Optional[str]
    notice_numbers: List[int]


class UserNoticeSchema(Schema):
    """Schema for a User Notice."""

    notice_reference: Optional[NoticeReferenceSchema]
    explicit_text: Optional[str]


class PolicySchema(Schema):
    """Schema for a certificate policy."""

    policy_identifier: str = Field(example="1.2.3.4")
    policy_qualifiers: Optional[List[Union[str, UserNoticeSchema]]]


class CertificatePoliciesSchema(Schema):
    """Schema for the Certificate Policies extension."""

    critical: bool = constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.CERTIFICATE_POLICIES]
    value: List[PolicySchema]


class CRLDistributionPointSchema(Schema):
    """ "Schema for a CRL Distribution Point."""

    full_name: Optional[List[str]] = Field(example=["URI:http://crl.example.com"])
    relative_name: Optional[str]
    crl_issuer: Optional[List[str]] = Field(example=["URI:http://crl-issuers.example.com"])
    reasons: Optional[List[x509.ReasonFlags]] = Field(
        example=["unspecified", "superseded", "cessationOfOperation"]
    )


class CRLDistributionPointsSchema(Schema):
    """Schema for the CRL Distribution Points extension."""

    critical: bool = constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.CRL_DISTRIBUTION_POINTS]
    value: List[CRLDistributionPointSchema]


class ExtendedKeyUsageSchema(Schema):
    """Schema for the Extended Key Usage extension."""

    critical: bool = constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.EXTENDED_KEY_USAGE]
    value: List[str] = Field(example=["serverAuth", "clientAuth"])


class FreshestCRLSchema(Schema):
    """Schema for the Freshest CRL extension."""

    critical: bool = constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.FRESHEST_CRL]
    value: List[CRLDistributionPointSchema]


class KeyUsageSchema(Schema):
    """Schema for the Key Usage extension."""

    critical: bool = constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.KEY_USAGE]
    value: List[str] = Field(example=["digitalSignature", "keyEncipherment"])


class OCSPNoCheckSchema(Schema):
    """Schema for the OCSP No Check extension."""

    critical: bool = constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.OCSP_NO_CHECK]


class SubjectAlternativeNameSchema(Schema):
    """Schema for a Subject Alternative Name extension."""

    critical: bool = constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.SUBJECT_ALTERNATIVE_NAME]
    value: List[str] = Field(example=["DNS:example.com", "IP:127.0.0.1"])


class TLSFeatureSchema(Schema):
    """Schema for the TLS Feature extension."""

    critical: bool = constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.TLS_FEATURE]
    value: List[str] = Field(example=["OCSPMustStaple"])


class ExtensionsSchema(Schema):
    """Schema for all extensions that may be added via the API."""

    authority_information_access: Optional[AuthorityInformationAccessSchema]
    certificate_policies: Optional[CertificatePoliciesSchema]
    crl_distribution_points: Optional[CRLDistributionPointsSchema]
    extended_key_usage: Optional[ExtendedKeyUsageSchema]
    freshest_crl: Optional[CRLDistributionPointsSchema]
    key_usage: Optional[KeyUsageSchema]
    ocsp_no_check: Optional[OCSPNoCheckSchema]
    subject_alternative_name: Optional[SubjectAlternativeNameSchema]
    tls_feature: Optional[TLSFeatureSchema]


class X509BaseSchema(ModelSchema, abc.ABC):
    """Base schema for CAs and Certificates."""

    created: datetime = Field(description="When the certificate was created.", example=DATETIME_EXAMPLE)
    not_after: datetime = Field(
        description="The certificate is not valid after this date.", example=DATETIME_EXAMPLE
    )
    not_before: datetime = Field(
        description="The certificate is not valid before this date.", example=DATETIME_EXAMPLE
    )
    pem: str = Field(
        description="The public key formatted as PEM.",
        example="-----BEGIN CERTIFICATE-----\n...-----END CERTIFICATE-----\n",
    )
    serial: str = Field(description="Serial (in hex) of the certificate.", example="ABC...0123")
    subject: str = Field(
        description="The subject as RFC 4514 formatted string.",
        example="CN=example.com,O=Example,ST=Vienna,C=AT",
    )
    revoked: bool = Field(description="If the certificate was revoked.", example=False)
    updated: datetime = Field(description="When the certificate was last updated.", example=DATETIME_EXAMPLE)

    class Config:  # pylint: disable=missing-class-docstring
        model = X509CertMixin
        model_fields = sorted(["created", "revoked", "serial", "updated"])

    @staticmethod
    def resolve_created(obj: CertificateAuthority) -> datetime:
        """Strip microseconds from the attribute."""
        return obj.created.replace(microsecond=0)

    @staticmethod
    def resolve_pem(obj: CertificateAuthority) -> str:
        """Convert the public certificate to its PEM format"""
        return obj.pub.pem

    @staticmethod
    def resolve_subject(obj: CertificateAuthority) -> str:
        """Convert the subject to its RFC 4514 representation."""
        return obj.subject.rfc4514_string()

    @staticmethod
    def resolve_updated(obj: CertificateAuthority) -> datetime:
        """Strip microseconds from the attribute."""
        return obj.updated.replace(microsecond=0)


class CertificateAuthoritySchema(X509BaseSchema):
    """Schema for serializing a certificate authority."""

    name: str = Field(description="The human-readable name of the certificate authority.")
    can_sign_certificates: bool = Field(
        description="If the certificate authority can be used to sign certificates via the API."
    )

    class Config(X509BaseSchema.Config):  # pylint: disable=missing-class-docstring
        model = CertificateAuthority
        model_fields = sorted(X509BaseSchema.Config.model_fields + ["name"])

    @staticmethod
    def resolve_can_sign_certificates(obj: CertificateAuthority) -> bool:
        """Strip microseconds from the attribute."""
        return obj.key_exists


class CertificateAuthorityFilterSchema(Schema):
    """Filter-schema for listing certificate authorities."""

    expired: bool = Field(default=False, description="Include expired CAs.")


class CertificateSchema(X509BaseSchema):
    """Schema for serializing a certificate."""

    autogenerated: bool = Field(
        description="If the field was automatically generated (e.g. for an OCSP responder)."
    )
    profile: str = Field(description="The profile that the certificate was generated with.")

    class Config(X509BaseSchema.Config):  # pylint: disable=missing-class-docstring
        model = Certificate
        model_fields = sorted(X509BaseSchema.Config.model_fields + ["autogenerated", "profile"])


class CertificateFilterSchema(Schema):
    """Filter schema for certificates."""

    autogenerated: bool = Field(
        default=False, description="Include auto-generated certificates (e.g. OCSP responder certificates)."
    )
    expired: bool = Field(default=False, description="Include expired certificates.")
    profile: Optional[str] = Field(
        description="Only return certificates generated with the given profile.",
        default=None,
        enum=sorted(ca_settings.CA_PROFILES),
    )
    revoked: bool = Field(default=False, description="Include revoked certificates.")


class SignCertificateSchema(Schema):
    """Schema for signing certificates."""

    algorithm: Optional[str] = Field(
        default=None,
        description="Hash algorithm used for signing (default: same as in the certificate authority).",
        enum=sorted(constants.HASH_ALGORITHM_TYPES),
    )
    autogenerated: bool = Field(
        default=False, description="If the certificate should be marked as auto-generated."
    )
    csr: str = Field(
        title="CSR",
        description="The certificate signing request (CSR) in PEM format",
        example="-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----\n",
    )
    expires: Optional[datetime] = Field(
        description="When the certificate is due to expire, defaults to the CA_DEFAULT_EXPIRES setting.",
        example=DATETIME_EXAMPLE,
    )
    extensions: Optional[ExtensionsSchema] = Field(
        default=None, description="**Optional** additional extensions to add to the certificate."
    )
    profile: Optional[str] = Field(
        description="Issue the certificate with the given profile.",
        default=ca_settings.CA_DEFAULT_PROFILE,
        enum=sorted(ca_settings.CA_PROFILES),
    )
    subject: str = Field(
        description="The subject as RFC 4514 formatted string.",
        example="CN=example.com,O=Example,ST=Vienna,C=AT",
    )


class RevokeCertificateSchema(Schema):
    """Schema for revoking certificates."""

    compromised: Optional[datetime] = Field(default=None, description="When the certificate was compromised.")

    reason: ReasonFlags = Field(
        default=ReasonFlags.unspecified,
        description="""The reason why the certificate was revoked. Valid values are `unspecified`,
        `keyCompromise`, `cACompromise`, `affiliationChanged`, `superseeded`, `cessationOfOperation`, 
        `certificateHold`, `privilegeWithdrawn`, `aACompromise` and `removeFromCRL`.""",
    )

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

"""Pydantic schemas for extensions."""
import base64
from typing import List, Optional, Union

from ninja import Schema
from pydantic import Field, field_serializer, field_validator, model_validator

from cryptography import x509
from cryptography.hazmat._oid import ExtensionOID, NameOID

from django_ca import constants

DATETIME_EXAMPLE = "2023-07-30T10:06:35Z"


class NameAttributeSchema(Schema):
    """docstring for class."""

    oid: str = Field(
        title="OID",
        description="The attribute OID as dotted string.",
        json_schema_extra={"example": NameOID.COMMON_NAME.dotted_string},
    )

    value: Union[str, bytes] = Field(
        description="The value of the attribute.",
    )

    @field_serializer("value")
    def serialize_value(self, value: Union[str, bytes]) -> str:
        if isinstance(value, bytes):
            return base64.b64encode(value).decode()
        return value


############################
# Extension member schemas #
############################


class CRLDistributionPointSchema(Schema):
    """Schema for a CRL Distribution Point.

    Note that in practice, this usually is just a single `full_name` with a URL pointing to the CRL.
    """

    full_name: Optional[List[str]] = Field(
        json_schema_extra={"example": ["URI:http://crl.example.com"]}, default=None
    )
    relative_name: Optional[List[NameAttributeSchema]] = None
    crl_issuer: Optional[List[str]] = Field(
        default=None, json_schema_extra={"example": ["URI:http://crl-issuers.example.com"]}
    )
    reasons: Optional[List[x509.ReasonFlags]] = Field(
        default=None, json_schema_extra={"example": ["unspecified", "superseded", "cessationOfOperation"]}
    )

    @model_validator(mode="after")
    def check_full_or_relative_name(self) -> "CRLDistributionPointSchema":
        """Validate that the distribution point has either a full_name OR a relative_name."""
        if self.full_name and self.relative_name:
            raise ValueError("Distribution point must contain either full_name OR relative_name.")
        if not self.full_name and not self.relative_name:
            raise ValueError("Distribution point must contain one of full_name OR relative_name.")
        return self


class NoticeReferenceSchema(Schema):
    """Schema for a Notice Reference."""

    organization: Optional[str] = None
    notice_numbers: List[int] = Field(default_factory=list)


class UserNoticeSchema(Schema):
    """Schema for a User Notice."""

    notice_reference: Optional[NoticeReferenceSchema] = None
    explicit_text: Optional[str] = ""


class PolicySchema(Schema):
    """Schema for a certificate policy."""

    policy_identifier: str = Field(json_schema_extra={"example": "1.2.3.4"})
    policy_qualifiers: Optional[List[Union[str, UserNoticeSchema]]] = Field(default=None)


#####################
# Extension schemas #
#####################
class AuthorityInformationAccessValueSchema(Schema):
    """Schema for the Authority Information Access extension value."""

    # TODO: validate that at least one is set

    issuers: Optional[List[str]] = Field(
        json_schema_extra={"example": ["URI:https://example.com/issuer"]}, default_factory=list
    )
    ocsp: Optional[List[str]] = Field(
        json_schema_extra={"example": ["URI:https://example.com/ocsp"]}, default_factory=list
    )


class AuthorityInformationAccessSchema(Schema):
    """Schema for the Authority Information Access extension.

    This extension is usually derived from the certificate authority signing the extension and not specified
    via the API. If given via the API, the `issuers` and `ocsp` fields will replace the respective field of
    the extension from the certificate authority.
    """

    critical: bool = constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.AUTHORITY_INFORMATION_ACCESS]
    value: AuthorityInformationAccessValueSchema


class CRLDistributionPointsSchema(Schema):
    """Schema for the CRL Distribution Points extension.

    This extension is usually derived from the certificate authority signing the extension and not specified
    via the API. If given via the API, it will replace any the extension from the certificate authority.
    """

    critical: bool = constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.CRL_DISTRIBUTION_POINTS]
    value: List[CRLDistributionPointSchema]


class CertificatePoliciesSchema(Schema):
    """Schema for the Certificate Policies extension."""

    critical: bool = constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.CERTIFICATE_POLICIES]
    value: List[PolicySchema]


class ExtendedKeyUsageSchema(Schema):
    """Schema for the Extended Key Usage extension."""

    critical: bool = constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.EXTENDED_KEY_USAGE]
    value: List[str] = Field(json_schema_extra={"example": ["serverAuth", "clientAuth"]})


class FreshestCRLSchema(Schema):
    """Schema for the Freshest CRL extension."""

    critical: bool = constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.FRESHEST_CRL]
    value: List[CRLDistributionPointSchema]


class KeyUsageSchema(Schema):
    """Schema for the Key Usage extension."""

    critical: bool = constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.KEY_USAGE]
    value: List[str] = Field(
        json_schema_extra={
            "example": ["digitalSignature", "keyEncipherment"],
            "enum": list(sorted(constants.KEY_USAGE_NAMES.values())),
        }
    )

    @field_validator("value")
    @classmethod
    def validate_key_usage(cls, values: List[str]) -> List[str]:
        """Make sure that only valid key usages are sent."""
        valid_values = tuple(constants.KEY_USAGE_NAMES.values())
        for key_usage in values:
            if key_usage not in valid_values:
                raise ValueError(f"{key_usage}: Invalid key usage.")
        return values


class OCSPNoCheckSchema(Schema):
    """Schema for the OCSP No Check extension."""

    critical: bool = constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.OCSP_NO_CHECK]


class SubjectAlternativeNameSchema(Schema):
    """Schema for a Subject Alternative Name extension."""

    critical: bool = constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.SUBJECT_ALTERNATIVE_NAME]
    value: List[str] = Field(json_schema_extra={"example": ["DNS:example.com", "IP:127.0.0.1"]})


class TLSFeatureSchema(Schema):
    """Schema for the TLS Feature extension."""

    critical: bool = constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.TLS_FEATURE]
    value: List[str] = Field(json_schema_extra={"example": ["OCSPMustStaple"]})


class ExtensionsSchema(Schema):
    """Schema for all extensions that may be added via the API."""

    authority_information_access: Optional[AuthorityInformationAccessSchema] = None
    certificate_policies: Optional[CertificatePoliciesSchema] = None
    crl_distribution_points: Optional[CRLDistributionPointsSchema] = None
    extended_key_usage: Optional[ExtendedKeyUsageSchema] = None
    freshest_crl: Optional[CRLDistributionPointsSchema] = None
    key_usage: Optional[KeyUsageSchema] = None
    ocsp_no_check: Optional[OCSPNoCheckSchema] = None
    subject_alternative_name: Optional[SubjectAlternativeNameSchema] = None
    tls_feature: Optional[TLSFeatureSchema] = None

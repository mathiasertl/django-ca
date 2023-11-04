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
from pydantic import Field, root_validator, validator

from cryptography import x509
from cryptography.hazmat._oid import ExtensionOID, NameOID

from django_ca import constants
from django_ca.typehints import SerializedDistributionPoint

DATETIME_EXAMPLE = "2023-07-30T10:06:35Z"


class NameAttributeSchema(Schema):
    """docstring for class."""

    oid: str = Field(
        title="OID",
        description="The attribute OID as dotted string.",
        example=NameOID.COMMON_NAME.dotted_string,
    )

    value: Union[str, bytes] = Field(
        description="The value of the attribute.",
    )

    class Config:  # pylint: disable=missing-class-docstring
        # NOTE: json_encoders does not seem to do anything if there is a Union[] annotation
        json_encoders = {bytes: lambda v: base64.b64encode(v).decode()}  # pragma: no cover


############################
# Extension member schemas #
############################


class CRLDistributionPointSchema(Schema):
    """Schema for a CRL Distribution Point.

    Note that in practice, this usually is just a single `full_name` with a URL pointing to the CRL.
    """

    full_name: Optional[List[str]] = Field(example=["URI:http://crl.example.com"])
    relative_name: Optional[List[NameAttributeSchema]]
    crl_issuer: Optional[List[str]] = Field(example=["URI:http://crl-issuers.example.com"])
    reasons: Optional[List[x509.ReasonFlags]] = Field(
        example=["unspecified", "superseded", "cessationOfOperation"]
    )

    @root_validator
    def check_full_or_relative_name(  # pylint: disable=no-self-argument  # -> pydantic
        cls, values: SerializedDistributionPoint
    ) -> SerializedDistributionPoint:
        """Validate that the distribution point has either a full_name OR a relative_name."""
        full_name = values.get("full_name")
        relative_name = values.get("relative_name")
        if full_name and relative_name:
            raise ValueError("Distribution point must contain either full_name OR relative_name.")
        if not full_name and not relative_name:
            raise ValueError("Distribution point must contain one of full_name OR relative_name.")
        return values


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


#####################
# Extension schemas #
#####################
class AuthorityInformationAccessValueSchema(Schema):
    """Schema for the Authority Information Access extension value."""

    issuers: Optional[List[str]] = Field(example=["URI:https://example.com/issuer"])
    ocsp: Optional[List[str]] = Field(example=["URI:https://example.com/ocsp"])


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
    value: List[str] = Field(example=["serverAuth", "clientAuth"])


class FreshestCRLSchema(Schema):
    """Schema for the Freshest CRL extension."""

    critical: bool = constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.FRESHEST_CRL]
    value: List[CRLDistributionPointSchema]


class KeyUsageSchema(Schema):
    """Schema for the Key Usage extension."""

    critical: bool = constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.KEY_USAGE]
    value: List[str] = Field(
        example=["digitalSignature", "keyEncipherment"], enum=sorted(constants.KEY_USAGE_NAMES.values())
    )

    @validator("value")
    def validate_key_usage(  # pylint: disable=no-self-argument  # -> pydantic
        cls, values: List[str]
    ) -> List[str]:
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

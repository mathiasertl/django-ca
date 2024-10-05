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
from typing import Optional

from ninja import Field, ModelSchema, Schema
from pydantic import field_serializer

from django_ca.conf import model_settings
from django_ca.constants import ReasonFlags
from django_ca.models import Certificate, CertificateAuthority, CertificateOrder, X509CertMixin
from django_ca.pydantic.base import DATETIME_EXAMPLE
from django_ca.pydantic.extensions import (
    AuthorityInformationAccessModel,
    CertificatePoliciesModel,
    CRLDistributionPointsModel,
    IssuerAlternativeNameModel,
)
from django_ca.pydantic.name import NameModel


class X509BaseSchema(ModelSchema, abc.ABC):
    """Base schema for CAs and Certificates."""

    created: datetime = Field(
        description="When the certificate was created.", json_schema_extra={"example": DATETIME_EXAMPLE}
    )
    not_after: datetime = Field(
        description="The certificate is not valid after this date.",
        json_schema_extra={"example": DATETIME_EXAMPLE},
    )
    not_before: datetime = Field(
        description="The certificate is not valid before this date.",
        json_schema_extra={"example": DATETIME_EXAMPLE},
    )
    pem: str = Field(
        description="The public key formatted as PEM.",
        alias="pub.pem",
        json_schema_extra={"example": "-----BEGIN CERTIFICATE-----\n...-----END CERTIFICATE-----\n"},
    )
    serial: str = Field(
        description="Serial (in hex) of the certificate.", json_schema_extra={"example": "ABC...0123"}
    )
    subject: NameModel = Field(description="The subject as list of name attributes.")
    issuer: NameModel = Field(description="The issuer as list of name attributes.")
    revoked: bool = Field(description="If the certificate was revoked.", json_schema_extra={"example": False})
    updated: datetime = Field(
        description="When the certificate was last updated.", json_schema_extra={"example": DATETIME_EXAMPLE}
    )

    class Meta:  # pylint: disable=missing-class-docstring
        model = X509CertMixin
        fields = sorted(["revoked", "serial"])

    @field_serializer("created")
    def serialize_created(self, created: datetime) -> datetime:
        """Strip microseconds from the attribute."""
        return created.replace(microsecond=0)

    @field_serializer("updated")
    def serialize_updated(self, updated: datetime) -> datetime:
        """Strip microseconds from the attribute."""
        return updated.replace(microsecond=0)


class CertificateAuthorityBaseSchema(ModelSchema, abc.ABC):
    """Base schema for certificate authorities.

    Contains all fields that can be read or updated.
    """

    name: str = Field(description="The human-readable name of the certificate authority.")
    sign_authority_information_access: Optional[AuthorityInformationAccessModel] = Field(
        default=None,
        json_schema_extra={
            "description": "The Authority Information Access extension added to newly signed certificates."
        },
    )
    sign_certificate_policies: Optional[CertificatePoliciesModel] = Field(
        default=None,
        json_schema_extra={
            "description": "The Certificate Policies extension added to newly signed certificates."
        },
    )
    sign_crl_distribution_points: Optional[CRLDistributionPointsModel] = Field(
        default=None,
        json_schema_extra={
            "description": "The CRL Distribution Points extension added to newly signed certificates."
        },
    )
    sign_issuer_alternative_name: Optional[IssuerAlternativeNameModel] = Field(
        default=None,
        json_schema_extra={
            "description": "The Issuer Alternative Name extension added to newly signed certificates."
        },
    )

    class Meta:  # pylint: disable=missing-class-docstring
        model = CertificateAuthority
        fields = (
            "name",
            "caa_identity",
            "website",
            "terms_of_service",
            "sign_authority_information_access",
            "sign_certificate_policies",
            "sign_crl_distribution_points",
            "sign_issuer_alternative_name",
            "ocsp_responder_key_validity",
            "ocsp_response_validity",
            "acme_enabled",
            "acme_registration",
            "acme_profile",
            "acme_requires_contact",
        )


class CertificateAuthoritySchema(CertificateAuthorityBaseSchema, X509BaseSchema):
    """Schema for serializing a certificate authority."""

    can_sign_certificates: bool = Field(
        description="If the certificate authority can be used to sign certificates via the API."
    )

    class Meta(X509BaseSchema.Meta):  # pylint: disable=missing-class-docstring
        model = CertificateAuthority
        fields = sorted((*X509BaseSchema.Meta.fields, *CertificateAuthorityBaseSchema.Meta.fields))

    @staticmethod
    def resolve_can_sign_certificates(obj: CertificateAuthority) -> bool:
        """Resolve the can_sign_certificates flag."""
        return obj.is_usable()


class CertificateAuthorityFilterSchema(Schema):
    """Filter-schema for listing certificate authorities."""

    expired: bool = Field(default=False, description="Include expired CAs.")


class CertificateAuthorityUpdateSchema(CertificateAuthorityBaseSchema):
    """Schema for updating certificate authorities."""

    # TYPE NOTE: fields_optional does not capture explicitly named fields, so we repeat this
    # with Optional[str], which is an incompatible override
    name: Optional[str] = Field(  # type: ignore[assignment]
        description="The human-readable name of the certificate authority.",
        default=None,
        json_schema_extra={"required": False},
    )

    class Meta(CertificateAuthorityBaseSchema.Meta):  # pylint: disable=missing-class-docstring
        fields_optional = "__all__"


class CertificateOrderSchema(ModelSchema):
    """Schema for certificate orders."""

    user: str = Field(alias="user.get_username", description="Username of the user.")
    serial: Optional[str] = Field(alias="certificate.serial", default=None)
    created: datetime = Field(
        description="When the order was created.", json_schema_extra={"example": DATETIME_EXAMPLE}
    )
    updated: datetime = Field(
        description="When the order was last updated.", json_schema_extra={"example": DATETIME_EXAMPLE}
    )

    class Meta:  # pylint: disable=missing-class-docstring
        model = CertificateOrder
        fields = sorted(["created", "updated", "slug", "status", "user"])


class CertificateSchema(X509BaseSchema):
    """Schema for serializing a certificate."""

    autogenerated: bool = Field(
        description="If the field was automatically generated (e.g. for an OCSP responder)."
    )
    profile: str = Field(description="The profile that the certificate was generated with.")

    class Meta(X509BaseSchema.Meta):  # pylint: disable=missing-class-docstring
        model = Certificate
        fields = sorted((*X509BaseSchema.Meta.fields, "autogenerated", "profile"))


class CertificateFilterSchema(Schema):
    """Filter schema for certificates."""

    autogenerated: bool = Field(
        default=False, description="Include auto-generated certificates (e.g. OCSP responder certificates)."
    )
    expired: bool = Field(default=False, description="Include expired certificates.")
    profile: Optional[str] = Field(
        description="Only return certificates generated with the given profile.",
        default=None,
        json_schema_extra={"enum": list(sorted(model_settings.CA_PROFILES))},
    )
    revoked: bool = Field(default=False, description="Include revoked certificates.")


class RevokeCertificateSchema(Schema):
    """Schema for revoking certificates."""

    compromised: Optional[datetime] = Field(default=None, description="When the certificate was compromised.")

    reason: ReasonFlags = Field(
        default=ReasonFlags.unspecified,
        description="""The reason why the certificate was revoked. Valid values are `unspecified`,
        `keyCompromise`, `cACompromise`, `affiliationChanged`, `superseeded`, `cessationOfOperation`, 
        `certificateHold`, `privilegeWithdrawn`, `aACompromise` and `removeFromCRL`.""",
    )

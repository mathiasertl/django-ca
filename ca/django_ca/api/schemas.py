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
from typing import List, Optional

from ninja import ModelSchema, Schema
from pydantic import Field

from django_ca import ca_settings, constants
from django_ca.api.extension_schemas import DATETIME_EXAMPLE, ExtensionsSchema, NameAttributeSchema
from django_ca.constants import ReasonFlags
from django_ca.extensions import serialize_extension
from django_ca.models import Certificate, CertificateAuthority, CertificateOrder, X509CertMixin
from django_ca.typehints import SerializedExtension


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
    subject: List[NameAttributeSchema] = Field(description="The subject as list of name attributes.")
    issuer: List[NameAttributeSchema] = Field(description="The issuer as list of name attributes.")
    revoked: bool = Field(description="If the certificate was revoked.", example=False)
    updated: datetime = Field(description="When the certificate was last updated.", example=DATETIME_EXAMPLE)

    class Config:  # pylint: disable=missing-class-docstring
        model = X509CertMixin
        model_fields = sorted(["created", "revoked", "serial", "updated"])

    @staticmethod
    def resolve_created(obj: X509CertMixin) -> datetime:
        """Strip microseconds from the attribute."""
        return obj.created.replace(microsecond=0)

    @staticmethod
    def resolve_pem(obj: X509CertMixin) -> str:
        """Convert the public certificate to its PEM format."""
        return obj.pub.pem

    @staticmethod
    def resolve_subject(obj: X509CertMixin) -> List[NameAttributeSchema]:
        """Convert the subject to its RFC 4514 representation."""
        return [NameAttributeSchema(oid=attr.oid.dotted_string, value=attr.value) for attr in obj.subject]

    @staticmethod
    def resolve_issuer(obj: X509CertMixin) -> List[NameAttributeSchema]:
        """Convert the issuer to its serialized representation."""
        return [NameAttributeSchema(oid=attr.oid.dotted_string, value=attr.value) for attr in obj.issuer]

    @staticmethod
    def resolve_updated(obj: X509CertMixin) -> datetime:
        """Strip microseconds from the attribute."""
        return obj.updated.replace(microsecond=0)


class CertificateAuthorityBaseSchema(ModelSchema, abc.ABC):
    """Base schema for certificate authorities.

    Contains all fields that can be read or updated.
    """

    name: str = Field(description="The human-readable name of the certificate authority.")

    class Config:  # pylint: disable=missing-class-docstring
        model = CertificateAuthority
        model_fields = [
            "name",
            "caa_identity",
            "website",
            "terms_of_service",
            "crl_url",
            "issuer_url",
            "ocsp_url",
            "issuer_alt_name",
            "sign_certificate_policies",
            "ocsp_responder_key_validity",
            "ocsp_response_validity",
            "acme_enabled",
            "acme_registration",
            "acme_profile",
            "acme_requires_contact",
        ]

    @staticmethod
    def resolve_sign_certificate_policies(obj: CertificateAuthority) -> Optional[SerializedExtension]:
        """Convert cryptography extensions to JSON serializable objects."""
        if obj.sign_certificate_policies is None:
            return None
        return serialize_extension(obj.sign_certificate_policies)


class CertificateAuthoritySchema(CertificateAuthorityBaseSchema, X509BaseSchema):
    """Schema for serializing a certificate authority."""

    can_sign_certificates: bool = Field(
        description="If the certificate authority can be used to sign certificates via the API."
    )

    class Config(X509BaseSchema.Config):  # pylint: disable=missing-class-docstring
        model = CertificateAuthority
        model_fields = sorted(
            X509BaseSchema.Config.model_fields + CertificateAuthorityBaseSchema.Config.model_fields
        )

    @staticmethod
    def resolve_can_sign_certificates(obj: CertificateAuthority) -> bool:
        """Strip microseconds from the attribute."""
        return obj.key_exists


class CertificateAuthorityFilterSchema(Schema):
    """Filter-schema for listing certificate authorities."""

    expired: bool = Field(default=False, description="Include expired CAs.")


class CertificateAuthorityUpdateSchema(CertificateAuthorityBaseSchema):
    """Schema for updating certificate authorities."""

    # TYPE NOTE: model_fields_optional does not capture explicitly named fields, so we repeat this
    # with Optional[str], which is an incompatible override
    name: Optional[str] = Field(  # type: ignore[assignment]
        description="The human-readable name of the certificate authority.", required=False
    )

    class Config(CertificateAuthorityBaseSchema.Config):  # pylint: disable=missing-class-docstring
        model_fields_optional = "__all__"


class CertificateOrderSchema(ModelSchema):
    """Schema for certificate orders."""

    user: str = Field(alias="user.get_username", description="Username of the user.")
    serial: Optional[str] = Field(alias="certificate.serial")
    updated: datetime = Field(description="When the order was last updated.", example=DATETIME_EXAMPLE)

    class Config:  # pylint: disable=missing-class-docstring
        model = CertificateOrder
        model_fields = sorted(["created", "updated", "slug", "status", "user"])


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
    extensions: ExtensionsSchema = Field(
        default_factory=ExtensionsSchema,
        description="**Optional** additional extensions to add to the certificate.",
    )
    profile: str = Field(
        description="Issue the certificate with the given profile.",
        default=ca_settings.CA_DEFAULT_PROFILE,
        enum=sorted(ca_settings.CA_PROFILES),
    )
    subject: List[NameAttributeSchema] = Field(description="The subject as list of name attributes.")


class RevokeCertificateSchema(Schema):
    """Schema for revoking certificates."""

    compromised: Optional[datetime] = Field(default=None, description="When the certificate was compromised.")

    reason: ReasonFlags = Field(
        default=ReasonFlags.unspecified,
        description="""The reason why the certificate was revoked. Valid values are `unspecified`,
        `keyCompromise`, `cACompromise`, `affiliationChanged`, `superseeded`, `cessationOfOperation`, 
        `certificateHold`, `privilegeWithdrawn`, `aACompromise` and `removeFromCRL`.""",
    )

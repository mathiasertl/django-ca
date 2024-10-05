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

"""Pydantic models representing messages exchanged between various parts of the system."""

from datetime import datetime, timedelta, timezone as tz
from typing import Annotated, Optional

from pydantic import AfterValidator, BaseModel, Field

from cryptography import x509

from django_ca.conf import model_settings
from django_ca.constants import HASH_ALGORITHM_TYPES
from django_ca.pydantic.base import DATETIME_EXAMPLE
from django_ca.pydantic.extensions import ConfigurableExtensionModel
from django_ca.pydantic.name import NameModel
from django_ca.pydantic.type_aliases import (
    EllipticCurveTypeAlias,
    HashAlgorithmTypeAlias,
    PowerOfTwoInt,
    Serial,
)
from django_ca.pydantic.validators import pem_csr_validator
from django_ca.typehints import (
    JSON,
    AllowedHashTypes,
    ConfigurableExtension,
    HashAlgorithms,
    ParsableKeyType,
    TypeAliasType,
)

# TypeAliasType is required for recursive types in Pydantic models. See:
#       https://docs.pydantic.dev/latest/concepts/types/#named-recursive-types
JSON = TypeAliasType("JSON", JSON)  # type: ignore[misc]   # we re-assign here


class GenerateOCSPKeyMessage(BaseModel):
    """Schema for a message to generate a OCSP certificate key.

    This message is used by :py:class:`~django_ca.tasks.generate_ocsp_key` to parse parameters.
    """

    serial: Serial
    profile: str = "ocsp"
    expires: Optional[timedelta] = Field(default=None, ge=timedelta(seconds=3600))
    key_type: Optional[ParsableKeyType] = None
    key_size: Optional[Annotated[PowerOfTwoInt, Field(ge=model_settings.CA_MIN_KEY_SIZE)]] = None
    elliptic_curve: Optional[EllipticCurveTypeAlias] = None
    algorithm: Optional[HashAlgorithmTypeAlias] = None
    autogenerated: bool = True
    force: bool = False


class SignCertificateMessage(BaseModel):
    """Schema for signing certificates."""

    key_backend_options: dict[str, JSON] = Field(
        default_factory=dict,
        description="Options for the key backend. Valid values depend on the key backend of the certificate "
        "authority. If not passed, the key backend must be configured for automatic signing in the backend.",
    )
    algorithm: Optional[HashAlgorithms] = Field(
        default=None,
        description="Hash algorithm used for signing (default: same as in the certificate authority).",
        # TODO: check if this is necessary since we now have a 'literal'
        # json_schema_extra={"enum": list(sorted(HASH_ALGORITHM_TYPES))},
    )
    autogenerated: bool = Field(
        default=False, description="If the certificate should be marked as auto-generated."
    )
    csr: Annotated[bytes, AfterValidator(pem_csr_validator)] = Field(
        title="CSR",
        description="The certificate signing request (CSR) in PEM format",
        json_schema_extra={
            "example": "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----\n"
        },
    )
    not_after: Optional[datetime] = Field(
        description="When the certificate is due to expire, defaults to the CA_DEFAULT_EXPIRES setting.",
        default_factory=lambda: datetime.now(tz=tz.utc) + model_settings.CA_DEFAULT_EXPIRES,
        json_schema_extra={"example": DATETIME_EXAMPLE},
    )
    extensions: Optional[list[ConfigurableExtensionModel]] = Field(
        default_factory=list,
        description="**Optional** additional extensions to add to the certificate.",
    )
    profile: str = Field(
        description="Issue the certificate with the given profile.",
        default=model_settings.CA_DEFAULT_PROFILE,
        json_schema_extra={"enum": list(sorted(model_settings.CA_PROFILES))},
    )
    subject: NameModel = Field(description="The subject as list of name attributes.")

    def get_algorithm(self) -> Optional[AllowedHashTypes]:
        """Get algorithm class if set."""
        if self.algorithm is not None:
            return HASH_ALGORITHM_TYPES[self.algorithm]()
        return None

    def get_csr(self) -> x509.CertificateSigningRequest:
        """Get CSR encoded in this message."""
        return x509.load_pem_x509_csr(self.csr)

    def get_extensions(self) -> list[ConfigurableExtension]:
        """Get extensions encoded in this message."""
        if self.extensions is None:
            return []
        extensions = [ext.cryptography for ext in self.extensions]

        # TYPEHINT NOTE: list has Extension[A] | Extension[B], but value has Extension[A | B].
        return extensions

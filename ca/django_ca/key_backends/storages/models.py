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

"""Models for the storages backend."""

from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic_core.core_schema import ValidationInfo

from django_ca.conf import model_settings
from django_ca.key_backends.base import CreatePrivateKeyOptionsBaseModel
from django_ca.pydantic.type_aliases import Base64EncodedBytes, EllipticCurveTypeAlias

if TYPE_CHECKING:
    from django_ca.models import CertificateAuthority


class StoragesCreatePrivateKeyOptions(CreatePrivateKeyOptionsBaseModel):
    """Options for initializing private keys."""

    # NOTE: we set frozen here to prevent accidental coding mistakes. Models should be immutable.
    model_config = ConfigDict(arbitrary_types_allowed=True)

    password: bytes | None
    path: Path
    elliptic_curve: EllipticCurveTypeAlias | None = None

    @model_validator(mode="after")
    def validate_elliptic_curve(self) -> "StoragesCreatePrivateKeyOptions":
        """Validate that the elliptic curve is not set for invalid key types."""
        if self.key_type == "EC" and self.elliptic_curve is None:
            self.elliptic_curve = model_settings.CA_DEFAULT_ELLIPTIC_CURVE
        elif self.key_type != "EC" and self.elliptic_curve is not None:
            raise ValueError(f"Elliptic curves are not supported for {self.key_type} keys.")
        return self


class StoragesStorePrivateKeyOptions(BaseModel):
    """Options for storing a private key."""

    # NOTE: we set frozen here to prevent accidental coding mistakes. Models should be immutable.
    model_config = ConfigDict(frozen=True)

    path: Path
    password: bytes | None


class StoragesUsePrivateKeyOptions(BaseModel):
    """Options for using a private key."""

    # NOTE: we set frozen here to prevent accidental coding mistakes. Models should be immutable.
    model_config = ConfigDict(frozen=True)

    password: Base64EncodedBytes | None = Field(default=None, validate_default=True)

    @field_validator("password", mode="after")
    @classmethod
    def load_default_password(cls, password: bytes | None, info: ValidationInfo) -> bytes | None:
        """Validator to load the password from CA_PASSWORDS if not given."""
        if info.context and password is None:
            ca: CertificateAuthority = info.context.get("ca")
            if ca is not None:  # pragma: no branch  # ca is always set, this is just a precaution.
                if settings_password := model_settings.CA_PASSWORDS.get(ca.serial):
                    return settings_password

        return password

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

"""Models used by the HSM backend."""

import typing
from typing import TYPE_CHECKING, Optional, cast

from pydantic import BaseModel, ConfigDict, field_validator, model_validator
from pydantic_core.core_schema import ValidationInfo

from django_ca import constants
from django_ca.conf import model_settings
from django_ca.key_backends.base import CreatePrivateKeyOptionsBaseModel
from django_ca.key_backends.hsm.typehints import SupportedKeyType
from django_ca.typehints import EllipticCurves

if TYPE_CHECKING:
    from django_ca.key_backends.hsm import HSMBackend


class PinModelMixin:
    """Mixin providing so/user pin and validation."""

    so_pin: Optional[str] = None
    user_pin: Optional[str] = None

    @field_validator("so_pin", "user_pin", mode="after")
    @classmethod
    def load_pins_from_backend(cls, value: Optional[str], info: ValidationInfo) -> Optional[str]:
        """Load pins from backend if configured."""
        if info.context and value is None:
            backend: HSMBackend = info.context.get("backend")
            if backend is not None:  # pragma: no branch  # backend is always set
                # TYPEHINT NOTE: field_name is always set in field validators for multiple fields.
                return cast(Optional[str], getattr(backend, info.field_name))  # type: ignore[arg-type]
        return value

    @model_validator(mode="after")
    def validate_pins(self) -> "typing.Self":
        """Validate that exactly one of `so_pin` and `user_pin` is set."""
        if self.so_pin is None and self.user_pin is None:
            raise ValueError("Provide one of so_pin or user_pin.")
        if self.so_pin is not None and self.user_pin is not None:
            raise ValueError("Provide either so_pin or user_pin.")
        return self


class HSMCreatePrivateKeyOptions(PinModelMixin, CreatePrivateKeyOptionsBaseModel):
    """Options for initializing private keys."""

    # NOTE: we set frozen here to prevent accidental coding mistakes. Models should be immutable.
    model_config = ConfigDict(arbitrary_types_allowed=True)

    key_label: str
    key_type: SupportedKeyType  # overwrites field from the base model
    elliptic_curve: Optional[EllipticCurves]

    @model_validator(mode="after")
    def validate_elliptic_curve(self) -> "HSMCreatePrivateKeyOptions":
        """Validate that the elliptic curve is not set for invalid key types."""
        if self.key_type == "EC" and self.elliptic_curve is None:
            default_elliptic_curve_type = type(model_settings.CA_DEFAULT_ELLIPTIC_CURVE)
            self.elliptic_curve = constants.ELLIPTIC_CURVE_NAMES[default_elliptic_curve_type]
        elif self.key_type != "EC" and self.elliptic_curve is not None:
            raise ValueError(f"Elliptic curves are not supported for {self.key_type} keys.")
        return self


class HSMStorePrivateKeyOptions(PinModelMixin, BaseModel):
    """Options for storing a private key."""

    # NOTE: we set frozen here to prevent accidental coding mistakes. Models should be immutable.
    model_config = ConfigDict(frozen=True)

    key_label: str


class HSMUsePrivateKeyOptions(PinModelMixin, BaseModel):
    """Options for using the private key."""

    model_config = ConfigDict(frozen=True)

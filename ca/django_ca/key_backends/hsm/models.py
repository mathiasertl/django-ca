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
from typing import Optional

from pydantic import BaseModel, ConfigDict, model_validator

from django_ca.key_backends.base import CreatePrivateKeyOptionsBaseModel
from django_ca.key_backends.hsm.typehints import SupportedKeyType
from django_ca.typehints import EllipticCurves


class PinModelMixin:
    """Mixin providing so/user pin and validation."""

    so_pin: Optional[str] = None
    user_pin: Optional[str] = None

    @model_validator(mode="after")
    def validate_pins(self) -> "typing.Self":
        """Validate that exactly one of `so_pin` and `user_pin` is set."""
        if self.so_pin is None and self.user_pin is None:
            raise ValueError("Provide one of so_pin or user_pin.")
        if self.so_pin is not None and self.user_pin is not None:
            raise ValueError("Provide either so_pin or user_pin.")
        return self


class CreatePrivateKeyOptions(PinModelMixin, CreatePrivateKeyOptionsBaseModel):
    """Options for initializing private keys."""

    # NOTE: we set frozen here to prevent accidental coding mistakes. Models should be immutable.
    model_config = ConfigDict(arbitrary_types_allowed=True)

    key_label: str
    key_type: SupportedKeyType  # overwrites field from the base model
    elliptic_curve: Optional[EllipticCurves]


class HSMBackendStorePrivateKeyOptions(PinModelMixin, BaseModel):
    """Options for storing a private key."""

    # NOTE: we set frozen here to prevent accidental coding mistakes. Models should be immutable.
    model_config = ConfigDict(frozen=True)

    key_label: str


class HSMBackendUsePrivateKeyOptions(PinModelMixin, BaseModel):
    """Options for using the private key."""

    model_config = ConfigDict(frozen=True)

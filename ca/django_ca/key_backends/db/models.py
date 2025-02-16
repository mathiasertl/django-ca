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


from pydantic import BaseModel, ConfigDict, model_validator

from django_ca.conf import model_settings
from django_ca.key_backends.base import CreatePrivateKeyOptionsBaseModel
from django_ca.pydantic.type_aliases import EllipticCurveTypeAlias


class DBCreatePrivateKeyOptions(CreatePrivateKeyOptionsBaseModel):
    """Options for initializing private keys."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    elliptic_curve: EllipticCurveTypeAlias | None = None

    @model_validator(mode="after")
    def validate_elliptic_curve(self) -> "DBCreatePrivateKeyOptions":
        """Validate that the elliptic curve is not set for invalid key types."""
        if self.key_type == "EC" and self.elliptic_curve is None:
            self.elliptic_curve = model_settings.CA_DEFAULT_ELLIPTIC_CURVE
        elif self.key_type != "EC" and self.elliptic_curve is not None:
            raise ValueError(f"Elliptic curves are not supported for {self.key_type} keys.")
        return self


class DBStorePrivateKeyOptions(BaseModel):
    """Options for storing a private key."""

    # NOTE: we set frozen here to prevent accidental coding mistakes. Models should be immutable.
    model_config = ConfigDict(frozen=True)


class DBUsePrivateKeyOptions(BaseModel):
    """Options for using a private key."""

    # NOTE: we set frozen here to prevent accidental coding mistakes. Models should be immutable.
    model_config = ConfigDict(frozen=True)

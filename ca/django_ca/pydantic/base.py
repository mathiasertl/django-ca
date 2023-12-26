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

"""Shared functionality for Pydantic models."""

import abc
import typing

from pydantic import BaseModel, RootModel
from pydantic.root_model import RootModelRootType

CryptographyModelTypeVar = typing.TypeVar("CryptographyModelTypeVar")
DATETIME_EXAMPLE = "2023-07-30T10:06:35Z"


class CryptographyModel(BaseModel, typing.Generic[CryptographyModelTypeVar]):
    """Abstract base class for all cryptography-related Pydantic models."""

    @property
    @abc.abstractmethod
    def cryptography(self) -> CryptographyModelTypeVar:
        """Convert to the respective cryptography instance."""


class CryptographyRootModel(
    RootModel[RootModelRootType], typing.Generic[RootModelRootType, CryptographyModelTypeVar]
):
    """Abstract base class for all cryptography-related Pydantic models with a different root type."""

    @property
    @abc.abstractmethod
    def cryptography(self) -> CryptographyModelTypeVar:
        """Convert to the respective cryptography instance."""

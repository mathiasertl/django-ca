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

"""Reusable type aliases for Pydantic models."""

from typing import Any, TypeVar

from pydantic import AfterValidator, BeforeValidator, Field

from django_ca import ca_settings
from django_ca.pydantic import validators
from django_ca.typehints import Annotated

PrivateKeySize = Annotated[
    int, Field(ge=ca_settings.CA_MIN_KEY_SIZE), AfterValidator(validators.is_power_two_validator)
]

NonEmptyOrderedSetTypeVar = TypeVar("NonEmptyOrderedSetTypeVar", bound=list[Any])

OIDType = Annotated[str, BeforeValidator(validators.oid_parser), AfterValidator(validators.oid_validator)]

# A list validated to be non-empty and have a unique set of elements.
NonEmptyOrderedSet = Annotated[
    NonEmptyOrderedSetTypeVar,
    AfterValidator(validators.unique_str_validator),
    AfterValidator(validators.non_empty_validator),
]

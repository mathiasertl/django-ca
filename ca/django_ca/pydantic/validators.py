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

"""Validators for Pydantic models."""

from typing import Any, Union

from cryptography import x509

from django_ca import constants


def oid_parser(value: Union[str, x509.ObjectIdentifier]) -> str:
    """Validate a :py:class:`~cryptography.x509.ObjectIdentifier`."""
    if isinstance(value, x509.ObjectIdentifier):
        return value.dotted_string
    return value


def oid_validator(value: str) -> str:
    """Validate that the given value is a valid dotted string."""
    try:
        x509.ObjectIdentifier(value)
    except ValueError as ex:
        raise ValueError(f"{value}: Invalid object identifier") from ex
    return value


def name_oid_parser(value: Any) -> Any:
    """Convert human-readable NameOID values into dotted strings."""
    if value in constants.NAME_OID_TYPES:
        return constants.NAME_OID_TYPES[value].dotted_string
    return value

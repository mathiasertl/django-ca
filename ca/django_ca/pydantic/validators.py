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
from django_ca.utils import is_power2


def access_method_parser(value: Any) -> Any:
    """Convert access method type aliases to dotted string."""
    if oid := constants.ACCESS_METHOD_TYPES.get(value):
        return oid.dotted_string
    return value


def is_power_two_validator(value: int) -> int:
    """Validate that a given integer is a power of two."""
    if not is_power2(value):
        raise ValueError(f"{value}: Must be a power of two")
    return value


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


def key_usage_validator(value: Any) -> Any:
    """Convert a human-readable key usage name to a valid parameter."""
    if value in constants.KEY_USAGE_PARAMETERS:
        return constants.KEY_USAGE_PARAMETERS[value]
    return value


def extended_key_usage_validator(value: str) -> str:
    """Convert human-readable ExtendedKeyUsage values into dotted strings."""
    if value in constants.EXTENDED_KEY_USAGE_OIDS:
        return constants.EXTENDED_KEY_USAGE_OIDS[value].dotted_string
    return value


def unique_str_validator(value: list[str]) -> list[str]:
    """Validate that every string in the list is unique."""
    for val in value:
        if value.count(val) > 1:
            raise ValueError(f"{val}: value must be unique")
    return value


def non_empty_validator(value: list[str]) -> list[str]:
    """Validate that the given list is not empty."""
    if len(value) == 0:
        raise ValueError("value must not be empty")
    return value


def tls_feature_validator(value: Union[str, x509.TLSFeatureType]) -> str:
    """Validate a :py:class:`~cryptography.x509.TLSFeatureType`."""
    if isinstance(value, x509.TLSFeatureType):
        return constants.TLS_FEATURE_KEYS[value]
    if value == "OCSPMustStaple":
        return "status_request"
    if value == "MultipleCertStatusRequest":
        return "status_request_v2"
    return value

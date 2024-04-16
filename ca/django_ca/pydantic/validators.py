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
from urllib.parse import urlsplit

import idna

from cryptography import x509

from django_ca import constants


def access_method_parser(value: Any) -> Any:
    """Convert access method type aliases to dotted string."""
    if oid := constants.ACCESS_METHOD_TYPES.get(value):
        return oid.dotted_string
    return value


def dns_validator(name: str) -> str:
    """IDNA encoding for domains.

    Examples::

        >>> dns_validator('example.com')
        'example.com'
        >>> dns_validator('exämple.com')
        'xn--exmple-cua.com'
        >>> dns_validator('.exämple.com')
        '.xn--exmple-cua.com'
        >>> dns_validator('*.exämple.com')
        '*.xn--exmple-cua.com'
    """
    try:
        if name.startswith("*."):
            return f"*.{idna.encode(name[2:]).decode('utf-8')}"
        if name.startswith("."):
            return f".{idna.encode(name[1:]).decode('utf-8')}"
        return idna.encode(name).decode("utf-8")
    except idna.IDNAError as ex:
        raise ValueError(f"Invalid domain: {name}: {ex}") from ex


def email_validator(addr: str) -> str:
    """Validate an email address.

    This function raises ``ValueError`` if the email address is not valid.

    >>> email_validator("user@example.com")
    'user@example.com'
    >>> email_validator("user@exämple.com")
    'user@xn--exmple-cua.com'

    """
    if "@" not in addr:
        raise ValueError(f"Invalid email address: {addr}")

    node, domain = addr.rsplit("@", 1)

    if not node:
        raise ValueError(f"{addr}: node part is empty")

    try:
        domain = idna.encode(domain).decode("utf-8")
    except idna.IDNAError as ex:
        raise ValueError(f"Invalid domain: {domain}: {ex}") from ex

    return f"{node}@{domain}"


def extended_key_usage_validator(value: str) -> str:
    """Convert human-readable ExtendedKeyUsage values into dotted strings."""
    if value in constants.EXTENDED_KEY_USAGE_OIDS:
        return constants.EXTENDED_KEY_USAGE_OIDS[value].dotted_string
    return value


def is_power_two_validator(value: int) -> int:
    """Validate that a given integer is a power of two."""
    if not (value != 0 and ((value & (value - 1)) == 0)):
        raise ValueError(f"{value}: Must be a power of two")
    return value


def key_usage_validator(value: Any) -> Any:
    """Convert a human-readable key usage name to a valid parameter."""
    if value in constants.KEY_USAGE_PARAMETERS:
        return constants.KEY_USAGE_PARAMETERS[value]
    return value


def name_oid_parser(value: Any) -> Any:
    """Convert human-readable NameOID values into dotted strings."""
    if value in constants.NAME_OID_TYPES:
        return constants.NAME_OID_TYPES[value].dotted_string
    return value


def non_empty_validator(value: list[str]) -> list[str]:
    """Validate that the given list is not empty."""
    if len(value) == 0:
        raise ValueError("value must not be empty")
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


def tls_feature_validator(value: Union[str, x509.TLSFeatureType]) -> str:
    """Validate a :py:class:`~cryptography.x509.TLSFeatureType`."""
    if isinstance(value, x509.TLSFeatureType):
        return constants.TLS_FEATURE_KEYS[value]
    if value == "OCSPMustStaple":
        return "status_request"
    if value == "MultipleCertStatusRequest":
        return "status_request_v2"
    return value


def unique_str_validator(value: list[str]) -> list[str]:
    """Validate that every string in the list is unique."""
    for val in value:
        if value.count(val) > 1:
            raise ValueError(f"{val}: value must be unique")
    return value


def url_validator(url: str) -> str:
    """IDNA encoding for domains in URLs.

    Examples::

        >>> url_validator('https://example.com')
        'https://example.com'
        >>> url_validator('https://exämple.com/foobar')
        'https://xn--exmple-cua.com/foobar'
        >>> url_validator('https://exämple.com:8000/foobar')
        'https://xn--exmple-cua.com:8000/foobar'
    """
    try:
        parsed = urlsplit(url)
    except Exception as ex:
        raise ValueError(f"Could not parse URL: {url}: {ex}") from ex

    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"URL requires scheme and network location: {url}")

    try:
        # Just reading the port may raise ValueError if it cannot be parsed as integer.
        parsed.port  # noqa: B018
    except ValueError as ex:
        raise ValueError(f"Invalid port: {url}: {ex}") from ex

    if parsed.hostname and parsed.port:
        try:
            hostname = idna.encode(parsed.hostname).decode("utf-8")
        except idna.IDNAError as ex:
            raise ValueError(f"Invalid domain: {parsed.hostname}: {ex}") from ex

        # pylint: disable-next=protected-access  # no public API for this
        parsed = parsed._replace(netloc=f"{hostname}:{parsed.port}")
    else:
        try:
            netloc = idna.encode(parsed.netloc).decode("utf-8")
        except idna.IDNAError as ex:
            raise ValueError(f"Invalid domain: {parsed.netloc}: {ex}") from ex

        # pylint: disable-next=protected-access  # no public API for this
        parsed = parsed._replace(netloc=netloc)

    return parsed.geturl()

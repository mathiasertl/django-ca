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

"""Test validators."""

import pytest

from django_ca.pydantic.validators import dns_validator, email_validator, url_validator
from django_ca.tests.base.utils import doctest_module


def test_doctests() -> None:
    """Load doctests."""
    failures, _tests = doctest_module("django_ca.pydantic.validators")
    assert failures == 0, f"{failures} doctests failed, see above for output."


@pytest.mark.parametrize(
    "name,validated",
    [
        ("example.com", "example.com"),
        ("er.tl", "er.tl"),
        ("exämple.com", "xn--exmple-cua.com"),
        (".example.com", ".example.com"),
        ("*.example.com", "*.example.com"),
        (".exämple.com", ".xn--exmple-cua.com"),
        ("*.exämple.com", "*.xn--exmple-cua.com"),
        # Examples from Wikipedia:
        ("ουτοπία.δπθ.gr", "xn--kxae4bafwg.xn--pxaix.gr"),
        ("bücher.example", "xn--bcher-kva.example"),
    ],
)
def test_dns_validator(name: str, validated: str) -> None:
    """Test :py:func:`django_ca.pydantic.validators.dns_validator`."""
    assert dns_validator(name) == validated


@pytest.mark.parametrize(
    "name,error",
    [("example com", "^Invalid domain: example com:"), ("@example.com", r"^Invalid domain: @example.com:")],
)
def test_dns_validator_errors(name: str, error: str) -> None:
    """Test errors for :py:func:`django_ca.pydantic.validators.dns_validator`."""
    with pytest.raises(ValueError, match=error):
        dns_validator(name)


@pytest.mark.parametrize(
    "email,validated",
    [("user@example.com", "user@example.com"), ("user@exämple.com", "user@xn--exmple-cua.com")],
)
def test_email_validator(email: str, validated: str) -> None:
    """Test :py:func:`django_ca.pydantic.validators.email_validator`."""
    assert email_validator(email) == validated


@pytest.mark.parametrize(
    "email,error",
    [
        ("user@example com", "^Invalid domain: example com"),
        ("user", "^Invalid email address: user$"),
        ("example.com", r"^Invalid email address: example\.com$"),
        ("@example.com", r"^@example.com: node part is empty$"),
    ],
)
def test_email_validator_errors(email: str, error: str) -> None:
    """Test errors for :py:func:`django_ca.pydantic.validators.email_validator`."""
    with pytest.raises(ValueError, match=error):
        email_validator(email)


@pytest.mark.parametrize(
    "url,validated",
    [
        ("http://example.com", "http://example.com"),
        ("http://exämple.com", "http://xn--exmple-cua.com"),
        ("https://www.example.net", "https://www.example.net"),
        ("https://www.example.net/", "https://www.example.net/"),
        ("https://www.example.net/test", "https://www.example.net/test"),
        ("https://www.example.net:443", "https://www.example.net:443"),
        ("https://www.exämple.net:443", "https://www.xn--exmple-cua.net:443"),
        ("https://www.example.net:443/", "https://www.example.net:443/"),
        ("https://www.example.net:443/test", "https://www.example.net:443/test"),
    ],
)
def test_url_validator(url: str, validated: str) -> None:
    """Test py:func:`django_ca.pydantic.validators.url_validator`."""
    assert url_validator(url) == validated


@pytest.mark.parametrize(
    "url,error",
    [
        ("https://example com", "^Invalid domain: example com: "),
        ("https://example com:80", "^Invalid domain: example com: "),
        ("example.com", r"^URL requires scheme and network location: example\.com$"),
        ("https://[abc", r"^Could not parse URL: https://\[abc: "),  # urlsplit() raises an error for this
        ("https://example.com:abc", r"^Invalid port: https://example\.com:abc: "),  # reading port...
        ("https://example.com:-1", r"^Invalid port: https://example\.com:-1: "),
    ],
)
def test_url_validator_errors(url: str, error: str) -> None:
    """Test errors for :py:func:`django_ca.pydantic.validators.url_validator`."""
    with pytest.raises(ValueError, match=error):
        url_validator(url)

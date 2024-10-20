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

"""Test :py:func:`~django_ca.utils.parse_general_name`."""

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Union

from cryptography import x509
from cryptography.x509.oid import NameOID

import pytest

from django_ca.tests.base.utils import cn, country, dns, uri
from django_ca.utils import parse_general_name


@pytest.mark.parametrize("prefix", ("", "ip:"))
@pytest.mark.parametrize(
    ("value", "expected"),
    (
        ("1.2.3.4", IPv4Address("1.2.3.4")),
        ("1.2.3.0/24", IPv4Network("1.2.3.0/24")),
        ("fd00::32", IPv6Address("fd00::32")),
        ("fd00::0/32", IPv6Network("fd00::0/32")),
    ),
)
def test_ip(
    prefix: str,
    value: str,
    expected: Union[IPv4Address, IPv4Network, IPv6Address, IPv6Network],
) -> None:
    """Test parsing an IPv4 address."""
    expected_name = x509.IPAddress(expected)
    assert parse_general_name(f"{prefix}{value}") == expected_name


@pytest.mark.parametrize("prefix", ("", "DNS:"))
@pytest.mark.parametrize(
    ("value", "expected"),
    (
        ("example.com", dns("example.com")),
        (".example.com", dns(".example.com")),
        ("*.example.com", dns("*.example.com")),
    ),
)
def test_domain(prefix: str, value: str, expected: x509.DNSName) -> None:
    """Test parsing a domain."""
    assert parse_general_name(f"{prefix}{value}") == expected


def test_invalid_wildcard_domain() -> None:
    """Test parsing a wildcard domain."""
    # Wildcard subdomains are allowed in DNS entries, however RFC 2595 limits their use to a single
    # wildcard in the outermost level
    msg = r"^Invalid domain: %s: "

    with pytest.raises(ValueError, match=msg % r"test\.\*\.example\.com"):
        parse_general_name("test.*.example.com")
    with pytest.raises(ValueError, match=msg % r"\*\.\*\.example\.com"):
        parse_general_name("*.*.example.com")
    with pytest.raises(ValueError, match=msg % r"example\.com\.\*"):
        parse_general_name("example.com.*")


def test_dirname() -> None:
    """Test parsing a dirname."""
    assert parse_general_name("dirname:CN=example.com") == x509.DirectoryName(x509.Name([cn("example.com")]))
    assert parse_general_name("dirname:C=AT,CN=example.com") == x509.DirectoryName(
        x509.Name([country("AT"), cn("example.com")])
    )


def test_uri() -> None:
    """Test parsing a URI."""
    url = "https://example.com"
    assert parse_general_name(url) == uri(url)
    assert parse_general_name(f"uri:{url}") == uri(url)


def test_rid() -> None:
    """Test parsing a Registered ID."""
    assert parse_general_name("rid:2.5.4.3") == x509.RegisteredID(NameOID.COMMON_NAME)


def test_unicode_domains() -> None:
    """Test some unicode domains."""
    assert parse_general_name("https://exämple.com/test") == uri("https://xn--exmple-cua.com/test")
    assert parse_general_name("https://exämple.com:8000/test") == uri("https://xn--exmple-cua.com:8000/test")
    assert parse_general_name("https://exämple.com:8000/test") == uri("https://xn--exmple-cua.com:8000/test")
    assert parse_general_name("uri:https://exämple.com:8000/test") == uri(
        "https://xn--exmple-cua.com:8000/test"
    )

    assert parse_general_name("exämple.com") == dns("xn--exmple-cua.com")
    assert parse_general_name(".exämple.com") == dns(".xn--exmple-cua.com")
    assert parse_general_name("*.exämple.com") == dns("*.xn--exmple-cua.com")
    assert parse_general_name("dns:exämple.com") == dns("xn--exmple-cua.com")
    assert parse_general_name("dns:.exämple.com") == dns(".xn--exmple-cua.com")
    assert parse_general_name("dns:*.exämple.com") == dns("*.xn--exmple-cua.com")


def test_wrong_email() -> None:
    """Test using an invalid email."""
    with pytest.raises(ValueError, match=r"^Invalid domain: user@:"):
        parse_general_name("user@")

    with pytest.raises(ValueError, match="^Invalid domain: : Empty domain$"):
        parse_general_name("email:user@")


def test_error() -> None:
    """Try parsing an unparsable IP address (b/c it has a network)."""
    with pytest.raises(ValueError, match=r"^Could not parse IP address\.$"):
        parse_general_name("ip:1.2.3.4/24")


def test_unparsable() -> None:
    """Test some unparsable domains."""
    with pytest.raises(ValueError, match=r"^Invalid domain: http://ex ample\.com: "):
        parse_general_name("http://ex ample.com")
    with pytest.raises(ValueError, match=r"^Invalid domain: ex ample\.com: "):
        parse_general_name("uri:http://ex ample.com")
    with pytest.raises(ValueError, match=r"^Invalid domain: ex ample\.com: "):
        parse_general_name("dns:ex ample.com")
    with pytest.raises(
        ValueError, match=r"^Cannot parse general name False: Must be of type str \(was: bool\)\.$"
    ):
        parse_general_name(False)  # type: ignore[arg-type]  # what we test

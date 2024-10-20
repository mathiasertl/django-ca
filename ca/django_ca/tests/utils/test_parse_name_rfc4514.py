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

"""Test parse_name_rfc4514 function."""

from cryptography import x509
from cryptography.x509.oid import NameOID

import pytest

from django_ca.tests.base.constants import CRYPTOGRAPHY_VERSION
from django_ca.tests.base.utils import cn, country
from django_ca.utils import parse_name_rfc4514


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        ("CN=example.com", x509.Name([cn("example.com")])),
        (f"{NameOID.COMMON_NAME.dotted_string}=example.com", x509.Name([cn("example.com")])),
        ("C=AT,CN=example.com", x509.Name([country("AT"), cn("example.com")])),
    ),
)
def test_parse_name_rfc4514(value: str, expected: x509.Name) -> None:
    """Test the parse_name_rfc4514 function."""
    assert parse_name_rfc4514(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        (
            "C=FOO",
            r"^Country name must be a 2 character country code$"
            if CRYPTOGRAPHY_VERSION < (43,)
            else r"^Attribute's length must be >= 2 and <= 2, but it was 3$",
        ),
        ("/CN=example.com", r"^/CN=example\.com: Could not parse name as RFC 4514 string\.$"),
        ("XXX=example.com", r"^XXX=example\.com: Could not parse name as RFC 4514 string\.$"),
    ),
)
def test_parse_name_rfc4514_with_error(value: str, expected: str) -> None:
    """Test various errors."""
    with pytest.raises(ValueError, match=expected):
        assert parse_name_rfc4514(value)


@pytest.mark.skipif(CRYPTOGRAPHY_VERSION < (43,), reason="cryptography check was added in version 43")
@pytest.mark.parametrize(
    ("value", "expected"),
    (
        ("CN=", r"^Attribute's length must be >= 1 and <= 64, but it was 0$"),
        (f"CN={'x' * 65}", r"^Attribute's length must be >= 1 and <= 64, but it was 65$"),
    ),
)
def test_parse_name_rfc4514_with_invalid_common_name(value: str, expected: str) -> None:
    """Test checks added in cryptography 43."""
    with pytest.raises(ValueError, match=expected):
        assert parse_name_rfc4514(value)

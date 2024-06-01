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

"""Test :py:func:`django_ca.utils.validate_hostname`."""

import pytest

from django_ca.utils import validate_hostname


@pytest.mark.parametrize("value", ("localhost", "testserver", "example.com", "test.example.com"))
def test_no_port(value: str) -> None:
    """Test with no port."""
    assert validate_hostname(value) == value


@pytest.mark.parametrize(
    "value",
    (
        "localhost:443",
        "testserver:443",
        "example.com:443",
        "test.example.com:443",
        "test.example.com:1",
        "example.com:65535",
    ),
)
def test_with_port(value: str) -> None:
    """Test with a port."""
    assert validate_hostname(value, allow_port=True) == value


@pytest.mark.parametrize("value", ("example..com", "..example.com"))
def test_invalid_hostname(value: str) -> None:
    """Test with an invalid hostname."""
    with pytest.raises(ValueError, match=f"{value}: Not a valid hostname"):
        validate_hostname(value)


@pytest.mark.parametrize("value", ("localhost:443", "test.example.com:443"))
def test_no_allow_port(value: str) -> None:
    """Test passing a port when it's not allowed."""
    with pytest.raises(ValueError, match=rf"^{value}: Not a valid hostname$"):
        validate_hostname(value)


@pytest.mark.parametrize(
    "value,error",
    (
        ("localhost:no-int", "^no-int: Port must be an integer$"),
        ("localhost:0", "^0: Port must be between 1 and 65535$"),
        ("localhost:-5", "^-5: Port must be between 1 and 65535$"),
        ("localhost:65536", "^65536: Port must be between 1 and 65535$"),
        ("localhost:double:colon", "^colon: Port must be an integer$"),
    ),
)
def test_port_errors(value: str, error: str) -> None:
    """Test passing an invalid port."""
    with pytest.raises(ValueError, match=error):
        validate_hostname(value, allow_port=True)

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

"""Test django_ca.utils.parse_encoding."""

from cryptography.hazmat.primitives.serialization import Encoding

import pytest

from django_ca.utils import parse_encoding


@pytest.mark.parametrize(
    ("value", "expected"),
    (("PEM", Encoding.PEM), ("DER", Encoding.DER), ("ASN1", Encoding.DER), ("OpenSSH", Encoding.OpenSSH)),
)
def test_parse_encoding(value: str, expected: Encoding) -> None:
    """Test :py:func:`django_ca.utils.parse_encoding`."""
    assert parse_encoding(value) == expected


def test_parse_encoding_with_invalid_value() -> None:
    """Test some error cases."""
    with pytest.raises(ValueError, match=r"^Unknown encoding: foo$"):
        parse_encoding("foo")

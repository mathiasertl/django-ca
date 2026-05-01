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

from django_ca.utils import format_encoding


@pytest.mark.parametrize(
    ("value", "expected"), ((Encoding.PEM, "PEM"), (Encoding.DER, "DER"), (Encoding.OpenSSH, "OpenSSH"))
)
def test_parse_encoding(value: Encoding, expected: str) -> None:
    """Test :py:func:`django_ca.utils.parse_encoding`."""
    assert format_encoding(value) == expected

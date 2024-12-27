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

"""Test ``django_ca.utils.name_for_display``."""

from cryptography import x509
from cryptography.x509 import NameOID
from cryptography.x509.name import _ASN1Type

import pytest

from django_ca.tests.base.utils import cn
from django_ca.utils import name_for_display


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        (x509.Name([cn("example.com")]), [("commonName (CN)", "example.com")]),
        (
            x509.Name([cn("example.net"), cn("example.com")]),
            [("commonName (CN)", "example.net"), ("commonName (CN)", "example.com")],
        ),
        (
            x509.Name(
                [
                    x509.NameAttribute(
                        oid=NameOID.X500_UNIQUE_IDENTIFIER, value=b"example.com", _type=_ASN1Type.BitString
                    )
                ]
            ),
            [("x500UniqueIdentifier", "65:78:61:6D:70:6C:65:2E:63:6F:6D")],
        ),
    ),
)
def test_name_for_display(value: x509.Name, expected: list[tuple[str, str]]) -> None:
    """Test the function."""
    assert name_for_display(value) == expected

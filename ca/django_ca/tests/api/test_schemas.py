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

"""Tests for pydantic schemas."""

import json

from cryptography import x509
from cryptography.x509.oid import NameOID

import pytest

from django_ca.api.extension_schemas import NameAttributeSchema


@pytest.mark.parametrize(
    "oid,value",
    [
        (NameOID.COMMON_NAME, "example.com"),
        (NameOID.COUNTRY_NAME, "AT"),
    ],
)
def test_name_attribute_schema(oid: x509.ObjectIdentifier, value: str) -> None:
    """Test NameAttributeSchema."""
    encoded = NameAttributeSchema(oid=oid.dotted_string, value=value).model_dump_json()
    assert json.loads(encoded) == {"oid": oid.dotted_string, "value": value}


def test_name_attribute_with_bytes() -> None:
    """Test name attribute with bytes."""
    encoded = NameAttributeSchema(
        oid=NameOID.X500_UNIQUE_IDENTIFIER.dotted_string, value=b"\x00\x01"
    ).model_dump_json()
    assert json.loads(encoded) == {"oid": NameOID.X500_UNIQUE_IDENTIFIER.dotted_string, "value": "AAE="}

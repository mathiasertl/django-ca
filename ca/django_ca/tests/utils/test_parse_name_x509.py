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

"""Test :py:func:`~django_ca.utils.parse_name_x509`."""

from cryptography import x509
from cryptography.x509.oid import NameOID

import pytest

from django_ca.tests.base.assertions import assert_removed_in_230
from django_ca.utils import parse_name_x509


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        ("/CN=example.com", [(NameOID.COMMON_NAME, "example.com")]),
        # leading or trailing spaces are always ok:
        (" /CN = example.com ", [(NameOID.COMMON_NAME, "example.com")]),
        # emailAddress is special because of the case:
        ("/emailAddress=user@example.com", [(NameOID.EMAIL_ADDRESS, "user@example.com")]),
        # test multiple tokens
        (
            "/C=AT/OU=foo/CN=example.com",
            [
                (NameOID.COUNTRY_NAME, "AT"),
                (NameOID.ORGANIZATIONAL_UNIT_NAME, "foo"),
                (NameOID.COMMON_NAME, "example.com"),
            ],
        ),
        (
            "/C=AT/OU=foo/OU=bar/CN=example.com",
            [
                (NameOID.COUNTRY_NAME, "AT"),
                (NameOID.ORGANIZATIONAL_UNIT_NAME, "foo"),
                (NameOID.ORGANIZATIONAL_UNIT_NAME, "bar"),
                (NameOID.COMMON_NAME, "example.com"),
            ],
        ),
        # test that cacse doesn't matter:
        (
            "/c=AT/ou=foo/cn=example.com/eMAIladdrESs=user@example.com",
            [
                (NameOID.COUNTRY_NAME, "AT"),
                (NameOID.ORGANIZATIONAL_UNIT_NAME, "foo"),
                (NameOID.COMMON_NAME, "example.com"),
                (NameOID.EMAIL_ADDRESS, "user@example.com"),
            ],
        ),
        # empty values are okay too
        ("", []),
        ("   ", []),
        # test multiple slashes
        ("/C=AT/O=GNU", [(NameOID.COUNTRY_NAME, "AT"), (NameOID.ORGANIZATION_NAME, "GNU")]),
        ("//C=AT/O=GNU", [(NameOID.COUNTRY_NAME, "AT"), (NameOID.ORGANIZATION_NAME, "GNU")]),
        ("/C=AT//O=GNU", [(NameOID.COUNTRY_NAME, "AT"), (NameOID.ORGANIZATION_NAME, "GNU")]),
        ("/C=AT///O=GNU", [(NameOID.COUNTRY_NAME, "AT"), (NameOID.ORGANIZATION_NAME, "GNU")]),
        # Test empty fields.
        (
            "/C=AT/O=GNU/OU=foo",
            [
                (NameOID.COUNTRY_NAME, "AT"),
                (NameOID.ORGANIZATION_NAME, "GNU"),
                (NameOID.ORGANIZATIONAL_UNIT_NAME, "foo"),
            ],
        ),
        (
            "/C=AT/O=/OU=foo",
            [
                (NameOID.COUNTRY_NAME, "AT"),
                (NameOID.ORGANIZATION_NAME, ""),
                (NameOID.ORGANIZATIONAL_UNIT_NAME, "foo"),
            ],
        ),
        (
            "/C=AT/O=GNU/OU=",
            [
                (NameOID.COUNTRY_NAME, "AT"),
                (NameOID.ORGANIZATION_NAME, "GNU"),
                (NameOID.ORGANIZATIONAL_UNIT_NAME, ""),
            ],
        ),
        ("/O=/OU=", [(NameOID.ORGANIZATION_NAME, ""), (NameOID.ORGANIZATIONAL_UNIT_NAME, "")]),
        # no slash at start works:
        ("CN=example.com", [(NameOID.COMMON_NAME, "example.com")]),
        (
            "/OU=foo/OU=bar",
            [(NameOID.ORGANIZATIONAL_UNIT_NAME, "foo"), (NameOID.ORGANIZATIONAL_UNIT_NAME, "bar")],
        ),
        (
            "/C=AT/O=bla/OU=foo/OU=bar/CN=example.com/",
            [
                (NameOID.COUNTRY_NAME, "AT"),
                (NameOID.ORGANIZATION_NAME, "bla"),
                (NameOID.ORGANIZATIONAL_UNIT_NAME, "foo"),
                (NameOID.ORGANIZATIONAL_UNIT_NAME, "bar"),
                (NameOID.COMMON_NAME, "example.com"),
            ],
        ),
        (
            "/C=AT/O=bla/OU=foo/OU=bar/OU=hugo/CN=example.com/",
            [
                (NameOID.COUNTRY_NAME, "AT"),
                (NameOID.ORGANIZATION_NAME, "bla"),
                (NameOID.ORGANIZATIONAL_UNIT_NAME, "foo"),
                (NameOID.ORGANIZATIONAL_UNIT_NAME, "bar"),
                (NameOID.ORGANIZATIONAL_UNIT_NAME, "hugo"),
                (NameOID.COMMON_NAME, "example.com"),
            ],
        ),
        (
            "/C=AT/DC=com/DC=example/CN=example.com",
            [
                (NameOID.COUNTRY_NAME, "AT"),
                (NameOID.DOMAIN_COMPONENT, "com"),
                (NameOID.DOMAIN_COMPONENT, "example"),
                (NameOID.COMMON_NAME, "example.com"),
            ],
        ),
        # Test parsing a few of the more exotic names.
        (
            "/DC=foo/serialNumber=serial/title=phd",
            [(NameOID.DOMAIN_COMPONENT, "foo"), (NameOID.SERIAL_NUMBER, "serial"), (NameOID.TITLE, "phd")],
        ),
        (
            "/C=AT/DC=foo/serialNumber=serial/CN=example.com/uid=123/title=phd",
            [
                (NameOID.COUNTRY_NAME, "AT"),
                (NameOID.DOMAIN_COMPONENT, "foo"),
                (NameOID.SERIAL_NUMBER, "serial"),
                (NameOID.COMMON_NAME, "example.com"),
                (NameOID.USER_ID, "123"),
                (NameOID.TITLE, "phd"),
            ],
        ),
        # test aliases
        (
            "commonName=example.com/surname=Ertl/userid=0",
            ((NameOID.COMMON_NAME, "example.com"), (NameOID.SURNAME, "Ertl"), (NameOID.USER_ID, "0")),
        ),
    ),
)
def test_parse_name_x509(value: str, expected: list[tuple[x509.ObjectIdentifier, str]]) -> None:
    """Some basic tests."""
    with assert_removed_in_230():
        assert parse_name_x509(value) == tuple(x509.NameAttribute(oid, value) for oid, value in expected)


def test_unknown() -> None:
    """Test unknown field."""
    with assert_removed_in_230(), pytest.raises(ValueError, match=r"^Unknown x509 name field: ABC$"):
        parse_name_x509("/ABC=example.com")

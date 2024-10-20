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

"""Test parsing and formatting :py:class:`~cg:cryptography.x509.OtherName` instances."""

import asn1crypto.core
from cryptography import x509
from cryptography.x509.oid import NameOID

import pytest

from django_ca.utils import format_other_name, parse_other_name


@pytest.mark.parametrize(
    ("value", "expected", "normalized"),
    (
        ("UNIVERSALSTRING:ex", b"\x1c\x08\x00\x00\x00e\x00\x00\x00x", True),
        ("UNIV:ex", b"\x1c\x08\x00\x00\x00e\x00\x00\x00x", False),
        ("IA5STRING:example", b"\x16\x07example", True),
        ("IA5:example", b"\x16\x07example", False),
        # BOOLEAN is tested in dedicated tests
        ("UTCTIME:211005220104Z", b"\x17\r211005220104Z", True),
        ("UTC:211005220104Z", b"\x17\r211005220104Z", False),
        ("GENERALIZEDTIME:20211005220104Z", b"\x18\x0f20211005220104Z", True),
        ("GENTIME:20211005220104Z", b"\x18\x0f20211005220104Z", False),
        # INTEGER is tested in dedicated tests
        ("NULL:", b"\x05\x00", True),
        (
            "OctetString:09CFF1A8F6DEFD4B85CE95FFA1B54217",
            b"\x04\x10\t\xcf\xf1\xa8\xf6\xde\xfdK\x85\xce\x95\xff\xa1\xb5B\x17",
            True,
        ),
        (
            "OctetString:09cff1a8f6defd4b85ce95ffa1b54217",  # same but lowercased hex
            b"\x04\x10\t\xcf\xf1\xa8\xf6\xde\xfdK\x85\xce\x95\xff\xa1\xb5B\x17",
            False,
        ),
    ),
)
def test_parse_and_format_othername(value: str, expected: bytes, normalized: bool) -> None:
    """Test generic parsing and formatting."""
    parsed_other_name = parse_other_name(f"2.5.4.3;{value}")
    assert parsed_other_name == x509.OtherName(NameOID.COMMON_NAME, expected)

    if normalized is True:
        assert format_other_name(parsed_other_name) == f"2.5.4.3;{value}"


@pytest.mark.parametrize("typ", ("UTF8", "UTF8String"))
@pytest.mark.parametrize(
    ("value", "expected"),
    (("example", b"\x0c\x07example"), ("example;wrong:val", b"\x0c\x11example;wrong:val")),
)
def test_othername_with_utf8(typ: str, value: str, expected: bytes) -> None:
    """Test UTF8 values."""
    parsed = x509.OtherName(NameOID.COMMON_NAME, expected)
    assert parse_other_name(f"2.5.4.3;{typ}:{value}") == parsed
    assert format_other_name(parsed) == f"2.5.4.3;UTF8String:{value}"


@pytest.mark.parametrize("typ", ("BOOL", "BOOLEAN"))
@pytest.mark.parametrize("value", ("TRUE", "true", "Y", "y", "YES", "yes"))
def test_othername_with_boolean_true(typ: str, value: str) -> None:
    """Test Boolean with a ``True`` value."""
    parsed = x509.OtherName(NameOID.COMMON_NAME, b"\x01\x01\xff")
    assert parse_other_name(f"2.5.4.3;{typ}:{value}") == parsed
    assert format_other_name(parsed) == "2.5.4.3;BOOLEAN:TRUE"


@pytest.mark.parametrize("typ", ("BOOL", "BOOLEAN"))
@pytest.mark.parametrize("value", ("FALSE", "false", "N", "n", "NO", "no"))
def test_othername_with_boolean_false(typ: str, value: str) -> None:
    """Test Boolean with a ``False`` value."""
    parsed = x509.OtherName(NameOID.COMMON_NAME, b"\x01\x01\x00")
    assert parse_other_name(f"2.5.4.3;{typ}:{value}") == parsed
    assert format_other_name(parsed) == "2.5.4.3;BOOLEAN:FALSE"


@pytest.mark.parametrize("typ", ("INT", "INTEGER"))
@pytest.mark.parametrize(
    ("raw_value", "expected_bytes", "formatted_value"),
    (
        ("0", b"\x02\x01\x00", "0"),
        ("1", b"\x02\x01\x01", "1"),
        ("-1", b"\x02\x01\xff", "-1"),
        ("0x123", b"\x02\x02\x01#", "291"),
    ),
)
def test_othername_integer(typ: str, raw_value: str, expected_bytes: bytes, formatted_value: str) -> None:
    """Test integer values."""
    parsed = parse_other_name(f"2.5.4.3;{typ}:{raw_value}")
    assert parsed == x509.OtherName(NameOID.COMMON_NAME, expected_bytes)
    assert format_other_name(parsed) == f"2.5.4.3;INTEGER:{formatted_value}"


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        (
            "2.4.5.3;BOOL:WRONG",
            r"^Unsupported BOOL specification for otherName: WRONG: Must be TRUE or FALSE$",
        ),
        (
            "2.4.5.3;UTC:WRONG",
            r"^time data 'WRONG' does not match format '%y%m%d%H%M%SZ'$",
        ),
        ("2.5.4.3;NULL:VALUE", r"^Invalid NULL specification for otherName: Value must not be present$"),
        ("", "^Incorrect otherName format: $"),
        ("2.3.5.3;", "^Incorrect otherName format: 2.3.5.3;$"),
        ("1.2.3;MagicString:Broken", "^Unsupported ASN type in otherName: MagicString$"),
    ),
)
def test_parse_othername_errors(value: str, expected: str) -> None:
    """Test various errors."""
    with pytest.raises(ValueError, match=expected):
        parse_other_name(value)


def test_format_othername_with_unsupported_format() -> None:
    """Test formatting an unsupported type."""
    value = x509.OtherName(NameOID.COMMON_NAME, asn1crypto.core.TeletexString("").dump())
    with pytest.raises(ValueError, match="^Unsupported ASN type in otherName: TeletexString$"):
        format_other_name(value)

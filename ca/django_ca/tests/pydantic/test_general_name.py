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

"""Test GeneralNameModel."""
import ipaddress
from datetime import datetime, timezone as tz
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Any, Dict, Type

from pydantic import ValidationError

from cryptography import x509
from cryptography.x509.oid import NameOID

import pytest

from django_ca import constants
from django_ca.pydantic.general_name import GeneralNameModel, OtherNameModel
from django_ca.pydantic.name import NameModel
from django_ca.tests.base.utils import dns, doctest_module, ip, uri
from django_ca.tests.pydantic.base import ExpectedErrors, assert_cryptography_model, assert_validation_errors


def test_doctests() -> None:
    """Load doctests."""
    failures, _tests = doctest_module("django_ca.pydantic.general_name")
    assert failures == 0, f"{failures} doctests failed, see above for output."


@pytest.mark.parametrize(
    "typ,value,encoded",
    (
        ("UTF8", "example", b"\x0c\x07example"),
        ("UTF8String", "example", b"\x0c\x07example"),
        ("UNIVERSALSTRING", "ex", b"\x1c\x08\x00\x00\x00e\x00\x00\x00x"),
        ("UNIV", "ex", b"\x1c\x08\x00\x00\x00e\x00\x00\x00x"),
        ("IA5STRING", "example", b"\x16\x07example"),
        ("IA5", "example", b"\x16\x07example"),
        ("BOOLEAN", True, b"\x01\x01\xff"),
        ("BOOL", True, b"\x01\x01\xff"),
        ("BOOLEAN", False, b"\x01\x01\x00"),
        ("UTCTIME", datetime(2021, 10, 5, 22, 1, 4, tzinfo=tz.utc), b"\x17\r211005220104Z"),
        ("UTC", datetime(2021, 10, 5, 22, 1, 4, tzinfo=tz.utc), b"\x17\r211005220104Z"),
        ("GENERALIZEDTIME", datetime(2021, 10, 5, 22, 1, 4, tzinfo=tz.utc), b"\x18\x0f20211005220104Z"),
        ("GENTIME", datetime(2021, 10, 5, 22, 1, 4, tzinfo=tz.utc), b"\x18\x0f20211005220104Z"),
        ("NULL", None, b"\x05\x00"),
        ("INTEGER", 0, b"\x02\x01\x00"),
        ("INTEGER", 1, b"\x02\x01\x01"),
        ("INTEGER", -1, b"\x02\x01\xff"),
        ("INTEGER", "256", b"\x02\x02\x01\x00"),
        ("INTEGER", "0x123", b"\x02\x02\x01#"),
        ("INT", 0, b"\x02\x01\x00"),
        ("OctetString", b"\t\xcf\xf1", b"\x04\x03\t\xcf\xf1"),
        (
            "OctetString",
            "09CFF1A8F6DEFD4B85CE95FFA1B54217",
            b"\x04\x10\t\xcf\xf1\xa8\xf6\xde\xfdK\x85\xce\x95\xff\xa1\xb5B\x17",
        ),
    ),
)
def test_other_name(typ: str, value: Any, encoded: bytes) -> None:
    """Test OtherName instances."""
    model = OtherNameModel(oid="1.2.3", type=typ, value=value)
    expected = x509.OtherName(type_id=x509.ObjectIdentifier("1.2.3"), value=encoded)
    assert model.cryptography == expected
    assert OtherNameModel.model_validate(expected) == model


@pytest.mark.parametrize("typ", ("UTF8String", "UNIVERSALSTRING", "IA5STRING", "UTF8", "UNIV", "IA5"))
def test_other_name_string_type_errors(typ: str) -> None:
    """Test errors for string-based values (UTF8String etc)."""
    output_type = constants.OTHER_NAME_ALIASES.get(typ, typ)
    errors: ExpectedErrors = [("value_error", (), f"Value error, {output_type}: Value must be a str object.")]
    assert_validation_errors(OtherNameModel, {"oid": "1.2.3", "value": 1, "type": typ}, errors)


@pytest.mark.parametrize("typ", ("BOOLEAN", "BOOL"))
def test_other_name_bool_type_errors(typ: str) -> None:
    """Test errors for BOOLEAN."""
    output_type = constants.OTHER_NAME_ALIASES.get(typ, typ)
    errors: ExpectedErrors = [("value_error", (), f"Value error, {output_type}: Value must be a boolean.")]
    assert_validation_errors(OtherNameModel, {"oid": "1.2.3", "value": "abc", "type": typ}, errors)


@pytest.mark.parametrize("typ", ("UTC", "UTCTIME", "GENTIME", "GENERALIZEDTIME"))
def test_other_name_datetime_type_errors(typ: str) -> None:
    """Test errors for UTCTIME and GENERALIZEDTIME."""
    output_type = constants.OTHER_NAME_ALIASES.get(typ, typ)
    errors: ExpectedErrors = [
        ("value_error", (), f"Value error, {output_type}: Value must be a datetime object.")
    ]
    assert_validation_errors(OtherNameModel, {"oid": "1.2.3", "value": "abc", "type": typ}, errors)


@pytest.mark.parametrize("typ", ("INT", "INTEGER"))
def test_other_name_int_type_errors(typ: str) -> None:
    """Test errors for INTEGER type."""
    output_type = constants.OTHER_NAME_ALIASES.get(typ, typ)
    errors: ExpectedErrors = [("value_error", (), f"Value error, {output_type}: Value must be an int.")]
    assert_validation_errors(OtherNameModel, {"oid": "1.2.3", "value": "abc", "type": typ}, errors)


def test_other_name_null_type_errors() -> None:
    """Test errors for NULL type."""
    errors: ExpectedErrors = [("value_error", (), "Value error, NULL: Value must be None.")]
    assert_validation_errors(OtherNameModel, {"oid": "1.2.3", "value": "abc", "type": "NULL"}, errors)


def test_other_name_octetstring_type_errors() -> None:
    """Test OctetString for OtherNameModel."""
    errors: ExpectedErrors = [("value_error", (), "Value error, OctetString: Value must be a str object.")]
    assert_validation_errors(OtherNameModel, {"oid": "1.2.3", "value": 1, "type": "OctetString"}, errors)


@pytest.mark.parametrize(
    "value,match",
    (
        (b"123", r"Value error, could not parse asn1 data: .*"),
        (b"\x03\x02\x04P", "3: Unknown otherName type found."),
    ),
)
def test_othername_general_errors(value: bytes, match: str) -> None:
    """Test errors for OtherNameModel."""
    other_name = x509.OtherName(type_id=x509.ObjectIdentifier("1.2.3"), value=value)
    with pytest.raises(ValidationError, match=match) as ex_info:
        OtherNameModel.model_validate(other_name)

    errors = ex_info.value.errors()
    assert len(errors) == 1, errors
    assert errors[0]["type"] == "value_error", errors[0]["type"]
    assert errors[0]["loc"] == ()


@pytest.mark.parametrize(
    "parameters,name,discriminated",
    (
        ({"type": "DNS", "value": "example.com"}, dns("example.com"), str),  # 0
        ({"type": "DNS", "value": "xn--exmple-cua.com"}, dns("xn--exmple-cua.com"), str),  # 1
        ({"type": "URI", "value": "http://example.com"}, uri("http://example.com"), str),  # 2
        ({"type": "URI", "value": "http://xn--exmple-cua.com"}, uri("http://xn--exmple-cua.com"), str),  # 3
        ({"type": "email", "value": "user@example.com"}, x509.RFC822Name("user@example.com"), str),  # 4
        (
            {"type": "email", "value": "user@xn--exmple-cua.com"},
            x509.RFC822Name("user@xn--exmple-cua.com"),
            str,
        ),
        ({"type": "IP", "value": "127.0.0.1"}, ip(IPv4Address("127.0.0.1")), ipaddress.IPv4Address),  # 6
        ({"type": "IP", "value": "127.0.0.1/32"}, ip(IPv4Network("127.0.0.1/32")), ipaddress.IPv4Network),
        ({"type": "IP", "value": "::1"}, ip(IPv6Address("::1")), ipaddress.IPv6Address),  # 8
        ({"type": "IP", "value": "2001::/64"}, ip(IPv6Network("2001::/64")), ipaddress.IPv6Network),  # 9
        ({"type": "RID", "value": "1.2.3"}, x509.RegisteredID(x509.ObjectIdentifier("1.2.3")), str),  # 10
        (
            {
                "type": "dirName",
                "value": [{"oid": NameOID.COMMON_NAME.dotted_string, "value": "example.com"}],
            },
            x509.DirectoryName(x509.Name([x509.NameAttribute(oid=NameOID.COMMON_NAME, value="example.com")])),
            NameModel,
        ),
        (
            {"type": "otherName", "value": {"oid": "1.2.3", "type": "BOOLEAN", "value": True}},
            x509.OtherName(x509.ObjectIdentifier("1.2.3"), b"\x01\x01\xff"),
            OtherNameModel,
        ),
    ),
)
def test_general_name(parameters: Dict[str, Any], name: x509.GeneralName, discriminated: Type[Any]) -> None:
    """Test GeneralNameModel."""
    model = assert_cryptography_model(GeneralNameModel, parameters, name)

    # Make sure that the value has the expected discriminated value (see model declaration for details)
    assert isinstance(model.value, discriminated)


@pytest.mark.parametrize(
    "typ,value,errors",
    (
        ("URI", 123, [("string_type", ("value", "str"), "Input should be a valid string")]),
        ("email", 123, [("string_type", ("value", "str"), "Input should be a valid string")]),
        (
            "URI",
            ipaddress.IPv4Address("127.0.0.1"),
            [("value_error", (), "Value error, 127.0.0.1: Must be a str for type URI")],
        ),
        (
            "URI",
            "https://-",
            [("value_error", (), "Value error, Could not parse DNS name in URL: https://-")],
        ),
        (
            "email",
            ipaddress.IPv4Address("127.0.0.1"),
            [("value_error", (), "Value error, 127.0.0.1: Must be a str for type email")],
        ),
        (
            "IP",
            "abc",
            [("value_error", (), "Value error, abc: Could not parse IP address")],
        ),
        (
            "IP",
            [{"type": NameOID.COMMON_NAME.dotted_string, "value": "example.com", "oid": "1.2.3"}],
            [
                (
                    "value_error",
                    (),
                    "Value error, root=[NameAttributeModel(oid='1.2.3', value='example.com')]: Must be an "
                    "IPAddress/IPNetwork for type IP",
                )
            ],
        ),
        (
            "RID",
            ipaddress.IPv4Address("127.0.0.1"),
            [("value_error", (), "Value error, 127.0.0.1: Must be a str for type RID")],
        ),
        (
            "otherName",
            ipaddress.IPv4Address("127.0.0.1"),
            [("value_error", (), "Value error, 127.0.0.1: Must be OtherNameModel for type otherName")],
        ),
        (
            "DNS",
            ipaddress.IPv4Address("127.0.0.1"),
            [("value_error", (), "Value error, 127.0.0.1: Must be a str for type DNS")],
        ),
    ),
)
def test_general_name_type_errors(typ: str, value: Any, errors: ExpectedErrors) -> None:
    """Test GeneralNameModel errors."""
    assert_validation_errors(GeneralNameModel, {"type": typ, "value": value}, errors)

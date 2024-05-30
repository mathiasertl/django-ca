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

"""Tests for NameAttributeModel and NameModel."""

from typing import Any

from cryptography import x509
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import NameOID

import pytest

from django_ca.pydantic.name import NameAttributeModel, NameModel
from django_ca.tests.base.doctest import doctest_module
from django_ca.tests.pydantic.base import ExpectedErrors, assert_cryptography_model, assert_validation_errors


def test_doctests() -> None:
    """Run doctests for this module."""
    failures, _tests = doctest_module("django_ca.pydantic.name")
    assert failures == 0, f"{failures} doctests failed, see above for output."


@pytest.mark.parametrize(
    "parameters,name_attr",
    (
        (
            {"oid": NameOID.COMMON_NAME.dotted_string, "value": "example.com"},
            x509.NameAttribute(oid=NameOID.COMMON_NAME, value="example.com"),
        ),
        (
            {"oid": "CN", "value": "example.com"},
            x509.NameAttribute(oid=NameOID.COMMON_NAME, value="example.com"),
        ),
        (
            {"oid": "C", "value": "AT"},
            x509.NameAttribute(oid=NameOID.COUNTRY_NAME, value="AT"),
        ),
        (
            {"oid": "countryName", "value": "AT"},
            x509.NameAttribute(oid=NameOID.COUNTRY_NAME, value="AT"),
        ),
        (
            {"oid": "streetAddress", "value": "example.com"},
            x509.NameAttribute(oid=NameOID.STREET_ADDRESS, value="example.com"),
        ),
        (
            {"oid": "organizationalUnitName", "value": "OrgUnit"},
            x509.NameAttribute(oid=NameOID.ORGANIZATIONAL_UNIT_NAME, value="OrgUnit"),
        ),
        (
            {"oid": "OU", "value": "OrgUnit"},
            x509.NameAttribute(oid=NameOID.ORGANIZATIONAL_UNIT_NAME, value="OrgUnit"),
        ),
        (
            {"oid": x509.OID_ORGANIZATIONAL_UNIT_NAME, "value": "OrgUnit"},
            x509.NameAttribute(oid=NameOID.ORGANIZATIONAL_UNIT_NAME, value="OrgUnit"),
        ),
        (
            {"oid": "x500UniqueIdentifier", "value": "ZXhhbXBsZS5jb20="},
            x509.NameAttribute(
                oid=NameOID.X500_UNIQUE_IDENTIFIER, value=b"example.com", _type=_ASN1Type.BitString
            ),
        ),
    ),
)
def test_name_attribute(parameters: dict[str, Any], name_attr: x509.NameAttribute) -> None:
    """Test NameAttributeModel."""
    assert_cryptography_model(NameAttributeModel, parameters, name_attr)


@pytest.mark.parametrize(
    "parameters,errors",
    (
        (
            {"oid": "foo", "value": "example.com"},
            [("value_error", ("oid",), "Value error, foo: Invalid object identifier")],
        ),
    ),
)
def test_name_attribute_errors(parameters: dict[str, str], errors: ExpectedErrors) -> None:
    """Test errors for NameAttributes."""
    assert_validation_errors(NameAttributeModel, parameters, errors)


@pytest.mark.parametrize("value", ("", "A", "ABC"))
@pytest.mark.parametrize(
    "oid",
    (
        NameOID.COUNTRY_NAME,
        NameOID.COUNTRY_NAME.dotted_string,
        "C",
        "countryName",
        NameOID.JURISDICTION_COUNTRY_NAME,
        NameOID.JURISDICTION_COUNTRY_NAME.dotted_string,
    ),
)
def test_name_attribute_country_code_errors(oid: str, value: str) -> None:
    """Test validation for country codes."""
    errors: ExpectedErrors = [("value_error", (), f"Value error, {value}: Must have exactly two characters")]
    assert_validation_errors(NameAttributeModel, {"oid": oid, "value": value}, errors)


@pytest.mark.parametrize(
    "oid",
    (NameOID.COMMON_NAME, NameOID.COMMON_NAME.dotted_string, "CN", "commonName"),
)
def test_name_attribute_empty_common_name(oid: Any) -> None:
    """Test validation for country codes."""
    errors: ExpectedErrors = [("value_error", (), "Value error, commonName must not be an empty value")]
    assert_validation_errors(NameAttributeModel, {"oid": oid, "value": ""}, errors)


@pytest.mark.parametrize(
    "serialized,expected",
    (
        ([], x509.Name([])),
        (
            [{"oid": NameOID.COMMON_NAME.dotted_string, "value": "example.com"}],
            [x509.NameAttribute(oid=NameOID.COMMON_NAME, value="example.com")],
        ),
        (
            [
                {"oid": NameOID.COUNTRY_NAME.dotted_string, "value": "AT"},
                {"oid": NameOID.ORGANIZATION_NAME.dotted_string, "value": "OrgName"},
                {"oid": NameOID.COMMON_NAME.dotted_string, "value": "example.com"},
            ],
            [
                x509.NameAttribute(oid=NameOID.COUNTRY_NAME, value="AT"),
                x509.NameAttribute(oid=NameOID.ORGANIZATION_NAME, value="OrgName"),
                x509.NameAttribute(oid=NameOID.COMMON_NAME, value="example.com"),
            ],
        ),
    ),
)
def test_name(serialized: list[dict[str, Any]], expected: list[x509.NameAttribute]) -> None:
    """Test NameModel."""
    assert_cryptography_model(NameModel, {"root": serialized}, x509.Name(expected))  # type: ignore[type-var]


@pytest.mark.parametrize(
    "value,errors",
    (
        (
            [
                {"oid": NameOID.COMMON_NAME.dotted_string, "value": "example.com"},
                {"oid": NameOID.COMMON_NAME.dotted_string, "value": "example.net"},
            ],
            [
                (
                    "value_error",
                    (),
                    "Value error, attribute of type commonName must not occur more then once in a name.",
                )
            ],
        ),
    ),
)
def test_name_errors(value: list[dict[str, Any]], errors: ExpectedErrors) -> None:
    """Test validation errors for NameModel."""
    assert_validation_errors(NameModel, value, errors)

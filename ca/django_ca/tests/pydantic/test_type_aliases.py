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

"""Test type aliases for Pydantic."""

from pydantic import BaseModel

import pytest

from django_ca.pydantic.type_aliases import Base64EncodedBytes, Serial


class JSONSerializableBytesModel(BaseModel):
    """Test class to test the Base64EncodedBytes type aliases."""

    value: Base64EncodedBytes


class SerialModel(BaseModel):
    """Test class to test the Serial type alias."""

    value: Serial


VALUES = (
    (b"\xb5\xee\x0e\x01\x10U", "te4OARBV"),
    (b"\xb5\xee\x0e\x01\x10U\xaa", "te4OARBVqg=="),
    # Examples from Wikipedia
    (b"light work.", "bGlnaHQgd29yay4="),
    (b"light work", "bGlnaHQgd29yaw=="),
    (b"light wor", "bGlnaHQgd29y"),
    (b"light wo", "bGlnaHQgd28="),
    (b"light w", "bGlnaHQgdw=="),
)


@pytest.mark.parametrize("value,encoded", VALUES)
def test_json_serializable_bytes(value: bytes, encoded: str) -> None:
    """Test Base64EncodedBytes."""
    model = JSONSerializableBytesModel(value=value)
    assert model.value == value
    assert JSONSerializableBytesModel.model_validate({"value": value}).value == value
    assert JSONSerializableBytesModel.model_validate({"value": value}).value == value
    assert JSONSerializableBytesModel.model_validate({"value": encoded}).value == value
    assert JSONSerializableBytesModel.model_validate({"value": encoded}, strict=True).value == value
    assert model.model_dump() == {"value": value}
    assert model.model_dump(mode="json") == {"value": encoded}


@pytest.mark.parametrize(
    "value,validated",
    (
        ("a", "A"),
        ("abc", "ABC"),
        ("0", "0"),
        ("0123456789abcdef", "0123456789ABCDEF"),  # all characters, lowercased
        ("0123456789ABCDEF", "0123456789ABCDEF"),  # all characters
        ("a" * 40, "A" * 40),  # maximum length
        (12345678, "BC614E"),
    ),
)
def test_serial(value: str, validated: str) -> None:
    """Test the Serial type alias."""
    model = SerialModel(value=value)
    assert model.value == validated
    assert SerialModel.model_validate({"value": value}).value == validated
    assert SerialModel.model_validate({"value": value}).value == validated
    assert SerialModel.model_validate({"value": validated}).value == validated
    assert SerialModel.model_validate({"value": validated}, strict=True).value == validated
    assert model.model_dump() == {"value": validated}
    assert model.model_dump(mode="json") == {"value": validated}


@pytest.mark.parametrize(
    "value",
    (
        "",  # too short
        True,  # invalid type
        "1" * 41,  # too long
        "x",  # invalid character
        "abcxdef",  # invalid character
    ),
)
def test_serial_errors(value: str) -> None:
    """Test invalid values for the Serial type alias."""
    with pytest.raises(ValueError):
        SerialModel(value=value)

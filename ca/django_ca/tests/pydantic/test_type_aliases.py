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

"""Test type aliases for Pydantic from django_ca.pydantic.type_aliases."""

import json
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, ConfigDict

from django.utils.functional import Promise
from django.utils.translation import gettext_lazy

import pytest

from django_ca.pydantic.type_aliases import Base64EncodedBytes, FutureAwareDatetime, PromiseTypeAlias, Serial


class JSONSerializableBytesModel(BaseModel):
    """Test class to test the Base64EncodedBytes type aliases."""

    value: Base64EncodedBytes


class SerialModel(BaseModel):
    """Test class to test the Serial type alias."""

    value: Serial


class FutureAwareDatetimeModel(BaseModel):
    """TEst model to test FutureAwareDatetime."""

    value: FutureAwareDatetime


class PromiseModel(BaseModel):
    """Test class for PromiseTypeAlias."""

    model_config = ConfigDict(arbitrary_types_allowed=True)
    value: PromiseTypeAlias | str


@pytest.mark.parametrize(
    ("value", "encoded"),
    (
        (b"\xb5\xee\x0e\x01\x10U", "te4OARBV"),
        (b"\xb5\xee\x0e\x01\x10U\xaa", "te4OARBVqg=="),
        # Examples from Wikipedia
        (b"light work.", "bGlnaHQgd29yay4="),
        (b"light work", "bGlnaHQgd29yaw=="),
        (b"light wor", "bGlnaHQgd29y"),
        (b"light wo", "bGlnaHQgd28="),
        (b"light w", "bGlnaHQgdw=="),
        ("bGlnaHQgd29yay4=", "bGlnaHQgd29yay4="),  # encoded value remains unchanged
    ),
)
def test_json_serializable_bytes(value: str, encoded: str) -> None:
    """Test Base64EncodedBytes."""
    model = JSONSerializableBytesModel(value=value)
    assert model.value == encoded
    assert JSONSerializableBytesModel.model_validate({"value": value}).value == encoded
    assert JSONSerializableBytesModel.model_validate({"value": value}).value == encoded
    assert JSONSerializableBytesModel.model_validate({"value": encoded}).value == encoded
    assert JSONSerializableBytesModel.model_validate({"value": encoded}, strict=True).value == encoded
    assert model.model_dump() == {"value": encoded}
    assert model.model_dump(mode="json") == {"value": encoded}


@pytest.mark.parametrize(
    ("value", "validated"),
    (
        ("a", "A"),
        ("abc", "ABC"),
        ("0", "0"),  # single zero is not stripped
        ("1234567890abcdef", "1234567890ABCDEF"),  # all characters, lowercased
        ("1234567890ABCDEF", "1234567890ABCDEF"),  # all characters
        ("0abc", "ABC"),  # leading zero is stripped
        ("a" * 40, "A" * 40),  # maximum length
        (12345678, "BC614E"),
    ),
)
def test_serial(value: str, validated: str) -> None:
    """Test the Serial type alias."""
    model = SerialModel(value=value)
    assert model.value == validated
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
    with pytest.raises(ValueError):  # noqa: PT011  # pydantic controls the message
        SerialModel(value=value)


@pytest.mark.parametrize(("value", "validated"), (("a", gettext_lazy("a")),))
def test_promise_type_alias(value: str, validated: Promise) -> None:
    """Test PromiseTypeAlias."""
    model = PromiseModel(value=value)
    assert model.value == validated
    assert PromiseModel.model_validate({"value": value}).value == validated
    assert PromiseModel.model_validate({"value": validated}).value == validated
    assert PromiseModel.model_validate({"value": validated}, strict=True).value == validated
    assert model.model_dump() == {"value": validated}
    assert model.model_dump(mode="json") == {"value": value} == {"value": str(validated)}

    # Test JSON validation:
    json_data = json.dumps({"value": value})
    assert PromiseModel.model_validate_json(json_data).value == validated
    assert PromiseModel.model_validate_json(json_data, strict=True).value == validated


def test_future_aware_datetime() -> None:
    """Test FutureAwareDatetime."""
    future = datetime.now(UTC) + timedelta(days=1)
    model = FutureAwareDatetimeModel(value=future)
    assert model.value == future


def test_future_aware_datetime_with_past_date() -> None:
    """Test FutureAwareDatetime with a datetime in the past."""
    future = datetime.now(UTC) - timedelta(days=1)
    with pytest.raises(ValueError, match="must be in the future"):
        FutureAwareDatetimeModel(value=future)


def test_future_aware_datetime_with_unaware_datetime() -> None:
    """Test FutureAwareDatetime with an unaware datetime."""
    future = datetime.now() + timedelta(days=1)
    with pytest.raises(ValueError, match="Input should have timezone info"):
        FutureAwareDatetimeModel(value=future)

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

"""Shared code for Pydantic-related tests."""

import re
import typing
from typing import Any, TypeVar, Union

from pydantic import ValidationError

import pytest

from django_ca.pydantic.base import CryptographyModel, CryptographyRootModel

CryptographyModelTypeVar = TypeVar("CryptographyModelTypeVar", bound=CryptographyModel[Any])
CryptographyRootModelTypeVar = TypeVar("CryptographyRootModelTypeVar", bound=CryptographyRootModel[Any, Any])
ExpectedErrors = list[tuple[str, tuple[str, ...], Union[str, "re.Pattern[str]"]]]


def assert_cryptography_model(
    model_class: type[CryptographyModelTypeVar], parameters: dict[str, Any], expected: Any
) -> CryptographyModelTypeVar:
    """Test that a cryptography model matches the expected value."""
    model = model_class(**parameters)
    assert model.cryptography == expected
    assert model == model_class.model_validate(expected), (model, expected)
    assert model == model_class.model_validate_json(model.model_dump_json())  # test JSON serialization
    return model  # for any further tests on the model


@typing.overload
def assert_validation_errors(
    model_class: type[CryptographyModelTypeVar],
    parameters: dict[str, Any],
    expected_errors: ExpectedErrors,
) -> None: ...


@typing.overload
def assert_validation_errors(
    model_class: type[CryptographyRootModelTypeVar],
    parameters: list[dict[str, Any]],
    expected_errors: ExpectedErrors,
) -> None: ...


def assert_validation_errors(
    model_class: Union[type[CryptographyModelTypeVar], type[CryptographyRootModelTypeVar]],
    parameters: Union[list[dict[str, Any]], dict[str, Any]],
    expected_errors: ExpectedErrors,
) -> None:
    """Assertion method to test validation errors."""
    with pytest.raises(ValidationError) as ex_info:  # noqa: PT012
        if isinstance(parameters, list):
            model_class(parameters)  # type: ignore[call-arg]  # ruled out with overload
        else:
            model_class(**parameters)

    errors = ex_info.value.errors()
    assert len(expected_errors) == len(errors)
    for expected, actual in zip(expected_errors, errors):
        assert expected[0] == actual["type"]
        assert expected[1] == actual["loc"]
        if isinstance(expected[2], str):
            assert expected[2] == actual["msg"]
        else:
            pattern: re.Pattern[str] = expected[2]
            assert pattern.search(actual["msg"])

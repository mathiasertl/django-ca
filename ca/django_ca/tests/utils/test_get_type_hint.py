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

"""Test get_type_hint."""

from collections.abc import Callable
from typing import Any, get_type_hints

import pytest

from django_ca.utils import get_type_hint


def _func(a: int, b: str | None) -> None:
    pass


class _Test:
    def _func(self, a: bool, b: float | None) -> None:
        pass


@pytest.mark.parametrize(
    ("func", "arg", "expected", "expected_optional"),
    (
        (_func, "a", int, False),
        (_func, "b", str, True),
        (_Test._func, "a", bool, False),
        (_Test._func, "b", float, True),
        (_Test()._func, "a", bool, False),
        (_Test()._func, "b", float, True),
    ),
)
def test_get_type_hint(
    func: Callable[..., Any], arg: str, expected: type[Any], expected_optional: bool
) -> None:
    """Test get_type_hint."""
    type_hints = get_type_hints(func)
    type_hint, optional = get_type_hint(type_hints[arg])
    assert type_hint is expected
    assert optional is expected_optional

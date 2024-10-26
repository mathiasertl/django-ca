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

"""Test :py:mod:`django_ca.deprecation`."""

import re
from typing import Any, Union

import pytest

from django_ca.deprecation import (
    DeprecationWarningType,
    RemovedInDjangoCA220Warning,
    RemovedInDjangoCA230Warning,
    RemovedInDjangoCA240Warning,
    deprecate_argument,
    deprecate_function,
    deprecate_type,
)

WARNING_TYPES: tuple[DeprecationWarningType, ...] = (
    RemovedInDjangoCA220Warning,
    RemovedInDjangoCA230Warning,
    RemovedInDjangoCA240Warning,
)


@pytest.mark.parametrize("cls", WARNING_TYPES)
def test_deprecation_warning_version(cls: DeprecationWarningType) -> None:
    """Test versions in deprecation warnings."""
    assert cls.__name__ == f"RemovedInDjangoCA{cls.version.replace('.', '')}0Warning"


@pytest.mark.parametrize("warning", WARNING_TYPES)
def test_deprecate_function(warning: DeprecationWarningType) -> None:
    """Test deprecate_function() decorator."""
    version = re.escape(warning.version)
    match = rf"^deprecated\(\) is deprecated and will be removed in django-ca {version}\.$"

    @deprecate_function(warning)
    def deprecated() -> None:
        pass

    with pytest.warns(warning, match=match):
        deprecated()


@pytest.mark.parametrize("warning", WARNING_TYPES)
def test_deprecated_argument(warning: DeprecationWarningType) -> None:
    """Test deprecate_argument() decorator."""
    version = re.escape(warning.version)
    match = rf"^Argument `kw` is deprecated and will be removed in django-ca {version}\.$"

    @deprecate_argument("kw", warning)
    def func_with_deprecated_kw(unused: Any, kw: str = "default") -> str:  # pylint: disable=all
        """Just  a test function with a deprecated argument (used in tests)."""
        return kw

    with pytest.warns(warning, match=match):
        assert func_with_deprecated_kw("arg", "foobar") == "foobar"
    with pytest.warns(warning, match=match):
        assert func_with_deprecated_kw("arg", kw="foobar") == "foobar"


@pytest.mark.parametrize("warning", WARNING_TYPES)
def test_deprecated_argument_not_passed(warning: DeprecationWarningType) -> None:
    """Test deprecate_argument() decorator when deprecated argument is not passed."""

    @deprecate_argument("kw", warning)
    def func_with_deprecated_kw(unused: Any, kw: str = "default") -> str:  # pylint: disable=all
        """Just  a test function with a deprecated argument (used in tests)."""
        return kw

    assert func_with_deprecated_kw("arg") == "default"


@pytest.mark.parametrize("typ", (int, (int, set)))
@pytest.mark.parametrize("warning", WARNING_TYPES)
def test_deprecate_type(
    typ: Union[type[Any], tuple[type[Any], ...]], warning: DeprecationWarningType
) -> None:
    """Test the deprecate_type() operator."""
    version = re.escape(warning.version)
    match = rf"^Passing int for arg is deprecated and will be removed in django-ca {version}\.$"

    @deprecate_type("arg", typ, warning)
    def func_with_deprecated_type(arg: str) -> None:
        pass

    with pytest.warns(warning, match=match):
        func_with_deprecated_type(3)  # type: ignore[arg-type]  # what we're testing

    # no warning if called with correct type:
    func_with_deprecated_type("foo")

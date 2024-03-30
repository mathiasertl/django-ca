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

import contextlib
from collections.abc import Iterator
from typing import Any

from django.test import TestCase

import pytest

from django_ca.deprecation import (
    DeprecationWarningType,
    RemovedInDjangoCA200Warning,
    RemovedInDjangoCA210Warning,
    RemovedInDjangoCA220Warning,
    RemovedInNextVersionWarning,
    deprecate_argument,
)


@pytest.mark.parametrize(
    "cls", (RemovedInDjangoCA200Warning, RemovedInDjangoCA210Warning, RemovedInDjangoCA220Warning)
)
def test_deprecation_warnings(cls: PendingDeprecationWarning) -> None:
    """Test versions in deprecation warnings."""
    assert cls.__name__ == f"RemovedInDjangoCA{cls.version.replace('.', '')}0Warning"


class DeprecateArgumentTestCase(TestCase):
    """Test the `@deprecate_argument` decorator."""

    @deprecate_argument("kw", RemovedInNextVersionWarning)
    def func(self, unused: Any, kw: str = "default") -> str:  # pylint: disable=all
        """Just  a test function with a deprecated argument (used in tests)."""
        return kw

    @contextlib.contextmanager
    def assertWarning(  # pylint: disable=invalid-name
        self, arg: str, cls: DeprecationWarningType = RemovedInNextVersionWarning
    ) -> Iterator[None]:
        """Shortcut for testing the deprecation warning emitted."""
        message = rf"Argument {arg} is deprecated and will be removed"
        with self.assertWarnsRegex(cls, message) as warn_cm:
            yield

        # make sure that the stacklevel is correct and the warning is issue from this file (= file where
        # function is called)
        self.assertEqual(warn_cm.filename, __file__)

    def test_basic(self) -> None:
        """Really basic test of the decorator."""
        self.assertEqual(self.func("arg"), "default")  # no kwarg -> no warning

        with self.assertWarning("kw"):
            self.assertEqual(self.func("arg", "foobar"), "foobar")

        with self.assertWarning("kw"):
            self.assertEqual(self.func("arg", kw="foobar"), "foobar")

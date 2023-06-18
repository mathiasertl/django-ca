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
import warnings
from typing import Any, Iterator

from django.test import TestCase

from django_ca.deprecation import (
    DeprecationWarningType,
    RemovedInDjangoCA127Warning,
    RemovedInDjangoCA128Warning,
    RemovedInDjangoCA129Warning,
    RemovedInNextVersionWarning,
    deprecate_argument,
)


class TestDjangoCATestCase(TestCase):
    """Test :py:mod:`django_ca.deprecation`."""

    msg_in_127 = "deprecated in 1.27"
    msg_in_128 = "deprecated in 1.28"
    msg_in_129 = "deprecated in 1.29"
    msg_in_next = "deprecated in next version"

    def deprecated_in_127(self) -> None:
        """Emit a message about deprecation in 1.27."""
        warnings.warn(self.msg_in_127, category=RemovedInDjangoCA127Warning)

    def deprecated_in_128(self) -> None:
        """Emit a message about deprecation in 1.28."""
        warnings.warn(self.msg_in_128, category=RemovedInDjangoCA128Warning)

    def deprecated_in_129(self) -> None:
        """Emit a message about deprecation in 1.29."""
        warnings.warn(self.msg_in_129, category=RemovedInDjangoCA129Warning)

    def deprecated_in_next(self) -> None:
        """Emit a message about deprecation in the next version."""
        warnings.warn(self.msg_in_next, category=RemovedInNextVersionWarning)

    def test_base(self) -> None:
        """Test warning messages."""

        with self.assertWarnsRegex(RemovedInDjangoCA127Warning, rf"^{self.msg_in_127}$"):
            self.deprecated_in_127()
        with self.assertWarnsRegex(RemovedInDjangoCA128Warning, rf"^{self.msg_in_128}$"):
            self.deprecated_in_128()
        with self.assertWarnsRegex(RemovedInDjangoCA129Warning, rf"^{self.msg_in_129}$"):
            self.deprecated_in_129()
        with self.assertWarnsRegex(RemovedInNextVersionWarning, rf"^{self.msg_in_next}$"):
            self.deprecated_in_next()


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

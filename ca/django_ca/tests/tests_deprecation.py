# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca.  If not,
# see <http://www.gnu.org/licenses/>.

"""Test :py:mod:`django_ca.deprecation`."""

import contextlib
import typing
import warnings

from django.test import TestCase

from ..deprecation import RemovedInDjangoCA122Warning
from ..deprecation import RemovedInDjangoCA123Warning
from ..deprecation import RemovedInNextVersionWarning
from ..deprecation import deprecate_argument


class TestDjangoCATestCase(TestCase):
    """Test :py:mod:`django_ca.deprecation`."""

    msg_in_122 = "deprecated in 1.21"
    msg_in_123 = "deprecated in 1.22"
    msg_in_next = "deprecated in next version"

    def deprecated_in_122(self) -> None:
        """Emit a message about deprecation in 1.22."""
        warnings.warn(self.msg_in_122, category=RemovedInDjangoCA122Warning)

    def deprecated_in_123(self) -> None:
        """Emit a message about deprecation in 1.23."""
        warnings.warn(self.msg_in_123, category=RemovedInDjangoCA123Warning)

    def deprecated_in_next(self) -> None:
        """Emit a message about deprecation in the next version."""
        warnings.warn(self.msg_in_next, category=RemovedInNextVersionWarning)

    def test_base(self) -> None:
        """Test warning messages."""

        with self.assertWarnsRegex(RemovedInDjangoCA122Warning, rf"^{self.msg_in_122}$"):
            self.deprecated_in_122()
        with self.assertWarnsRegex(RemovedInDjangoCA123Warning, rf"^{self.msg_in_123}$"):
            self.deprecated_in_123()
        with self.assertWarnsRegex(RemovedInNextVersionWarning, rf"^{self.msg_in_next}$"):
            self.deprecated_in_next()


class DeprecateArgumentTestCase(TestCase):
    @deprecate_argument("kw", RemovedInNextVersionWarning)
    def func(self, unused: typing.Any, kw: typing.Any = "default") -> None:
        return kw

    @deprecate_argument("kw", DeprecationWarning)
    def func2(self, unused: typing.Any, kw: typing.Any = "default") -> None:
        return kw

    @contextlib.contextmanager
    def assertWarning(self, arg, cls=RemovedInNextVersionWarning):
        message = rf"Argument {arg} is deprecated and will be removed"
        with self.assertWarnsRegex(cls, message) as cm:
            yield

        # make sure that the stacklevel is correct and the warning is issue from this file (= file where
        # function is called)
        self.assertEqual(cm.filename, __file__)

    def test_basic(self) -> None:
        self.assertEqual(self.func("arg"), "default")  # no kwarg -> no warning

        with self.assertWarning("kw"):
            self.assertEqual(self.func("arg", "foobar"), "foobar")

        with self.assertWarning("kw"):
            self.assertEqual(self.func("arg", kw="foobar"), "foobar")

    def test_generic(self) -> None:
        self.assertEqual(self.func2("arg"), "default")  # no kwarg -> no warning

        with self.assertWarning("kw", DeprecationWarning):
            self.assertEqual(self.func2("arg", "foobar"), "foobar")

        with self.assertWarning("kw", DeprecationWarning):
            self.assertEqual(self.func2("arg", kw="foobar"), "foobar")

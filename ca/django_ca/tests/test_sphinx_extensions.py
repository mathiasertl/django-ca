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

"""Test custom Sphinx extensions."""


from typing import List
from unittest import TestCase

from django_ca_sphinx.console_include import CommandLineTextWrapper


class CommandLineTextWrapperTestCase(TestCase):
    """Test custom TextWrapper that smartly does not wrap short options and their value."""

    def assertWraps(self, command: str, expected: List[str]) -> None:  # pylint: disable=invalid-name
        """Assert that the given command wraps to the expected full text."""
        wrapper = CommandLineTextWrapper(width=12)
        self.assertEqual(wrapper.wrap(command), expected)

    def assertSplits(self, command: str, expected: List[str]) -> None:  # pylint: disable=invalid-name
        """Assert that the given command splits into the expected tokens."""
        wrapper = CommandLineTextWrapper()
        # PYLINT note: this is the function that we override
        self.assertEqual(wrapper._split(command), expected)  # pylint: disable=protected-access

    def test_split(self) -> None:
        """Test the overwritten split function."""
        self.assertSplits("a", ["a"])
        self.assertSplits("a b", ["a", " ", "b"])
        self.assertSplits("a -b", ["a", " ", "-b"])
        self.assertSplits("a -b value", ["a", " ", "-b value"])
        self.assertSplits("a -b -c value", ["a", " ", "-b", " ", "-c value"])
        self.assertSplits("a -b -c", ["a", " ", "-b", " ", "-c"])
        self.assertSplits("a -b --long", ["a", " ", "-b", " ", "--long"])
        self.assertSplits("a -b --long value", ["a", " ", "-b", " ", "--long", " ", "value"])

    def test_wrap(self) -> None:
        """Some end to end testing of wrapping code."""
        command = "a" * 4  # convenient lenght with test line width
        self.assertWraps(f"{command}", [command])
        self.assertWraps(f"{command} --long", [f"{command} --long"])
        self.assertWraps(f"{command} -a", [f"{command} -a"])
        self.assertWraps(f"{command} -a long_value", [command, ">    -a long_value"])
        self.assertWraps(f"{command} -a long_value -b", [command, ">    -a long_value", ">    -b"])
        self.assertWraps(f"{command} -a l -b", [f"{command} -a l -b"])

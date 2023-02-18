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

"""Test extension doctests."""

import doctest
import typing
from unittest import TestLoader, TestSuite

from cryptography.hazmat._oid import ExtensionOID


def load_tests(  # pylint: disable=unused-argument
    loader: TestLoader, tests: TestSuite, ignore: typing.Optional[str] = None
) -> TestSuite:
    """Load doctests."""
    globs = {"ExtensionOID": ExtensionOID}
    tests.addTests(doctest.DocTestSuite("django_ca.extensions.parse", extraglobs=globs))
    tests.addTests(doctest.DocTestSuite("django_ca.extensions", extraglobs=globs))
    return tests

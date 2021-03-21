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

import warnings

from django.test import TestCase

from ..deprecation import RemovedInDjangoCA119Warning
from ..deprecation import RemovedInDjangoCA120Warning
from ..deprecation import RemovedInNextVersionWarning


class TestDjangoCATestCase(TestCase):
    """Test :py:mod:`django_ca.deprecation`."""

    msg_in_119 = "deprecated in 1.19"
    msg_in_120 = "deprecated in 1.20"
    msg_in_next = "deprecated in next version"

    def deprecated_in_119(self):
        """Emit a message about deprecation in 1.19."""
        warnings.warn(self.msg_in_119, category=RemovedInDjangoCA119Warning)

    def deprecated_in_120(self):
        """Emit a message about deprecation in 1.20."""
        warnings.warn(self.msg_in_120, category=RemovedInDjangoCA120Warning)

    def deprecated_in_next(self):
        """Emit a message about deprecation in the next version."""
        warnings.warn(self.msg_in_next, category=RemovedInNextVersionWarning)

    def test_base(self):
        """Test warning messages."""

        with self.assertWarnsRegex(RemovedInDjangoCA119Warning, r"^%s$" % self.msg_in_119):
            self.deprecated_in_119()
        with self.assertWarnsRegex(RemovedInDjangoCA120Warning, r"^%s$" % self.msg_in_120):
            self.deprecated_in_120()
        with self.assertWarnsRegex(RemovedInNextVersionWarning, r"^%s$" % self.msg_in_next):
            self.deprecated_in_next()

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

import warnings

from django.test import TestCase

from ..deprecation import RemovedInDjangoCA17Warning
from ..deprecation import RemovedInDjangoCA18Warning
from ..deprecation import RemovedInNextVersionWarning


class TestDjangoCATestCase(TestCase):
    msg_in_117 = 'deprecated in 1.17'
    msg_in_118 = 'deprecated in 1.18'
    msg_in_next = 'deprecated in next version'

    def deprecated_in_117(self):
        warnings.warn(self.msg_in_117, category=RemovedInDjangoCA17Warning)

    def deprecated_in_118(self):
        warnings.warn(self.msg_in_118, category=RemovedInDjangoCA18Warning)

    def deprecated_in_next(self):
        warnings.warn(self.msg_in_next, category=RemovedInNextVersionWarning)

    def test_base(self):
        with self.assertWarnsRegex(RemovedInDjangoCA17Warning, r'^%s$' % self.msg_in_117):
            self.deprecated_in_117()
        with self.assertWarnsRegex(RemovedInDjangoCA18Warning, r'^%s$' % self.msg_in_118):
            self.deprecated_in_118()
        with self.assertWarnsRegex(RemovedInNextVersionWarning, r'^%s$' % self.msg_in_next):
            self.deprecated_in_next()

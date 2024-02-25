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

"""Test the cert_watchers management command."""

from django.test import TestCase

from django_ca.tests.base.mixins import TestCaseMixin
from django_ca.tests.base.utils import cmd


class CertWatchersTestCase(TestCaseMixin, TestCase):
    """Main test class for this command."""

    load_cas = ("root",)
    load_certs = ("root-cert",)

    def test_basic(self) -> None:
        """Just some basic tests here."""
        stdout, stderr = cmd("cert_watchers", self.cert.serial, add=["user-added@example.com"])
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        self.assertTrue(self.cert.watchers.filter(mail="user-added@example.com").exists())

        # remove user again
        stdout, stderr = cmd("cert_watchers", self.cert.serial, rm=["user-added@example.com"])
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        self.assertFalse(self.cert.watchers.filter(mail="user-added@example.com").exists())

        # removing again does nothing, but doesn't throw an error either
        stdout, stderr = cmd("cert_watchers", self.cert.serial, rm=["user-added@example.com"])
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        self.assertFalse(self.cert.watchers.filter(mail="user-added@example.com").exists())

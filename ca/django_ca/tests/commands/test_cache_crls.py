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
# see <http://www.gnu.org/licenses/>

"""Test the cache_crls management command."""

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from django.core.cache import cache
from django.test import TestCase

from freezegun import freeze_time

from django_ca.tests.base import override_tmpcadir, timestamps
from django_ca.tests.base.mixins import TestCaseMixin
from django_ca.utils import get_crl_cache_key


class CacheCRLsTestCase(TestCaseMixin, TestCase):
    """Main test class for this command."""

    load_cas = "__usable__"

    @override_tmpcadir()
    @freeze_time(timestamps["everything_valid"])
    def test_basic(self) -> None:
        """Test the basic command.

        Note: Without an explicit serial expired CAs are excluded, that's why we need @freeze_time().
        """

        stdout, stderr = self.cmd("cache_crls")
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")

        for ca in self.cas.values():
            key = get_crl_cache_key(ca.serial, ca.algorithm, Encoding.DER, "ca")
            crl = x509.load_der_x509_crl(cache.get(key))
            self.assertIsInstance(crl.signature_hash_algorithm, type(ca.algorithm))

            key = get_crl_cache_key(ca.serial, ca.algorithm, Encoding.DER, "user")
            crl = x509.load_der_x509_crl(cache.get(key))
            self.assertIsInstance(crl.signature_hash_algorithm, type(ca.algorithm))

    @override_tmpcadir()
    def test_serial(self) -> None:
        """Test passing an explicit serial."""

        stdout, stderr = self.cmd("cache_crls", self.ca.serial)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")

        key = get_crl_cache_key(self.ca.serial, self.ca.algorithm, Encoding.DER, "ca")
        crl = x509.load_der_x509_crl(cache.get(key))
        self.assertIsInstance(crl.signature_hash_algorithm, type(self.ca.algorithm))

        key = get_crl_cache_key(self.ca.serial, self.ca.algorithm, Encoding.DER, "user")
        crl = x509.load_der_x509_crl(cache.get(key))
        self.assertIsInstance(crl.signature_hash_algorithm, type(self.ca.algorithm))

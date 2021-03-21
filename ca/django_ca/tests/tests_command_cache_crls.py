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
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

from django.core.cache import cache

from freezegun import freeze_time

from ..utils import get_crl_cache_key
from .base import DjangoCAWithGeneratedCAsTestCase
from .base import override_tmpcadir
from .base import timestamps


class CacheCRLsTestCase(DjangoCAWithGeneratedCAsTestCase):
    """Main test class for this command."""

    @override_tmpcadir()
    @freeze_time(timestamps["everything_valid"])
    def test_basic(self):
        """Test the basic command.

        Note: Without an explicit serial expired CAs are excluded, that's why we need @freeze_time().
        """

        hash_cls = hashes.SHA512
        enc_cls = Encoding.DER
        stdout, stderr = self.cmd("cache_crls")
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")

        for ca in self.cas.values():
            key = get_crl_cache_key(ca.serial, hash_cls, enc_cls, "ca")
            crl = x509.load_der_x509_crl(cache.get(key), default_backend())
            self.assertIsNotNone(crl)
            self.assertIsInstance(crl.signature_hash_algorithm, hash_cls)

            key = get_crl_cache_key(ca.serial, hash_cls, enc_cls, "user")
            crl = x509.load_der_x509_crl(cache.get(key), default_backend())
            self.assertIsNotNone(crl)

    @override_tmpcadir()
    def test_serial(self):
        """Test passing an explicit serial."""
        ca = self.cas["root"]

        hash_cls = hashes.SHA512
        enc_cls = Encoding.DER
        stdout, stderr = self.cmd("cache_crls", ca.serial)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")

        key = get_crl_cache_key(ca.serial, hash_cls, enc_cls, "ca")
        crl = x509.load_der_x509_crl(cache.get(key), default_backend())
        self.assertIsNotNone(crl)
        self.assertIsInstance(crl.signature_hash_algorithm, hash_cls)

        key = get_crl_cache_key(ca.serial, hash_cls, enc_cls, "user")
        crl = x509.load_der_x509_crl(cache.get(key), default_backend())
        self.assertIsNotNone(crl)

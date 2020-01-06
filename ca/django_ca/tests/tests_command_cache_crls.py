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

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

from django.core.cache import cache

from ..utils import get_crl_cache_key
from .base import DjangoCAWithGeneratedCAsTestCase
from .base import override_tmpcadir


class CacheCRLsTestCase(DjangoCAWithGeneratedCAsTestCase):
    @override_tmpcadir()
    def test_basic(self):
        hash_cls = hashes.SHA512
        enc_cls = Encoding.DER
        stdout, stderr = self.cmd('cache_crls')
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')

        for name, ca in self.cas.items():
            key = get_crl_cache_key(ca.serial, hash_cls, enc_cls, 'ca')
            crl = x509.load_der_x509_crl(cache.get(key), default_backend())
            self.assertIsNotNone(crl)
            self.assertIsInstance(crl.signature_hash_algorithm, hash_cls)

            key = get_crl_cache_key(ca.serial, hash_cls, enc_cls, 'user')
            crl = x509.load_der_x509_crl(cache.get(key), default_backend())
            self.assertIsNotNone(crl)

    @override_tmpcadir()
    def test_serial(self):
        ca = self.cas['root']

        hash_cls = hashes.SHA512
        enc_cls = Encoding.DER
        stdout, stderr = self.cmd('cache_crls', ca.serial)
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')

        key = get_crl_cache_key(ca.serial, hash_cls, enc_cls, 'ca')
        crl = x509.load_der_x509_crl(cache.get(key), default_backend())
        self.assertIsNotNone(crl)
        self.assertIsInstance(crl.signature_hash_algorithm, hash_cls)

        key = get_crl_cache_key(ca.serial, hash_cls, enc_cls, 'user')
        crl = x509.load_der_x509_crl(cache.get(key), default_backend())
        self.assertIsNotNone(crl)

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

"""Basic tests for various celery tasks."""

import importlib
import types
from unittest import mock

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

from django.core.cache import cache

from freezegun import freeze_time

from .. import tasks
from ..utils import ca_storage
from ..utils import get_crl_cache_key
from .base import DjangoCAWithGeneratedCAsTestCase
from .base import override_tmpcadir
from .base import timestamps


class TestBasic(DjangoCAWithGeneratedCAsTestCase):
    """Test the basic handling of celery tasks."""

    def test_missing_celery(self):
        """Test that we work even if celery is not installed."""

        # negative assertion to make sure that the IsInstance assertion below is actually meaningful
        self.assertNotIsInstance(tasks.cache_crl, types.FunctionType)

        try:
            with mock.patch.dict('sys.modules', celery=None):
                importlib.reload(tasks)
                self.assertIsInstance(tasks.cache_crl, types.FunctionType)
        finally:
            # Make sure that module is reloaded, or any failed test in the try block will cause *all other
            # tests* to fail, because the celery import would be cached to *not* work
            importlib.reload(tasks)

    def test_run_task(self):
        """Test our run_task wrapper."""

        # run_task() without celery
        with self.settings(CA_USE_CELERY=False), self.patch('django_ca.tasks.cache_crls') as task_mock:
            tasks.run_task(tasks.cache_crls)
            self.assertEqual(task_mock.call_count, 1)

        # finally, run_task() with celery
        with self.settings(CA_USE_CELERY=True), self.mute_celery() as test_mock:
            tasks.run_task(tasks.cache_crls)
            self.assertEqual(test_mock.call_count, 1)


class TestCacheCRLs(DjangoCAWithGeneratedCAsTestCase):
    """Test the cache_crl Celery task."""

    @override_tmpcadir()
    def test_basic(self):
        """Test caching with a specific serial."""

        hash_cls = hashes.SHA512
        enc_cls = Encoding.DER

        for data in self.cas.values():
            tasks.cache_crl(data.serial)

            key = get_crl_cache_key(data.serial, hash_cls, enc_cls, 'ca')
            crl = x509.load_der_x509_crl(cache.get(key), default_backend())
            self.assertIsInstance(crl.signature_hash_algorithm, hash_cls)

            key = get_crl_cache_key(data.serial, hash_cls, enc_cls, 'user')
            crl = x509.load_der_x509_crl(cache.get(key), default_backend())

    @override_tmpcadir()
    @freeze_time(timestamps['everything_valid'])
    def test_cache_all_crls(self):
        """Test caching when all CAs are valid."""
        hash_cls = hashes.SHA512
        enc_cls = Encoding.DER
        tasks.cache_crls()

        for data in self.cas.values():
            key = get_crl_cache_key(data.serial, hash_cls, enc_cls, 'ca')
            crl = x509.load_der_x509_crl(cache.get(key), default_backend())
            self.assertIsInstance(crl.signature_hash_algorithm, hash_cls)

            key = get_crl_cache_key(data.serial, hash_cls, enc_cls, 'user')
            crl = x509.load_der_x509_crl(cache.get(key), default_backend())

    @override_tmpcadir()
    @freeze_time(timestamps['everything_expired'])
    def test_cache_all_crls_expired(self):
        """Test that nothing is cashed if all CAs are expired."""

        hash_cls = hashes.SHA512
        enc_cls = Encoding.DER
        tasks.cache_crls()

        for data in self.cas.values():
            key = get_crl_cache_key(data.serial, hash_cls, enc_cls, 'ca')
            self.assertIsNone(cache.get(key))

    @override_tmpcadir()
    def test_no_password(self):
        """Test creating a CRL for a CA where we have no password."""

        msg = r'^Password was not given but private key is encrypted$'
        with self.settings(CA_PASSWORDS={}), self.assertRaisesRegex(TypeError, msg):
            tasks.cache_crl(self.cas['pwd'].serial)

    def test_no_private_key(self):
        """Test creating a CRL for a CA where no private key is available."""

        with self.assertRaises(FileNotFoundError):
            tasks.cache_crl(self.cas['pwd'].serial)


class GenerateOCSPKeysTestCase(DjangoCAWithGeneratedCAsTestCase):
    """Test the generate_ocsp_key task."""

    @override_tmpcadir()
    def test_single(self):
        """Test creating a single key."""

        for ca in self.cas.values():
            tasks.generate_ocsp_key(ca.serial)
            self.assertTrue(ca_storage.exists('ocsp/%s.key' % ca.serial))
            self.assertTrue(ca_storage.exists('ocsp/%s.pem' % ca.serial))

    @override_tmpcadir()
    def test_all(self):
        """Test creating all keys."""

        tasks.generate_ocsp_keys()

        for ca in self.cas.values():
            tasks.generate_ocsp_key(ca.serial)
            self.assertTrue(ca_storage.exists('ocsp/%s.key' % ca.serial))
            self.assertTrue(ca_storage.exists('ocsp/%s.pem' % ca.serial))

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

import copy
import importlib
import types
from unittest import mock

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

from django.core.cache import cache

from .. import ca_settings
from .. import tasks
from ..utils import get_crl_cache_key
from .base import DjangoCAWithGeneratedCAsTestCase
from .base import override_tmpcadir


class TestBasic(DjangoCAWithGeneratedCAsTestCase):
    def test_missing_celery(self):
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
        # first, unknown task raises KeyError
        with self.assertRaises(KeyError):
            tasks.run_task('unknown_task')

        # run_task() without celery
        with self.settings(CA_USE_CELERY=False), self.patch('django_ca.tasks.cache_crls') as mock:
            tasks.run_task('cache_crls')
            self.assertTrue(mock.called)

        # finally, run_task() with celery
        with self.settings(CA_USE_CELERY=True), self.mute_celery() as mock:
            tasks.run_task('cache_crls')
            self.assertEqual(mock.call_count, 1)


class TestCacheCRLs(DjangoCAWithGeneratedCAsTestCase):
    @override_tmpcadir()
    def test_basic(self):
        hash_cls = hashes.SHA512
        enc_cls = Encoding.DER

        for ca, data in self.cas.items():
            tasks.cache_crl(data.serial)

            key = get_crl_cache_key(data.serial, hash_cls, enc_cls, 'ca')
            crl = x509.load_der_x509_crl(cache.get(key), default_backend())
            self.assertIsInstance(crl.signature_hash_algorithm, hash_cls)

            key = get_crl_cache_key(data.serial, hash_cls, enc_cls, 'user')
            crl = x509.load_der_x509_crl(cache.get(key), default_backend())

    @override_tmpcadir()
    def test_cache_all_crls(self):
        hash_cls = hashes.SHA512
        enc_cls = Encoding.DER
        tasks.cache_crls()

        for ca, data in self.cas.items():
            key = get_crl_cache_key(data.serial, hash_cls, enc_cls, 'ca')
            crl = x509.load_der_x509_crl(cache.get(key), default_backend())
            self.assertIsInstance(crl.signature_hash_algorithm, hash_cls)

            key = get_crl_cache_key(data.serial, hash_cls, enc_cls, 'user')
            crl = x509.load_der_x509_crl(cache.get(key), default_backend())

    @override_tmpcadir()
    def test_no_password(self):
        profiles = copy.deepcopy(ca_settings.CA_CRL_PROFILES)
        for v in profiles.values():
            if 'OVERRIDES' in v:
                del v['OVERRIDES']

        msg = r'^Password was not given but private key is encrypted$'
        with self.settings(CA_CRL_PROFILES=profiles), self.assertRaisesRegex(TypeError, msg):
            tasks.cache_crl(self.cas['pwd'].serial)

    def test_no_private_key(self):
        with self.assertRaises(FileNotFoundError):
            tasks.cache_crl(self.cas['pwd'].serial)

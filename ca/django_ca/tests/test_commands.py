"""
This file demonstrates writing tests using the unittest module. These will pass
when you run "manage.py test".

Replace this with more appropriate tests for your application.
"""

import os
import shutil
import subprocess
import tempfile

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.test.utils import override_settings as _override_settings
from django.utils import six
from django.utils.six.moves import reload_module

from django_ca import ca_settings
from django_ca.models import CertificateAuthority


class override_settings(_override_settings):
    """Enhance override_settings to also reload django_ca.ca_settings."""

    def save_options(self, test_func):
        super(override_settings, self).save_options(test_func)
        reload_module(ca_settings)

    def enable(self):
        super(override_settings, self).enable()
        reload_module(ca_settings)

    def disable(self):
        super(override_settings, self).disable()
        reload_module(ca_settings)


class override_tmpcadir(override_settings):
    """Sets the CA_DIR directory to a temporary directory.

    .. NOTE: This also takes any additional settings.
    """

    def __init__(self, **kwargs):
        super(override_tmpcadir, self).__init__(**kwargs)
        self.options['CA_DIR'] = tempfile.mkdtemp()

    def disable(self):
        super(override_tmpcadir, self).disable()
        shutil.rmtree(self.options['CA_DIR'])


class DjangoCATestCase(TestCase):
    """Base class for all testcases with some enhancements."""

    def setUp(self):
        reload_module(ca_settings)

    def settings(self, **kwargs):
        return override_settings(**kwargs)

    def tmpcadir(self, **kwargs):
        return override_tmpcadir(**kwargs)

    @classmethod
    def init_ca(cls, **kwargs):
        kwargs.setdefault('key_size', 2048)
        call_command('init_ca', 'Root CA', 'AT', 'Vienna', 'Vienna', 'HTU', 'FSINF', 'ca.fsinf.at',
                     **kwargs)

    def create_csr(self, name='example.com', key_size=512):
        key = os.path.join(ca_settings.CA_DIR, '%s.key' % name)
        csr = os.path.join(ca_settings.CA_DIR, '%s.csr' % name)
        subj = '/C=AT/ST=Vienna/L=Vienna/CN=csr.%s' % name

        p1 = subprocess.Popen(['openssl', 'genrsa', '-out', key, str(key_size)],
                              stderr=subprocess.PIPE)
        p1.communicate()
        p2 = subprocess.Popen(['openssl', 'req', '-new', '-key', key, '-out', csr, '-utf8',
                               '-batch', '-subj', '%s' % subj])
        p2.communicate()
        return key, csr


class TestDjangoCATestCase(DjangoCATestCase):
    # test the base test-class

    @override_tmpcadir()
    def test_override_tmpcadir(self):
        ca_dir = ca_settings.CA_DIR
        self.assertTrue(ca_dir.startswith(tempfile.gettempdir()))

    def test_tmpcadir(self):
        old_ca_dir = ca_settings.CA_DIR

        with self.tmpcadir():
            ca_dir = ca_settings.CA_DIR
            self.assertNotEqual(ca_dir, old_ca_dir)
            self.assertTrue(ca_dir.startswith(tempfile.gettempdir()))

        self.assertEqual(ca_settings.CA_DIR, old_ca_dir)  # ensure that they're equal again


class InitCATest(DjangoCATestCase):
    @override_tmpcadir()
    def test_basic(self):
        self.init_ca()
        cert = CertificateAuthority.objects.first().x509
        self.assertEqual(cert.get_signature_algorithm(), six.b('sha512WithRSAEncryption'))

    @override_tmpcadir()
    def test_small_key_size(self):
        with self.assertRaises(CommandError):
            self.init_ca(key_size=256)

    @override_tmpcadir()
    def test_key_not_power_of_two(self):
        with self.assertRaises(CommandError):
            self.init_ca(key_size=2049)

    @override_tmpcadir()
    def test_algorithm(self):
        self.init_ca(algorithm='sha1')
        cert = CertificateAuthority.objects.first().x509
        self.assertEqual(cert.get_signature_algorithm(), six.b('sha1WithRSAEncryption'))


@override_tmpcadir()
class SignCertTest(DjangoCATestCase):
    def test_basic(self):
        self.init_ca()
        out = six.StringIO()
        key, csr = self.create_csr()
        call_command('sign_cert', alt=['example.com'], csr=csr, stdout=out)

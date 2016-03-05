"""
This file demonstrates writing tests using the unittest module. These will pass
when you run "manage.py test".

Replace this with more appropriate tests for your application.
"""

from django.core.management import call_command
from django.core.management.base import CommandError
from django.utils import six

from django_ca.models import CertificateAuthority
from django_ca.tests.base import DjangoCATestCase
from django_ca.tests.base import override_tmpcadir


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

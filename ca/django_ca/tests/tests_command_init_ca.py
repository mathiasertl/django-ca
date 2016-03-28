# -*- coding: utf-8 -*-
#
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

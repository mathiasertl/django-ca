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
# see <http://www.gnu.org/licenses/>

from ..models import CertificateAuthority
from .base import DjangoCAWithCATestCase
from .base import override_settings


@override_settings(CA_MIN_KEY_SIZE=1024, CA_PROFILES={}, CA_DEFAULT_SUBJECT={})
class SignCertTestCase(DjangoCAWithCATestCase):
    def test_basic(self):
        issuer = 'https://issuer-test.example.org'
        ian = 'http://ian-test.example.org'
        ocsp = 'http://ocsp-test.example.org'
        crl = ['http://example.org/crl-test']

        stdout, stderr = self.cmd(
            'edit_ca', self.ca.serial, issuer_url=issuer, issuer_alt_name=ian,
            ocsp_url=ocsp, crl_url=crl, disable=False)
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')

        ca = CertificateAuthority.objects.get(serial=self.ca.serial)
        self.assertEqual(ca.issuer_url, issuer)
        self.assertEqual(ca.issuer_alt_name, ian)
        self.assertEqual(ca.ocsp_url, ocsp)
        self.assertEqual(ca.crl_url, '\n'.join(crl))
        self.assertFalse(ca.enabled)

    def test_enable(self):
        ca = CertificateAuthority.objects.get(serial=self.ca.serial)
        ca.enable = False
        ca.save()

        # we can also change nothing at all
        stdout, stderr = self.cmd('edit_ca', self.ca.serial, enable=True, crl_url=None)
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')

        ca = CertificateAuthority.objects.get(serial=self.ca.serial)
        self.assertEqual(ca.issuer_url, self.ca.issuer_url)
        self.assertEqual(ca.issuer_alt_name, self.ca.issuer_alt_name)
        self.assertEqual(ca.ocsp_url, self.ca.ocsp_url)
        self.assertEqual(ca.crl_url, self.ca.crl_url)
        self.assertTrue(ca.enabled)

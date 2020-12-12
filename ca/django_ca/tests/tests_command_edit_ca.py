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

"""Test the edit_ca management command."""

from ..models import CertificateAuthority
from .base import DjangoCAWithCATestCase
from .base import override_tmpcadir


class EditCATestCase(DjangoCAWithCATestCase):
    """Test the edit_ca management command."""

    issuer = 'https://issuer-test.example.org'
    ian = 'http://ian-test.example.org'
    ocsp = 'http://ocsp-test.example.org'
    crl = ['http://example.org/crl-test']
    caa = 'caa.example.com'
    website = 'https://website.example.com'
    tos = 'https://tos.example.com'

    def setUp(self):
        super().setUp()
        self.ca = self.cas['root']

    @override_tmpcadir()
    def test_basic(self):
        """Test command with e2e cli argument parsing."""

        stdout, stderr = self.cmd_e2e([
            'edit_ca', self.ca.serial,
            '--issuer-url=%s' % self.issuer, '--issuer-alt-name=%s' % self.ian,
            '--ocsp-url=%s' % self.ocsp, '--crl-url=%s' % '\n'.join(self.crl), '--caa=%s' % self.caa,
            '--website=%s' % self.website, '--tos=%s' % self.tos,
        ])
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')

        ca = CertificateAuthority.objects.get(serial=self.ca.serial)
        self.assertEqual(ca.issuer_url, self.issuer)
        self.assertEqual(ca.issuer_alt_name, 'URI:%s' % self.ian)
        self.assertEqual(ca.ocsp_url, self.ocsp)
        self.assertEqual(ca.crl_url, '\n'.join(self.crl))
        self.assertEqual(ca.caa_identity, self.caa)
        self.assertEqual(ca.website, self.website)
        self.assertEqual(ca.terms_of_service, self.tos)

    @override_tmpcadir()
    def test_enable_disable(self):
        """Test the enable/disable options."""
        self.assertTrue(self.ca.enabled)  # initial state

        stdout, stderr = self.cmd_e2e(['edit_ca', self.ca.serial, '--disable'])
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')
        self.assertFalse(CertificateAuthority.objects.get(pk=self.ca.pk).enabled)

        stdout, stderr = self.cmd_e2e(['edit_ca', self.ca.serial, '--enable'])
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')
        self.assertTrue(CertificateAuthority.objects.get(pk=self.ca.pk).enabled)

        with self.assertRaisesRegex(SystemExit, r'^2$') as excm:
            stdout, stderr = self.cmd_e2e(['edit_ca', self.ca.serial, '--enable', '--disable'])
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')
        self.assertEqual(excm.exception.args, (2, ))

        self.assertTrue(CertificateAuthority.objects.get(pk=self.ca.pk).enabled)

    @override_tmpcadir()
    def test_enable(self):
        """Test enabling the CA."""
        ca = CertificateAuthority.objects.get(serial=self.ca.serial)
        ca.enabled = False
        ca.save()

        # we can also change nothing at all
        stdout, stderr = self.cmd('edit_ca', self.ca.serial, enabled=True, crl_url=None)
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')

        ca = CertificateAuthority.objects.get(serial=self.ca.serial)
        self.assertEqual(ca.issuer_url, self.ca.issuer_url)
        self.assertEqual(ca.issuer_alt_name, self.ca.issuer_alt_name)
        self.assertEqual(ca.ocsp_url, self.ca.ocsp_url)
        self.assertEqual(ca.crl_url, self.ca.crl_url)
        self.assertTrue(ca.enabled)

        # disable it again
        stdout, stderr = self.cmd('edit_ca', self.ca.serial, enabled=False)
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')
        ca = CertificateAuthority.objects.get(serial=self.ca.serial)
        self.assertFalse(ca.enabled)

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

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from ..models import Certificate
from ..utils import add_colons
from ..utils import ca_storage
from .base import DjangoCATestCase
from .base import certs
from .base import override_tmpcadir


class RegenerateOCSPKeyTestCase(DjangoCATestCase):
    def setUp(self):
        super(RegenerateOCSPKeyTestCase, self).setUp()
        self.load_usable_cas()
        self.existing_certs = list(Certificate.objects.values_list('pk', flat=True))

    def assertKey(self, ca, key_type=RSAPrivateKey, password=None):
        priv_path = 'ocsp/%s.key' % ca.serial
        cert_path = 'ocsp/%s.pem' % ca.serial

        self.assertTrue(ca_storage.exists(priv_path))
        self.assertTrue(ca_storage.exists(cert_path))

        with ca_storage.open(priv_path, 'rb') as stream:
            priv = stream.read()
        priv = load_pem_private_key(priv, password, default_backend())
        self.assertIsInstance(priv, key_type)

        with ca_storage.open(cert_path, 'rb') as stream:
            cert = stream.read()
        cert = x509.load_pem_x509_certificate(cert, default_backend())
        self.assertIsInstance(cert, x509.Certificate)

        db_cert = Certificate.objects.exclude(pk__in=self.existing_certs).first()
        self.assertEqual(db_cert.authority_information_access.ocsp, [])

        return priv, cert

    def assertHasNoKey(self, serial):
        priv_path = 'ocsp/%s.key' % serial
        cert_path = 'ocsp/%s.pem' % serial
        self.assertFalse(ca_storage.exists(priv_path))
        self.assertFalse(ca_storage.exists(cert_path))

    @override_tmpcadir()
    def test_basic(self):
        stdout, stderr = self.cmd('regenerate_ocsp_keys', certs['root']['serial'])
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')
        self.assertKey(self.cas['root'])

    @override_tmpcadir()
    def test_all(self):
        # Delete pwd_ca, because it will fail, since we do not give a password
        self.cas['pwd'].delete()
        del self.cas['pwd']

        stdout, stderr = self.cmd('regenerate_ocsp_keys')
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')
        for name in self.cas:
            self.assertKey(self.cas[name])

    @override_tmpcadir()
    def test_overwrite(self):
        stdout, stderr = self.cmd('regenerate_ocsp_keys', certs['root']['serial'])
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')
        priv, cert = self.assertKey(self.cas['root'])

        # write again
        stdout, stderr = self.cmd('regenerate_ocsp_keys', certs['root']['serial'])
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')
        new_priv, new_cert = self.assertKey(self.cas['root'])

        # Key/Cert should now be different
        self.assertNotEqual(priv, new_priv)
        self.assertNotEqual(cert, new_cert)

    @override_tmpcadir()
    def test_wrong_serial(self):
        serial = 'ZZZZZ'
        stdout, stderr = self.cmd('regenerate_ocsp_keys', serial, no_color=True)
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '0Z:ZZ:ZZ: Unknown CA.\n')
        self.assertHasNoKey(serial)

    @override_tmpcadir(CA_PROFILES={'ocsp': None})
    def test_no_ocsp_profile(self):
        with self.assertCommandError(r'^ocsp: Undefined profile\.$'):
            self.cmd('regenerate_ocsp_keys', certs['root']['serial'])
        self.assertHasNoKey(certs['root']['serial'])

    @override_tmpcadir()
    def test_no_private_key(self):
        ca = self.cas['root']
        ca_storage.delete(ca.private_key_path)
        stdout, stderr = self.cmd('regenerate_ocsp_keys', ca.serial, no_color=True)
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '%s: CA has no private key.\n' % add_colons(ca.serial))
        self.assertHasNoKey(ca.serial)

        # and in quiet mode
        stdout, stderr = self.cmd('regenerate_ocsp_keys', ca.serial, quiet=True, no_color=True)
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')
        self.assertHasNoKey(ca.serial)

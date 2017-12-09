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

import os
from io import BytesIO

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from django.core.management.base import CommandError
from django.utils import six

from .. import ca_settings
from ..models import Certificate
from ..models import CertificateAuthority
from .base import DjangoCAWithCertTestCase
from .base import override_settings
from .base import override_tmpcadir


@override_tmpcadir(CA_MIN_KEY_SIZE=1024, CA_PROFILES={}, CA_DEFAULT_SUBJECT={})
class DumpCRLTestCase(DjangoCAWithCertTestCase):
    def assertSerial(self, revokation, cert):
        self.assertEqual(revokation.get_serial(),
                         cert.serial.replace(':', '').encode('utf-8'))

    def test_basic(self):
        stdout, stderr = self.cmd('dump_crl', stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b'')

        crl = x509.load_pem_x509_crl(stdout, default_backend())
        self.assertIsInstance(crl.signature_hash_algorithm, hashes.SHA512)
        self.assertEqual(list(crl), [])

    @override_settings(USE_TZ=True)
    def test_basic_with_use_tz(self):
        self.test_basic()

    def test_file(self):
        path = os.path.join(ca_settings.CA_DIR, 'crl-test.crl')
        stdout, stderr = self.cmd('dump_crl', path, stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stdout, b'')
        self.assertEqual(stderr, b'')

        with open(path, 'rb') as stream:
            crl = x509.load_pem_x509_crl(stream.read(), default_backend())
        self.assertIsInstance(crl.signature_hash_algorithm, hashes.SHA512)
        self.assertEqual(list(crl), [])

        # test an output path that doesn't exist
        path = os.path.join(ca_settings.CA_DIR, 'test', 'crl-test.crl')
        with self.assertRaises(CommandError):
            self.cmd('dump_crl', path, stdout=BytesIO(), stderr=BytesIO())

    def test_password(self):
        password = b'testpassword'
        ca = self.create_ca('with password', password=password)
        ca = CertificateAuthority.objects.get(pk=ca.pk)

        # Giving no password raises a CommandError
        stdin = six.StringIO(self.csr_pem)
        with self.assertRaisesRegex(CommandError, '^Password was not given but private key is encrypted$'):
            self.cmd('dump_crl', ca=ca, stdin=stdin)

        # False password
        stdin = six.StringIO(self.csr_pem)
        ca = CertificateAuthority.objects.get(pk=ca.pk)
        stdin = six.StringIO(self.csr_pem)
        with self.assertRaisesRegex(CommandError, '^Bad decrypt\. Incorrect password\?$'):
            self.cmd('dump_crl', ca=ca, stdin=stdin, password=b'wrong')

        stdout, stderr = self.cmd('dump_crl', ca=ca, stdout=BytesIO(), stderr=BytesIO(), password=password)
        self.assertEqual(stderr, b'')

        crl = x509.load_pem_x509_crl(stdout, default_backend())
        self.assertIsInstance(crl.signature_hash_algorithm, hashes.SHA512)
        self.assertEqual(list(crl), [])

    def test_disabled(self):
        ca = self.create_ca('disabled')
        ca.enabled = False
        ca.save()

        stdout, stderr = self.cmd('dump_crl', ca=ca, stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b'')

        crl = x509.load_pem_x509_crl(stdout, default_backend())
        self.assertIsInstance(crl.signature_hash_algorithm, hashes.SHA512)
        self.assertEqual(list(crl), [])

    def test_revoked(self):
        cert = Certificate.objects.get(serial=self.cert.serial)
        cert.revoke()
        stdout, stderr = self.cmd('dump_crl', stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b'')

        crl = x509.load_pem_x509_crl(stdout, default_backend())
        self.assertIsInstance(crl.signature_hash_algorithm, hashes.SHA512)
        self.assertEqual(len(list(crl)), 1)
        self.assertEqual(crl[0].serial_number, cert.x509.serial)
        self.assertEqual(len(crl[0].extensions), 0)

        # try all possible reasons
        for reason in [r[0] for r in Certificate.REVOCATION_REASONS if r[0]]:
            cert.revoked_reason = reason
            cert.save()

            stdout, stderr = self.cmd('dump_crl', stdout=BytesIO(), stderr=BytesIO())
            crl = x509.load_pem_x509_crl(stdout, default_backend())
            self.assertIsInstance(crl.signature_hash_algorithm, hashes.SHA512)
            self.assertEqual(len(list(crl)), 1)
            self.assertEqual(crl[0].serial_number, cert.x509.serial)
            self.assertEqual(crl[0].extensions[0].value.reason.name, reason)

    def test_ca_crl(self):
        # create a child CA
        child = self.create_ca(name='Child', parent=self.ca)

        stdout, stderr = self.cmd('dump_crl', ca=self.ca, ca_crl=True,
                                  stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b'')

        crl = x509.load_pem_x509_crl(stdout, default_backend())
        self.assertIsInstance(crl.signature_hash_algorithm, hashes.SHA512)
        self.assertEqual(list(crl), [])

        # revoke the CA and see if it's there
        child.revoke()
        stdout, stderr = self.cmd('dump_crl', ca=self.ca, ca_crl=True, stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b'')

        crl = x509.load_pem_x509_crl(stdout, default_backend())
        self.assertIsInstance(crl.signature_hash_algorithm, hashes.SHA512)
        self.assertEqual(len(list(crl)), 1)
        self.assertEqual(crl[0].serial_number, child.x509.serial)
        self.assertEqual(len(crl[0].extensions), 0)

    @override_settings(USE_TZ=True)
    def test_revoked_with_use_tz(self):
        self.test_revoked()

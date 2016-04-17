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

from OpenSSL import crypto

from django.core.management.base import CommandError

from ..models import Certificate
from .. import ca_settings
from .base import DjangoCAWithCertTestCase
from .base import override_tmpcadir


@override_tmpcadir(CA_MIN_KEY_SIZE=1024, CA_PROFILES={}, CA_DEFAULT_SUBJECT={})
class DumpCRLTestCase(DjangoCAWithCertTestCase):
    def assertSerial(self, revokation, cert):
        self.assertEqual(revokation.get_serial(),
                         cert.serial.replace(':', '').encode('utf-8'))

    def test_basic(self):
        stdout, stderr = self.cmd('dump_crl', stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b'')
        crl = crypto.load_crl(crypto.FILETYPE_PEM, stdout)
        self.assertIsNone(crl.get_revoked())

    def test_file(self):
        path = os.path.join(ca_settings.CA_DIR, 'crl-test.crl')
        stdout, stderr = self.cmd('dump_crl', path, stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stdout, b'')
        self.assertEqual(stderr, b'')

        with open(path, 'rb') as stream:
            crl = crypto.load_crl(crypto.FILETYPE_PEM, stream.read())
        self.assertIsNone(crl.get_revoked())

        # test an output path that doesn't exist
        path = os.path.join(ca_settings.CA_DIR, 'test', 'crl-test.crl')
        with self.assertRaises(CommandError):
            self.cmd('dump_crl', path, stdout=BytesIO(), stderr=BytesIO())

    def test_revoked(self):
        cert = Certificate.objects.get(serial=self.cert.serial)
        cert.revoke()
        stdout, stderr = self.cmd('dump_crl', stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b'')
        crl = crypto.load_crl(crypto.FILETYPE_PEM, stdout)

        revoked = crl.get_revoked()
        self.assertEqual(len(revoked), 1)
        self.assertIsNone(revoked[0].get_reason())
        self.assertSerial(revoked[0], cert)

        # try all possible reasons
        for readable_reason, byte_reason in [
            (b'Unspecified', b'unspecified'),
            (b'Key Compromise', b'keyCompromise'),
            (b'CA Compromise', b'CACompromise'),
            (b'Affiliation Changed', b'affiliationChanged'),
            (b'Superseded', b'superseded'),
            (b'Cessation Of Operation', b'cessationOfOperation'),
            (b'Certificate Hold', b'certificateHold'),
        ]:
            cert.revoked_reason = byte_reason.decode('utf-8')
            cert.save()

            stdout, stderr = self.cmd('dump_crl', stdout=BytesIO(), stderr=BytesIO())
            crl = crypto.load_crl(crypto.FILETYPE_PEM, stdout)
            revoked = crl.get_revoked()
            self.assertEqual(len(revoked), 1)
            self.assertEqual(revoked[0].get_reason(), readable_reason)
            self.assertSerial(revoked[0], cert)

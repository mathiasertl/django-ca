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

from datetime import timedelta

from OpenSSL import crypto

from django.core.management.base import CommandError
from django.utils import six
from django.utils import timezone

from ..models import Certificate
from ..models import Watcher
from .base import DjangoCAWithCertTestCase
from .base import override_tmpcadir


@override_tmpcadir(CA_MIN_KEY_SIZE=1024, CA_PROFILES={}, CA_DEFAULT_SUBJECT={})
class ViewCertTestCase(DjangoCAWithCertTestCase):
    def assertSerial(self, revokation, cert):
        self.assertEqual(revokation.get_serial(),
                         cert.serial.replace(':', '').encode('utf-8'))

    def test_basic(self):
        stdout, stderr = self.cmd('dump_crl')
        crl = crypto.load_crl(crypto.FILETYPE_PEM, stdout)
        self.assertIsNone(crl.get_revoked())

    def test_revoked(self):
        cert = Certificate.objects.get(serial=self.cert.serial)
        cert.revoke()
        stdout, stderr = self.cmd('dump_crl')
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

            stdout, stderr = self.cmd('dump_crl')
            crl = crypto.load_crl(crypto.FILETYPE_PEM, stdout)
            revoked = crl.get_revoked()
            self.assertEqual(len(revoked), 1)
            self.assertEqual(revoked[0].get_reason(), readable_reason)
            self.assertSerial(revoked[0], cert)

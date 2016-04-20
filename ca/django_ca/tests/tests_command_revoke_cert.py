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

from django.core.management.base import CommandError

from ..models import Certificate
from .base import DjangoCAWithCertTestCase
from .base import override_tmpcadir


@override_tmpcadir(CA_MIN_KEY_SIZE=1024, CA_PROFILES={}, CA_DEFAULT_SUBJECT={})
class RevokeCertTestCase(DjangoCAWithCertTestCase):
    def test_no_reason(self):
        self.assertFalse(self.cert.revoked)

        stdout, stderr = self.cmd('revoke_cert', self.cert.serial)
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')

        cert = Certificate.objects.get(serial=self.cert.serial)
        self.assertTrue(cert.revoked)
        self.assertTrue(cert.revoked_date is not None)
        self.assertIsNone(cert.revoked_reason)

    def test_with_reason(self):
        self.assertFalse(self.cert.revoked)

        stdout, stderr = self.cmd('revoke_cert', self.cert.serial, reason='keyCompromise')
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')

        cert = Certificate.objects.get(serial=self.cert.serial)
        self.assertTrue(cert.revoked)
        self.assertTrue(cert.revoked_date is not None)
        self.assertEqual(cert.revoked_reason, 'keyCompromise')

    def test_revoked(self):
        # you cannot revoke a revoked certificate (and not update the reason)

        self.assertFalse(self.cert.revoked)

        self.cmd('revoke_cert', self.cert.serial, reason='keyCompromise')

        with self.assertRaises(CommandError):
            self.cmd('revoke_cert', self.cert.serial, reason='certificateHold')

        cert = Certificate.objects.get(serial=self.cert.serial)
        self.assertTrue(cert.revoked)
        self.assertTrue(cert.revoked_date is not None)
        self.assertEqual(cert.revoked_reason, 'keyCompromise')

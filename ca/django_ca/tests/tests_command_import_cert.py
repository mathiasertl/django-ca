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

import os

from freezegun import freeze_time

from django.conf import settings

from ..models import Certificate
from .base import DjangoCAWithCATestCase
from .base import certs
from .base import override_tmpcadir


@freeze_time('2019-04-14 12:26:00')
class ImportCertTest(DjangoCAWithCATestCase):
    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_basic(self):
        pem_path = os.path.join(settings.FIXTURES_DIR, 'cert1.pem')
        out, err = self.cmd('import_cert', pem_path, ca=self.ca)

        self.assertEqual(out, '')
        self.assertEqual(err, '')

        cert = Certificate.objects.get(serial=certs['cert1']['serial'])
        self.assertSignature([self.ca], cert)
        cert.full_clean()  # assert e.g. max_length in serials
        self.assertBasic(cert.x509, algo='sha512')

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_der(self):
        pem_path = os.path.join(settings.FIXTURES_DIR, 'cert1-pub.der')
        out, err = self.cmd('import_cert', pem_path, ca=self.ca)

        self.assertEqual(out, '')
        self.assertEqual(err, '')

        cert = Certificate.objects.get(serial=certs['cert1']['serial'])
        self.assertSignature([self.ca], cert)
        cert.full_clean()  # assert e.g. max_length in serials
        self.assertBasic(cert.x509, algo='sha512')

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_bogus(self):
        with self.assertCommandError(r'^Unable to load public key\.$'):
            self.cmd('import_cert', __file__, ca=self.ca)
        self.assertEqual(Certificate.objects.count(), 0)

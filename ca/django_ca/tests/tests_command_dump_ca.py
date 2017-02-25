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

from .. import ca_settings
from .base import DjangoCAWithCATestCase
from .base import override_tmpcadir


@override_tmpcadir(CA_MIN_KEY_SIZE=1024, CA_PROFILES={}, CA_DEFAULT_SUBJECT={})
class DumpCertTestCase(DjangoCAWithCATestCase):
    def test_basic(self):
        stdout, stderr = self.cmd('dump_ca', self.ca.serial,
                                  stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b'')
        self.assertEqual(stdout, self.ca.pub.encode('utf-8'))

    def test_format(self):
        for option in ['PEM', 'TEXT', 'ASN1']:
            format = getattr(crypto, 'FILETYPE_%s' % option)
            stdout, stderr = self.cmd('dump_ca', self.ca.serial, format=format,
                                      stdout=BytesIO(), stderr=BytesIO())
            self.assertEqual(stderr, b'')
            self.assertEqual(stdout, crypto.dump_certificate(format, self.ca.x509))

    def test_explicit_stdout(self):
        stdout, stderr = self.cmd('dump_ca', self.ca.serial, '-',
                                  stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b'')
        self.assertEqual(stdout, self.ca.pub.encode('utf-8'))

    def test_file_output(self):
        path = os.path.join(ca_settings.CA_DIR, 'test_ca.pem')
        stdout, stderr = self.cmd('dump_ca', self.ca.serial, path,
                                  stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b'')
        self.assertEqual(stdout, b'')

        with open(path) as stream:
            self.assertEqual(stream.read(), self.ca.pub)

    def test_wrong_path(self):
        path = os.path.join(ca_settings.CA_DIR, 'does-not-exist', 'test_ca.pem')
        with self.assertRaises(CommandError):
            self.cmd('dump_ca', self.ca.serial, path, stdout=BytesIO(),
                     stderr=BytesIO())

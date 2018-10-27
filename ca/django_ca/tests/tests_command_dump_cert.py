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

from cryptography.hazmat.primitives.serialization import Encoding

from django.core.management.base import CommandError

from .. import ca_settings
from .base import DjangoCAWithCertTestCase
from .base import override_settings
from .base import override_tmpcadir


@override_settings(CA_MIN_KEY_SIZE=1024, CA_PROFILES={}, CA_DEFAULT_SUBJECT={})
class DumpCertTestCase(DjangoCAWithCertTestCase):
    def test_basic(self):
        stdout, stderr = self.cmd('dump_cert', self.cert.serial,
                                  stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b'')
        self.assertEqual(stdout, self.cert.pub.encode('utf-8'))

    def test_format(self):
        for option in ['PEM', 'DER']:
            encoding = getattr(Encoding, option)
            stdout, stderr = self.cmd('dump_cert', self.cert.serial, format=encoding,
                                      stdout=BytesIO(), stderr=BytesIO())
            self.assertEqual(stderr, b'')
            self.assertEqual(stdout, self.cert.dump_certificate(encoding))

    def test_explicit_stdout(self):
        stdout, stderr = self.cmd('dump_cert', self.cert.serial, '-',
                                  stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b'')
        self.assertEqual(stdout, self.cert.pub.encode('utf-8'))

    @override_tmpcadir()
    def test_file_output(self):
        path = os.path.join(ca_settings.CA_DIR, 'test_cert.pem')
        stdout, stderr = self.cmd('dump_cert', self.cert.serial, path,
                                  stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b'')
        self.assertEqual(stdout, b'')

        with open(path) as stream:
            self.assertEqual(stream.read(), self.cert.pub)

    def test_wrong_path(self):
        path = os.path.join(ca_settings.CA_DIR, 'does-not-exist', 'test_cert.pem')
        with self.assertRaises(CommandError):
            self.cmd('dump_cert', self.cert.serial, path, stdout=BytesIO(),
                     stderr=BytesIO())

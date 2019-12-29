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

from .. import ca_settings
from .base import DjangoCAWithCATestCase
from .base import override_tmpcadir


class DumpCertTestCase(DjangoCAWithCATestCase):
    def setUp(self):
        super(DumpCertTestCase, self).setUp()
        self.ca = self.cas['root']

    @override_tmpcadir()
    def test_basic(self):
        stdout, stderr = self.cmd('dump_ca', self.ca.serial,
                                  stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b'')
        self.assertEqual(stdout, self.ca.pub.encode('utf-8'))

    @override_tmpcadir()
    def test_format(self):
        for option in ['PEM', 'DER']:
            encoding = getattr(Encoding, option)
            stdout, stderr = self.cmd('dump_ca', self.ca.serial, format=encoding,
                                      stdout=BytesIO(), stderr=BytesIO())
            self.assertEqual(stderr, b'')
            self.assertEqual(stdout, self.ca.dump_certificate(encoding))

    @override_tmpcadir()
    def test_explicit_stdout(self):
        stdout, stderr = self.cmd('dump_ca', self.ca.serial, '-',
                                  stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b'')
        self.assertEqual(stdout, self.ca.pub.encode('utf-8'))

    @override_tmpcadir()
    def test_bundle(self):
        stdout, stderr = self.cmd('dump_ca', self.ca.serial, '-', bundle=True,
                                  stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b'')
        self.assertEqual(stdout, self.ca.pub.encode('utf-8'))

        child = self.cas['child']
        stdout, stderr = self.cmd('dump_ca', child.serial, '-', bundle=True,
                                  stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b'')
        self.assertEqual(stdout, child.pub.encode('utf-8') + self.ca.pub.encode('utf-8'))

    @override_tmpcadir()
    def test_file_output(self):
        path = os.path.join(ca_settings.CA_DIR, 'test_ca.pem')
        stdout, stderr = self.cmd('dump_ca', self.ca.serial, path,
                                  stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b'')
        self.assertEqual(stdout, b'')

        with open(path) as stream:
            self.assertEqual(stream.read(), self.ca.pub)

    @override_tmpcadir()
    def test_errors(self):
        path = os.path.join(ca_settings.CA_DIR, 'does-not-exist', 'test_ca.pem')
        msg = r"^\[Errno 2\] No such file or directory: '%s/does-not-exist/test_ca\.pem'$" % (
            ca_settings.CA_DIR)

        with self.assertCommandError(msg):
            self.cmd('dump_ca', self.ca.serial, path, stdout=BytesIO(), stderr=BytesIO())

        with self.assertCommandError(r'^Cannot dump bundle when using DER format\.$'):
            self.cmd('dump_ca', self.ca.serial, format=Encoding.DER, bundle=True,
                     stdout=BytesIO(), stderr=BytesIO())

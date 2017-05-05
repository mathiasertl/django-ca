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
from io import BufferedReader

from six import BytesIO

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from django.conf import settings
from django.core.management.base import CommandError

from django_ca.models import CertificateAuthority
from django_ca.tests.base import DjangoCATestCase
from django_ca.tests.base import override_tmpcadir

from .base import certs
from .. import ca_settings


class ImportCATest(DjangoCATestCase):
    def get_reader(self, path):
        path = os.path.join(settings.FIXTURES_DIR, path)
        with open(path, 'rb') as stream:
            data = stream.read()

        return BufferedReader(BytesIO(data))

    def init_ca(self, **kwargs):
        name = kwargs.pop('name', 'Test CA')
        kwargs.setdefault('key_size', ca_settings.CA_MIN_KEY_SIZE)
        return self.cmd('init_ca', name, '/C=AT/ST=Vienna/L=Vienna/O=Org/OU=OrgUnit/CN=%s' % name,
                        **kwargs)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_basic(self):
        name = 'testname'
        pem_path = os.path.join(settings.FIXTURES_DIR, 'root.pem')
        key_path = os.path.join(settings.FIXTURES_DIR, 'root.key')
        out, err = self.cmd('import_ca', name, key_path, pem_path)

        self.assertEqual(out, '')
        self.assertEqual(err, '')

        ca = CertificateAuthority.objects.get(name=name)
        self.assertSignature([ca], ca)
        ca.full_clean()  # assert e.g. max_length in serials
        self.assertBasic(ca.x509, algo='sha512')

        # test the private key
        key = ca.key(None)
        self.assertIsInstance(key, RSAPrivateKey)
        self.assertEqual(key.key_size, certs['root']['key_size'])
        self.assertEqual(ca.serial, certs['root']['serial'])

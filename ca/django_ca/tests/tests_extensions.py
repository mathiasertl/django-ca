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

import doctest

import six

from cryptography import x509
from cryptography.x509.extensions import Extension
from cryptography.x509.oid import ExtensionOID

from django.test import TestCase

from ..extensions import KeyUsage


def load_tests(loader, tests, ignore):
    if six.PY3:  # pragma: only py3
        # unicode strings make this very hard to test doctests in both py2 and py3
        tests.addTests(doctest.DocTestSuite('django_ca.extensions'))
    return tests


class TestKeyUsage(TestCase):
    def assertBasic(self, ext):
        self.assertTrue(ext.critical)
        self.assertIn('cRLSign', ext)
        self.assertIn('keyCertSign', ext)
        self.assertNotIn('keyEncipherment', ext)

        crypto = ext.extension_type
        self.assertIsInstance(crypto, x509.KeyUsage)
        self.assertTrue(crypto.crl_sign)
        self.assertTrue(crypto.key_cert_sign)
        self.assertFalse(crypto.key_encipherment)

    def test_basic(self):
        self.assertBasic(KeyUsage('critical,cRLSign,keyCertSign'))
        self.assertBasic(KeyUsage(['critical', ['cRLSign', 'keyCertSign']]))
        self.assertBasic(KeyUsage(('critical', ['cRLSign', 'keyCertSign'])))
        self.assertBasic(KeyUsage(('critical', ('cRLSign', 'keyCertSign'))))
        self.assertBasic(KeyUsage(Extension(
            oid=ExtensionOID.KEY_USAGE,
            critical=True,
            value=x509.KeyUsage(
                content_commitment=False,
                crl_sign=True,
                data_encipherment=True,
                decipher_only=False,
                digital_signature=False,
                encipher_only=False,
                key_agreement=True,
                key_cert_sign=True,
                key_encipherment=False,
            )
        )))

        ext = KeyUsage('critical,cRLSign,keyCertSign')
        ext2 = KeyUsage(ext.as_extension())
        self.assertEqual(ext, ext2)

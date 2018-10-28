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
from cryptography.x509 import TLSFeatureType
from cryptography.x509.extensions import Extension
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.oid import ExtensionOID

from django.test import TestCase

from ..extensions import ExtendedKeyUsage
from ..extensions import KeyUsage
from ..extensions import TLSFeature


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

        typ = ext.extension_type
        self.assertIsInstance(typ, x509.KeyUsage)
        self.assertTrue(typ.crl_sign)
        self.assertTrue(typ.key_cert_sign)
        self.assertFalse(typ.key_encipherment)

        crypto = ext.as_extension()
        self.assertEqual(crypto.oid, ExtensionOID.KEY_USAGE)

    def test_basic(self):
        self.assertBasic(KeyUsage('critical,cRLSign,keyCertSign'))
        self.assertBasic(KeyUsage([True, ['cRLSign', 'keyCertSign']]))
        self.assertBasic(KeyUsage((True, ['cRLSign', 'keyCertSign'])))
        self.assertBasic(KeyUsage((True, ('cRLSign', 'keyCertSign'))))
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

    def test_empty_str(self):
        # we want to accept an empty str as constructor
        ku = KeyUsage('')
        self.assertEqual(len(ku), 0)
        self.assertFalse(bool(ku))

    def test_dunder(self):
        # test __contains__ and __len__
        ku = KeyUsage('cRLSign')
        self.assertIn('cRLSign', ku)
        self.assertNotIn('keyCertSign', ku)
        self.assertEqual(len(ku), 1)
        self.assertTrue(bool(ku))

    def test_error(self):
        with self.assertRaisesRegex(ValueError, r'^Unknown value\(s\): foo$'):
            KeyUsage('foo')
        with self.assertRaisesRegex(ValueError, r'^Unknown value\(s\): foobar$'):
            KeyUsage('foobar')

        with self.assertRaisesRegex(ValueError, r'^Unknown value\(s\): foo$'):
            KeyUsage('critical,foo')

    def test_completeness(self):
        # make sure whe haven't forgotton any keys anywhere
        self.assertEqual(set(KeyUsage.CRYPTOGRAPHY_MAPPING.keys()),
                         set([e[0] for e in KeyUsage.CHOICES]))


class ExtendedKeyUsageTestCase(TestCase):
    def assertBasic(self, ext, critical=True):
        self.assertEqual(ext.critical, critical)
        self.assertIn('clientAuth', ext)
        self.assertIn('serverAuth', ext)
        self.assertNotIn('smartcardLogon', ext)

        typ = ext.extension_type
        self.assertIsInstance(typ, x509.ExtendedKeyUsage)
        self.assertEqual(typ.oid, ExtensionOID.EXTENDED_KEY_USAGE)

        crypto = ext.as_extension()
        self.assertEqual(crypto.critical, critical)
        self.assertEqual(crypto.oid, ExtensionOID.EXTENDED_KEY_USAGE)

        self.assertIn(ExtendedKeyUsageOID.SERVER_AUTH, crypto.value)
        self.assertIn(ExtendedKeyUsageOID.CLIENT_AUTH, crypto.value)
        self.assertNotIn(ExtendedKeyUsageOID.OCSP_SIGNING, crypto.value)

    def test_basic(self):
        self.assertBasic(ExtendedKeyUsage('critical,serverAuth,clientAuth'))
        self.assertBasic(ExtendedKeyUsage([True, ['clientAuth', 'serverAuth']]))
        self.assertBasic(ExtendedKeyUsage((True, ['clientAuth', 'serverAuth'])))
        self.assertBasic(ExtendedKeyUsage((True, ('clientAuth', 'serverAuth'))))
        self.assertBasic(ExtendedKeyUsage(Extension(
            oid=ExtensionOID.EXTENDED_KEY_USAGE,
            critical=True,
            value=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH])))
        )

    def test_not_critical(self):
        self.assertBasic(ExtendedKeyUsage('serverAuth,clientAuth'), critical=False)
        self.assertBasic(ExtendedKeyUsage([False, ['clientAuth', 'serverAuth']]), critical=False)
        self.assertBasic(ExtendedKeyUsage((False, ['clientAuth', 'serverAuth'])), critical=False)
        self.assertBasic(ExtendedKeyUsage((False, ('clientAuth', 'serverAuth'))), critical=False)
        ext_value = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH])
        self.assertBasic(ExtendedKeyUsage(
            Extension(
                oid=ExtensionOID.EXTENDED_KEY_USAGE,
                critical=False,
                value=ext_value
            ),
        ), critical=False)

    def test_completeness(self):
        # make sure whe haven't forgotton any keys anywhere
        self.assertEqual(set(ExtendedKeyUsage.CRYPTOGRAPHY_MAPPING.keys()),
                         set([e[0] for e in ExtendedKeyUsage.CHOICES]))


class TLSFeatureTestCase(TestCase):
    def assertBasic(self, ext, critical=True):
        self.assertEqual(ext.critical, critical)
        self.assertEqual(ext.value, ['OCSPMustStaple'])

        typ = ext.extension_type
        self.assertIsInstance(typ, x509.TLSFeature)
        self.assertEqual(typ.oid, ExtensionOID.TLS_FEATURE)

        crypto = ext.as_extension()
        self.assertEqual(crypto.critical, critical)
        self.assertEqual(crypto.oid, ExtensionOID.TLS_FEATURE)

        self.assertIn(TLSFeatureType.status_request, crypto.value)
        self.assertNotIn(TLSFeatureType.status_request_v2, crypto.value)

    def test_basic(self):
        self.assertBasic(TLSFeature('critical,OCSPMustStaple'))
        self.assertBasic(TLSFeature([True, ['OCSPMustStaple']]))

    def test_completeness(self):
        # make sure whe haven't forgotton any keys anywhere
        self.assertEqual(set(TLSFeature.CRYPTOGRAPHY_MAPPING.keys()),
                         set([e[0] for e in TLSFeature.CHOICES]))

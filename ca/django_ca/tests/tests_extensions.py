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
#from cryptography.x509.extensions import Extension
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.oid import ExtensionOID

from django.test import TestCase

from ..extensions import ExtendedKeyUsage
from ..extensions import Extension
from ..extensions import KeyUsage
from ..extensions import MultiValueExtension
from ..extensions import TLSFeature


def load_tests(loader, tests, ignore):
    if six.PY3:  # pragma: only py3
        # unicode strings make this very hard to test doctests in both py2 and py3
        tests.addTests(doctest.DocTestSuite('django_ca.extensions'))
    return tests


class ExtensionTestCase(TestCase):
    value = 'foobar'

    def assertExtension(self, ext, critical=True):
        self.assertEqual(ext.value, self.value)
        self.assertEqual(ext.critical, critical)

    def test_basic(self):
        self.assertExtension(Extension([True, self.value]))
        self.assertExtension(Extension('critical,%s' % self.value))
        self.assertExtension(Extension({'critical': True, 'value': self.value}))

        self.assertExtension(Extension([False, self.value]), critical=False)
        self.assertExtension(Extension(self.value), critical=False)
        self.assertExtension(Extension({'critical': False, 'value': self.value}), critical=False)
        self.assertExtension(Extension({'value': self.value}), critical=False)

    def test_eq(self):
        ext = Extension([True, self.value])
        self.assertEqual(ext, Extension([True, self.value]))
        self.assertNotEqual(ext, Extension([False, self.value]))
        self.assertNotEqual(ext, Extension([True, 'other']))
        self.assertNotEqual(ext, Extension([False, 'other']))

    def test_as_text(self):
        self.assertEqual(Extension([True, self.value]).as_text(), self.value)

    def test_str_repr(self):
        self.assertEqual(str(Extension('critical,%s' % self.value)), '%s/critical' % self.value)
        self.assertEqual(str(Extension(self.value)), self.value)

        self.assertEqual(repr(Extension('critical,%s' % self.value)),
                         '<Extension: \'%s\', critical=True>' % self.value)
        self.assertEqual(repr(Extension(self.value)), '<Extension: \'%s\', critical=False>' % self.value)

    def test_error(self):
        with self.assertRaisesRegex(ValueError, r'^None: Invalid critical value passed$'):
            Extension((None, ['cRLSign']))

        with self.assertRaisesRegex(ValueError, r'^Value is of unsupported type object$'):
            Extension(object())

        with self.assertRaises(NotImplementedError):
            Extension(x509.extensions.Extension(ExtensionOID.BASIC_CONSTRAINTS, True, b''))

        # Test that methods that should be implemented by sub-classes raise NotImplementedError
        ext = Extension([True, self.value])
        with self.assertRaises(NotImplementedError):
            ext.extension_type

        with self.assertRaises(NotImplementedError):
            ext.for_builder()

        # These do not work because base class does not define an OID
        with self.assertRaises(AttributeError):
            ext.as_extension()
        with self.assertRaises(AttributeError):
            ext.name


class MultiValueExtensionTestCase(TestCase):
    def setUp(self):
        self.known = {'foo', 'bar', }

        class TestExtension(MultiValueExtension):
            KNOWN_VALUES = self.known

        self.cls = TestExtension

    def assertExtension(self, ext, value, critical=True):
        self.assertEqual(ext.critical, critical)
        self.assertCountEqual(ext.value, value)
        self.assertEqual(len(ext), len(value))
        for v in value:
            self.assertIn(v, ext)

    def test_basic(self):
        self.assertExtension(self.cls('critical,'), [])
        self.assertExtension(self.cls('critical,foo'), ['foo'])
        self.assertExtension(self.cls('critical,bar'), ['bar'])
        self.assertExtension(self.cls('critical,foo,bar'), ['foo', 'bar'])


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
        KeyUsage({'value': ['keyAgreement', 'keyEncipherment']})
        self.assertBasic(KeyUsage((True, ('cRLSign', 'keyCertSign'))))
        self.assertBasic(KeyUsage({'critical': True, 'value': ['cRLSign', 'keyCertSign']}))
        self.assertBasic(KeyUsage(x509.extensions.Extension(
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

        with self.assertRaisesRegex(ValueError, r'^None: Invalid critical value passed$'):
            KeyUsage((None, ['cRLSign']))

        with self.assertRaisesRegex(ValueError, r'^Value is of unsupported type object$'):
            KeyUsage(object())

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
        self.assertBasic(ExtendedKeyUsage(x509.extensions.Extension(
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
            x509.extensions.Extension(
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

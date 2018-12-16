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

from ..extensions import AuthorityKeyIdentifier
from ..extensions import BasicConstraints
from ..extensions import ExtendedKeyUsage
from ..extensions import Extension
from ..extensions import KeyUsage
from ..extensions import KnownValuesExtension
from ..extensions import ListExtension
from ..extensions import SubjectKeyIdentifier
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
        self.assertExtension(Extension('critical,%s' % self.value))
        self.assertExtension(Extension({'critical': True, 'value': self.value}))

        self.assertExtension(Extension(self.value), critical=False)
        self.assertExtension(Extension({'critical': False, 'value': self.value}), critical=False)
        self.assertExtension(Extension({'value': self.value}), critical=False)

    def test_eq(self):
        ext = Extension({'value': self.value, 'critical': True})
        self.assertEqual(ext, Extension('critical,%s' % self.value))
        self.assertNotEqual(ext, Extension(self.value))
        self.assertNotEqual(ext, Extension('critical,other'))
        self.assertNotEqual(ext, Extension('other'))

    def test_as_text(self):
        self.assertEqual(Extension('critical,%s' % self.value).as_text(), self.value)

    def test_str_repr(self):
        self.assertEqual(str(Extension('critical,%s' % self.value)), '%s/critical' % self.value)
        self.assertEqual(str(Extension(self.value)), self.value)

        self.assertEqual(repr(Extension('critical,%s' % self.value)),
                         '<Extension: \'%s\', critical=True>' % self.value)
        self.assertEqual(repr(Extension(self.value)), '<Extension: \'%s\', critical=False>' % self.value)

    def test_error(self):
        with self.assertRaisesRegex(ValueError, r'^None: Invalid critical value passed$'):
            Extension({'critical': None, 'value': ['cRLSign']})

        with self.assertRaisesRegex(ValueError, r'^Value is of unsupported type object$'):
            Extension(object())

        with self.assertRaises(NotImplementedError):
            Extension(x509.extensions.Extension(ExtensionOID.BASIC_CONSTRAINTS, True, b''))

        # Test that methods that should be implemented by sub-classes raise NotImplementedError
        ext = Extension('critical,%s' % self.value)
        with self.assertRaises(NotImplementedError):
            ext.extension_type

        with self.assertRaises(NotImplementedError):
            ext.for_builder()

        with self.assertRaises(NotImplementedError):
            ext.serialize()

        # These do not work because base class does not define an OID
        with self.assertRaises(AttributeError):
            ext.as_extension()
        with self.assertRaises(AttributeError):
            ext.name


class ListExtensionTestCase(TestCase):
    def test_operators(self):
        ext = ListExtension(['foo'])
        self.assertIn('foo', ext)
        self.assertNotIn('bar', ext)

    def test_list_funcs(self):
        ext = ListExtension(['foo'])
        ext.append('bar')
        self.assertEqual(ext.value, ['foo', 'bar'])
        self.assertEqual(ext.count('foo'), 1)
        self.assertEqual(ext.count('bar'), 1)
        self.assertEqual(ext.count('bla'), 0)

        ext.clear()
        self.assertEqual(ext.value, [])
        self.assertEqual(ext.count('foo'), 0)

        ext.extend(['bar', 'bla'])
        self.assertEqual(ext.value, ['bar', 'bla'])
        ext.extend(['foo'])
        self.assertEqual(ext.value, ['bar', 'bla', 'foo'])

        self.assertEqual(ext.pop(), 'foo')
        self.assertEqual(ext.value, ['bar', 'bla'])

        self.assertIsNone(ext.remove('bar'))
        self.assertEqual(ext.value, ['bla'])

    def test_slices(self):
        val = ['foo', 'bar', 'bla']
        ext = ListExtension(val)
        self.assertEqual(ext[0], val[0])
        self.assertEqual(ext[1], val[1])
        self.assertEqual(ext[0:], val[0:])
        self.assertEqual(ext[1:], val[1:])
        self.assertEqual(ext[:1], val[:1])
        self.assertEqual(ext[1:2], val[1:2])

        ext[0] = 'test'
        val[0] = 'test'
        self.assertEqual(ext.value, val)
        ext[1:2] = ['x', 'y']
        val[1:2] = ['x', 'y']
        self.assertEqual(ext.value, val)
        ext[1:] = ['a', 'b']
        val[1:] = ['a', 'b']
        self.assertEqual(ext.value, val)

        del ext[0]
        del val[0]
        self.assertEqual(ext.value, val)

    def test_serialization(self):
        val = ['foo', 'bar', 'bla']
        ext = ListExtension({'value': val, 'critical': False})
        self.assertEqual(ext, ListExtension(ext.serialize()))
        ext = ListExtension({'value': val, 'critical': True})
        self.assertEqual(ext, ListExtension(ext.serialize()))


class KnownValuesExtensionTestCase(TestCase):
    def setUp(self):
        self.known = {'foo', 'bar', }

        class TestExtension(KnownValuesExtension):
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

        self.assertExtension(self.cls({'value': 'foo'}), ['foo'], critical=False)
        self.assertExtension(self.cls({'critical': True, 'value': ['foo']}), ['foo'])

        with self.assertRaisesRegex(ValueError, r'^Unknown value\(s\): hugo$'):
            self.cls({'value': 'hugo'})

        with self.assertRaisesRegex(ValueError, r'^Unknown value\(s\): bla, hugo$'):
            self.cls({'value': ['bla', 'hugo']})

    def test_operators(self):
        ext = self.cls('foo')

        # in operator
        self.assertIn('foo', ext)
        self.assertNotIn('bar', ext)
        self.assertNotIn('something else', ext)

        # equality
        self.assertEqual(ext, self.cls('foo'))
        self.assertNotEqual(ext, self.cls('critical,foo'))
        self.assertNotEqual(ext, self.cls('foo,bar'))
        self.assertNotEqual(ext, self.cls('bar'))

        # as_text
        self.assertEqual(ext.as_text(), '* foo')
        self.assertEqual(self.cls('foo,bar').as_text(), '* foo\n* bar')
        self.assertEqual(self.cls('bar,foo').as_text(), '* bar\n* foo')
        self.assertEqual(self.cls('bar').as_text(), '* bar')
        self.assertEqual(self.cls('critical,bar').as_text(), '* bar')

        # str()
        self.assertEqual(str(ext), 'foo')
        self.assertEqual(str(self.cls('foo,bar')), 'foo,bar')
        self.assertEqual(str(self.cls('bar,foo')), 'bar,foo')
        self.assertEqual(str(self.cls('bar')), 'bar')
        self.assertEqual(str(self.cls('critical,bar')), 'bar/critical')
        self.assertEqual(str(self.cls('critical,foo,bar')), 'foo,bar/critical')
        self.assertEqual(str(self.cls('critical,bar,foo')), 'bar,foo/critical')


class AuthorityKeyIdentifierTestCase(TestCase):
    def test_basic(self):
        ext = AuthorityKeyIdentifier(x509.Extension(
            oid=x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER, critical=True,
            value=x509.AuthorityKeyIdentifier(b'33333', None, None)))
        self.assertEqual(ext.as_text(), 'keyid:33:33:33:33:33')


class BasicConstraintsTestCase(TestCase):
    def assertBC(self, bc, ca, pathlen, critical=True):
        self.assertEqual(bc.ca, ca)
        self.assertEqual(bc.pathlen, pathlen)
        self.assertEqual(bc.critical, critical)

    def test_from_extension(self):
        self.assertBC(BasicConstraints(x509.Extension(
            oid=x509.ExtensionOID.BASIC_CONSTRAINTS, critical=True,
            value=x509.BasicConstraints(ca=True, path_length=3))), True, 3, True)

    def test_dict(self):
        self.assertBC(BasicConstraints({'ca': True}), True, None, True)
        self.assertBC(BasicConstraints({'ca': False}), False, None, True)
        self.assertBC(BasicConstraints({'ca': True, 'pathlen': 3}), True, 3, True)
        self.assertBC(BasicConstraints({'ca': True, 'pathlen': None}), True, None, True)
        self.assertBC(BasicConstraints({'ca': True, 'critical': False}), True, None, False)

    def test_str(self):
        # test without pathlen
        self.assertBC(BasicConstraints('CA:FALSE'), False, None, False)
        self.assertBC(BasicConstraints('CA : FAlse '), False, None, False)
        self.assertBC(BasicConstraints('CA: true'), True, None, False)
        self.assertBC(BasicConstraints('CA=true'), True, None, False)

        # test adding a pathlen
        self.assertBC(BasicConstraints('CA:TRUE,pathlen=0'), True, 0, False)
        self.assertBC(BasicConstraints('CA:trUe,pathlen:1'), True, 1, False)
        self.assertBC(BasicConstraints('CA: true , pathlen = 2 '), True, 2, False)

        with self.assertRaisesRegex(ValueError, r'^Could not parse pathlen: pathlen=foo$'):
            BasicConstraints('CA:FALSE, pathlen=foo')

        with self.assertRaisesRegex(ValueError, r'^Could not parse pathlen: pathlen=$'):
            BasicConstraints('CA:FALSE, pathlen=')

        with self.assertRaisesRegex(ValueError, r'^Could not parse pathlen: foobar$'):
            BasicConstraints('CA:FALSE, foobar')

    def test_consistency(self):
        # pathlen must be None if CA=False
        with self.assertRaisesRegex(ValueError, r'^pathlen must be None when ca is False$'):
            BasicConstraints('CA:FALSE, pathlen=3')

    def test_as_text(self):
        self.assertEqual(BasicConstraints('CA=true').as_text(), 'CA:TRUE')
        self.assertEqual(BasicConstraints('CA= true , pathlen = 3').as_text(), 'CA:TRUE, pathlen:3')
        self.assertEqual(BasicConstraints('CA = FALSE').as_text(), 'CA:FALSE')

    def test_extension_type(self):
        bc = BasicConstraints('CA=true').extension_type
        self.assertTrue(bc.ca)
        self.assertIsNone(bc.path_length)

        bc = BasicConstraints('CA=true, pathlen: 5').extension_type
        self.assertTrue(bc.ca)
        self.assertEqual(bc.path_length, 5)

        bc = BasicConstraints('CA=false').extension_type
        self.assertFalse(bc.ca)
        self.assertEqual(bc.path_length, None)


class KeyUsageTestCase(TestCase):
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

    def test_sanity_checks(self):
        # there are some sanity checks
        self.assertEqual(KeyUsage('decipherOnly').value, ['decipherOnly', 'keyAgreement'])

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
            KeyUsage({'critical': None, 'value': ['cRLSign']})

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
        self.assertBasic(ExtendedKeyUsage(x509.extensions.Extension(
            oid=ExtensionOID.EXTENDED_KEY_USAGE,
            critical=True,
            value=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH])))
        )

    def test_not_critical(self):
        self.assertBasic(ExtendedKeyUsage('serverAuth,clientAuth'), critical=False)
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


class SubjectKeyIdentifierTestCase(TestCase):
    def test_basic(self):
        ext = SubjectKeyIdentifier(x509.Extension(
            oid=x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER, critical=True,
            value=x509.SubjectKeyIdentifier(b'33333')))
        self.assertEqual(ext.as_text(), '33:33:33:33:33')


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
        self.assertBasic(TLSFeature(x509.Extension(
            oid=x509.ExtensionOID.TLS_FEATURE, critical=True,
            value=x509.TLSFeature(features=[x509.TLSFeatureType.status_request])))
        )

    def test_completeness(self):
        # make sure whe haven't forgotton any keys anywhere
        self.assertEqual(set(TLSFeature.CRYPTOGRAPHY_MAPPING.keys()),
                         set([e[0] for e in TLSFeature.CHOICES]))

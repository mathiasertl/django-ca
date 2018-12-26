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

from __future__ import unicode_literals

import doctest

import six

from cryptography import x509
from cryptography.x509 import TLSFeatureType
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.oid import ExtensionOID

from django.test import TestCase

from ..extensions import AuthorityInformationAccess
from ..extensions import AuthorityKeyIdentifier
from ..extensions import BasicConstraints
from ..extensions import ExtendedKeyUsage
from ..extensions import Extension
from ..extensions import IssuerAlternativeName
from ..extensions import KeyUsage
from ..extensions import KnownValuesExtension
from ..extensions import ListExtension
from ..extensions import NameConstraints
from ..extensions import SubjectAlternativeName
from ..extensions import SubjectKeyIdentifier
from ..extensions import TLSFeature


def dns(d):  # just a shortcut
    return x509.DNSName(d)


def uri(u):  # just a shortcut
    return x509.UniformResourceIdentifier(u)


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
                         '<Extension: %s, critical=True>' % self.value)
        self.assertEqual(repr(Extension(self.value)), '<Extension: %s, critical=False>' % self.value)

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

        ext.insert(0, 'foo')
        self.assertEqual(ext.value, ['foo', 'bla'])

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


class AuthorityInformationAccessTestCase(TestCase):
    ext_empty = x509.extensions.Extension(
        oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS, critical=False,
        value=x509.AuthorityInformationAccess(descriptions=[])
    )
    ext_issuer = x509.extensions.Extension(
        oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS, critical=False,
        value=x509.AuthorityInformationAccess(descriptions=[
            x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS,
                                   uri('https://example.com')),
        ])
    )
    ext_ocsp = x509.extensions.Extension(
        oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS, critical=False,
        value=x509.AuthorityInformationAccess(descriptions=[
            x509.AccessDescription(AuthorityInformationAccessOID.OCSP,
                                   uri('https://example.com')),
        ])
    )
    ext_both = x509.extensions.Extension(
        oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS, critical=False,
        value=x509.AuthorityInformationAccess(descriptions=[
            x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS,
                                   uri('https://example.com')),
            x509.AccessDescription(AuthorityInformationAccessOID.OCSP,
                                   uri('https://example.net')),
            x509.AccessDescription(AuthorityInformationAccessOID.OCSP,
                                   uri('https://example.org')),
        ])
    )

    # test the constructor with some list values
    def test_from_list(self):
        ext = AuthorityInformationAccess([['https://example.com'], []])
        self.assertEqual(ext.issuers, [uri('https://example.com')])
        self.assertEqual(ext.ocsp, [])
        self.assertFalse(ext.critical)
        self.assertEqual(ext.as_extension(), self.ext_issuer)

        ext = AuthorityInformationAccess([[], ['https://example.com']])
        self.assertEqual(ext.issuers, [])
        self.assertEqual(ext.ocsp, [uri('https://example.com')])
        self.assertFalse(ext.critical)
        self.assertEqual(ext.as_extension(), self.ext_ocsp)

        ext = AuthorityInformationAccess([[uri('https://example.com')], []])
        self.assertEqual(ext.issuers, [uri('https://example.com')])
        self.assertEqual(ext.ocsp, [])
        self.assertFalse(ext.critical)
        self.assertEqual(ext.as_extension(), self.ext_issuer)

        ext = AuthorityInformationAccess([[], [uri('https://example.com')]])
        self.assertEqual(ext.ocsp, [uri('https://example.com')])
        self.assertEqual(ext.issuers, [])
        self.assertFalse(ext.critical)
        self.assertEqual(ext.as_extension(), self.ext_ocsp)

        ext = AuthorityInformationAccess([['https://example.com'], ['https://example.net',
                                                                    'https://example.org']])
        self.assertEqual(ext.issuers, [uri('https://example.com')])
        self.assertEqual(ext.ocsp, [uri('https://example.net'), uri('https://example.org')])
        self.assertFalse(ext.critical)
        self.assertEqual(ext.as_extension(), self.ext_both)

    def test_from_dict(self):
        ext = AuthorityInformationAccess({'issuers': ['https://example.com']})
        self.assertEqual(ext.issuers, [uri('https://example.com')])
        self.assertEqual(ext.ocsp, [])
        self.assertFalse(ext.critical)
        self.assertEqual(ext.as_extension(), self.ext_issuer)

        ext = AuthorityInformationAccess({'ocsp': ['https://example.com']})
        self.assertEqual(ext.issuers, [])
        self.assertEqual(ext.ocsp, [uri('https://example.com')])
        self.assertFalse(ext.critical)
        self.assertEqual(ext.as_extension(), self.ext_ocsp)

        ext = AuthorityInformationAccess({'issuers': [uri('https://example.com')]})
        self.assertEqual(ext.issuers, [uri('https://example.com')])
        self.assertEqual(ext.ocsp, [])
        self.assertFalse(ext.critical)
        self.assertEqual(ext.as_extension(), self.ext_issuer)

        ext = AuthorityInformationAccess({'ocsp': [uri('https://example.com')]})
        self.assertEqual(ext.ocsp, [uri('https://example.com')])
        self.assertEqual(ext.issuers, [])
        self.assertFalse(ext.critical)
        self.assertEqual(ext.as_extension(), self.ext_ocsp)

        ext = AuthorityInformationAccess({
            'issuers': ['https://example.com'],
            'ocsp': ['https://example.net', 'https://example.org']
        })
        self.assertEqual(ext.issuers, [uri('https://example.com')])
        self.assertEqual(ext.ocsp, [uri('https://example.net'), uri('https://example.org')])
        self.assertFalse(ext.critical)
        self.assertEqual(ext.as_extension(), self.ext_both)

    def test_from_extension(self):
        ext = AuthorityInformationAccess(self.ext_issuer)
        self.assertEqual(ext.issuers, [uri('https://example.com')])
        self.assertEqual(ext.ocsp, [])
        self.assertFalse(ext.critical)
        self.assertEqual(ext.as_extension(), self.ext_issuer)

        ext = AuthorityInformationAccess(self.ext_ocsp)
        self.assertEqual(ext.issuers, [])
        self.assertEqual(ext.ocsp, [uri('https://example.com')])
        self.assertFalse(ext.critical)
        self.assertEqual(ext.as_extension(), self.ext_ocsp)

        ext = AuthorityInformationAccess(self.ext_both)
        self.assertEqual(ext.issuers, [uri('https://example.com')])
        self.assertEqual(ext.ocsp, [uri('https://example.net'), uri('https://example.org')])
        self.assertFalse(ext.critical)
        self.assertEqual(ext.as_extension(), self.ext_both)

    def test_empty_value(self):
        for val in [self.ext_empty, [[], []], {}, {'issuers': [], 'ocsp': []}]:
            ext = AuthorityInformationAccess(val)
            self.assertEqual(ext.ocsp, [], val)
            self.assertEqual(ext.issuers, [], val)
            self.assertFalse(ext.critical)
            self.assertEqual(ext.as_extension(), self.ext_empty)

    def test_unsupported(self):
        with self.assertRaisesRegex(ValueError, r'^Value is of unsupported type NoneType$'):
            AuthorityInformationAccess(None)
        with self.assertRaisesRegex(ValueError, r'^Value is of unsupported type bool$'):
            AuthorityInformationAccess(False)
        with self.assertRaises(NotImplementedError):
            AuthorityInformationAccess('')

    def test_equal(self):
        self.assertEqual(AuthorityInformationAccess([[], []]), AuthorityInformationAccess([[], []]))
        self.assertEqual(AuthorityInformationAccess([['https://example.com'], []]),
                         AuthorityInformationAccess([['https://example.com'], []]))
        self.assertEqual(AuthorityInformationAccess([[], ['https://example.com']]),
                         AuthorityInformationAccess([[], ['https://example.com']]))
        self.assertEqual(AuthorityInformationAccess([['https://example.com'], ['https://example.com']]),
                         AuthorityInformationAccess([['https://example.com'], ['https://example.com']]))

        for ext in [self.ext_empty, self.ext_issuer, self.ext_ocsp, self.ext_both]:
            self.assertEqual(AuthorityInformationAccess(ext), AuthorityInformationAccess(ext))

    def test_bool(self):
        self.assertEqual(bool(AuthorityInformationAccess(self.ext_empty)), False)
        self.assertEqual(bool(AuthorityInformationAccess([[], []])), False)
        self.assertEqual(bool(AuthorityInformationAccess(self.ext_empty)), False)

        self.assertEqual(bool(AuthorityInformationAccess(self.ext_issuer)), True)
        self.assertEqual(bool(AuthorityInformationAccess(self.ext_ocsp)), True)
        self.assertEqual(bool(AuthorityInformationAccess(self.ext_both)), True)

    def test_str(self):  # various methods converting to str
        self.assertEqual(repr(AuthorityInformationAccess(self.ext_empty)),
                         '<AuthorityInformationAccess: issuers=[], ocsp=[], critical=False>')
        self.assertEqual(
            repr(AuthorityInformationAccess(self.ext_issuer)),
            '<AuthorityInformationAccess: issuers=[\'URI:https://example.com\'], ocsp=[], critical=False>')
        self.assertEqual(
            repr(AuthorityInformationAccess(self.ext_ocsp)),
            "<AuthorityInformationAccess: issuers=[], ocsp=['URI:https://example.com'], critical=False>")
        self.assertEqual(
            repr(AuthorityInformationAccess(self.ext_both)),
            "<AuthorityInformationAccess: issuers=['URI:https://example.com'], ocsp=['URI:https://example.net', 'URI:https://example.org'], critical=False>")  # NOQA

        self.assertEqual(str(AuthorityInformationAccess(self.ext_empty)),
                         'AuthorityInformationAccess(issuers=[], ocsp=[], critical=False)')
        self.assertEqual(
            str(AuthorityInformationAccess(self.ext_issuer)),
            "AuthorityInformationAccess(issuers=['URI:https://example.com'], ocsp=[], critical=False)")
        self.assertEqual(
            str(AuthorityInformationAccess(self.ext_ocsp)),
            "AuthorityInformationAccess(issuers=[], ocsp=['URI:https://example.com'], critical=False)")
        self.assertEqual(
            str(AuthorityInformationAccess(self.ext_both)),
            "AuthorityInformationAccess(issuers=['URI:https://example.com'], ocsp=['URI:https://example.net', 'URI:https://example.org'], critical=False)") # NOQA

        self.assertEqual(
            AuthorityInformationAccess(self.ext_empty).as_text(),
            "")
        self.assertEqual(
            AuthorityInformationAccess(self.ext_issuer).as_text(),
            "CA Issuers:\n  * URI:https://example.com\n")
        self.assertEqual(
            AuthorityInformationAccess(self.ext_ocsp).as_text(),
            "OCSP:\n  * URI:https://example.com\n")
        self.assertEqual(
            AuthorityInformationAccess(self.ext_both).as_text(),
            "CA Issuers:\n  * URI:https://example.com\nOCSP:\n  * URI:https://example.net\n  * URI:https://example.org\n")  # NOQA


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
        self.assertEqual(bc.value, (ca, pathlen))

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


class IssuerAlternativeNameTestCase(TestCase):
    # NOTE: this extension is almost identical to the SubjectAlternativeName extension, most is tested there
    def test_as_extension(self):
        ext = IssuerAlternativeName('https://example.com')
        self.assertEqual(ext.as_extension(), x509.extensions.Extension(
            oid=ExtensionOID.ISSUER_ALTERNATIVE_NAME,
            critical=False,
            value=x509.IssuerAlternativeName([uri('https://example.com')])
        ))


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


class NameConstraintsTestCase(TestCase):
    ext_empty = x509.extensions.Extension(
        oid=ExtensionOID.NAME_CONSTRAINTS, critical=True,
        value=x509.NameConstraints(permitted_subtrees=[], excluded_subtrees=[])
    )
    ext_permitted = x509.extensions.Extension(
        oid=ExtensionOID.NAME_CONSTRAINTS, critical=True,
        value=x509.NameConstraints(permitted_subtrees=[dns('example.com')], excluded_subtrees=[])
    )
    ext_excluded = x509.extensions.Extension(
        oid=ExtensionOID.NAME_CONSTRAINTS, critical=True,
        value=x509.NameConstraints(permitted_subtrees=[], excluded_subtrees=[dns('example.com')])
    )
    ext_both = x509.extensions.Extension(
        oid=ExtensionOID.NAME_CONSTRAINTS, critical=True,
        value=x509.NameConstraints(permitted_subtrees=[dns('example.com')],
                                   excluded_subtrees=[dns('example.net')])
    )

    def test_from_list(self):
        ext = NameConstraints([[], []])
        self.assertEqual(ext.permitted, [])
        self.assertEqual(ext.excluded, [])
        self.assertEqual(ext.as_extension(), self.ext_empty)
        self.assertEqual(ext, NameConstraints([[], []]))
        self.assertTrue(ext.critical)
        self.assertFalse(bool(ext))

        ext = NameConstraints([['example.com'], []])
        self.assertEqual(ext.permitted, [dns('example.com')])
        self.assertEqual(ext.excluded, [])
        self.assertEqual(ext.as_extension(), self.ext_permitted)
        self.assertEqual(ext, NameConstraints([['example.com'], []]))
        self.assertTrue(ext.critical)
        self.assertTrue(bool(ext))

        ext = NameConstraints([[], ['example.com']])
        self.assertEqual(ext.permitted, [])
        self.assertEqual(ext.excluded, [dns('example.com')])
        self.assertEqual(ext.as_extension(), self.ext_excluded)
        self.assertEqual(ext, NameConstraints([[], ['example.com']]))
        self.assertTrue(ext.critical)
        self.assertTrue(bool(ext))

        ext = NameConstraints([['example.com'], ['example.net']])
        self.assertEqual(ext.permitted, [dns('example.com')])
        self.assertEqual(ext.excluded, [dns('example.net')])
        self.assertEqual(ext.as_extension(), self.ext_both)
        self.assertEqual(ext, NameConstraints([['example.com'], ['example.net']]))
        self.assertTrue(ext.critical)
        self.assertTrue(bool(ext))

        # same thing again but with GeneralName instances
        ext = NameConstraints([[dns('example.com')], []])
        self.assertEqual(ext.permitted, [dns('example.com')])
        self.assertEqual(ext.excluded, [])
        self.assertEqual(ext.as_extension(), self.ext_permitted)
        self.assertEqual(ext, NameConstraints([[dns('example.com')], []]))
        self.assertTrue(ext.critical)
        self.assertTrue(bool(ext))

        ext = NameConstraints([[], [dns('example.com')]])
        self.assertEqual(ext.permitted, [])
        self.assertEqual(ext.excluded, [dns('example.com')])
        self.assertEqual(ext.as_extension(), self.ext_excluded)
        self.assertEqual(ext, NameConstraints([[], [dns('example.com')]]))
        self.assertTrue(ext.critical)
        self.assertTrue(bool(ext))

        ext = NameConstraints([[dns('example.com')], [dns('example.net')]])
        self.assertEqual(ext.permitted, [dns('example.com')])
        self.assertEqual(ext.excluded, [dns('example.net')])
        self.assertEqual(ext.as_extension(), self.ext_both)
        self.assertEqual(ext, NameConstraints([[dns('example.com')], [dns('example.net')]]))
        self.assertTrue(ext.critical)
        self.assertTrue(bool(ext))

    def test_from_dict(self):
        pass

    def test_from_extension(self):
        pass

    def test_error(self):
        with self.assertRaisesRegex(ValueError, r'^Value is of unsupported type NoneType$'):
            NameConstraints(None)
        with self.assertRaisesRegex(ValueError, r'^Value is of unsupported type bool$'):
            NameConstraints(False)


class SubjectAlternativeNameTestCase(TestCase):
    def test_operators(self):
        ext = SubjectAlternativeName(['https://example.com'])
        self.assertIn('https://example.com', ext)
        self.assertIn(uri('https://example.com'), ext)
        self.assertNotIn('https://example.net', ext)
        self.assertNotIn(uri('https://example.net'), ext)

        self.assertEqual(len(ext), 1)
        self.assertEqual(bool(ext), True)

    def test_from_extension(self):
        x509_ext = x509.extensions.Extension(
            oid=ExtensionOID.SUBJECT_ALTERNATIVE_NAME, critical=True,
            value=x509.SubjectAlternativeName([dns('example.com')]))
        ext = SubjectAlternativeName(x509_ext)
        self.assertEqual(ext.as_extension(), x509_ext)

    def test_from_dict(self):
        ext = SubjectAlternativeName({})
        self.assertEqual(ext.value, [])
        self.assertFalse(ext.critical)
        self.assertEqual(len(ext), 0)
        self.assertEqual(bool(ext), False)

        ext = SubjectAlternativeName({'value': None})
        self.assertEqual(ext.value, [])
        self.assertFalse(ext.critical)
        self.assertEqual(len(ext), 0)
        self.assertEqual(bool(ext), False)

        ext = SubjectAlternativeName({'value': []})
        self.assertEqual(ext.value, [])
        self.assertFalse(ext.critical)
        self.assertEqual(len(ext), 0)
        self.assertEqual(bool(ext), False)

        ext = SubjectAlternativeName({'value': 'example.com'})
        self.assertEqual(ext.value, [dns('example.com')])
        self.assertFalse(ext.critical)
        self.assertEqual(len(ext), 1)
        self.assertEqual(bool(ext), True)

        ext = SubjectAlternativeName({'value': dns('example.com')})
        self.assertEqual(ext.value, [dns('example.com')])
        self.assertFalse(ext.critical)
        self.assertEqual(len(ext), 1)
        self.assertEqual(bool(ext), True)

        ext = SubjectAlternativeName({'value': ['example.com']})
        self.assertEqual(ext.value, [dns('example.com')])
        self.assertFalse(ext.critical)
        self.assertEqual(len(ext), 1)
        self.assertEqual(bool(ext), True)

        ext = SubjectAlternativeName({'value': ['example.com', dns('example.net')]})
        self.assertEqual(ext.value, [dns('example.com'), dns('example.net')])
        self.assertFalse(ext.critical)
        self.assertEqual(len(ext), 2)
        self.assertEqual(bool(ext), True)

    def test_list_funcs(self):
        ext = SubjectAlternativeName(['https://example.com'])
        ext.append('https://example.net')
        self.assertEqual(ext.value, [uri('https://example.com'), uri('https://example.net')])
        self.assertEqual(ext.count('https://example.com'), 1)
        self.assertEqual(ext.count(uri('https://example.com')), 1)
        self.assertEqual(ext.count('https://example.net'), 1)
        self.assertEqual(ext.count(uri('https://example.net')), 1)
        self.assertEqual(ext.count('https://example.org'), 0)
        self.assertEqual(ext.count(uri('https://example.org')), 0)

        ext.clear()
        self.assertEqual(ext.value, [])
        self.assertEqual(ext.count('https://example.com'), 0)
        self.assertEqual(ext.count(uri('https://example.com')), 0)

        ext.extend(['https://example.com', 'https://example.net'])
        self.assertEqual(ext.value, [uri('https://example.com'), uri('https://example.net')])
        ext.extend(['https://example.org'])
        self.assertEqual(ext.value, [uri('https://example.com'), uri('https://example.net'),
                                     uri('https://example.org')])

        ext.clear()
        ext.extend([uri('https://example.com'), uri('https://example.net')])
        self.assertEqual(ext.value, [uri('https://example.com'), uri('https://example.net')])
        ext.extend([uri('https://example.org')])
        self.assertEqual(ext.value, [uri('https://example.com'), uri('https://example.net'),
                                     uri('https://example.org')])

        self.assertEqual(ext.pop(), 'URI:https://example.org')
        self.assertEqual(ext.value, [uri('https://example.com'), uri('https://example.net')])

        self.assertIsNone(ext.remove('https://example.com'))
        self.assertEqual(ext.value, [uri('https://example.net')])

        self.assertIsNone(ext.remove(uri('https://example.net')))
        self.assertEqual(ext.value, [])

        ext.insert(0, 'https://example.com')
        self.assertEqual(ext.value, [uri('https://example.com')])

    def test_slices(self):
        val = ['DNS:foo', 'DNS:bar', 'DNS:bla']
        ext = SubjectAlternativeName(val)
        self.assertEqual(ext[0], val[0])
        self.assertEqual(ext[1], val[1])
        self.assertEqual(ext[0:], val[0:])
        self.assertEqual(ext[1:], val[1:])
        self.assertEqual(ext[:1], val[:1])
        self.assertEqual(ext[1:2], val[1:2])

        ext[0] = 'test'
        val = [dns('test'), dns('bar'), dns('bla')]
        self.assertEqual(ext.value, val)
        ext[1:2] = ['x', 'y']
        val[1:2] = [dns('x'), dns('y')]
        self.assertEqual(ext.value, val)
        ext[1:] = ['a', 'b']
        val[1:] = [dns('a'), dns('b')]
        self.assertEqual(ext.value, val)

        del ext[0]
        del val[0]
        self.assertEqual(ext.value, val)

    def test_serialization(self):
        val = ['foo', 'bar', 'bla']
        ext = SubjectAlternativeName({'value': val, 'critical': False})
        self.assertEqual(ext, SubjectAlternativeName(ext.serialize()))
        ext = SubjectAlternativeName({'value': val, 'critical': True})
        self.assertEqual(ext, SubjectAlternativeName(ext.serialize()))

    def test_as_str(self):  # test various string conversion methods
        san = SubjectAlternativeName([])
        self.assertEqual(str(san), "")
        self.assertEqual(repr(san), "<SubjectAlternativeName: [], critical=False>")
        self.assertEqual(san.as_text(), "")
        san.critical = True
        self.assertEqual(str(san), "/critical")
        self.assertEqual(repr(san), "<SubjectAlternativeName: [], critical=True>")
        self.assertEqual(san.as_text(), "")

        san = SubjectAlternativeName(['example.com'])
        self.assertEqual(str(san), "DNS:example.com")
        self.assertEqual(repr(san), "<SubjectAlternativeName: ['DNS:example.com'], critical=False>")
        self.assertEqual(san.as_text(), "* DNS:example.com")
        san.critical = True
        self.assertEqual(str(san), "DNS:example.com/critical")
        self.assertEqual(repr(san), "<SubjectAlternativeName: ['DNS:example.com'], critical=True>")
        self.assertEqual(san.as_text(), "* DNS:example.com")

        san = SubjectAlternativeName([dns('example.com')])
        self.assertEqual(str(san), "DNS:example.com")
        self.assertEqual(repr(san), "<SubjectAlternativeName: ['DNS:example.com'], critical=False>")
        self.assertEqual(san.as_text(), "* DNS:example.com")
        san.critical = True
        self.assertEqual(str(san), "DNS:example.com/critical")
        self.assertEqual(repr(san), "<SubjectAlternativeName: ['DNS:example.com'], critical=True>")
        self.assertEqual(san.as_text(), "* DNS:example.com")

        san = SubjectAlternativeName([dns('example.com'), dns('example.org')])
        self.assertEqual(str(san), "DNS:example.com,DNS:example.org")
        self.assertEqual(repr(san),
                         "<SubjectAlternativeName: ['DNS:example.com', 'DNS:example.org'], critical=False>")
        self.assertEqual(san.as_text(), "* DNS:example.com\n* DNS:example.org")
        san.critical = True
        self.assertEqual(str(san), "DNS:example.com,DNS:example.org/critical")
        self.assertEqual(repr(san),
                         "<SubjectAlternativeName: ['DNS:example.com', 'DNS:example.org'], critical=True>")
        self.assertEqual(san.as_text(), "* DNS:example.com\n* DNS:example.org")

    def test_error(self):
        with self.assertRaisesRegex(ValueError, r'^Value is of unsupported type NoneType$'):
            SubjectAlternativeName(None)
        with self.assertRaisesRegex(ValueError, r'^Value is of unsupported type bool$'):
            SubjectAlternativeName(False)


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

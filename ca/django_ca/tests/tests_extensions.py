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
import unittest

import six

from cryptography import x509
from cryptography.x509 import TLSFeatureType
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.oid import NameOID

from django.test import TestCase

from .. import ca_settings
from ..extensions import AuthorityInformationAccess
from ..extensions import AuthorityKeyIdentifier
from ..extensions import BasicConstraints
from ..extensions import CRLDistributionPoints
from ..extensions import DistributionPoint
from ..extensions import ExtendedKeyUsage
from ..extensions import Extension
from ..extensions import IssuerAlternativeName
from ..extensions import KeyUsage
from ..extensions import KnownValuesExtension
from ..extensions import ListExtension
from ..extensions import NameConstraints
from ..extensions import OCSPNoCheck
from ..extensions import PrecertificateSignedCertificateTimestamps
from ..extensions import SubjectAlternativeName
from ..extensions import SubjectKeyIdentifier
from ..extensions import TLSFeature
from ..extensions import UnrecognizedExtension
from .base import DjangoCAWithCertTestCase
from .base import certs

if ca_settings.CRYPTOGRAPHY_HAS_PRECERT_POISON:  # pragma: only cryptography>=2.4
    from ..extensions import PrecertPoison


def dns(d):  # just a shortcut
    return x509.DNSName(d)


def uri(u):  # just a shortcut
    return x509.UniformResourceIdentifier(u)


def load_tests(loader, tests, ignore):
    if six.PY3:  # pragma: only py3
        # unicode strings make this very hard to test doctests in both py2 and py3
        tests.addTests(doctest.DocTestSuite('django_ca.extensions'))
    return tests


class ExtensionTestMixin:
    def test_as_extension(self):
        raise NotImplementedError

    def test_as_text(self):
        raise NotImplementedError

    def test_hash(self):
        raise NotImplementedError

    def test_eq(self):
        raise NotImplementedError

    def test_extension_type(self):
        raise NotImplementedError

    def test_for_builder(self):
        raise NotImplementedError

    def test_ne(self):
        raise NotImplementedError

    def test_repr(self):
        raise NotImplementedError

    def test_serialize(self):
        raise NotImplementedError

    def test_str(self):
        raise NotImplementedError


class ListExtensionTestMixin(ExtensionTestMixin):
    def test_count(self):
        raise NotImplementedError

    def test_del(self):
        raise NotImplementedError

    def test_extend(self):
        raise NotImplementedError

    def test_from_list(self):
        raise NotImplementedError

    def test_getitem(self):
        raise NotImplementedError

    def test_getitem_slices(self):
        raise NotImplementedError

    def test_in(self):
        raise NotImplementedError

    def test_insert(self):
        raise NotImplementedError

    def test_len(self):
        raise NotImplementedError

    def test_not_in(self):
        raise NotImplementedError

    def test_pop(self):
        raise NotImplementedError

    def test_remove(self):
        raise NotImplementedError

    def test_setitem(self):
        raise NotImplementedError

    def test_setitem_slices(self):
        raise NotImplementedError


class KnownValuesExtensionTestMixin(ListExtensionTestMixin):
    def test_eq_order(self):
        raise NotImplementedError

    def test_hash_order(self):
        raise NotImplementedError

    def test_unknown_values(self):
        raise NotImplementedError

    # Currently overwritten b/c KnownValues should behave like a set, not like a list
    def test_del(self):
        pass

    def test_extend(self):
        pass

    def test_getitem(self):
        pass

    def test_getitem_slices(self):
        pass

    def test_insert(self):
        pass

    def test_pop(self):
        pass

    def test_remove(self):
        pass

    def test_setitem(self):
        pass

    def test_setitem_slices(self):
        pass


class ExtensionTestCase(ExtensionTestMixin, TestCase):
    value = 'foobar'

    def assertExtension(self, ext, critical=True):
        self.assertEqual(ext.value, self.value)
        self.assertEqual(ext.critical, critical)

    def test_as_extension(self):
        with self.assertRaises(NotImplementedError):
            Extension(self.value).as_extension()

    def test_extension_type(self):
        with self.assertRaises(NotImplementedError):
            Extension(self.value).extension_type

    def test_eq(self):
        ext = Extension({'value': self.value, 'critical': True})
        self.assertEqual(ext, Extension('critical,%s' % self.value))

    def test_for_builder(self):
        with self.assertRaises(NotImplementedError):
            Extension(self.value).for_builder()

    def test_hash(self):
        self.assertEqual(hash(Extension(self.value)), hash(Extension(self.value)))
        self.assertEqual(hash(Extension({'critical': False, 'value': self.value})),
                         hash(Extension({'critical': False, 'value': self.value})))

        self.assertNotEqual(hash(Extension({'critical': True, 'value': self.value})),
                            hash(Extension({'critical': False, 'value': self.value})))
        self.assertNotEqual(hash(Extension({'critical': False, 'value': self.value[::-1]})),
                            hash(Extension({'critical': False, 'value': self.value})))

    def test_ne(self):
        ext = Extension({'value': self.value, 'critical': True})
        self.assertNotEqual(ext, Extension(self.value))
        self.assertNotEqual(ext, Extension('critical,other'))
        self.assertNotEqual(ext, Extension('other'))

    def test_repr(self):
        self.assertEqual(repr(Extension('critical,%s' % self.value)),
                         '<Extension: %s, critical=True>' % self.value)
        self.assertEqual(repr(Extension(self.value)), '<Extension: %s, critical=False>' % self.value)

    def test_serialize(self):
        value = self.value
        ext = Extension(value)
        self.assertEqual(ext.serialize(), value)
        self.assertEqual(ext, Extension(ext.serialize()))

        value = 'critical,%s' % self.value
        ext = Extension(value)
        self.assertEqual(ext.serialize(), value)
        self.assertEqual(ext, Extension(ext.serialize()))

    def test_str(self):
        self.assertEqual(str(Extension('critical,%s' % self.value)), '%s/critical' % self.value)
        self.assertEqual(str(Extension(self.value)), self.value)

    def test_basic(self):
        self.assertExtension(Extension('critical,%s' % self.value))
        self.assertExtension(Extension({'critical': True, 'value': self.value}))

        self.assertExtension(Extension(self.value), critical=False)
        self.assertExtension(Extension({'critical': False, 'value': self.value}), critical=False)
        self.assertExtension(Extension({'value': self.value}), critical=False)

    def test_as_text(self):
        self.assertEqual(Extension('critical,%s' % self.value).as_text(), self.value)

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

        # These do not work because base class does not define an OID
        with self.assertRaises(AttributeError):
            ext.name


class ListExtensionTestCase(TestCase):
    def test_hash(self):
        self.assertEqual(hash(ListExtension(['foo'])), hash(ListExtension(['foo'])))
        self.assertNotEqual(hash(ListExtension({'value': 'foo', 'critical': False})),
                            hash(ListExtension({'value': 'bar', 'critical': False})))
        self.assertNotEqual(hash(ListExtension({'value': 'foo', 'critical': False})),
                            hash(ListExtension({'value': 'foo', 'critical': True})))

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

    def test_serialize(self):
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

    def test_eq(self):
        self.assertEqual(self.cls('foo'), self.cls('foo'))
        self.assertEqual(self.cls('foo,bar'), self.cls('foo,bar'))
        self.assertEqual(self.cls('foo,bar'), self.cls('bar,foo'))

        self.assertEqual(self.cls('critical,foo'), self.cls('critical,foo'))
        self.assertEqual(self.cls('critical,foo,bar'), self.cls('critical,foo,bar'))
        self.assertEqual(self.cls('critical,foo,bar'), self.cls('critical,bar,foo'))

    def test_ne(self):
        self.assertNotEqual(self.cls('foo'), self.cls('bar'))
        self.assertNotEqual(self.cls('foo'), self.cls('critical,foo'))

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
        self.assertEqual(str(self.cls('foo,bar')), 'bar,foo')
        self.assertEqual(str(self.cls('bar,foo')), 'bar,foo')
        self.assertEqual(str(self.cls('bar')), 'bar')
        self.assertEqual(str(self.cls('critical,bar')), 'bar/critical')
        self.assertEqual(str(self.cls('critical,foo,bar')), 'bar,foo/critical')
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
    ext_critical = x509.extensions.Extension(
        oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS, critical=True,
        value=x509.AuthorityInformationAccess(descriptions=[
            x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS,
                                   uri('https://example.com')),
            x509.AccessDescription(AuthorityInformationAccessOID.OCSP,
                                   uri('https://example.net')),
            x509.AccessDescription(AuthorityInformationAccessOID.OCSP,
                                   uri('https://example.org')),
        ])
    )

    def test_hash(self):
        self.assertEqual(hash(AuthorityInformationAccess(self.ext_empty)),
                         hash(AuthorityInformationAccess(self.ext_empty)))
        self.assertEqual(hash(AuthorityInformationAccess(self.ext_issuer)),
                         hash(AuthorityInformationAccess(self.ext_issuer)))
        self.assertEqual(hash(AuthorityInformationAccess(self.ext_ocsp)),
                         hash(AuthorityInformationAccess(self.ext_ocsp)))
        self.assertEqual(hash(AuthorityInformationAccess(self.ext_both)),
                         hash(AuthorityInformationAccess(self.ext_both)))

        self.assertNotEqual(hash(AuthorityInformationAccess(self.ext_empty)),
                            hash(AuthorityInformationAccess(self.ext_both)))
        self.assertNotEqual(hash(AuthorityInformationAccess(self.ext_empty)),
                            hash(AuthorityInformationAccess(self.ext_issuer)))
        self.assertNotEqual(hash(AuthorityInformationAccess(self.ext_empty)),
                            hash(AuthorityInformationAccess(self.ext_ocsp)))

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

    def test_serialize(self):
        extensions = [
            AuthorityInformationAccess(self.ext_empty),
            AuthorityInformationAccess(self.ext_issuer),
            AuthorityInformationAccess(self.ext_ocsp),
            AuthorityInformationAccess(self.ext_both),
            AuthorityInformationAccess(self.ext_critical),
        ]
        for ext in extensions:
            self.assertEqual(AuthorityInformationAccess(ext.serialize()), ext)


class AuthorityKeyIdentifierTestCase(ExtensionTestMixin, TestCase):
    hex1 = '33:33:33:33:33:33'
    hex2 = '44:44:44:44:44:44'
    hex3 = '55:55:55:55:55:55'

    b1 = b'333333'
    b2 = b'DDDDDD'
    b3 = b'UUUUUU'

    x1 = x509.Extension(
        oid=x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER, critical=False,
        value=x509.AuthorityKeyIdentifier(b1, None, None))
    x2 = x509.Extension(
        oid=x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER, critical=False,
        value=x509.AuthorityKeyIdentifier(b2, None, None))
    x3 = x509.Extension(
        oid=x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER, critical=True,
        value=x509.AuthorityKeyIdentifier(b3, None, None)
    )

    def setUp(self):
        super(AuthorityKeyIdentifierTestCase, self).setUp()
        self.ext1 = AuthorityKeyIdentifier(self.x1)
        self.ext2 = AuthorityKeyIdentifier(self.x2)
        self.ext3 = AuthorityKeyIdentifier(self.x3)

    def test_as_extension(self):
        self.assertEqual(AuthorityKeyIdentifier(self.hex1).as_extension(), self.x1)
        self.assertEqual(AuthorityKeyIdentifier(self.hex2).as_extension(), self.x2)

        self.assertEqual(self.ext1.as_extension(), self.x1)
        self.assertEqual(self.ext2.as_extension(), self.x2)
        self.assertEqual(self.ext3.as_extension(), self.x3)

    def test_as_text(self):
        self.assertEqual(self.ext1.as_text(), 'keyid:%s' % self.hex1)
        self.assertEqual(self.ext2.as_text(), 'keyid:%s' % self.hex2)
        self.assertEqual(self.ext3.as_text(), 'keyid:%s' % self.hex3)

    def test_eq(self):
        self.assertEqual(self.ext1, self.ext1)
        self.assertEqual(self.ext2, self.ext2)
        self.assertEqual(self.ext3, self.ext3)
        self.assertEqual(AuthorityKeyIdentifier(self.hex1), self.ext1)
        self.assertEqual(AuthorityKeyIdentifier(self.hex2), self.ext2)

    def test_extension_type(self):
        self.assertEqual(self.ext1.extension_type, self.x1.value)
        self.assertEqual(self.ext2.extension_type, self.x2.value)
        self.assertEqual(self.ext3.extension_type, self.x3.value)

    def test_for_builder(self):
        exp1 = {'critical': False, 'extension': self.x1.value}
        exp2 = {'critical': False, 'extension': self.x2.value}
        exp3 = {'critical': True, 'extension': self.x3.value}

        self.assertEqual(self.ext1.for_builder(), exp1)
        self.assertEqual(self.ext2.for_builder(), exp2)
        self.assertEqual(self.ext3.for_builder(), exp3)

    def test_hash(self):
        self.assertEqual(hash(self.ext1), hash(self.ext1))
        self.assertEqual(hash(self.ext2), hash(self.ext2))
        self.assertEqual(hash(self.ext3), hash(self.ext3))
        self.assertNotEqual(hash(self.ext1), hash(self.ext2))
        self.assertNotEqual(hash(self.ext1), hash(self.ext3))
        self.assertNotEqual(hash(self.ext2), hash(self.ext3))

    def test_ne(self):
        self.assertNotEqual(self.ext1, self.ext2)
        self.assertNotEqual(self.ext1, self.ext3)
        self.assertNotEqual(self.ext2, self.ext3)
        self.assertNotEqual(self.ext3, AuthorityKeyIdentifier(self.hex3))  # ext3 is critical

    def test_repr(self):
        if six.PY2:  # pragma: only py2
            self.assertEqual(repr(self.ext1), '<AuthorityKeyIdentifier: 333333, critical=False>')
            self.assertEqual(repr(self.ext2), '<AuthorityKeyIdentifier: DDDDDD, critical=False>')
            self.assertEqual(repr(self.ext3), '<AuthorityKeyIdentifier: UUUUUU, critical=True>')
        else:
            self.assertEqual(repr(self.ext1), '<AuthorityKeyIdentifier: b\'333333\', critical=False>')
            self.assertEqual(repr(self.ext2), '<AuthorityKeyIdentifier: b\'DDDDDD\', critical=False>')
            self.assertEqual(repr(self.ext3), '<AuthorityKeyIdentifier: b\'UUUUUU\', critical=True>')

    def test_serialize(self):
        self.assertEqual(self.ext1.serialize(), self.hex1)
        self.assertEqual(self.ext2.serialize(), self.hex2)
        self.assertEqual(self.ext3.serialize(), self.hex3)
        self.assertEqual(self.ext1.serialize(), AuthorityKeyIdentifier(self.hex1).serialize())
        self.assertNotEqual(self.ext1.serialize(), self.ext2.serialize())

    def test_str(self):
        ext = AuthorityKeyIdentifier(self.hex1)
        self.assertEqual(str(ext), 'keyid:%s' % self.hex1)

    @unittest.skipUnless(six.PY3, 'bytes only work in python3')
    def test_from_bytes(self):
        ext = AuthorityKeyIdentifier(self.b1)
        self.assertEqual(ext.as_text(), 'keyid:%s' % self.hex1)
        self.assertEqual(ext.as_extension(), self.x1)

    def test_subject_key_identifier(self):
        ski = SubjectKeyIdentifier(self.hex1)
        ext = AuthorityKeyIdentifier(ski)
        self.assertEqual(ext.as_text(), 'keyid:%s' % self.hex1)
        self.assertEqual(ext.extension_type.key_identifier, self.x1.value.key_identifier)

    def test_error(self):
        with self.assertRaisesRegex(ValueError, r'^Value is of unsupported type NoneType$'):
            AuthorityKeyIdentifier(None)
        with self.assertRaisesRegex(ValueError, r'^Value is of unsupported type bool$'):
            AuthorityKeyIdentifier(False)


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

    def test_hash(self):
        ext1 = BasicConstraints('CA:FALSE')
        ext2 = BasicConstraints('CA:TRUE')
        ext3 = BasicConstraints('CA:TRUE,pathlen=1')

        self.assertEqual(hash(ext1), hash(ext1))
        self.assertEqual(hash(ext2), hash(ext2))
        self.assertEqual(hash(ext3), hash(ext3))

        self.assertNotEqual(hash(ext1), hash(ext2))
        self.assertNotEqual(hash(ext1), hash(ext3))
        self.assertNotEqual(hash(ext2), hash(ext3))

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

    def test_serialize(self):
        exts = [
            BasicConstraints({'ca': True}),
            BasicConstraints({'ca': False}),
            BasicConstraints({'ca': True, 'pathlen': 3}),
            BasicConstraints({'ca': True, 'pathlen': None}),
            BasicConstraints({'ca': True, 'critical': False}),
        ]
        for ext in exts:
            self.assertEqual(BasicConstraints(ext.serialize()), ext)


class DistributionPointTestCase(TestCase):
    def test_init_basic(self):
        dp = DistributionPoint({})
        self.assertIsNone(dp.full_name)
        self.assertIsNone(dp.relative_name)
        self.assertIsNone(dp.crl_issuer)
        self.assertIsNone(dp.reasons)

        dp = DistributionPoint({
            'full_name': ['http://example.com'],
            'crl_issuer': ['http://example.net'],
        })
        self.assertEqual(dp.full_name, [uri('http://example.com')])
        self.assertIsNone(dp.relative_name)
        self.assertEqual(dp.crl_issuer, [uri('http://example.net')])
        self.assertIsNone(dp.reasons)

        dp = DistributionPoint({
            'full_name': 'http://example.com',
            'crl_issuer': 'http://example.net',
        })
        self.assertEqual(dp.full_name, [uri('http://example.com')])
        self.assertIsNone(dp.relative_name)
        self.assertEqual(dp.crl_issuer, [uri('http://example.net')])
        self.assertIsNone(dp.reasons)

    def test_init_errors(self):
        with self.assertRaisesRegex(ValueError, r'^data must be x509.DistributionPoint or dict$'):
            DistributionPoint('foobar')

        with self.assertRaisesRegex(ValueError, r'^full_name and relative_name cannot both have a value$'):
            DistributionPoint({
                'full_name': ['http://example.com'],
                'relative_name': '/CN=example.com',
            })


class CRLDistributionPointsTestCase(ListExtensionTestMixin, TestCase):
    dp1 = x509.DistributionPoint(
        full_name=[
            x509.UniformResourceIdentifier('http://ca.example.com/crl'),
        ],
        relative_name=None,
        crl_issuer=None,
        reasons=None
    )
    dp2 = x509.DistributionPoint(
        full_name=[
            x509.UniformResourceIdentifier('http://ca.example.com/crl'),
            x509.DirectoryName(x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u"AT")])),
        ],
        relative_name=None,
        crl_issuer=None,
        reasons=None
    )
    dp3 = x509.DistributionPoint(
        full_name=None,
        relative_name=x509.RelativeDistinguishedName([
            x509.NameAttribute(NameOID.COMMON_NAME, u'example.com'),
        ]),
        crl_issuer=None,
        reasons=None
    )
    dp4 = x509.DistributionPoint(
        full_name=[
            x509.UniformResourceIdentifier('http://ca.example.com/crl'),
        ],
        relative_name=None,
        crl_issuer=[
            x509.UniformResourceIdentifier('http://ca.example.com/'),
        ],
        reasons=frozenset([x509.ReasonFlags.key_compromise, x509.ReasonFlags.ca_compromise])
    )

    # serialized versions of dps above
    s1 = {'full_name': ['URI:http://ca.example.com/crl']}
    s2 = {'full_name': ['URI:http://ca.example.com/crl', 'dirname:/C=AT']}
    s3 = {'relative_name': '/CN=example.com'}
    s4 = {
        'full_name': ['URI:http://ca.example.com/crl'],
        'crl_issuer': ['URI:http://ca.example.com/'],
        'reasons': ['ca_compromise', 'key_compromise'],
    }

    # cryptography extensions
    x1 = x509.Extension(oid=ExtensionOID.CRL_DISTRIBUTION_POINTS, critical=False,
                        value=x509.CRLDistributionPoints([dp1]))
    x2 = x509.Extension(oid=ExtensionOID.CRL_DISTRIBUTION_POINTS, critical=False,
                        value=x509.CRLDistributionPoints([dp2]))
    x3 = x509.Extension(oid=ExtensionOID.CRL_DISTRIBUTION_POINTS, critical=False,
                        value=x509.CRLDistributionPoints([dp3]))
    x4 = x509.Extension(oid=ExtensionOID.CRL_DISTRIBUTION_POINTS, critical=False,
                        value=x509.CRLDistributionPoints([dp4]))
    x5 = x509.Extension(oid=ExtensionOID.CRL_DISTRIBUTION_POINTS, critical=True,
                        value=x509.CRLDistributionPoints([dp2, dp4]))

    def setUp(self):
        super(CRLDistributionPointsTestCase, self).setUp()
        # django_ca extensions
        self.ext1 = CRLDistributionPoints(self.x1)
        self.ext2 = CRLDistributionPoints(self.x2)
        self.ext3 = CRLDistributionPoints(self.x3)
        self.ext4 = CRLDistributionPoints(self.x4)
        self.ext5 = CRLDistributionPoints(self.x5)

    def test_as_extension(self):
        self.assertEqual(self.ext1.as_extension(), self.x1)
        self.assertEqual(self.ext2.as_extension(), self.x2)
        self.assertEqual(self.ext3.as_extension(), self.x3)
        self.assertEqual(self.ext4.as_extension(), self.x4)
        self.assertEqual(self.ext5.as_extension(), self.x5)

    def test_as_text(self):
        self.assertEqual(self.ext1.as_text(), """* DistributionPoint:
  * Full Name:
    * URI:http://ca.example.com/crl""")
        self.assertEqual(self.ext2.as_text(), """* DistributionPoint:
  * Full Name:
    * URI:http://ca.example.com/crl
    * dirname:/C=AT""")
        self.assertEqual(self.ext3.as_text(), """* DistributionPoint:
  * Relative Name: /CN=example.com""")
        self.assertEqual(self.ext4.as_text(), """* DistributionPoint:
  * Full Name:
    * URI:http://ca.example.com/crl
  * CRL Issuer:
    * URI:http://ca.example.com/
  * Reasons: ca_compromise, key_compromise""")
        self.assertEqual(self.ext5.as_text(), """* DistributionPoint:
  * Full Name:
    * URI:http://ca.example.com/crl
    * dirname:/C=AT
* DistributionPoint:
  * Full Name:
    * URI:http://ca.example.com/crl
  * CRL Issuer:
    * URI:http://ca.example.com/
  * Reasons: ca_compromise, key_compromise""")

    def test_count(self):
        self.assertEqual(self.ext1.count(self.s1), 1)
        self.assertEqual(self.ext1.count(self.dp1), 1)
        self.assertEqual(self.ext1.count(DistributionPoint(self.s1)), 1)
        self.assertEqual(self.ext1.count(self.s2), 0)
        self.assertEqual(self.ext1.count(self.dp2), 0)
        self.assertEqual(self.ext1.count(DistributionPoint(self.s2)), 0)
        self.assertEqual(self.ext5.count(self.s2), 1)
        self.assertEqual(self.ext5.count(self.dp2), 1)
        self.assertEqual(self.ext5.count(DistributionPoint(self.s2)), 1)
        self.assertEqual(self.ext5.count(self.s4), 1)
        self.assertEqual(self.ext5.count(self.dp4), 1)
        self.assertEqual(self.ext5.count(DistributionPoint(self.s4)), 1)
        self.assertEqual(self.ext5.count(self.s3), 0)
        self.assertEqual(self.ext5.count(self.dp3), 0)
        self.assertEqual(self.ext5.count(DistributionPoint(self.s3)), 0)
        self.assertEqual(self.ext5.count(None), 0)

    def test_del(self):
        self.assertIn(self.dp1, self.ext1)
        del self.ext1[0]
        self.assertNotIn(self.dp1, self.ext1)
        self.assertEqual(len(self.ext1), 0)

        self.assertIn(self.dp2, self.ext5)
        self.assertIn(self.dp4, self.ext5)
        del self.ext5[1]
        self.assertIn(self.dp2, self.ext5)
        self.assertNotIn(self.dp4, self.ext5)
        self.assertEqual(len(self.ext5), 1)

        self.assertEqual(len(self.ext4), 1)
        with self.assertRaisesRegex(IndexError, '^list assignment index out of range$'):
            del self.ext4[1]
        self.assertEqual(len(self.ext4), 1)

    def test_eq(self):
        self.assertEqual(self.ext1, self.ext1)
        self.assertEqual(self.ext2, self.ext2)
        self.assertEqual(self.ext3, self.ext3)
        self.assertEqual(self.ext4, self.ext4)
        self.assertEqual(self.ext5, self.ext5)
        self.assertEqual(self.ext1, CRLDistributionPoints(self.x1))
        self.assertEqual(self.ext2, CRLDistributionPoints(self.x2))
        self.assertEqual(self.ext3, CRLDistributionPoints(self.x3))
        self.assertEqual(self.ext4, CRLDistributionPoints(self.x4))
        self.assertEqual(self.ext5, CRLDistributionPoints(self.x5))
        # ext5 has other critical value then default

    def test_extend(self):
        self.ext1.extend([self.s2])
        self.assertEqual(self.ext1, CRLDistributionPoints([
            DistributionPoint(self.dp1), DistributionPoint(self.dp2)]))
        self.ext1.extend([self.dp3])
        self.assertEqual(self.ext1, CRLDistributionPoints([
            DistributionPoint(self.dp1), DistributionPoint(self.dp2), DistributionPoint(self.dp3),
        ]))
        self.ext1.extend([DistributionPoint(self.dp4)])
        self.assertEqual(self.ext1, CRLDistributionPoints([
            DistributionPoint(self.dp1), DistributionPoint(self.dp2), DistributionPoint(self.dp3),
            DistributionPoint(self.dp4),
        ]))

    def test_extension_type(self):
        self.assertEqual(self.ext1.extension_type, x509.CRLDistributionPoints([self.dp1]))
        self.assertEqual(self.ext2.extension_type, x509.CRLDistributionPoints([self.dp2]))
        self.assertEqual(self.ext3.extension_type, x509.CRLDistributionPoints([self.dp3]))
        self.assertEqual(self.ext4.extension_type, x509.CRLDistributionPoints([self.dp4]))
        self.assertEqual(self.ext5.extension_type, x509.CRLDistributionPoints([self.dp2, self.dp4]))

    def test_for_builder(self):
        self.assertEqual(self.ext1.for_builder(), {'critical': False, 'extension': self.x1.value})
        self.assertEqual(self.ext2.for_builder(), {'critical': False, 'extension': self.x2.value})
        self.assertEqual(self.ext3.for_builder(), {'critical': False, 'extension': self.x3.value})
        self.assertEqual(self.ext4.for_builder(), {'critical': False, 'extension': self.x4.value})
        self.assertEqual(self.ext5.for_builder(), {'critical': True, 'extension': self.x5.value})

    def test_from_list(self):
        self.assertEqual(self.ext1, CRLDistributionPoints([DistributionPoint(self.dp1)]))
        self.assertEqual(self.ext2, CRLDistributionPoints([DistributionPoint(self.dp2)]))
        self.assertEqual(self.ext3, CRLDistributionPoints([DistributionPoint(self.dp3)]))
        self.assertEqual(self.ext4, CRLDistributionPoints([DistributionPoint(self.dp4)]))

    def test_getitem(self):
        self.assertEqual(self.ext1[0], DistributionPoint(self.dp1))
        self.assertEqual(self.ext2[0], DistributionPoint(self.dp2))
        self.assertEqual(self.ext5[0], DistributionPoint(self.dp2))
        self.assertEqual(self.ext5[1], DistributionPoint(self.dp4))

        with self.assertRaisesRegex(IndexError, '^list index out of range$'):
            self.ext5[2]

    def test_getitem_slices(self):
        self.assertEqual(self.ext1[0:], [DistributionPoint(self.dp1)])
        self.assertEqual(self.ext1[1:], [])
        self.assertEqual(self.ext1[2:], [])
        self.assertEqual(self.ext5[0:], [DistributionPoint(self.dp2), DistributionPoint(self.dp4)])

    def test_hash(self):
        self.assertEqual(hash(self.ext1), hash(self.ext1))
        self.assertEqual(hash(self.ext2), hash(self.ext2))
        self.assertEqual(hash(self.ext3), hash(self.ext3))
        self.assertEqual(hash(self.ext4), hash(self.ext4))
        self.assertEqual(hash(self.ext5), hash(self.ext5))

        self.assertEqual(hash(self.ext1), hash(CRLDistributionPoints(self.x1)))
        self.assertEqual(hash(self.ext2), hash(CRLDistributionPoints(self.x2)))
        self.assertEqual(hash(self.ext3), hash(CRLDistributionPoints(self.x3)))
        self.assertEqual(hash(self.ext4), hash(CRLDistributionPoints(self.x4)))
        self.assertEqual(hash(self.ext5), hash(CRLDistributionPoints(self.x5)))

        self.assertNotEqual(hash(self.ext1), hash(self.ext2))
        self.assertNotEqual(hash(self.ext1), hash(self.ext3))
        self.assertNotEqual(hash(self.ext1), hash(self.ext4))
        self.assertNotEqual(hash(self.ext1), hash(self.ext5))
        self.assertNotEqual(hash(self.ext2), hash(self.ext3))
        self.assertNotEqual(hash(self.ext2), hash(self.ext4))
        self.assertNotEqual(hash(self.ext2), hash(self.ext5))
        self.assertNotEqual(hash(self.ext3), hash(self.ext4))
        self.assertNotEqual(hash(self.ext3), hash(self.ext5))

    def test_in(self):
        self.assertIn(self.s1, self.ext1)
        self.assertIn(self.s2, self.ext2)
        self.assertIn(self.s3, self.ext3)
        self.assertIn(self.s4, self.ext4)
        self.assertIn(self.s2, self.ext5)
        self.assertIn(self.s4, self.ext5)

        self.assertIn(self.dp1, self.ext1)
        self.assertIn(self.dp2, self.ext2)
        self.assertIn(self.dp3, self.ext3)
        self.assertIn(self.dp4, self.ext4)
        self.assertIn(self.dp2, self.ext5)
        self.assertIn(self.dp4, self.ext5)

    def test_insert(self):
        self.ext1.insert(0, self.dp2)
        self.assertEqual(self.ext1.serialize(), {'critical': False, 'value': [self.s2, self.s1]})
        self.ext1.insert(1, self.s3)
        self.assertEqual(self.ext1.serialize(), {'critical': False, 'value': [self.s2, self.s3, self.s1]})

    def test_len(self):
        self.assertEqual(len(self.ext1), 1)
        self.assertEqual(len(self.ext2), 1)
        self.assertEqual(len(self.ext3), 1)
        self.assertEqual(len(self.ext4), 1)
        self.assertEqual(len(self.ext5), 2)

    def test_ne(self):
        self.assertNotEqual(self.ext1, self.ext2)
        self.assertNotEqual(self.ext2, self.ext3)
        self.assertNotEqual(self.ext3, self.ext4)
        self.assertNotEqual(self.ext4, self.ext5)
        self.assertNotEqual(self.ext1, self.ext5)

    def test_not_in(self):
        self.assertNotIn(self.s2, self.ext1)
        self.assertNotIn(self.s3, self.ext2)
        self.assertNotIn(self.dp2, self.ext1)
        self.assertNotIn(self.dp3, self.ext4)

    def test_pop(self):
        ext = CRLDistributionPoints({'value': [self.dp1, self.dp2, self.dp3]})
        self.assertEqual(ext.pop(), DistributionPoint(self.dp3))
        self.assertEqual(ext.serialize(), {'critical': False, 'value': [self.s1, self.s2]})

        self.assertEqual(ext.pop(0), DistributionPoint(self.dp1))
        self.assertEqual(ext.serialize(), {'critical': False, 'value': [self.s2]})

        with self.assertRaisesRegex(IndexError, '^pop index out of range'):
            ext.pop(3)

    def test_remove(self):
        ext = CRLDistributionPoints({'value': [self.dp1, self.dp2, self.dp3]})
        self.assertEqual(ext.serialize(), {'critical': False, 'value': [self.s1, self.s2, self.s3]})

        ext.remove(self.dp2)
        self.assertEqual(ext.serialize(), {'critical': False, 'value': [self.s1, self.s3]})

        ext.remove(self.s3)
        self.assertEqual(ext.serialize(), {'critical': False, 'value': [self.s1]})

    def test_repr(self):
        if six.PY3:
            self.assertEqual(
                repr(self.ext1),
                "<CRLDistributionPoints: [<DistributionPoint: full_name=['URI:http://ca.example.com/crl']>], "
                "critical=False>"
            )
            self.assertEqual(
                repr(self.ext2),
                "<CRLDistributionPoints: [<DistributionPoint: full_name=['URI:http://ca.example.com/crl', "
                "'dirname:/C=AT']>], critical=False>"
            )
            self.assertEqual(
                repr(self.ext3),
                "<CRLDistributionPoints: [<DistributionPoint: relative_name='/CN=example.com'>], "
                "critical=False>"
            )
            self.assertEqual(
                repr(self.ext4),
                "<CRLDistributionPoints: [<DistributionPoint: full_name=['URI:http://ca.example.com/crl'], "
                "crl_issuer=['URI:http://ca.example.com/'], reasons=['ca_compromise', 'key_compromise']>], "
                "critical=False>"
            )
            self.assertEqual(
                repr(self.ext5),
                "<CRLDistributionPoints: ["
                "<DistributionPoint: full_name=['URI:http://ca.example.com/crl', 'dirname:/C=AT']>, "
                "<DistributionPoint: full_name=['URI:http://ca.example.com/crl'], "
                "crl_issuer=['URI:http://ca.example.com/'], reasons=['ca_compromise', 'key_compromise']>], "
                "critical=True>"
            )
        else:  # pragma: only py2
            self.assertEqual(
                repr(self.ext1),
                "<CRLDistributionPoints: [<DistributionPoint: full_name=[u'URI:http://ca.example.com/crl']>],"
                " critical=False>"
            )
            self.assertEqual(
                repr(self.ext2),
                "<CRLDistributionPoints: [<DistributionPoint: full_name=[u'URI:http://ca.example.com/crl', "
                "u'dirname:/C=AT']>], critical=False>"
            )
            self.assertEqual(
                repr(self.ext3),
                "<CRLDistributionPoints: [<DistributionPoint: relative_name='/CN=example.com'>], "
                "critical=False>"
            )
            self.assertEqual(
                repr(self.ext4),
                "<CRLDistributionPoints: [<DistributionPoint: full_name=[u'URI:http://ca.example.com/crl'], "
                "crl_issuer=[u'URI:http://ca.example.com/'], "
                "reasons=['ca_compromise', 'key_compromise']>], critical=False>"
            )
            self.assertEqual(
                repr(self.ext5),
                "<CRLDistributionPoints: [<DistributionPoint: "
                "full_name=[u'URI:http://ca.example.com/crl', u'dirname:/C=AT']>, "
                "<DistributionPoint: full_name=[u'URI:http://ca.example.com/crl'], "
                "crl_issuer=[u'URI:http://ca.example.com/'], reasons=['ca_compromise', 'key_compromise']>], "
                "critical=True>"
            )

    def test_serialize(self):
        self.assertEqual(self.ext1.serialize(), {'critical': False, 'value': [self.s1]})
        self.assertEqual(self.ext2.serialize(), {'critical': False, 'value': [self.s2]})
        self.assertEqual(self.ext3.serialize(), {'critical': False, 'value': [self.s3]})
        self.assertEqual(self.ext4.serialize(), {'critical': False, 'value': [self.s4]})
        self.assertEqual(self.ext5.serialize(), {'critical': True, 'value': [self.s2, self.s4]})

    def test_setitem(self):
        self.ext1[0] = self.s2
        self.assertEqual(self.ext1, self.ext2)
        self.ext1[0] = self.s3
        self.assertEqual(self.ext1, self.ext3)
        self.ext1[0] = self.dp4
        self.assertEqual(self.ext1, self.ext4)

        with self.assertRaisesRegex(IndexError, r'^list assignment index out of range$'):
            self.ext1[1] = self.dp4

    def test_setitem_slices(self):
        expected = CRLDistributionPoints({'value': [self.dp1, self.dp2, self.dp3]})
        self.ext1[1:] = [self.dp2, self.dp3]
        self.assertEqual(self.ext1, expected)
        self.ext1[1:] = [self.s2, self.s3]
        self.assertEqual(self.ext1, expected)

    def test_str(self):
        if six.PY3:
            self.assertEqual(
                str(self.ext1),
                "CRLDistributionPoints([DistributionPoint(full_name=['URI:http://ca.example.com/crl'])], "
                "critical=False)"
            )
            self.assertEqual(
                str(self.ext2),
                "CRLDistributionPoints([DistributionPoint("
                "full_name=['URI:http://ca.example.com/crl', 'dirname:/C=AT'])], critical=False)"
            )
            self.assertEqual(
                str(self.ext3),
                "CRLDistributionPoints([DistributionPoint(relative_name='/CN=example.com')], critical=False)"
            )
            self.assertEqual(
                str(self.ext4),
                "CRLDistributionPoints([DistributionPoint(full_name=['URI:http://ca.example.com/crl'], "
                "crl_issuer=['URI:http://ca.example.com/'], reasons=['ca_compromise', 'key_compromise'])], "
                "critical=False)"
            )
            self.assertEqual(
                str(self.ext5),
                "CRLDistributionPoints([DistributionPoint("
                "full_name=['URI:http://ca.example.com/crl', 'dirname:/C=AT']), "
                "DistributionPoint(full_name=['URI:http://ca.example.com/crl'], "
                "crl_issuer=['URI:http://ca.example.com/'], "
                "reasons=['ca_compromise', 'key_compromise'])], critical=True)"
            )
        else:  # pragma: only py2
            self.assertEqual(
                str(self.ext1),
                "CRLDistributionPoints([DistributionPoint(full_name=[u'URI:http://ca.example.com/crl'])], "
                "critical=False)"
            )
            self.assertEqual(
                str(self.ext2),
                "CRLDistributionPoints([DistributionPoint("
                "full_name=[u'URI:http://ca.example.com/crl', u'dirname:/C=AT'])], critical=False)"
            )
            self.assertEqual(
                str(self.ext3),
                "CRLDistributionPoints([DistributionPoint(relative_name='/CN=example.com')], critical=False)"
            )
            self.assertEqual(
                str(self.ext4),
                "CRLDistributionPoints([DistributionPoint(full_name=[u'URI:http://ca.example.com/crl'], "
                "crl_issuer=[u'URI:http://ca.example.com/'], "
                "reasons=['ca_compromise', 'key_compromise'])], critical=False)"
            )
            self.assertEqual(
                str(self.ext5),
                "CRLDistributionPoints([DistributionPoint("
                "full_name=[u'URI:http://ca.example.com/crl', u'dirname:/C=AT']), "
                "DistributionPoint(full_name=[u'URI:http://ca.example.com/crl'], "
                "crl_issuer=[u'URI:http://ca.example.com/'], "
                "reasons=['ca_compromise', 'key_compromise'])], critical=True)"
            )


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

    def test_hash(self):
        ext1 = KeyUsage('critical,cRLSign,keyCertSign')
        ext2 = KeyUsage('cRLSign,keyCertSign')
        ext3 = KeyUsage('cRLSign,keyCertSign,keyEncipherment')

        self.assertEqual(hash(ext1), hash(ext1))
        self.assertEqual(hash(ext2), hash(ext2))
        self.assertEqual(hash(ext3), hash(ext3))

        self.assertNotEqual(hash(ext1), hash(ext2))
        self.assertNotEqual(hash(ext1), hash(ext3))
        self.assertNotEqual(hash(ext2), hash(ext3))

    def test_eq(self):
        self.assertEqual(KeyUsage('cRLSign'), KeyUsage('cRLSign'))
        self.assertEqual(KeyUsage('cRLSign,keyCertSign'), KeyUsage('cRLSign,keyCertSign'))
        self.assertEqual(KeyUsage('cRLSign,keyCertSign'), KeyUsage('keyCertSign,cRLSign'))

        self.assertEqual(KeyUsage('critical,cRLSign'), KeyUsage('critical,cRLSign'))
        self.assertEqual(KeyUsage('critical,cRLSign,keyCertSign'), KeyUsage('critical,cRLSign,keyCertSign'))
        self.assertEqual(KeyUsage('critical,cRLSign,keyCertSign'), KeyUsage('critical,keyCertSign,cRLSign'))

    def test_ne(self):
        self.assertNotEqual(KeyUsage('cRLSign'), KeyUsage('keyCertSign'))
        self.assertNotEqual(KeyUsage('cRLSign'), KeyUsage('critical,cRLSign'))
        self.assertNotEqual(KeyUsage('cRLSign'), 10)

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

    def test_hash(self):
        ext1 = ExtendedKeyUsage('critical,serverAuth')
        ext2 = ExtendedKeyUsage('serverAuth')
        ext3 = ExtendedKeyUsage('serverAuth,clientAuth')

        self.assertEqual(hash(ext1), hash(ext1))
        self.assertEqual(hash(ext2), hash(ext2))
        self.assertEqual(hash(ext3), hash(ext3))

        self.assertNotEqual(hash(ext1), hash(ext2))
        self.assertNotEqual(hash(ext1), hash(ext3))
        self.assertNotEqual(hash(ext2), hash(ext3))

    def test_eq(self):
        self.assertEqual(ExtendedKeyUsage('serverAuth'), ExtendedKeyUsage('serverAuth'))
        self.assertEqual(ExtendedKeyUsage('serverAuth,clientAuth'), ExtendedKeyUsage('serverAuth,clientAuth'))
        self.assertEqual(ExtendedKeyUsage('serverAuth,clientAuth'), ExtendedKeyUsage('clientAuth,serverAuth'))

        self.assertEqual(ExtendedKeyUsage('critical,serverAuth'), ExtendedKeyUsage('critical,serverAuth'))
        self.assertEqual(ExtendedKeyUsage('critical,serverAuth,clientAuth'),
                         ExtendedKeyUsage('critical,serverAuth,clientAuth'))
        self.assertEqual(ExtendedKeyUsage('critical,serverAuth,clientAuth'),
                         ExtendedKeyUsage('critical,clientAuth,serverAuth'))

    def test_ne(self):
        self.assertNotEqual(ExtendedKeyUsage('serverAuth'), ExtendedKeyUsage('clientAuth'))
        self.assertNotEqual(ExtendedKeyUsage('serverAuth'), ExtendedKeyUsage('critical,serverAuth'))
        self.assertNotEqual(ExtendedKeyUsage('serverAuth'), 10)

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
    ext_not_critical = x509.extensions.Extension(
        oid=ExtensionOID.NAME_CONSTRAINTS, critical=False,
        value=x509.NameConstraints(permitted_subtrees=[dns('example.com')],
                                   excluded_subtrees=[dns('example.net')])
    )

    def assertEmpty(self, ext):
        self.assertEqual(ext.permitted, [])
        self.assertEqual(ext.excluded, [])
        self.assertEqual(ext, NameConstraints([[], []]))
        self.assertFalse(bool(ext))
        self.assertTrue(ext.critical)
        self.assertEqual(ext.as_extension(), self.ext_empty)

    def assertPermitted(self, ext):
        self.assertEqual(ext.permitted, [dns('example.com')])
        self.assertEqual(ext.excluded, [])
        self.assertEqual(ext, NameConstraints([['example.com'], []]))
        self.assertTrue(bool(ext))
        self.assertTrue(ext.critical)
        self.assertEqual(ext.as_extension(), self.ext_permitted)

    def assertExcluded(self, ext):
        self.assertEqual(ext.permitted, [])
        self.assertEqual(ext.excluded, [dns('example.com')])
        self.assertEqual(ext, NameConstraints([[], ['example.com']]))
        self.assertTrue(bool(ext))
        self.assertTrue(ext.critical)
        self.assertEqual(ext.as_extension(), self.ext_excluded)

    def assertBoth(self, ext):
        self.assertEqual(ext.permitted, [dns('example.com')])
        self.assertEqual(ext.excluded, [dns('example.net')])
        self.assertEqual(ext, NameConstraints([['example.com'], ['example.net']]))
        self.assertTrue(bool(ext))
        self.assertEqual(ext.as_extension(), self.ext_both)
        self.assertTrue(ext.critical)

    def test_from_list(self):
        self.assertEmpty(NameConstraints([[], []]))
        self.assertPermitted(NameConstraints([['example.com'], []]))
        self.assertExcluded(NameConstraints([[], ['example.com']]))
        self.assertBoth(NameConstraints([['example.com'], ['example.net']]))

        # same thing again but with GeneralName instances
        self.assertPermitted(NameConstraints([[dns('example.com')], []]))
        self.assertExcluded(NameConstraints([[], [dns('example.com')]]))
        self.assertBoth(NameConstraints([[dns('example.com')], [dns('example.net')]]))

    def test_from_dict(self):
        self.assertEmpty(NameConstraints({}))
        self.assertEmpty(NameConstraints({'value': {}}))
        self.assertEmpty(NameConstraints({'value': {'permitted': [], 'excluded': []}}))

        self.assertPermitted(NameConstraints({'value': {'permitted': ['example.com']}}))
        self.assertPermitted(NameConstraints({'value': {'permitted': ['example.com'], 'excluded': []}}))
        self.assertPermitted(NameConstraints({'value': {'permitted': [dns('example.com')]}}))
        self.assertPermitted(NameConstraints({'value': {'permitted': [dns('example.com')], 'excluded': []}}))

        self.assertExcluded(NameConstraints({'value': {'excluded': ['example.com']}}))
        self.assertExcluded(NameConstraints({'value': {'excluded': ['example.com'], 'permitted': []}}))
        self.assertExcluded(NameConstraints({'value': {'excluded': [dns('example.com')]}}))
        self.assertExcluded(NameConstraints({'value': {'excluded': [dns('example.com')], 'permitted': []}}))

        self.assertBoth(NameConstraints({'value': {'permitted': ['example.com'],
                                                   'excluded': ['example.net']}}))
        self.assertBoth(NameConstraints({'value': {'permitted': [dns('example.com')],
                                                   'excluded': [dns('example.net')]}}))

    def test_from_extension(self):
        self.assertEmpty(NameConstraints(self.ext_empty))
        self.assertPermitted(NameConstraints(self.ext_permitted))
        self.assertExcluded(NameConstraints(self.ext_excluded))
        self.assertBoth(NameConstraints(self.ext_both))

    def test_hash(self):
        ext1 = NameConstraints([['example.com'], []])
        ext2 = NameConstraints([['example.com'], ['example.net']])
        ext3 = NameConstraints([[], ['example.net']])

        self.assertEqual(hash(ext1), hash(ext1))
        self.assertEqual(hash(ext2), hash(ext2))
        self.assertEqual(hash(ext3), hash(ext3))

        self.assertNotEqual(hash(ext1), hash(ext2))
        self.assertNotEqual(hash(ext1), hash(ext3))
        self.assertNotEqual(hash(ext2), hash(ext3))

    def test_as_str(self):  # test various string conversion methods
        ext = NameConstraints(self.ext_empty)
        self.assertEqual(str(ext), "NameConstraints(permitted=[], excluded=[], critical=True)")
        self.assertEqual(repr(ext), "<NameConstraints: permitted=[], excluded=[], critical=True>")
        self.assertEqual(ext.as_text(), "")

        ext = NameConstraints(self.ext_permitted)
        self.assertEqual(str(ext),
                         "NameConstraints(permitted=['DNS:example.com'], excluded=[], critical=True)")
        self.assertEqual(repr(ext),
                         "<NameConstraints: permitted=['DNS:example.com'], excluded=[], critical=True>")
        self.assertEqual(ext.as_text(), "Permitted:\n  * DNS:example.com\n")

        ext = NameConstraints(self.ext_excluded)
        self.assertEqual(str(ext),
                         "NameConstraints(permitted=[], excluded=['DNS:example.com'], critical=True)")
        self.assertEqual(repr(ext),
                         "<NameConstraints: permitted=[], excluded=['DNS:example.com'], critical=True>")
        self.assertEqual(ext.as_text(), "Excluded:\n  * DNS:example.com\n")

        ext = NameConstraints(self.ext_both)
        self.assertEqual(
            str(ext),
            "NameConstraints(permitted=['DNS:example.com'], excluded=['DNS:example.net'], critical=True)")
        self.assertEqual(
            repr(ext),
            "<NameConstraints: permitted=['DNS:example.com'], excluded=['DNS:example.net'], critical=True>")
        self.assertEqual(ext.as_text(), """Permitted:
  * DNS:example.com
Excluded:
  * DNS:example.net
""")

    def test_error(self):
        with self.assertRaisesRegex(ValueError, r'^Value is of unsupported type NoneType$'):
            NameConstraints(None)
        with self.assertRaisesRegex(ValueError, r'^Value is of unsupported type bool$'):
            NameConstraints(False)

    def test_serialize(self):
        empty = NameConstraints(self.ext_empty)
        permitted = NameConstraints(self.ext_permitted)
        excluded = NameConstraints(self.ext_excluded)
        both = NameConstraints(self.ext_both)
        not_critical = NameConstraints(self.ext_not_critical)

        self.assertEqual(NameConstraints(empty.serialize()), empty)
        self.assertEqual(NameConstraints(permitted.serialize()), permitted)
        self.assertEqual(NameConstraints(excluded.serialize()), excluded)
        self.assertEqual(NameConstraints(both.serialize()), both)
        self.assertEqual(NameConstraints(not_critical.serialize()), not_critical)


class OCSPNoCheckTestCase(ExtensionTestMixin, TestCase):
    # x509.OCSPNoCheck does not compare as equal:
    #   https://github.com/pyca/cryptography/issues/4818
    @unittest.skipUnless(x509.OCSPNoCheck() == x509.OCSPNoCheck(),
                         'Extensions compare as equal.')
    def test_as_extension(self):
        ext1 = x509.extensions.Extension(oid=ExtensionOID.OCSP_NO_CHECK, critical=True,
                                         value=x509.OCSPNoCheck())
        ext2 = x509.extensions.Extension(oid=ExtensionOID.OCSP_NO_CHECK, critical=False,
                                         value=x509.OCSPNoCheck())

        self.assertEqual(OCSPNoCheck({}).as_extension(), ext2)
        self.assertEqual(OCSPNoCheck({'critical': False}).as_extension(), ext2)
        self.assertEqual(OCSPNoCheck({'critical': True}).as_extension(), ext1)

        self.assertEqual(OCSPNoCheck({}).as_extension(), OCSPNoCheck(ext2).as_extension())
        self.assertEqual(OCSPNoCheck({'critical': False}).as_extension(), OCSPNoCheck(ext2).as_extension())
        self.assertEqual(OCSPNoCheck({'critical': True}).as_extension(), OCSPNoCheck(ext1).as_extension())

    def test_as_text(self):
        ext1 = OCSPNoCheck()
        ext2 = OCSPNoCheck({'critical': True})
        self.assertEqual(ext1.as_text(), "OCSPNoCheck")
        self.assertEqual(ext2.as_text(), "OCSPNoCheck")

    def test_eq(self):
        ext1 = x509.extensions.Extension(oid=ExtensionOID.OCSP_NO_CHECK, critical=True, value=None)
        ext2 = x509.extensions.Extension(oid=ExtensionOID.OCSP_NO_CHECK, critical=False, value=None)

        self.assertEqual(OCSPNoCheck(), OCSPNoCheck())
        self.assertEqual(OCSPNoCheck(ext1), OCSPNoCheck(ext1))
        self.assertEqual(OCSPNoCheck({'critical': True}), OCSPNoCheck({'critical': True}))

        self.assertEqual(OCSPNoCheck(), OCSPNoCheck(ext2))
        self.assertEqual(OCSPNoCheck(), OCSPNoCheck({'critical': False}))

    def test_extension_type(self):
        self.assertIsInstance(OCSPNoCheck().extension_type, x509.OCSPNoCheck)
        self.assertIsInstance(OCSPNoCheck({'critical': True}).extension_type, x509.OCSPNoCheck)
        self.assertIsInstance(OCSPNoCheck({'critical': False}).extension_type, x509.OCSPNoCheck)

    def test_ne(self):
        ext1 = x509.extensions.Extension(oid=ExtensionOID.OCSP_NO_CHECK, critical=True, value=None)
        ext2 = x509.extensions.Extension(oid=ExtensionOID.OCSP_NO_CHECK, critical=False, value=None)

        self.assertNotEqual(OCSPNoCheck(ext1), OCSPNoCheck(ext2))
        self.assertNotEqual(OCSPNoCheck({'critical': True}), OCSPNoCheck({'critical': False}))

    def test_hash(self):
        ext1 = OCSPNoCheck()
        ext2 = OCSPNoCheck({'critical': True})

        self.assertEqual(hash(ext1), hash(ext1))
        self.assertEqual(hash(ext2), hash(ext2))
        self.assertNotEqual(hash(ext1), hash(ext2))

    def test_for_builder(self):
        # NOTE: x509.OCSPNoCheck instances do not compare as equal
        ext1 = OCSPNoCheck({'critical': True})
        ext2 = OCSPNoCheck({'critical': False})
        val1 = ext1.for_builder()
        val2 = ext2.for_builder()
        inst1 = val1.pop('extension')
        inst2 = val2.pop('extension')

        self.assertIsInstance(inst1, x509.OCSPNoCheck)
        self.assertIsInstance(inst2, x509.OCSPNoCheck)
        self.assertEqual(val1, {'critical': True})
        self.assertEqual(val2, {'critical': False})

    def test_from_extension(self):
        ext = OCSPNoCheck(x509.extensions.Extension(
            oid=ExtensionOID.OCSP_NO_CHECK, critical=True, value=None))
        self.assertTrue(ext.critical)

        ext = OCSPNoCheck(x509.extensions.Extension(
            oid=ExtensionOID.OCSP_NO_CHECK, critical=False, value=None))
        self.assertFalse(ext.critical)

    def test_from_dict(self):
        self.assertFalse(OCSPNoCheck({}).critical)
        self.assertTrue(OCSPNoCheck({'critical': True}).critical)
        self.assertTrue(OCSPNoCheck({'critical': True, 'foo': 'bar'}).critical)
        self.assertFalse(OCSPNoCheck({'critical': False}).critical)
        self.assertFalse(OCSPNoCheck({'critical': False, 'foo': 'bar'}).critical)

    def test_from_str(self):
        with self.assertRaises(NotImplementedError):
            OCSPNoCheck('foobar')

    def test_str(self):
        ext1 = OCSPNoCheck({'critical': True})
        ext2 = OCSPNoCheck({'critical': False})

        self.assertEqual(str(ext1), 'OCSPNoCheck/critical')
        self.assertEqual(str(ext2), 'OCSPNoCheck')

    def test_repr(self):
        ext1 = OCSPNoCheck({'critical': True})
        ext2 = OCSPNoCheck({'critical': False})

        self.assertEqual(repr(ext1), '<OCSPNoCheck: critical=True>')
        self.assertEqual(repr(ext2), '<OCSPNoCheck: critical=False>')

    def test_serialize(self):
        ext1 = OCSPNoCheck({'critical': True})
        ext2 = OCSPNoCheck({'critical': False})

        self.assertEqual(ext1.serialize(), ext1.serialize())
        self.assertNotEqual(ext1.serialize(), ext2.serialize())
        self.assertEqual(ext1, OCSPNoCheck(ext1.serialize()))
        self.assertEqual(ext2, OCSPNoCheck(ext2.serialize()))


@unittest.skipUnless(ca_settings.CRYPTOGRAPHY_HAS_PRECERT_POISON,
                     "This version of cryptography does not support the PrecertPoison extension.")
class PrecertPoisonTestCase(ExtensionTestMixin, TestCase):
    # PrecertPoison does not compare as equal:
    #   https://github.com/pyca/cryptography/issues/4818
    @unittest.skipUnless(hasattr(x509, 'PrecertPoison') and x509.PrecertPoison() == x509.PrecertPoison(),
                         'Extensions compare as equal.')
    def test_as_extension(self):
        ext1 = x509.extensions.Extension(oid=ExtensionOID.PRECERT_POISON, critical=True, value=None)

        self.assertEqual(PrecertPoison({}).as_extension(), PrecertPoison(ext1).as_extension())
        self.assertEqual(PrecertPoison({'critical': True}).as_extension(), PrecertPoison(ext1).as_extension())

    def test_as_text(self):
        self.assertEqual(PrecertPoison().as_text(), "PrecertPoison")

    def test_eq(self):
        ext1 = x509.extensions.Extension(oid=ExtensionOID.PRECERT_POISON, critical=True, value=None)

        self.assertEqual(PrecertPoison(), PrecertPoison())
        self.assertEqual(PrecertPoison(), PrecertPoison(ext1))
        self.assertEqual(PrecertPoison(ext1), PrecertPoison(ext1))
        self.assertEqual(PrecertPoison({'critical': True}), PrecertPoison({'critical': True}))
        self.assertEqual(PrecertPoison(), PrecertPoison({'critical': True}))

    def test_extension_type(self):
        self.assertIsInstance(PrecertPoison().extension_type, x509.PrecertPoison)
        self.assertIsInstance(PrecertPoison({'critical': True}).extension_type, x509.PrecertPoison)

    def test_for_builder(self):
        # NOTE: x509.PrecertPoison instances do not compare as equal
        ext1 = PrecertPoison()
        ext2 = PrecertPoison({'critical': True})
        val1 = ext1.for_builder()
        val2 = ext2.for_builder()
        inst1 = val1.pop('extension')
        inst2 = val2.pop('extension')

        self.assertIsInstance(inst1, x509.PrecertPoison)
        self.assertIsInstance(inst2, x509.PrecertPoison)
        self.assertEqual(val1, {'critical': True})
        self.assertEqual(val2, {'critical': True})

    def test_hash(self):
        ext1 = PrecertPoison()
        ext2 = PrecertPoison({'critical': True})

        self.assertEqual(hash(ext1), hash(ext1))
        self.assertEqual(hash(ext2), hash(ext2))
        self.assertEqual(hash(ext1), hash(ext2))

    def test_ne(self):
        # PrecertPoison is always critical and has no value, thus all instances compare as equal (and there
        # is nothing we could test)
        pass

    def test_from_extension(self):
        ext = PrecertPoison(x509.extensions.Extension(
            oid=ExtensionOID.PRECERT_POISON, critical=True, value=None))
        self.assertTrue(ext.critical)

    def test_from_dict(self):
        self.assertTrue(PrecertPoison({}).critical)
        self.assertTrue(PrecertPoison({'critical': True}).critical)
        self.assertTrue(PrecertPoison({'critical': True, 'foo': 'bar'}).critical)

    def test_from_str(self):
        with self.assertRaises(NotImplementedError):
            PrecertPoison('foobar')

    def test_str(self):
        self.assertEqual(str(PrecertPoison({'critical': True})), 'PrecertPoison/critical')

    def test_repr(self):
        self.assertEqual(repr(PrecertPoison({'critical': True})), '<PrecertPoison: critical=True>')

    def test_serialize(self):
        ext1 = PrecertPoison()
        ext2 = PrecertPoison({'critical': True})

        self.assertEqual(ext1.serialize(), ext1.serialize())
        self.assertEqual(ext1.serialize(), ext2.serialize())
        self.assertEqual(ext1, PrecertPoison(ext1.serialize()))
        self.assertEqual(ext2, PrecertPoison(ext2.serialize()))

    def test_non_critical(self):
        ext = x509.extensions.Extension(oid=ExtensionOID.PRECERT_POISON, critical=False, value=None)

        with self.assertRaisesRegex(ValueError, '^PrecertPoison must always be marked as critical$'):
            PrecertPoison(ext)
        with self.assertRaisesRegex(ValueError, '^PrecertPoison must always be marked as critical$'):
            PrecertPoison({'critical': False})


@unittest.skipUnless(ca_settings.OPENSSL_SUPPORTS_SCT,
                     'This version of OpenSSL does not support SCTs')
class PrecertificateSignedCertificateTimestampsTestCase(
        DjangoCAWithCertTestCase):  # pragma: only cryptography>=2.4

    def setUp(self):
        super(PrecertificateSignedCertificateTimestampsTestCase, self).setUp()
        self.name1 = 'letsencrypt_x3-cert'
        self.name2 = 'comodo_ev-cert'
        cert1 = self.certs[self.name1]
        cert2 = self.certs[self.name2]

        self.x1 = cert1.x509.extensions.get_extension_for_oid(
            ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
        self.x2 = cert2.x509.extensions.get_extension_for_oid(
            ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
        self.ext1 = PrecertificateSignedCertificateTimestamps(self.x1)
        self.ext2 = PrecertificateSignedCertificateTimestamps(self.x2)
        self.data1 = certs[self.name1]['precertificate_signed_certificate_timestamps']
        self.data2 = certs[self.name2]['precertificate_signed_certificate_timestamps']

    def test_as_extension(self):
        self.assertEqual(self.ext1.as_extension(), self.x1)
        self.assertEqual(self.ext2.as_extension(), self.x2)

    def test_count(self):
        self.assertEqual(self.ext1.count(self.data1['values'][0]), 1)
        self.assertEqual(self.ext1.count(self.data2['values'][0]), 0)
        self.assertEqual(self.ext1.count(self.x1.value[0]), 1)
        self.assertEqual(self.ext1.count(self.x2.value[0]), 0)

        self.assertEqual(self.ext2.count(self.data1['values'][0]), 0)
        self.assertEqual(self.ext2.count(self.data2['values'][0]), 1)
        self.assertEqual(self.ext2.count(self.x1.value[0]), 0)
        self.assertEqual(self.ext2.count(self.x2.value[0]), 1)

    def test_del(self):
        with self.assertRaises(NotImplementedError):
            del self.ext1[0]
        with self.assertRaises(NotImplementedError):
            del self.ext2[0]

    def test_eq(self):
        self.assertEqual(self.ext1, self.ext1)
        self.assertEqual(self.ext2, self.ext2)

    def test_extend(self):
        with self.assertRaises(NotImplementedError):
            self.ext1.extend([])
        with self.assertRaises(NotImplementedError):
            self.ext2.extend([])

    def test_extension_type(self):
        self.assertEqual(self.ext1.extension_type, self.x1.value)
        self.assertEqual(self.ext2.extension_type, self.x2.value)

    def test_for_builder(self):
        self.assertEqual(self.ext1.for_builder(), {'critical': False, 'extension': self.x1.value})
        self.assertEqual(self.ext2.for_builder(), {'critical': False, 'extension': self.x2.value})

    def test_from_list(self):
        with self.assertRaises(NotImplementedError):
            PrecertificateSignedCertificateTimestamps([])

    def test_getitem(self):
        self.assertEqual(self.ext1[0], self.data1['values'][0])
        self.assertEqual(self.ext1[1], self.data1['values'][1])
        with self.assertRaises(IndexError):
            self.ext1[2]

        self.assertEqual(self.ext2[0], self.data2['values'][0])
        self.assertEqual(self.ext2[1], self.data2['values'][1])
        self.assertEqual(self.ext2[2], self.data2['values'][2])
        with self.assertRaises(IndexError):
            self.ext2[3]

    def test_getitem_slices(self):
        self.assertEqual(self.ext1[:1], self.data1['values'][:1])
        self.assertEqual(self.ext2[:2], self.data2['values'][:2])
        self.assertEqual(self.ext2[:], self.data2['values'][:])

    def test_hash(self):
        self.assertEqual(hash(self.ext1), hash(self.ext1))
        self.assertEqual(hash(self.ext2), hash(self.ext2))
        self.assertNotEqual(hash(self.ext1), hash(self.ext2))

    def test_in(self):
        for val in self.data1['values']:
            self.assertIn(val, self.ext1)
        for val in self.x1.value:
            self.assertIn(val, self.ext1)
        for val in self.data2['values']:
            self.assertIn(val, self.ext2)
        for val in self.x2.value:
            self.assertIn(val, self.ext2)

    def test_insert(self):
        with self.assertRaises(NotImplementedError):
            self.ext1.insert(0, self.data1['values'][0])
        with self.assertRaises(NotImplementedError):
            self.ext2.insert(0, self.data2['values'][0])

    def test_len(self):
        self.assertEqual(len(self.ext1), 2)
        self.assertEqual(len(self.ext2), 3)

    def test_ne(self):
        self.assertNotEqual(self.ext1, self.ext2)

    def test_not_in(self):
        self.assertNotIn(self.data1['values'][0], self.ext2)
        self.assertNotIn(self.data2['values'][0], self.ext1)

        self.assertNotIn(self.x1.value[0], self.ext2)
        self.assertNotIn(self.x2.value[0], self.ext1)

    def test_pop(self):
        with self.assertRaises(NotImplementedError):
            self.ext1.pop(self.data1['values'][0])
        with self.assertRaises(NotImplementedError):
            self.ext2.pop(self.data2['values'][0])

    def test_remove(self):
        with self.assertRaises(NotImplementedError):
            self.ext1.remove(self.data1['values'][0])
        with self.assertRaises(NotImplementedError):
            self.ext2.remove(self.data2['values'][0])

    def test_repr(self):
        if six.PY2:  # pragma: only py2
            exp1 = [{str(k): str(v) for k, v in e.items()} for e in self.data1['values']]
            exp2 = [{str(k): str(v) for k, v in e.items()} for e in self.data2['values']]
        else:
            exp1 = self.data1['values']
            exp2 = self.data2['values']

        self.assertEqual(
            repr(self.ext1),
            '<PrecertificateSignedCertificateTimestamps: %s, critical=False>' % repr(exp1))
        self.assertEqual(
            repr(self.ext2),
            '<PrecertificateSignedCertificateTimestamps: %s, critical=False>' % repr(exp2))

    def test_serialize(self):
        self.assertEqual(self.ext1.serialize(), self.data1)
        self.assertEqual(self.ext2.serialize(), self.data2)

    def test_setitem(self):
        with self.assertRaises(NotImplementedError):
            self.ext1[0] = self.data2['values'][0]
        with self.assertRaises(NotImplementedError):
            self.ext2[0] = self.data1['values'][0]

    def test_setitem_slices(self):
        with self.assertRaises(NotImplementedError):
            self.ext1[:] = self.data2
        with self.assertRaises(NotImplementedError):
            self.ext2[:] = self.data1

    def test_str(self):
        self.assertEqual(str(self.ext1), '<2 entry(s)>')
        self.assertEqual(str(self.ext2), '<3 entry(s)>')

        with self.patch_object(self.ext2, 'critical', True):
            self.assertEqual(str(self.ext2), '<3 entry(s)>/critical')


class UnknownExtensionTestCase(TestCase):
    def test_basic(self):
        unk = SubjectAlternativeName(['https://example.com']).as_extension()
        ext = UnrecognizedExtension(unk)
        self.assertEqual(ext.name, 'Unsupported extension (OID %s)' % unk.oid.dotted_string)
        self.assertEqual(ext.as_text(), 'Could not parse extension')

        name = 'my name'
        error = 'my error'
        ext = UnrecognizedExtension(unk, name=name, error=error)
        self.assertEqual(ext.name, name)
        self.assertEqual(ext.as_text(), 'Could not parse extension (%s)' % error)


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

    def test_serialize(self):
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

    def test_hash(self):
        ext1 = SubjectAlternativeName('example.com')
        ext2 = SubjectAlternativeName('critical,example.com')
        ext3 = SubjectAlternativeName('critical,example.com,example.net')

        self.assertEqual(hash(ext1), hash(ext1))
        self.assertEqual(hash(ext2), hash(ext2))
        self.assertEqual(hash(ext3), hash(ext3))

        self.assertNotEqual(hash(ext1), hash(ext2))
        self.assertNotEqual(hash(ext1), hash(ext3))
        self.assertNotEqual(hash(ext2), hash(ext3))

    def test_error(self):
        with self.assertRaisesRegex(ValueError, r'^Value is of unsupported type NoneType$'):
            SubjectAlternativeName(None)
        with self.assertRaisesRegex(ValueError, r'^Value is of unsupported type bool$'):
            SubjectAlternativeName(False)


class SubjectKeyIdentifierTestCase(ExtensionTestMixin, TestCase):
    hex1 = '33:33:33:33:33:33'
    hex2 = '44:44:44:44:44:44'
    ext = x509.Extension(
        oid=x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER, critical=False,
        value=x509.SubjectKeyIdentifier(b'333333')
    )
    ext2 = x509.Extension(
        oid=x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER, critical=False,
        value=x509.SubjectKeyIdentifier(b'DDDDDD')  # = hex2
    )

    def test_basic(self):
        ext = SubjectKeyIdentifier(self.ext)
        self.assertEqual(ext.as_text(), '33:33:33:33:33:33')
        self.assertEqual(ext.as_extension(), self.ext)

    def test_as_extension(self):
        critical_ext = x509.Extension(
            oid=x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER, critical=True,
            value=x509.SubjectKeyIdentifier(b'333333')
        )

        ext1 = SubjectKeyIdentifier(self.hex1)
        ext3 = SubjectKeyIdentifier(critical_ext)

        self.assertEqual(ext1.as_extension(), self.ext)
        self.assertEqual(ext3.as_extension(), critical_ext)
        self.assertEqual(ext3.as_extension().critical, True)

    def test_as_text(self):
        self.assertEqual(SubjectKeyIdentifier(self.hex1).as_text(), self.hex1)
        self.assertEqual(SubjectKeyIdentifier(self.hex2).as_text(), self.hex2)
        self.assertEqual(SubjectKeyIdentifier(self.ext).as_text(), self.hex1)

    def test_eq(self):
        ext1 = SubjectKeyIdentifier(self.hex1)
        ext2 = SubjectKeyIdentifier(self.hex2)
        ext3 = SubjectKeyIdentifier(self.ext)

        self.assertEqual(ext1, ext3)
        self.assertEqual(ext1, ext1)
        self.assertEqual(ext2, ext2)
        self.assertEqual(ext3, ext3)

    def test_extension_type(self):
        ext1 = SubjectKeyIdentifier(self.hex1)
        ext2 = SubjectKeyIdentifier(self.hex2)
        ext3 = SubjectKeyIdentifier(self.ext)

        self.assertEqual(ext1.extension_type, x509.SubjectKeyIdentifier(digest=b'333333'))
        self.assertEqual(ext2.extension_type, x509.SubjectKeyIdentifier(digest=b'DDDDDD'))
        self.assertEqual(ext3.extension_type, x509.SubjectKeyIdentifier(digest=b'333333'))

    def test_for_builder(self):
        ext1 = SubjectKeyIdentifier(self.hex1)
        ext2 = SubjectKeyIdentifier(self.hex2)
        ext3 = SubjectKeyIdentifier(self.ext)
        exp1 = {'critical': False, 'extension': self.ext.value}
        exp2 = {'critical': False, 'extension': self.ext2.value}

        self.assertEqual(ext1.for_builder(), exp1)
        self.assertEqual(ext2.for_builder(), exp2)
        self.assertEqual(ext3.for_builder(), exp1)

    def test_hash(self):
        ext1 = SubjectKeyIdentifier(self.hex1)
        ext2 = SubjectKeyIdentifier(self.hex2)
        ext3 = SubjectKeyIdentifier(self.ext)

        self.assertEqual(hash(ext1), hash(ext1))
        self.assertEqual(hash(ext1), hash(ext3))
        self.assertEqual(hash(ext2), hash(ext2))
        self.assertNotEqual(hash(ext1), hash(ext2))

    def test_ne(self):
        ext1 = SubjectKeyIdentifier(self.hex1)
        ext2 = SubjectKeyIdentifier(self.hex2)
        ext3 = SubjectKeyIdentifier(self.ext)

        self.assertNotEqual(ext1, ext2)
        self.assertNotEqual(ext2, ext3)

    def test_repr(self):
        ext1 = SubjectKeyIdentifier(self.hex1)
        ext2 = SubjectKeyIdentifier(self.hex2)
        ext3 = SubjectKeyIdentifier(self.ext)

        if six.PY2:  # pragma: only py2
            self.assertEqual(repr(ext1), '<SubjectKeyIdentifier: 333333, critical=False>')
            self.assertEqual(repr(ext2), '<SubjectKeyIdentifier: DDDDDD, critical=False>')
            self.assertEqual(repr(ext3), '<SubjectKeyIdentifier: 333333, critical=False>')
        else:
            self.assertEqual(repr(ext1), '<SubjectKeyIdentifier: b\'333333\', critical=False>')
            self.assertEqual(repr(ext2), '<SubjectKeyIdentifier: b\'DDDDDD\', critical=False>')
            self.assertEqual(repr(ext3), '<SubjectKeyIdentifier: b\'333333\', critical=False>')

    def test_serialize(self):
        ext1 = SubjectKeyIdentifier(self.hex1)
        ext2 = SubjectKeyIdentifier(self.hex2)
        ext3 = SubjectKeyIdentifier(self.ext)

        self.assertEqual(ext1.serialize(), self.hex1)
        self.assertEqual(ext2.serialize(), self.hex2)
        self.assertEqual(ext3.serialize(), self.hex1)
        self.assertEqual(ext1.serialize(), SubjectKeyIdentifier(self.hex1).serialize())
        self.assertNotEqual(ext1.serialize(), ext2.serialize())

    def test_str(self):
        ext = SubjectKeyIdentifier(self.hex1)
        self.assertEqual(str(ext), self.hex1)


class TLSFeatureTestCase(TestCase):
    ext1 = TLSFeature('critical,OCSPMustStaple')
    ext2 = TLSFeature('OCSPMustStaple')
    ext3 = TLSFeature('OCSPMustStaple,MultipleCertStatusRequest')
    ext4 = TLSFeature('MultipleCertStatusRequest,OCSPMustStaple')  # reversed order

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

    def test_completeness(self):
        # make sure whe haven't forgotton any keys anywhere
        self.assertEqual(set(TLSFeature.CRYPTOGRAPHY_MAPPING.keys()),
                         set([e[0] for e in TLSFeature.CHOICES]))
        self.assertCountEqual(TLSFeature.CRYPTOGRAPHY_MAPPING.values(),
                              x509.TLSFeatureType.__members__.values())

    def test_as_extension(self):
        self.assertEqual(self.ext1.as_extension(), x509.extensions.Extension(
            oid=ExtensionOID.TLS_FEATURE,
            critical=True,
            value=x509.TLSFeature(features=[TLSFeatureType.status_request])
        ))
        self.assertEqual(self.ext2.as_extension(), x509.extensions.Extension(
            oid=ExtensionOID.TLS_FEATURE,
            critical=False,
            value=x509.TLSFeature(features=[TLSFeatureType.status_request])
        ))

    def test_count(self):
        self.assertEqual(self.ext1.count('OCSPMustStaple'), 1)
        self.assertEqual(self.ext2.count('OCSPMustStaple'), 1)
        self.assertEqual(self.ext3.count('OCSPMustStaple'), 1)
        self.assertEqual(self.ext4.count('OCSPMustStaple'), 1)

        self.assertEqual(self.ext1.count(TLSFeatureType.status_request), 1)
        self.assertEqual(self.ext2.count(TLSFeatureType.status_request), 1)
        self.assertEqual(self.ext3.count(TLSFeatureType.status_request), 1)
        self.assertEqual(self.ext4.count(TLSFeatureType.status_request), 1)

        self.assertEqual(self.ext1.count('MultipleCertStatusRequest'), 0)
        self.assertEqual(self.ext2.count('MultipleCertStatusRequest'), 0)
        self.assertEqual(self.ext3.count('MultipleCertStatusRequest'), 1)
        self.assertEqual(self.ext4.count('MultipleCertStatusRequest'), 1)

        self.assertEqual(self.ext1.count(TLSFeatureType.status_request_v2), 0)
        self.assertEqual(self.ext2.count(TLSFeatureType.status_request_v2), 0)
        self.assertEqual(self.ext3.count(TLSFeatureType.status_request_v2), 1)
        self.assertEqual(self.ext4.count(TLSFeatureType.status_request_v2), 1)

        with self.assertRaisesRegex(ValueError, r'^Unknown value: foo$'):
            self.assertEqual(self.ext1.count('foo'), 0)

    def test_eq(self):
        self.assertEqual(self.ext1, TLSFeature('critical,OCSPMustStaple'))
        self.assertEqual(self.ext2, TLSFeature('OCSPMustStaple'))
        self.assertEqual(self.ext3, TLSFeature('OCSPMustStaple,MultipleCertStatusRequest'))

    def test_eq_order(self):
        self.assertEqual(self.ext3, self.ext4),
        self.assertEqual(TLSFeature('critical,OCSPMustStaple,MultipleCertStatusRequest'),
                         TLSFeature('critical,MultipleCertStatusRequest,OCSPMustStaple'))

    def test_extension_type(self):
        self.assertEqual(self.ext1.extension_type, x509.TLSFeature(features=[TLSFeatureType.status_request]))
        self.assertEqual(self.ext3.extension_type, x509.TLSFeature(features=[
            TLSFeatureType.status_request,
            TLSFeatureType.status_request_v2,
        ]))
        self.assertEqual(self.ext4.extension_type, x509.TLSFeature(features=[
            TLSFeatureType.status_request,
            TLSFeatureType.status_request_v2,
        ]))

    def test_for_builder(self):
        val1 = x509.TLSFeature(features=[TLSFeatureType.status_request])
        val2 = x509.TLSFeature(features=[
            TLSFeatureType.status_request,
            TLSFeatureType.status_request_v2,
        ])

        self.assertEqual(self.ext1.for_builder(), {
            'critical': True,
            'extension': val1,
        })
        self.assertEqual(self.ext2.for_builder(), {
            'critical': False,
            'extension': val1,
        })
        self.assertEqual(self.ext3.for_builder(), {
            'critical': False,
            'extension': val2,
        })
        self.assertEqual(self.ext4.for_builder(), {
            'critical': False,
            'extension': val2,
        })

    def test_from_list(self):
        self.assertEqual(TLSFeature(['OCSPMustStaple']), self.ext2)
        self.assertEqual(TLSFeature(['OCSPMustStaple', 'MultipleCertStatusRequest']), self.ext3)
        self.assertEqual(TLSFeature(['OCSPMustStaple', 'MultipleCertStatusRequest']), self.ext4)
        self.assertEqual(TLSFeature(['MultipleCertStatusRequest', 'OCSPMustStaple']), self.ext4)

    def test_hash(self):
        self.assertEqual(hash(self.ext1), hash(self.ext1))
        self.assertEqual(hash(self.ext2), hash(self.ext2))
        self.assertEqual(hash(self.ext3), hash(self.ext3))

        self.assertNotEqual(hash(self.ext1), hash(self.ext2))
        self.assertNotEqual(hash(self.ext1), hash(self.ext3))
        self.assertNotEqual(hash(self.ext2), hash(self.ext3))

    def test_hash_order(self):
        self.assertEqual(hash(self.ext3), hash(self.ext4))

    def test_in(self):
        self.assertIn('OCSPMustStaple', self.ext1)
        self.assertIn('OCSPMustStaple', self.ext2)
        self.assertIn('OCSPMustStaple', self.ext3)
        self.assertIn('OCSPMustStaple', self.ext4)
        self.assertIn('MultipleCertStatusRequest', self.ext3)
        self.assertIn('MultipleCertStatusRequest', self.ext4)

        self.assertIn(TLSFeatureType.status_request, self.ext1)
        self.assertIn(TLSFeatureType.status_request, self.ext2)
        self.assertIn(TLSFeatureType.status_request_v2, self.ext3)

    def test_len(self):
        self.assertEqual(len(self.ext1), 1)
        self.assertEqual(len(self.ext2), 1)
        self.assertEqual(len(self.ext3), 2)
        self.assertEqual(len(self.ext4), 2)

    def test_ne(self):
        self.assertNotEqual(self.ext1, self.ext2)
        self.assertNotEqual(self.ext1, self.ext3)
        self.assertNotEqual(self.ext2, self.ext3)
        self.assertNotEqual(self.ext1, 10)

    def test_not_in(self):
        self.assertNotIn('MultipleCertStatusRequest', self.ext1)
        self.assertNotIn('MultipleCertStatusRequest', self.ext2)
        self.assertNotIn(TLSFeatureType.status_request_v2, self.ext1)
        self.assertNotIn(TLSFeatureType.status_request_v2, self.ext2)

    def test_repr(self):
        self.assertEqual(repr(self.ext1), "<TLSFeature: ['OCSPMustStaple'], critical=True>")
        self.assertEqual(repr(self.ext2), "<TLSFeature: ['OCSPMustStaple'], critical=False>")

        # Make sure that different order results in the same output
        self.assertEqual(repr(self.ext3),
                         "<TLSFeature: ['MultipleCertStatusRequest', 'OCSPMustStaple'], critical=False>")
        self.assertEqual(repr(self.ext4),
                         "<TLSFeature: ['MultipleCertStatusRequest', 'OCSPMustStaple'], critical=False>")

    def test_serialize(self):
        self.assertEqual(self.ext1.serialize(), 'critical,OCSPMustStaple')
        self.assertEqual(self.ext2.serialize(), 'OCSPMustStaple')
        self.assertEqual(self.ext3.serialize(), 'OCSPMustStaple,MultipleCertStatusRequest')
        self.assertEqual(TLSFeature(self.ext1.serialize()), self.ext1)
        self.assertEqual(TLSFeature(self.ext2.serialize()), self.ext2)
        self.assertEqual(TLSFeature(self.ext3.serialize()), self.ext3)
        self.assertNotEqual(TLSFeature(self.ext1.serialize()), self.ext2)

    def test_str(self):
        exp_order = 'MultipleCertStatusRequest,OCSPMustStaple'
        self.assertEqual(str(self.ext1), 'OCSPMustStaple/critical')
        self.assertEqual(str(self.ext2), 'OCSPMustStaple')

        # Make sure that different order results in the same output
        self.assertEqual(str(self.ext3), exp_order)
        self.assertEqual(str(self.ext4), exp_order)

    def test_unknown_values(self):
        with self.assertRaisesRegex(ValueError, r'^Unknown value\(s\): foo$'):
            TLSFeature('foo')
        with self.assertRaisesRegex(ValueError, r'^Unknown value\(s\): foo$'):
            TLSFeature('critical,foo')

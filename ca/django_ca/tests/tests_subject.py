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

from cryptography import x509
from cryptography.x509.oid import NameOID

from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase

from ..subject import Subject
from ..subject import get_default_subject
from .base import override_settings


def load_tests(loader, tests, ignore):
    tests.addTests(doctest.DocTestSuite('django_ca.subject'))
    return tests


class TestSubject(TestCase):
    def test_init_str(self):
        self.assertEqual(str(Subject('/CN=example.com')), '/CN=example.com')
        self.assertEqual(str(Subject('/C=AT/L=Vienna/O=example/CN=example.com')),
                         '/C=AT/L=Vienna/O=example/CN=example.com')
        self.assertEqual(str(Subject('/C=/CN=example.com')), '/CN=example.com')

    def test_init_dict(self):
        self.assertEqual(str(Subject({'CN': 'example.com'})), '/CN=example.com')
        self.assertEqual(str(Subject({'C': 'AT', 'L': 'Vienna', 'O': 'example', 'CN': 'example.com'})),
                         '/C=AT/L=Vienna/O=example/CN=example.com')
        self.assertEqual(str(Subject({'C': '', 'CN': 'example.com'})), '/CN=example.com')

    def test_init_list(self):
        self.assertEqual(str(Subject([('CN', 'example.com')])), '/CN=example.com')
        self.assertEqual(str(Subject([('C', 'AT'), ('L', 'Vienna'), ('O', 'example'),
                                      ('CN', 'example.com')])),
                         '/C=AT/L=Vienna/O=example/CN=example.com')
        self.assertEqual(str(Subject([('C', '')])), '/')

        # we also accept tuples
        self.assertEqual(str(Subject((('CN', 'example.com'), ))), '/CN=example.com')
        self.assertEqual(str(Subject((('C', 'AT'), ('L', 'Vienna'), ('O', 'example'),
                                      ('CN', 'example.com')))),
                         '/C=AT/L=Vienna/O=example/CN=example.com')
        self.assertEqual(str(Subject((('C', ''), ('CN', 'example.com'), ))), '/CN=example.com')

    def test_init_empty(self):
        self.assertEqual(str(Subject()), '/')
        self.assertEqual(str(Subject([])), '/')
        self.assertEqual(str(Subject({})), '/')
        self.assertEqual(str(Subject('')), '/')
        self.assertEqual(str(Subject(x509.Name(attributes=[]))), '/')

    def test_init_name(self):
        name = x509.Name(attributes=[
            x509.NameAttribute(oid=NameOID.COUNTRY_NAME, value=u'AT'),
            x509.NameAttribute(oid=NameOID.COMMON_NAME, value=u'example.com'),
        ])
        self.assertEqual(str(Subject(name)), '/C=AT/CN=example.com')

    def test_init_order(self):
        self.assertEqual(str(Subject([
            ('C', 'AT'),
            ('O', 'example'),
            ('L', 'Vienna'),
            ('CN', 'example.com'),
        ])), '/C=AT/L=Vienna/O=example/CN=example.com')

    def test_init_multiple(self):
        # OU can occur multiple times
        self.assertEqual(str(Subject([
            ('C', 'AT'),
            ('OU', 'foo'),
            ('OU', 'bar'),
            ('L', 'Vienna'),
            ('CN', 'example.com'),
        ])), '/C=AT/L=Vienna/OU=foo/OU=bar/CN=example.com')

        # C should not occur multiple times
        with self.assertRaisesRegex(ValueError, r'^C: Must not occur multiple times$'):
            Subject([('C', 'AT'), ('C', 'US')])

    def test_init_type(self):
        with self.assertRaisesRegex(ValueError, r'^Invalid subject: 33$'):
            Subject(33)

    def test_contains(self):
        self.assertIn('CN', Subject('/CN=example.com'))
        self.assertIn(NameOID.COMMON_NAME, Subject('/CN=example.com'))
        self.assertNotIn(NameOID.LOCALITY_NAME, Subject('/CN=example.com'))
        self.assertNotIn(NameOID.COUNTRY_NAME, Subject('/CN=example.com'))
        self.assertIn(NameOID.COUNTRY_NAME, Subject('/C=AT/CN=example.com'))
        self.assertIn(NameOID.COMMON_NAME, Subject('/C=AT/CN=example.com'))

    def test_getitem(self):
        self.assertEqual(Subject('/CN=example.com')['CN'], 'example.com')
        self.assertEqual(Subject('/C=AT/CN=example.com')['C'], 'AT')
        self.assertEqual(Subject('/C=AT/CN=example.com')['CN'], 'example.com')

        # try NameOID:
        self.assertEqual(Subject('/CN=example.com')[NameOID.COMMON_NAME], 'example.com')
        self.assertEqual(Subject('/C=AT/CN=example.com')[NameOID.COUNTRY_NAME], 'AT')
        self.assertEqual(Subject('/C=AT/CN=example.com')[NameOID.COMMON_NAME], 'example.com')

        # OUs
        self.assertEqual(Subject('/C=AT/OU=foo/CN=example.com')['OU'], ['foo'])
        self.assertEqual(Subject('/C=AT/OU=foo/OU=bar/CN=example.com')['OU'], ['foo', 'bar'])

        # test keyerror
        with self.assertRaisesRegex(KeyError, r"^'L'$"):
            Subject('/C=AT/OU=foo/CN=example.com')['L']

        with self.assertRaisesRegex(KeyError, r"^'L'$"):
            Subject('/C=AT/OU=foo/CN=example.com')[NameOID.LOCALITY_NAME]

    def test_eq(self):
        self.assertEqual(Subject('/CN=example.com'), Subject([('CN', 'example.com')]))
        self.assertNotEqual(Subject('/CN=example.com'), Subject([('CN', 'example.org')]))

        # Also make sure that objects are equal regardless of added order
        self.assertEqual(Subject('/CN=example.com'), Subject('/CN=example.com'))
        self.assertEqual(Subject('/C=AT/CN=example.com'), Subject('/CN=example.com/C=AT'))

    def test_len(self):
        self.assertEqual(len(Subject('')), 0)
        self.assertEqual(len(Subject('/C=AT')), 1)
        self.assertEqual(len(Subject('/C=AT/CN=example.com')), 2)
        self.assertEqual(len(Subject('/C=AT/OU=foo/CN=example.com')), 3)
        self.assertEqual(len(Subject('/C=AT/OU=foo/OU=bar/CN=example.com')), 3)

    def test_repr(self):
        self.assertEqual(repr(Subject('/C=AT/CN=example.com')), 'Subject("/C=AT/CN=example.com")')
        self.assertEqual(repr(Subject('/CN=example.com/C=AT')), 'Subject("/C=AT/CN=example.com")')
        self.assertEqual(repr(Subject('/cn=example.com/c=AT')), 'Subject("/C=AT/CN=example.com")')

    def test_setitem(self):
        s = Subject('')
        s['C'] = 'AT'
        self.assertEqual(s, Subject('/C=AT'))
        s['C'] = 'DE'
        self.assertEqual(s, Subject('/C=DE'))
        s[NameOID.COUNTRY_NAME] = ['AT']
        self.assertEqual(s, Subject('/C=AT'))

        s = Subject('/CN=example.com')
        s[NameOID.COUNTRY_NAME] = ['AT']
        self.assertEqual(s, Subject('/C=AT/CN=example.com'))

        # also test multiples
        s = Subject('/C=AT/CN=example.com')
        s['OU'] = ['foo', 'bar']
        self.assertEqual(s, Subject('/C=AT/OU=foo/OU=bar/CN=example.com'))

        with self.assertRaisesRegex(ValueError, r'L: Must not occur multiple times'):
            s['L'] = ['foo', 'bar']
        self.assertEqual(s, Subject('/C=AT/OU=foo/OU=bar/CN=example.com'))

        # setting an empty str or list effectively removes the value
        s = Subject('/C=AT/CN=example.com')
        s['C'] = None
        self.assertEqual(s, Subject('/CN=example.com'))

        s = Subject('/C=AT/CN=example.com')
        s['C'] = ''
        self.assertEqual(s, Subject('/CN=example.com'))

        s = Subject('/C=AT/CN=example.com')
        s['C'] = []
        self.assertEqual(s, Subject('/CN=example.com'))

        with self.assertRaisesRegex(ValueError, r'^Value must be str or list$'):
            s['C'] = 33

    def test_get(self):
        self.assertEqual(Subject('/CN=example.com').get('CN'), 'example.com')
        self.assertEqual(Subject('/C=AT/CN=example.com').get('C'), 'AT')
        self.assertEqual(Subject('/C=AT/CN=example.com').get('CN'), 'example.com')

        # try NameOID:
        self.assertEqual(Subject('/CN=example.com').get(NameOID.COMMON_NAME), 'example.com')
        self.assertEqual(Subject('/C=AT/CN=example.com').get(NameOID.COUNTRY_NAME), 'AT')
        self.assertEqual(Subject('/C=AT/CN=example.com').get(NameOID.COMMON_NAME), 'example.com')

        # OUs
        self.assertEqual(Subject('/C=AT/OU=foo/CN=example.com').get('OU'), ['foo'])
        self.assertEqual(Subject('/C=AT/OU=foo/OU=bar/CN=example.com').get('OU'), ['foo', 'bar'])

        # test that default doesn't overwrite anytying
        self.assertEqual(Subject('/CN=example.com').get('CN', 'x'), 'example.com')
        self.assertEqual(Subject('/C=AT/CN=example.com').get('C', 'x'), 'AT')
        self.assertEqual(Subject('/C=AT/CN=example.com').get('CN', 'x'), 'example.com')

        # test default value
        self.assertIsNone(Subject('/C=AT/OU=foo/CN=example.com').get('L'))
        self.assertEqual(Subject('/C=AT/OU=foo/CN=example.com').get('L', 'foo'), 'foo')
        self.assertIsNone(Subject('/C=AT/OU=foo/CN=example.com').get(NameOID.LOCALITY_NAME))
        self.assertEqual(Subject('/C=AT/OU=foo/CN=example.com').get(NameOID.LOCALITY_NAME, 'foo'), 'foo')

    def test_iters(self):
        s = Subject('/CN=example.com')
        self.assertCountEqual(s.keys(), ['CN'])
        self.assertCountEqual(s.values(), ['example.com'])
        self.assertCountEqual(s.items(), [('CN', 'example.com')])

        s = Subject('/C=AT/O=Org/OU=foo/OU=bar/CN=example.com')
        self.assertCountEqual(s.keys(), ['C', 'O', 'OU', 'OU', 'CN'])
        self.assertCountEqual(s.values(), ['AT', 'Org', 'foo', 'bar', 'example.com'])
        self.assertCountEqual(s.items(), [('C', 'AT'), ('O', 'Org'), ('OU', 'foo'), ('OU', 'bar'),
                                          ('CN', 'example.com')])

        keys = ['C', 'O', 'OU', 'OU', 'CN']
        for i, key in enumerate(s):
            self.assertEqual(key, keys[i])

    def test_setdefault(self):
        s = Subject('/CN=example.com')
        s.setdefault('CN', 'example.org')
        self.assertEqual(s, Subject('/CN=example.com'))

        s.setdefault(NameOID.COMMON_NAME, 'example.org')
        self.assertEqual(s, Subject('/CN=example.com'))

        # set a new value
        s.setdefault('C', 'AT')
        self.assertEqual(s, Subject('/C=AT/CN=example.com'))
        s.setdefault('C', 'DE')
        self.assertEqual(s, Subject('/C=AT/CN=example.com'))

        # ok, now set multiple OUs
        s = Subject('/C=AT/CN=example.com')
        s.setdefault('OU', ['foo', 'bar'])
        self.assertEqual(s, Subject('/C=AT/OU=foo/OU=bar/CN=example.com'))

        # We can't set multiple C's
        with self.assertRaisesRegex(ValueError, r'L: Must not occur multiple times'):
            s.setdefault('L', ['AT', 'DE'])
        self.assertEqual(s, Subject('/C=AT/OU=foo/OU=bar/CN=example.com'))

        s = Subject()
        with self.assertRaisesRegex(ValueError, r'^Value must be str or list$'):
            s.setdefault('C', 33)

    def test_clear_copy(self):
        s = Subject('/O=Org/CN=example.com')
        s2 = s.copy()
        s.clear()
        self.assertFalse(s)
        self.assertTrue(s2)

    def test_update(self):
        merged = Subject('/C=AT/O=Org/CN=example.net')

        s = Subject('/O=Org/CN=example.com')
        s.update(Subject('/C=AT/CN=example.net'))
        self.assertEqual(s, merged)

        s = Subject('/O=Org/CN=example.com')
        s.update({'C': 'AT', 'CN': 'example.net'})
        self.assertEqual(s, merged)

        s = Subject('/O=Org/CN=example.com')
        s.update([('C', 'AT'), ('CN', 'example.net')])
        self.assertEqual(s, merged)

        s = Subject('/O=Org/CN=example.com')
        s.update([('C', 'AT')], CN='example.net')
        self.assertEqual(s, merged)

        s = Subject('/O=Org/CN=example.com')
        s.update(C='AT', CN='example.net')
        self.assertEqual(s, merged)

        s = Subject('/O=Org/CN=example.com')
        s.update([('C', 'DE')], C='AT', CN='example.net')
        self.assertEqual(s, merged)

    def test_fields(self):
        s = Subject('')
        self.assertEqual(list(s.fields), [])

        s = Subject('/C=AT')
        self.assertEqual(list(s.fields), [(NameOID.COUNTRY_NAME, 'AT')])

        s = Subject('/C=AT/CN=example.com')
        self.assertEqual(list(s.fields), [(NameOID.COUNTRY_NAME, 'AT'), (NameOID.COMMON_NAME, 'example.com')])

        s = Subject('/C=AT/OU=foo/CN=example.com')
        self.assertEqual(list(s.fields), [(NameOID.COUNTRY_NAME, 'AT'),
                                          (NameOID.ORGANIZATIONAL_UNIT_NAME, 'foo'),
                                          (NameOID.COMMON_NAME, 'example.com')])
        s = Subject('/C=AT/OU=foo/OU=bar/CN=example.com')
        self.assertEqual(list(s.fields), [(NameOID.COUNTRY_NAME, 'AT'),
                                          (NameOID.ORGANIZATIONAL_UNIT_NAME, 'foo'),
                                          (NameOID.ORGANIZATIONAL_UNIT_NAME, 'bar'),
                                          (NameOID.COMMON_NAME, 'example.com')])

        # Also test order
        s = Subject('/CN=example.com/C=AT/OU=foo/OU=bar')
        self.assertEqual(list(s.fields), [(NameOID.COUNTRY_NAME, 'AT'),
                                          (NameOID.ORGANIZATIONAL_UNIT_NAME, 'foo'),
                                          (NameOID.ORGANIZATIONAL_UNIT_NAME, 'bar'),
                                          (NameOID.COMMON_NAME, 'example.com')])

    def test_default_subject(self):
        with self.assertRaisesRegex(ImproperlyConfigured, r'^CA_DEFAULT_SUBJECT: Invalid subject: True$'):
            with override_settings(CA_DEFAULT_SUBJECT=True):
                get_default_subject()

        with self.assertRaisesRegex(ImproperlyConfigured, r'^CA_DEFAULT_SUBJECT: Invalid OID: XYZ$'):
            with override_settings(CA_DEFAULT_SUBJECT={'XYZ': 'error'}):
                get_default_subject()

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

from cryptography.x509.oid import NameOID

from django.test import TestCase

from ..subject import Subject


class TestSubject(TestCase):
    def test_init_str(self):
        self.assertEqual(str(Subject('/CN=example.com')), '/CN=example.com')
        self.assertEqual(str(Subject('/C=AT/L=Vienna/O=example/CN=example.com')),
                         '/C=AT/L=Vienna/O=example/CN=example.com')

    def test_init_dict(self):
        self.assertEqual(str(Subject({'CN': 'example.com'})), '/CN=example.com')
        self.assertEqual(str(Subject({'C': 'AT', 'L': 'Vienna', 'O': 'example', 'CN': 'example.com'})),
                         '/C=AT/L=Vienna/O=example/CN=example.com')

    def test_init_list(self):
        self.assertEqual(str(Subject([('CN', 'example.com')])), '/CN=example.com')
        self.assertEqual(str(Subject([('C', 'AT'), ('L', 'Vienna'), ('O', 'example'),
                                      ('CN', 'example.com')])),
                         '/C=AT/L=Vienna/O=example/CN=example.com')

        # we also accept tuples
        self.assertEqual(str(Subject((('CN', 'example.com'), ))), '/CN=example.com')
        self.assertEqual(str(Subject((('C', 'AT'), ('L', 'Vienna'), ('O', 'example'),
                                      ('CN', 'example.com')))),
                         '/C=AT/L=Vienna/O=example/CN=example.com')

    def test_init_empty(self):
        self.assertEqual(str(Subject([])), '/')
        self.assertEqual(str(Subject({})), '/')
        self.assertEqual(str(Subject('')), '/')

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
        with self.assertRaisesRegex(ValueError, '^C: Must not occur multiple times$'):
            Subject([('C', 'AT'), ('C', 'US')])

    def test_contains(self):
        self.assertIn('CN', Subject('/CN=example.com'))
        self.assertIn(NameOID.COMMON_NAME, Subject('/CN=example.com'))
        self.assertNotIn(NameOID.LOCALITY_NAME, Subject('/CN=example.com'))
        self.assertNotIn(NameOID.COUNTRY_NAME, Subject('/CN=example.com'))
        self.assertIn(NameOID.COUNTRY_NAME, Subject('/C=AT/CN=example.com'))
        self.assertIn(NameOID.COMMON_NAME, Subject('/C=AT/CN=example.com'))

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
        with self.assertRaisesRegex(ValueError, 'L: Must not occur multiple times'):
            s.setdefault('L', ['AT', 'DE'])

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

"""Test utility functions."""

from __future__ import unicode_literals

import doctest
import ipaddress
import json
import unittest
from datetime import datetime
from datetime import timedelta

import idna
from freezegun import freeze_time
from idna.core import IDNAError

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import six
from django.utils.translation import ugettext as _
from django.utils.translation import ugettext_lazy as _l

from .. import ca_settings
from .. import utils
from ..extensions import ExtendedKeyUsage
from ..extensions import KeyUsage
from ..extensions import TLSFeature
from ..profiles import get_cert_profile_kwargs
from ..utils import NAME_RE
from ..utils import LazyEncoder
from ..utils import format_name
from ..utils import get_cert_builder
from ..utils import is_power2
from ..utils import multiline_url_validator
from ..utils import parse_general_name
from ..utils import parse_key_curve
from ..utils import parse_name
from ..utils import validate_email
from .base import DjangoCATestCase
from .base import override_settings


def load_tests(loader, tests, ignore):
    if six.PY3:  # pragma: only py3
        # unicode strings make this very hard to test doctests in both py2 and py3
        tests.addTests(doctest.DocTestSuite(utils))
    return tests


class NameMatchTest(TestCase):
    def match(self, value, expected):
        value = [(t[0], t[2]) for t in NAME_RE.findall(value)]
        self.assertEqual(value, expected)

    def test_empty(self):
        self.match('', [])
        self.match(' ', [])
        self.match('  ', [])

    def test_single(self):
        self.match('C=AT', [('C', 'AT')])
        self.match('C="AT"', [('C', 'AT')])
        self.match('C=" AT "', [('C', 'AT')])

        # test quotes
        self.match('C=" AT \' DE"', [('C', 'AT \' DE')])
        self.match('C=\' AT " DE\'', [('C', 'AT " DE')])

        self.match('C=AT/DE', [('C', 'AT')])  # slash is delimiter when unquoted
        self.match('C="AT/DE"', [('C', 'AT/DE')])
        self.match("C='AT/DE/US'", [('C', 'AT/DE/US')])
        self.match("C='AT/DE'", [('C', 'AT/DE')])
        self.match("C='AT/DE/US'", [('C', 'AT/DE/US')])

        self.match("C='AT \\' DE'", [('C', "AT \\' DE")])

    def test_two(self):
        self.match('C=AT/OU=example', [('C', 'AT'), ('OU', 'example')])
        self.match('C="AT"/OU=example', [('C', 'AT'), ('OU', 'example')])
        self.match('C=" AT "/OU=example', [('C', 'AT'), ('OU', 'example')])

        # test quotes
        self.match('C=" AT \' DE"/OU=example', [('C', 'AT \' DE'), ('OU', 'example')])
        self.match('C=\' AT " DE\'/OU=example', [('C', 'AT " DE'), ('OU', 'example')])

        self.match('C="AT/DE"/OU=example', [('C', 'AT/DE'), ('OU', 'example')])
        self.match("C='AT/DE/US'/OU=example", [('C', 'AT/DE/US'), ('OU', 'example')])
        self.match("C='AT/DE'/OU=example", [('C', 'AT/DE'), ('OU', 'example')])
        self.match("C='AT/DE/US'/OU=example", [('C', 'AT/DE/US'), ('OU', 'example')])

        self.match("C='AT \\' DE'/OU=example", [('C', "AT \\' DE"), ('OU', 'example')])

        # now both are quoted
        self.match('C="AT"/OU="ex ample"', [('C', 'AT'), ('OU', 'ex ample')])
        self.match('C=" AT "/OU="ex ample"', [('C', 'AT'), ('OU', 'ex ample')])
        self.match('C=" AT \' DE"/OU="ex ample"', [('C', 'AT \' DE'), ('OU', 'ex ample')])
        self.match('C=\' AT " DE\'/OU="ex ample"', [('C', 'AT " DE'), ('OU', 'ex ample')])
        self.match('C="AT/DE"/OU="ex ample"', [('C', 'AT/DE'), ('OU', 'ex ample')])
        self.match("C='AT/DE/US'/OU='ex ample'", [('C', 'AT/DE/US'), ('OU', 'ex ample')])
        self.match("C='AT/DE'/OU='ex ample'", [('C', 'AT/DE'), ('OU', 'ex ample')])
        self.match("C='AT/DE/US'/OU='ex ample'", [('C', 'AT/DE/US'), ('OU', 'ex ample')])

        self.match("C='AT \\' DE'/OU='ex ample'", [('C', "AT \\' DE"), ('OU', 'ex ample')])

        # Now include a slash in OU
        self.match('C="AT"/OU="ex / ample"', [('C', 'AT'), ('OU', 'ex / ample')])
        self.match('C=" AT "/OU="ex / ample"', [('C', 'AT'), ('OU', 'ex / ample')])
        self.match('C=" AT \' DE"/OU="ex / ample"', [('C', 'AT \' DE'), ('OU', 'ex / ample')])
        self.match('C=\' AT " DE\'/OU="ex / ample"', [('C', 'AT " DE'), ('OU', 'ex / ample')])
        self.match('C="AT/DE"/OU="ex / ample"', [('C', 'AT/DE'), ('OU', 'ex / ample')])
        self.match("C='AT/DE/US'/OU='ex / ample'", [('C', 'AT/DE/US'), ('OU', 'ex / ample')])
        self.match("C='AT/DE'/OU='ex / ample'", [('C', 'AT/DE'), ('OU', 'ex / ample')])
        self.match("C='AT/DE/US'/OU='ex / ample'", [('C', 'AT/DE/US'), ('OU', 'ex / ample')])
        self.match("C='AT \\' DE'/OU='ex / ample'", [('C', "AT \\' DE"), ('OU', 'ex / ample')])

        # Append a slash in the end (It's a delimiter - doesn't influence the output)
        self.match('C="AT"/OU="ex / ample"/', [('C', 'AT'), ('OU', 'ex / ample')])
        self.match('C=" AT "/OU="ex / ample"/', [('C', 'AT'), ('OU', 'ex / ample')])
        self.match('C=" AT \' DE"/OU="ex / ample"/', [('C', 'AT \' DE'), ('OU', 'ex / ample')])
        self.match('C=\' AT " DE\'/OU="ex / ample"/', [('C', 'AT " DE'), ('OU', 'ex / ample')])
        self.match('C="AT/DE"/OU="ex / ample"/', [('C', 'AT/DE'), ('OU', 'ex / ample')])
        self.match("C='AT/DE/US'/OU='ex / ample'/", [('C', 'AT/DE/US'), ('OU', 'ex / ample')])
        self.match("C='AT/DE'/OU='ex / ample'/", [('C', 'AT/DE'), ('OU', 'ex / ample')])
        self.match("C='AT/DE/US'/OU='ex / ample'/", [('C', 'AT/DE/US'), ('OU', 'ex / ample')])
        self.match("C='AT \\' DE'/OU='ex / ample'/", [('C', "AT \\' DE"), ('OU', 'ex / ample')])

    def test_unquoted_slashes(self):
        self.match('C=AT/DE/OU=example', [('C', 'AT'), ('DE/OU', 'example')])
        self.match('C=AT/DE/OU="ex ample"', [('C', 'AT'), ('DE/OU', 'ex ample')])
        self.match('C=AT/DE/OU="ex / ample"', [('C', 'AT'), ('DE/OU', 'ex / ample')])
        self.match('C=AT/DE/OU="ex / ample"/', [('C', 'AT'), ('DE/OU', 'ex / ample')])

    def test_full_examples(self):
        expected = [('C', 'AT'), ('ST', 'Vienna'), ('L', 'Loc Fünf'), ('O', 'Org Name'),
                    ('OU', 'Org Unit'), ('CN', 'example.com')]

        self.match('/C=AT/ST=Vienna/L=Loc Fünf/O=Org Name/OU=Org Unit/CN=example.com', expected)
        self.match('/C=AT/ST=Vienna/L="Loc Fünf"/O=\'Org Name\'/OU=Org Unit/CN=example.com', expected)


class LazyEncoderTestCase(TestCase):
    def test_basic(self):
        self.assertEqual('{"a": "b"}', json.dumps({'a': 'b'}, cls=LazyEncoder))

    def test_translated(self):
        self.assertEqual('{"a": "b"}', json.dumps({'a': _l('b')}, cls=LazyEncoder))

        # these are just here to improve branch coverage :-)
        self.assertEqual('{"a": "b"}', json.dumps({'a': _('b')}, cls=LazyEncoder))
        self.assertEqual('{"a": "2016-03-26T00:00:00"}',
                         json.dumps({'a': datetime(2016, 3, 26)}, cls=LazyEncoder))


class ParseNameTestCase(DjangoCATestCase):
    def assertSubject(self, actual, expected):
        self.assertEqual(parse_name(actual), expected)

    def test_basic(self):
        self.assertSubject('/CN=example.com', [('CN', 'example.com')])

        # leading or trailing spaces are always ok.
        self.assertSubject(' /CN = example.com ', [('CN', 'example.com')])

        # emailAddress is special because of the case
        self.assertSubject('/emailAddress=user@example.com', [('emailAddress', 'user@example.com')])

    def test_multiple(self):
        self.assertSubject('/C=AT/OU=foo/CN=example.com', [('C', 'AT'), ('OU', 'foo'), ('CN', 'example.com')])

    def test_case(self):
        # test that we generally ignore case in subject keys
        self.assertSubject(
            '/c=AT/ou=foo/cn=example.com/eMAIladdreSS=user@example.com',
            [('C', 'AT'), ('OU', 'foo'), ('CN', 'example.com'), ('emailAddress', 'user@example.com')])

    def test_emtpy(self):
        # empty subjects are ok
        self.assertSubject('', [])
        self.assertSubject('   ', [])

    def test_multiple_slashes(self):
        self.assertSubject('/C=AT/O=GNU', [('C', 'AT'), ('O', 'GNU')])
        self.assertSubject('//C=AT/O=GNU', [('C', 'AT'), ('O', 'GNU')])
        self.assertSubject('/C=AT//O=GNU', [('C', 'AT'), ('O', 'GNU')])
        self.assertSubject('/C=AT///O=GNU', [('C', 'AT'), ('O', 'GNU')])

    def test_empty_field(self):
        self.assertSubject('/C=AT/O=GNU/OU=foo', [('C', 'AT'), ('O', 'GNU'), ('OU', 'foo')])
        self.assertSubject('/C=/O=GNU/OU=foo', [('C', ''), ('O', 'GNU'), ('OU', 'foo')])
        self.assertSubject('/C=AT/O=/OU=foo', [('C', 'AT'), ('O', ''), ('OU', 'foo')])
        self.assertSubject('/C=AT/O=GNU/OU=', [('C', 'AT'), ('O', 'GNU'), ('OU', '')])
        self.assertSubject('/C=/O=/OU=', [('C', ''), ('O', ''), ('OU', '')])

    def test_no_slash_at_start(self):
        self.assertSubject('CN=example.com', [('CN', 'example.com')])

    def test_multiple_ous(self):
        self.assertSubject('/OU=foo/OU=bar', [('OU', 'foo'), ('OU', 'bar')])
        self.assertSubject('/C=AT/O=bla/OU=foo/OU=bar/CN=example.com/',
                           [('C', 'AT'), ('O', 'bla'), ('OU', 'foo'), ('OU', 'bar'), ('CN', 'example.com')])
        self.assertSubject('/C=AT/O=bla/OU=foo/OU=bar/OU=hugo/CN=example.com/',
                           [('C', 'AT'), ('O', 'bla'), ('OU', 'foo'), ('OU', 'bar'), ('OU', 'hugo'),
                            ('CN', 'example.com')])

    def test_multiple_other(self):
        with self.assertRaisesRegex(ValueError, '^Subject contains multiple "C" fields$'):
            parse_name('/C=AT/C=FOO')
        with self.assertRaisesRegex(ValueError, '^Subject contains multiple "CN" fields$'):
            parse_name('/CN=AT/CN=FOO')

    def test_unknown(self):
        field = 'ABC'
        with self.assertRaisesRegex(ValueError, '^Unknown x509 name field: ABC$') as e:
            parse_name('/%s=example.com' % field)
        self.assertEqual(e.exception.args, ('Unknown x509 name field: %s' % field, ))


class ValidateEmailTestCase(DjangoCATestCase):
    def test_basic(self):
        self.assertEqual(validate_email('user@example.com'), 'user@example.com')

    def test_i18n(self):
        self.assertEqual(validate_email('user@exämple.com'), 'user@xn--exmple-cua.com')

    def test_invalid_domain(self):
        with self.assertRaisesRegex(ValueError, '^Invalid domain: example.com$'):
            validate_email('user@example com')

    def test_no_at(self):
        with self.assertRaisesRegex(ValueError, '^Invalid email address: user$'):
            validate_email('user')

        with self.assertRaisesRegex(ValueError, '^Invalid email address: example.com$'):
            validate_email('example.com')


class ParseGeneralNameTest(DjangoCATestCase):
    # some paths are not covered in doctests

    def test_ipv4(self):
        self.assertEqual(parse_general_name('1.2.3.4'), x509.IPAddress(ipaddress.ip_address(u'1.2.3.4')))
        self.assertEqual(parse_general_name('ip:1.2.3.4'), x509.IPAddress(ipaddress.ip_address(u'1.2.3.4')))

    def test_ipv4_network(self):
        self.assertEqual(parse_general_name('1.2.3.0/24'),
                         x509.IPAddress(ipaddress.ip_network(u'1.2.3.0/24')))
        self.assertEqual(parse_general_name('ip:1.2.3.0/24'),
                         x509.IPAddress(ipaddress.ip_network(u'1.2.3.0/24')))

    def test_ipv6(self):
        self.assertEqual(parse_general_name('fd00::32'), x509.IPAddress(ipaddress.ip_address(u'fd00::32')))
        self.assertEqual(parse_general_name('ip:fd00::32'), x509.IPAddress(ipaddress.ip_address(u'fd00::32')))

    def test_ipv6_network(self):
        self.assertEqual(parse_general_name('fd00::0/32'),
                         x509.IPAddress(ipaddress.ip_network(u'fd00::0/32')))
        self.assertEqual(parse_general_name('ip:fd00::0/32'),
                         x509.IPAddress(ipaddress.ip_network(u'fd00::0/32')))

    def test_domain(self):
        self.assertEqual(parse_general_name('DNS:example.com'), x509.DNSName('example.com'))
        self.assertEqual(parse_general_name('DNS:.example.com'), x509.DNSName('.example.com'))

    def test_wildcard_domain(self):
        self.assertEqual(parse_general_name('*.example.com'), x509.DNSName(u'*.example.com'))
        self.assertEqual(parse_general_name('DNS:*.example.com'), x509.DNSName(u'*.example.com'))

        # Wildcard subdomains are allowed in DNS entries, however RFC 2595 limits their use to a single
        # wildcard in the outermost level
        if idna.__version__ >= '2.8':
            if six.PY2:
                msg = r'^Codepoint U\+002A at position 1 of u\'\*\' not allowed$'
            else:
                msg = r'^Codepoint U\+002A at position 1 of \'\*\' not allowed$'
        else:
            msg = r'^The label b?\'?\*\'? is not a valid A-label$'

        with self.assertRaisesRegex(IDNAError, msg):
            parse_general_name(u'test.*.example.com')
        with self.assertRaisesRegex(IDNAError, msg):
            parse_general_name(u'*.*.example.com')
        with self.assertRaisesRegex(IDNAError, msg):
            parse_general_name(u'example.com.*')

    def test_wrong_email(self):
        if idna.__version__ >= '2.8':
            if six.PY2:
                msg = r"^Codepoint U\+0040 at position 5 of u'user@' not allowed$"
            else:
                msg = r"^Codepoint U\+0040 at position 5 of 'user@' not allowed$"
        else:
            if six.PY2:
                msg = "The label user@ is not a valid A-label"
            else:
                msg = "The label b'user@' is not a valid A-label"
        with self.assertRaisesRegex(IDNAError, msg):
            parse_general_name('user@')

        with self.assertRaisesRegex(ValueError, '^Invalid domain: $'):
            parse_general_name('email:user@')

    def test_otherName_octetString(self):
        self.assertEqual(parse_general_name(
                         'otherName:1.3.6.1.4.1.311.25.1;OctetString:09CFF1A8F6DEFD4B85CE95FFA1B54217'),
                         x509.OtherName(
                         x509.oid.ObjectIdentifier('1.3.6.1.4.1.311.25.1'),
                         b'\x04\x10\t\xcf\xf1\xa8\xf6\xde\xfdK\x85\xce\x95\xff\xa1\xb5B\x17'))

        with self.assertRaisesRegex(ValueError, '^Incorrect otherName format: foobar$'):
            parse_general_name('otherName:foobar')

        with self.assertRaisesRegex(ValueError, '^Unsupported ASN type in otherName: MagicString$'):
            parse_general_name('otherName:1.2.3;MagicString:Broken')

    def test_error(self):
        with self.assertRaisesRegex(ValueError, r'^Could not parse IP address\.$'):
            parse_general_name('ip:1.2.3.4/24')


class FormatNameTestCase(TestCase):
    def test_basic(self):
        subject = '/C=AT/ST=Vienna/L=Vienna/O=O/OU=OU/CN=example.com/emailAddress=user@example.com'

        subject_dict = [('C', 'AT'), ('ST', 'Vienna'), ('L', 'Vienna'), ('O', 'O'), ('OU', 'OU'),
                        ('CN', 'example.com'), ('emailAddress', 'user@example.com'), ]
        self.assertEqual(format_name(subject_dict), subject)


class Power2TestCase(TestCase):
    def test_true(self):
        for i in range(0, 20):
            self.assertTrue(is_power2(2 ** i))

    def test_false(self):
        self.assertFalse(is_power2(0))
        self.assertFalse(is_power2(3))
        self.assertFalse(is_power2(5))

        for i in range(2, 20):
            self.assertFalse(is_power2((2 ** i) - 1))
            self.assertFalse(is_power2((2 ** i) + 1))


class ParseKeyCurveTestCase(TestCase):
    def test_basic(self):
        self.assertIsInstance(parse_key_curve(), type(ca_settings.CA_DEFAULT_ECC_CURVE))
        self.assertIsInstance(parse_key_curve('SECT409R1'), ec.SECT409R1)
        self.assertIsInstance(parse_key_curve('SECP521R1'), ec.SECP521R1)
        self.assertIsInstance(parse_key_curve('SECP192R1'), ec.SECP192R1)

    def test_error(self):
        with self.assertRaisesRegex(ValueError, '^FOOBAR: Not a known Eliptic Curve$'):
            parse_key_curve('FOOBAR')

        with self.assertRaisesRegex(ValueError, '^ECDH: Not a known Eliptic Curve$'):
            parse_key_curve('ECDH')  # present in the module, but *not* an EllipticCurve


class AddColonsTestCase(TestCase):
    def test_basic(self):
        self.assertEqual(utils.add_colons(''), '')
        self.assertEqual(utils.add_colons('a'), 'a')
        self.assertEqual(utils.add_colons('ab'), 'ab')
        self.assertEqual(utils.add_colons('abc'), 'ab:c')
        self.assertEqual(utils.add_colons('abcd'), 'ab:cd')
        self.assertEqual(utils.add_colons('abcde'), 'ab:cd:e')
        self.assertEqual(utils.add_colons('abcdef'), 'ab:cd:ef')
        self.assertEqual(utils.add_colons('abcdefg'), 'ab:cd:ef:g')


class IntToHexTestCase(TestCase):
    def test_basic(self):
        self.assertEqual(utils.int_to_hex(0), '0')
        self.assertEqual(utils.int_to_hex(1), '1')
        self.assertEqual(utils.int_to_hex(2), '2')
        self.assertEqual(utils.int_to_hex(3), '3')
        self.assertEqual(utils.int_to_hex(4), '4')
        self.assertEqual(utils.int_to_hex(5), '5')
        self.assertEqual(utils.int_to_hex(6), '6')
        self.assertEqual(utils.int_to_hex(7), '7')
        self.assertEqual(utils.int_to_hex(8), '8')
        self.assertEqual(utils.int_to_hex(9), '9')
        self.assertEqual(utils.int_to_hex(10), 'A')
        self.assertEqual(utils.int_to_hex(11), 'B')
        self.assertEqual(utils.int_to_hex(12), 'C')
        self.assertEqual(utils.int_to_hex(13), 'D')
        self.assertEqual(utils.int_to_hex(14), 'E')
        self.assertEqual(utils.int_to_hex(15), 'F')
        self.assertEqual(utils.int_to_hex(16), '10')
        self.assertEqual(utils.int_to_hex(17), '11')
        self.assertEqual(utils.int_to_hex(18), '12')
        self.assertEqual(utils.int_to_hex(19), '13')
        self.assertEqual(utils.int_to_hex(20), '14')
        self.assertEqual(utils.int_to_hex(21), '15')
        self.assertEqual(utils.int_to_hex(22), '16')
        self.assertEqual(utils.int_to_hex(23), '17')
        self.assertEqual(utils.int_to_hex(24), '18')
        self.assertEqual(utils.int_to_hex(25), '19')
        self.assertEqual(utils.int_to_hex(26), '1A')
        self.assertEqual(utils.int_to_hex(27), '1B')
        self.assertEqual(utils.int_to_hex(28), '1C')
        self.assertEqual(utils.int_to_hex(29), '1D')
        self.assertEqual(utils.int_to_hex(30), '1E')
        self.assertEqual(utils.int_to_hex(31), '1F')
        self.assertEqual(utils.int_to_hex(32), '20')
        self.assertEqual(utils.int_to_hex(33), '21')
        self.assertEqual(utils.int_to_hex(34), '22')
        self.assertEqual(utils.int_to_hex(35), '23')
        self.assertEqual(utils.int_to_hex(36), '24')
        self.assertEqual(utils.int_to_hex(37), '25')
        self.assertEqual(utils.int_to_hex(38), '26')
        self.assertEqual(utils.int_to_hex(39), '27')
        self.assertEqual(utils.int_to_hex(40), '28')
        self.assertEqual(utils.int_to_hex(41), '29')
        self.assertEqual(utils.int_to_hex(42), '2A')
        self.assertEqual(utils.int_to_hex(43), '2B')
        self.assertEqual(utils.int_to_hex(44), '2C')
        self.assertEqual(utils.int_to_hex(45), '2D')
        self.assertEqual(utils.int_to_hex(46), '2E')
        self.assertEqual(utils.int_to_hex(47), '2F')
        self.assertEqual(utils.int_to_hex(48), '30')
        self.assertEqual(utils.int_to_hex(49), '31')

    def test_high(self):
        self.assertEqual(utils.int_to_hex(1513282098), '5A:32:DA:32')
        self.assertEqual(utils.int_to_hex(1513282099), '5A:32:DA:33')
        self.assertEqual(utils.int_to_hex(1513282100), '5A:32:DA:34')
        self.assertEqual(utils.int_to_hex(1513282101), '5A:32:DA:35')
        self.assertEqual(utils.int_to_hex(1513282102), '5A:32:DA:36')
        self.assertEqual(utils.int_to_hex(1513282103), '5A:32:DA:37')
        self.assertEqual(utils.int_to_hex(1513282104), '5A:32:DA:38')
        self.assertEqual(utils.int_to_hex(1513282105), '5A:32:DA:39')
        self.assertEqual(utils.int_to_hex(1513282106), '5A:32:DA:3A')
        self.assertEqual(utils.int_to_hex(1513282107), '5A:32:DA:3B')
        self.assertEqual(utils.int_to_hex(1513282108), '5A:32:DA:3C')
        self.assertEqual(utils.int_to_hex(1513282109), '5A:32:DA:3D')
        self.assertEqual(utils.int_to_hex(1513282110), '5A:32:DA:3E')
        self.assertEqual(utils.int_to_hex(1513282111), '5A:32:DA:3F')
        self.assertEqual(utils.int_to_hex(1513282112), '5A:32:DA:40')
        self.assertEqual(utils.int_to_hex(1513282113), '5A:32:DA:41')

    @unittest.skipUnless(six.PY2, 'long is only defined in py2')
    def test_long(self):
        self.assertEqual(utils.int_to_hex(long(0)), '0')  # NOQA
        self.assertEqual(utils.int_to_hex(long(43)), '2B')  # NOQA
        self.assertEqual(utils.int_to_hex(long(1513282104)), '5A:32:DA:38')  # NOQA


class MultilineURLValidatorTestCase(TestCase):
    def test_basic(self):
        multiline_url_validator('')
        multiline_url_validator('http://example.com')
        multiline_url_validator('http://example.com\nhttp://www.example.org')
        multiline_url_validator('''http://example.com\nhttp://www.example.org
http://www.example.net''')

    def test_error(self):
        with self.assertRaises(ValidationError) as e:
            multiline_url_validator('foo')
        self.assertEqual(e.exception.args, ('Enter a valid URL.', 'invalid', None))

        with self.assertRaises(ValidationError):
            multiline_url_validator('foo\nhttp://www.example.com')
        self.assertEqual(e.exception.args, ('Enter a valid URL.', 'invalid', None))

        with self.assertRaises(ValidationError):
            multiline_url_validator('http://www.example.com\nfoo')
        self.assertEqual(e.exception.args, ('Enter a valid URL.', 'invalid', None))

        with self.assertRaises(ValidationError):
            multiline_url_validator('http://www.example.com\nfoo\nhttp://example.org')
        self.assertEqual(e.exception.args, ('Enter a valid URL.', 'invalid', None))


class GetCertBuilderTestCase(DjangoCATestCase):
    def parse_date(self, date):
        return datetime.strptime(date, '%Y%m%d%H%M%SZ')

    @freeze_time('2018-11-03 11:21:33')
    @override_settings(CA_DEFAULT_EXPIRES=100)
    def test_basic(self):
        now = datetime.utcnow()
        after = datetime(2020, 10, 23, 11, 21)
        before = datetime(2018, 11, 3, 11, 21)
        builder = get_cert_builder(now + timedelta(days=720))
        self.assertEqual(builder._not_valid_after, after)
        self.assertEqual(builder._not_valid_before, before)
        self.assertIsInstance(builder._serial_number, six.integer_types)

        builder = get_cert_builder(None)
        self.assertEqual(builder._not_valid_after, datetime(2019, 2, 12, 11, 21))
        self.assertEqual(builder._not_valid_before, before)  # before shouldn't change
        self.assertIsInstance(builder._serial_number, six.integer_types)

    @freeze_time('2018-11-03 11:21:33')
    def test_negative(self):
        with self.assertRaisesRegex(ValueError,
                                    r'^The not valid after date must be after the not valid before date\.$'):
            get_cert_builder(datetime(2017, 12, 12))


class GetCertProfileKwargsTestCase(DjangoCATestCase):
    # NOTE: These test-cases will start failing if you change the default profiles.

    @override_settings(CA_PROFILES={})
    def test_default(self):
        expected = {
            'cn_in_san': True,
            'key_usage': KeyUsage('critical,digitalSignature,keyAgreement,keyEncipherment'),
            'extended_key_usage': ExtendedKeyUsage('serverAuth'),
            'subject': [
                ('C', 'AT'),
                ('ST', 'Vienna'),
                ('L', 'Vienna'),
                ('O', 'Django CA'),
                ('OU', 'Django CA Testsuite'),
            ],
        }
        self.assertEqual(get_cert_profile_kwargs(), expected)
        self.assertEqual(get_cert_profile_kwargs(ca_settings.CA_DEFAULT_PROFILE), expected)

    def test_types(self):
        expected = {
            'cn_in_san': True,
            'key_usage': KeyUsage('digitalSignature'),
            'extended_key_usage': ExtendedKeyUsage('critical,msKDC'),
            'tls_feature': TLSFeature('critical,OCSPMustStaple'),
            'subject': [
                ('C', 'AT'),
                ('ST', 'Vienna'),
                ('L', 'Vienna'),
                ('O', 'Django CA'),
                ('OU', 'Django CA Testsuite'),
            ],
        }

        CA_PROFILES = {
            'testprofile': {
                'keyUsage': {
                    'critical': False,
                    'value': 'digitalSignature',
                },
                'extendedKeyUsage': {
                    'critical': True,
                    'value': 'msKDC',
                },
                'TLSFeature': {
                    'critical': True,
                    'value': 'OCSPMustStaple',
                },
            },
        }

        with self.settings(CA_PROFILES=CA_PROFILES):
            self.assertEqual(get_cert_profile_kwargs('testprofile'), expected)

        CA_PROFILES['testprofile']['keyUsage']['value'] = 'encipherOnly'
        expected['key_usage'] = KeyUsage('encipherOnly')
        with self.settings(CA_PROFILES=CA_PROFILES):
            self.assertEqual(get_cert_profile_kwargs('testprofile'), expected)

        CA_PROFILES['testprofile']['keyUsage']['value'] = b''
        del expected['key_usage']
        with self.settings(CA_PROFILES=CA_PROFILES):
            self.assertEqual(get_cert_profile_kwargs('testprofile'), expected)

        # Ok, no we have *no* extensions
        expected = {
            'cn_in_san': True,
            'subject': [
                ('C', 'AT'),
                ('ST', 'Vienna'),
                ('L', 'Vienna'),
                ('O', 'Django CA'),
                ('OU', 'Django CA Testsuite'),
            ],
        }

        CA_PROFILES = {
            'testprofile': {},
        }

        with self.settings(CA_PROFILES=CA_PROFILES):
            self.assertEqual(get_cert_profile_kwargs('testprofile'), expected)

# -*- coding: utf-8 -*-

"""Test utility functions."""

import doctest
import json
from datetime import datetime
from datetime import timedelta

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import six
from django.utils.translation import ugettext as _
from django.utils.translation import ugettext_lazy as _l

from django_ca import ca_settings
from django_ca import utils
from django_ca.tests.base import DjangoCATestCase
from django_ca.tests.base import override_settings
from django_ca.utils import NAME_RE
from django_ca.utils import LazyEncoder
from django_ca.utils import format_date
from django_ca.utils import format_subject
from django_ca.utils import get_cert_builder
from django_ca.utils import get_cert_profile_kwargs
from django_ca.utils import is_power2
from django_ca.utils import multiline_url_validator
from django_ca.utils import parse_subject
from django_ca.utils import sort_subject_dict


def load_tests(loader, tests, ignore):
    if six.PY3:
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
        self.match('C=" AT "', [('C', ' AT ')])

        # test quotes
        self.match('C=" AT \' DE"', [('C', ' AT \' DE')])
        self.match('C=\' AT " DE\'', [('C', ' AT " DE')])

        self.match('C=AT/DE', [('C', 'AT')])  # slash is delimiter when unquoted
        self.match('C="AT/DE"', [('C', 'AT/DE')])
        self.match("C='AT/DE/US'", [('C', 'AT/DE/US')])
        self.match("C='AT/DE'", [('C', 'AT/DE')])
        self.match("C='AT/DE/US'", [('C', 'AT/DE/US')])

        self.match("C='AT \\' DE'", [('C', "AT \\' DE")])

    def test_two(self):
        self.match('C=AT/OU=example', [('C', 'AT'), ('OU', 'example')])
        self.match('C="AT"/OU=example', [('C', 'AT'), ('OU', 'example')])
        self.match('C=" AT "/OU=example', [('C', ' AT '), ('OU', 'example')])

        # test quotes
        self.match('C=" AT \' DE"/OU=example', [('C', ' AT \' DE'), ('OU', 'example')])
        self.match('C=\' AT " DE\'/OU=example', [('C', ' AT " DE'), ('OU', 'example')])

        self.match('C=AT/DE/OU=example', [('C', 'AT'), ('OU', 'example')])
        self.match('C="AT/DE"/OU=example', [('C', 'AT/DE'), ('OU', 'example')])
        self.match("C='AT/DE/US'/OU=example", [('C', 'AT/DE/US'), ('OU', 'example')])
        self.match("C='AT/DE'/OU=example", [('C', 'AT/DE'), ('OU', 'example')])
        self.match("C='AT/DE/US'/OU=example", [('C', 'AT/DE/US'), ('OU', 'example')])

        self.match("C='AT \\' DE'/OU=example", [('C', "AT \\' DE"), ('OU', 'example')])

        # now both are quoted
        self.match('C="AT"/OU="ex ample"', [('C', 'AT'), ('OU', 'ex ample')])
        self.match('C=" AT "/OU="ex ample"', [('C', ' AT '), ('OU', 'ex ample')])
        self.match('C=" AT \' DE"/OU="ex ample"', [('C', ' AT \' DE'), ('OU', 'ex ample')])
        self.match('C=\' AT " DE\'/OU="ex ample"', [('C', ' AT " DE'), ('OU', 'ex ample')])
        self.match('C=AT/DE/OU="ex ample"', [('C', 'AT'), ('OU', 'ex ample')])
        self.match('C="AT/DE"/OU="ex ample"', [('C', 'AT/DE'), ('OU', 'ex ample')])
        self.match("C='AT/DE/US'/OU='ex ample'", [('C', 'AT/DE/US'), ('OU', 'ex ample')])
        self.match("C='AT/DE'/OU='ex ample'", [('C', 'AT/DE'), ('OU', 'ex ample')])
        self.match("C='AT/DE/US'/OU='ex ample'", [('C', 'AT/DE/US'), ('OU', 'ex ample')])

        self.match("C='AT \\' DE'/OU='ex ample'", [('C', "AT \\' DE"), ('OU', 'ex ample')])

        # Now include a slash in OU
        self.match('C="AT"/OU="ex / ample"', [('C', 'AT'), ('OU', 'ex / ample')])
        self.match('C=" AT "/OU="ex / ample"', [('C', ' AT '), ('OU', 'ex / ample')])
        self.match('C=" AT \' DE"/OU="ex / ample"', [('C', ' AT \' DE'), ('OU', 'ex / ample')])
        self.match('C=\' AT " DE\'/OU="ex / ample"', [('C', ' AT " DE'), ('OU', 'ex / ample')])
        self.match('C=AT/DE/OU="ex / ample"', [('C', 'AT'), ('OU', 'ex / ample')])
        self.match('C="AT/DE"/OU="ex / ample"', [('C', 'AT/DE'), ('OU', 'ex / ample')])
        self.match("C='AT/DE/US'/OU='ex / ample'", [('C', 'AT/DE/US'), ('OU', 'ex / ample')])
        self.match("C='AT/DE'/OU='ex / ample'", [('C', 'AT/DE'), ('OU', 'ex / ample')])
        self.match("C='AT/DE/US'/OU='ex / ample'", [('C', 'AT/DE/US'), ('OU', 'ex / ample')])
        self.match("C='AT \\' DE'/OU='ex / ample'", [('C', "AT \\' DE"), ('OU', 'ex / ample')])

        # Append a slash in the end (It's a delimiter - doesn't influence the output)
        self.match('C="AT"/OU="ex / ample"/', [('C', 'AT'), ('OU', 'ex / ample')])
        self.match('C=" AT "/OU="ex / ample"/', [('C', ' AT '), ('OU', 'ex / ample')])
        self.match('C=" AT \' DE"/OU="ex / ample"/', [('C', ' AT \' DE'), ('OU', 'ex / ample')])
        self.match('C=\' AT " DE\'/OU="ex / ample"/', [('C', ' AT " DE'), ('OU', 'ex / ample')])
        self.match('C=AT/DE/OU="ex / ample"/', [('C', 'AT'), ('OU', 'ex / ample')])
        self.match('C="AT/DE"/OU="ex / ample"/', [('C', 'AT/DE'), ('OU', 'ex / ample')])
        self.match("C='AT/DE/US'/OU='ex / ample'/", [('C', 'AT/DE/US'), ('OU', 'ex / ample')])
        self.match("C='AT/DE'/OU='ex / ample'/", [('C', 'AT/DE'), ('OU', 'ex / ample')])
        self.match("C='AT/DE/US'/OU='ex / ample'/", [('C', 'AT/DE/US'), ('OU', 'ex / ample')])
        self.match("C='AT \\' DE'/OU='ex / ample'/", [('C', "AT \\' DE"), ('OU', 'ex / ample')])

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


class FormatDateTestCase(TestCase):
    def test_format(self):
        d = datetime(2016, 3, 5, 14, 53, 12)
        self.assertEqual(format_date(d), '20160305145312Z')


class ParseSubjectTestCase(TestCase):
    def test_basic(self):
        self.assertEqual(parse_subject('/CN=example.com'), {'CN': 'example.com'})

        # leading or trailing spaces are always ok.
        self.assertEqual(parse_subject(' /CN = example.com '), {'CN': 'example.com'})

        # emailAddress is special because of the case
        self.assertEqual(parse_subject('/emailAddress=user@example.com'),
                         {'emailAddress': 'user@example.com'})

    def test_multiple(self):
        self.assertEqual(parse_subject('/C=AT/OU=foo/CN=example.com'),
                         {'C': 'AT', 'OU': 'foo', 'CN': 'example.com'})

    def test_case(self):
        # test that we generally ignore case in subject keys
        self.assertEqual(
            parse_subject('/c=AT/ou=foo/cn=example.com/eMAIladdreSS=user@example.com'),
            {'C': 'AT', 'OU': 'foo', 'CN': 'example.com', 'emailAddress': 'user@example.com'})

    def test_emtpy(self):
        # empty subjects are ok
        self.assertEqual(parse_subject(''), {})
        self.assertEqual(parse_subject('   '), {})

    def test_multiple_slashes(self):
        self.assertEqual(parse_subject('/C=AT/O=GNU'), {'C': 'AT', 'O': 'GNU'})
        self.assertEqual(parse_subject('//C=AT/O=GNU'), {'C': 'AT', 'O': 'GNU'})
        self.assertEqual(parse_subject('/C=AT//O=GNU'), {'C': 'AT', 'O': 'GNU'})
        self.assertEqual(parse_subject('/C=AT///O=GNU'), {'C': 'AT', 'O': 'GNU'})

    def test_empty_field(self):
        self.assertEqual(parse_subject('/C=AT/O=GNU/OU=foo'), {'C': 'AT', 'O': 'GNU', 'OU': 'foo'})
        self.assertEqual(parse_subject('/C=/O=GNU/OU=foo'), {'C': '', 'O': 'GNU', 'OU': 'foo'})
        self.assertEqual(parse_subject('/C=AT/O=/OU=foo'), {'C': 'AT', 'O': '', 'OU': 'foo'})
        self.assertEqual(parse_subject('/C=AT/O=GNU/OU='), {'C': 'AT', 'O': 'GNU', 'OU': ''})
        self.assertEqual(parse_subject('/C=/O=/OU='), {'C': '', 'O': '', 'OU': ''})

    def test_no_slash_at_start(self):
        with self.assertRaises(ValueError) as e:
            parse_subject('CN=example.com')
        self.assertEqual(e.exception.args, ('Unparseable subject: Does not start with a "/".', ))

    def test_duplicate_fields(self):
        with self.assertRaises(ValueError) as e:
            parse_subject('/CN=example.com/ CN = example.org')
        self.assertEqual(e.exception.args, ('Unparseable subject: Duplicate field "CN".', ))

    def test_unknown(self):
        field = 'ABC'
        with self.assertRaises(ValueError) as e:
            parse_subject('/%s=example.com' % field)
        self.assertEqual(e.exception.args, ('Unparseable subject: Unknown field "%s".' % field, ))


class FormatSubjectTestCase(TestCase):
    def test_basic(self):
        subject = '/C=AT/ST=Vienna/L=Vienna/O=O/OU=OU/CN=example.com/emailAddress=user@example.com'

        subject_dict = {'emailAddress': 'user@example.com', 'C': 'AT', 'L': 'Vienna',
                        'ST': 'Vienna', 'O': 'O', 'OU': 'OU', 'CN': 'example.com', }
        self.assertEqual(format_subject(subject_dict), subject)

        subject_list = sort_subject_dict(subject_dict)
        self.assertEqual(format_subject(subject_list), subject)


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


class MultilineURLValidatorTestCase(TestCase):
    def test_basic(self):
        multiline_url_validator('')
        multiline_url_validator('http://example.com')
        multiline_url_validator('http://example.com\nhttp://www.example.org')
        multiline_url_validator('''http://example.com\nhttp://www.example.org
http://www.example.net''')

    def test_error(self):
        with self.assertRaises(ValidationError):
            multiline_url_validator('foo')
        with self.assertRaises(ValidationError):
            multiline_url_validator('foo\nhttp://www.example.com')
        with self.assertRaises(ValidationError):
            multiline_url_validator('http://www.example.com\nfoo')
        with self.assertRaises(ValidationError):
            multiline_url_validator('http://www.example.com\nfoo\nhttp://example.org')


class GetBasicCertTestCase(TestCase):
    def parse_date(self, date):
        return datetime.strptime(date, '%Y%m%d%H%M%SZ')

    def assertCert(self, delta):
        now = datetime.utcnow()
        before = now.replace(second=0, microsecond=0)
        after = before.replace(hour=0, minute=0) + timedelta(delta + 1)

        cert = get_cert_builder(after, now=now)  # NOQA

        # TODO: Write new tests for this function
        # self.assertFalse(cert.has_expired())
        # self.assertEqual(self.parse_date(cert.get_notBefore().decode('utf-8')), before)
        # self.assertEqual(self.parse_date(cert.get_notAfter().decode('utf-8')), after)

    def test_basic(self):
        self.assertCert(720)
        self.assertCert(365)

    def test_zero(self):
        self.assertCert(0)

    def test_negative(self):
        with self.assertRaises(ValueError):
            self.assertCert(-1)
        with self.assertRaises(ValueError):
            self.assertCert(-2)


class GetCertProfileKwargsTestCase(DjangoCATestCase):
    # NOTE: These test-cases will start failing if you change the default profiles.

    @override_settings(CA_PROFILES={})
    def test_default(self):
        expected = {
            'cn_in_san': True,
            'keyUsage': (True, b'digitalSignature,keyAgreement,keyEncipherment'),
            'extendedKeyUsage': (False, b'serverAuth'),
            'subject': {
                'C': 'AT',
                'L': 'Vienna',
                'O': 'Django CA',
                'OU': 'Django CA Testsuite',
                'ST': 'Vienna',
            },
        }
        self.assertEqual(get_cert_profile_kwargs(), expected)
        self.assertEqual(get_cert_profile_kwargs(ca_settings.CA_DEFAULT_PROFILE), expected)

    def test_types(self):
        expected = {
            'cn_in_san': True,
            'keyUsage': (False, b'digitalSignature'),
            'subject': {
                'C': 'AT',
                'L': 'Vienna',
                'O': 'Django CA',
                'OU': 'Django CA Testsuite',
                'ST': 'Vienna',
            },
        }

        CA_PROFILES = {
            'testprofile': {
                'keyUsage': {
                    'critical': False,
                    'value': 'digitalSignature',
                },
            },
        }

        with self.settings(CA_PROFILES=CA_PROFILES):
            self.assertEqual(get_cert_profile_kwargs('testprofile'), expected)

        CA_PROFILES['testprofile']['keyUsage']['value'] = b'encipherOnly'
        expected['keyUsage'] = (False, b'encipherOnly')
        with self.settings(CA_PROFILES=CA_PROFILES):
            self.assertEqual(get_cert_profile_kwargs('testprofile'), expected)

        CA_PROFILES['testprofile']['keyUsage']['value'] = b''
        del expected['keyUsage']
        with self.settings(CA_PROFILES=CA_PROFILES):
            self.assertEqual(get_cert_profile_kwargs('testprofile'), expected)

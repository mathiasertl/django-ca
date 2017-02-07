"""Test utility functions."""

import json

from datetime import datetime
from datetime import timedelta

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils.translation import ugettext as _
from django.utils.translation import ugettext_lazy as _l

from django_ca import ca_settings
from django_ca.tests.base import DjangoCATestCase
from django_ca.tests.base import override_settings
from django_ca.utils import format_date
from django_ca.utils import format_subject
from django_ca.utils import parse_subject
from django_ca.utils import sort_subject_dict
from django_ca.utils import get_basic_cert
from django_ca.utils import get_cert_profile_kwargs
from django_ca.utils import is_power2
from django_ca.utils import get_subjectAltName
from django_ca.utils import LazyEncoder
from django_ca.utils import multiline_url_validator


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
        self.assertEqual(parse_subject('/c=AT/ou=foo/cn=example.com/eMAIladdreSS=user@example.com'),
                         {'C': 'AT', 'OU': 'foo', 'CN': 'example.com',
                          'emailAddress': 'user@example.com'})

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

        cert = get_basic_cert(after, now=now)
        self.assertFalse(cert.has_expired())
        self.assertEqual(self.parse_date(cert.get_notBefore().decode('utf-8')), before)
        self.assertEqual(self.parse_date(cert.get_notAfter().decode('utf-8')), after)

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


class GetSubjectAltNamesTest(TestCase):
    def test_basic(self):
        self.assertEqual(get_subjectAltName(['https://example.com']), b'URI:https://example.com')
        self.assertEqual(get_subjectAltName(['user@example.com']), b'email:user@example.com')
        self.assertEqual(get_subjectAltName(['example.com']), b'DNS:example.com')
        self.assertEqual(get_subjectAltName(['8.8.8.8']), b'IP:8.8.8.8')

        # NOTE: I could not find any info on if this format is correct or we need to use square
        #       brackets
        self.assertEqual(get_subjectAltName(['2001:4860:4860::8888']), b'IP:2001:4860:4860::8888')

    def test_multiple(self):
        self.assertEqual(get_subjectAltName(
            ['https://example.com', 'https://example.org']),
            b'URI:https://example.com,URI:https://example.org')

        self.assertEqual(get_subjectAltName(
            ['https://example.com', 'user@example.org']),
            b'URI:https://example.com,email:user@example.org')

    def test_literal(self):
        self.assertEqual(get_subjectAltName(['URI:foo']), b'URI:foo')
        self.assertEqual(get_subjectAltName(['email:foo']), b'email:foo')
        self.assertEqual(get_subjectAltName(['IP:foo']), b'IP:foo')
        self.assertEqual(get_subjectAltName(['RID:foo']), b'RID:foo')
        self.assertEqual(get_subjectAltName(['dirName:foo']), b'dirName:foo')
        self.assertEqual(get_subjectAltName(['otherName:foo']), b'otherName:foo')

    def test_empty(self):
        self.assertEqual(get_subjectAltName([]), b'')
        self.assertEqual(get_subjectAltName(['']), b'')

    def test_bytes(self):
        self.assertEqual(get_subjectAltName([b'example.com']), b'DNS:example.com')
        self.assertEqual(get_subjectAltName([b'DNS:example.com']), b'DNS:example.com')

    def test_cn(self):
        self.assertEqual(get_subjectAltName([], cn='example.com'), b'DNS:example.com')
        self.assertEqual(get_subjectAltName(['example.com'], cn='example.com'), b'DNS:example.com')
        self.assertEqual(get_subjectAltName(['DNS:example.com'], cn='example.com'),
                         b'DNS:example.com')

        self.assertEqual(
            get_subjectAltName(['example.com', 'example.org'], cn='example.com'),
            b'DNS:example.com,DNS:example.org')

        self.assertEqual(
            get_subjectAltName(['example.org'], cn='example.com'),
            b'DNS:example.com,DNS:example.org')

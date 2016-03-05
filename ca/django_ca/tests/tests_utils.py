"""Test utility functions."""

from datetime import datetime
from datetime import timedelta

from django.test import TestCase

from django_ca import ca_settings
from django_ca.tests.base import DjangoCATestCase
from django_ca.tests.base import override_settings
from django_ca.utils import format_date
from django_ca.utils import get_basic_cert
from django_ca.utils import get_cert_profile_kwargs
from django_ca.utils import is_power2
from django_ca.utils import parse_date
from django_ca.utils import get_subjectAltName


class FormatDateTestCase(TestCase):
    def test_format(self):
        d = datetime(2016, 3, 5, 14, 53, 12)
        self.assertEqual(format_date(d), '20160305145312Z')

    def test_parse(self):
        d = datetime(2016, 3, 5, 14, 53, 12)
        formatted = '20160305145312Z'
        self.assertEqual(parse_date(formatted), d)

    def test_indempotent(self):
        d = datetime(2016, 3, 5, 14, 53, 12)
        f = format_date(d)
        self.assertEqual(d, parse_date(f))


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


class GetBasicCertTestCase(TestCase):
    def assertCert(self, delta):
        now = datetime.utcnow()
        before = now.replace(second=0, microsecond=0)
        after = before.replace(hour=0, minute=0) + timedelta(delta + 1)

        cert = get_basic_cert(delta, now=now)
        self.assertFalse(cert.has_expired())
        self.assertEqual(parse_date(cert.get_notBefore().decode('utf-8')), before)
        self.assertEqual(parse_date(cert.get_notAfter().decode('utf-8')), after)

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
                'OU': 'Fachschaft Informatik',
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
                'OU': 'Fachschaft Informatik',
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


class GetSubjectAltNamesTest(TestCase):
    def test_basic(self):
        self.assertEqual(get_subjectAltName(['https://example.com']), b'URI:https://example.com')
        self.assertEqual(get_subjectAltName(['user@example.com']), b'email:user@example.com')
        self.assertEqual(get_subjectAltName(['example.com']), b'DNS:example.com')
        self.assertEqual(get_subjectAltName(['8.8.8.8']), b'IP:8.8.8.8')

        # NOTE: I could not find any info on if this format is correct or we need to use square brackets
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

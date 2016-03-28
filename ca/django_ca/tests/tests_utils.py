"""Test utility functions."""

import json

from datetime import datetime
from datetime import timedelta

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils.translation import ugettext as _
from django.utils.translation import ugettext_lazy as _l

from django_ca import ca_settings
from django_ca.models import CertificateAuthority
from django_ca.tests.base import DjangoCATestCase
from django_ca.tests.base import DjangoCAWithCSRTestCase
from django_ca.tests.base import override_settings
from django_ca.tests.base import override_tmpcadir
from django_ca.utils import format_date
from django_ca.utils import get_basic_cert
from django_ca.utils import get_cert
from django_ca.utils import get_cert_profile_kwargs
from django_ca.utils import is_power2
from django_ca.utils import parse_date
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


class MultilineURLValidatorTestCase(TestCase):
    def test_basic(self):
        multiline_url_validator('')
        multiline_url_validator('http://example.com')
        multiline_url_validator('http://example.com\nhttp://www.example.org')
        multiline_url_validator('http://example.com\nhttp://www.example.org\nhttp://www.example.net')

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
        self.assertEqual(get_subjectAltName([b'DNS:example.com']), b'DNS:example.com')

    def test_cn(self):
        self.assertEqual(get_subjectAltName([], cn='example.com'), b'DNS:example.com')
        self.assertEqual(get_subjectAltName(['example.com'], cn='example.com'), b'DNS:example.com')
        self.assertEqual(get_subjectAltName(['DNS:example.com'], cn='example.com'), b'DNS:example.com')

        self.assertEqual(
            get_subjectAltName(['example.com', 'example.org'], cn='example.com'),
            b'DNS:example.com,DNS:example.org')

        self.assertEqual(
            get_subjectAltName(['example.org'], cn='example.com'),
            b'DNS:example.com,DNS:example.org')


@override_tmpcadir(CA_PROFILES={})
class GetCertTestCase(DjangoCAWithCSRTestCase):
    def assertExtensions(self, cert, expected):
        expected[b'basicConstraints'] = 'CA:FALSE'
        expected[b'authorityKeyIdentifier'] = self.ca.authorityKeyIdentifier()

        if self.ca.issuer_alt_name:
            expected[b'issuerAltName'] = 'URI:%s' % self.ca.issuer_alt_name
        else:
            expected[b'issuerAltName'] = self.ca.subjectAltName()

        # TODO: Does not account for multiple CRLs yet
        if self.ca.crl_url:
            expected[b'crlDistributionPoints']  = '\nFull Name:\n  URI:%s\n' % self.ca.crl_url

        auth_info_access = ''
        if self.ca.ocsp_url:
            auth_info_access += 'OCSP - URI:%s\n' % self.ca.ocsp_url
        if self.ca.issuer_url:
            auth_info_access += 'CA Issuers - URI:%s\n' % self.ca.issuer_url
        if auth_info_access:
            expected[b'authorityInfoAccess'] = auth_info_access

        exts = [cert.get_extension(i) for i in range(0, cert.get_extension_count())]
        exts = {ext.get_short_name(): str(ext) for ext in exts}

        # TODO: Can't find out how to calculate this, so we just verify presence and length
        skid = exts.pop(b'subjectKeyIdentifier')
        self.assertEqual(len(skid), 59)

        self.assertEqual(exts, expected)

    def test_basic(self):
        kwargs = get_cert_profile_kwargs()

        cert = get_cert(self.ca, self.csr_pem, expires=720, algorithm='sha256',
                        subjectAltName=['example.com'], **kwargs)

        self.assertEqual(cert.get_signature_algorithm(), b'sha256WithRSAEncryption')

        # verify subject
        expected_subject = kwargs['subject']
        expected_subject['CN'] = 'example.com'
        self.assertSubject(cert, list(expected_subject.items()))

        self.assertEqual(cert.get_signature_algorithm(), b'sha256WithRSAEncryption')

        # verify extensions
        extensions = {
#            b'authorityInfoAccess': 'OCSP - URI:https://ocsp.ca.example.com\n'
#                                    'CA Issuers - URI:https://ca.example.com/ca.crt\n',
            b'extendedKeyUsage': 'TLS Web Server Authentication',
            b'keyUsage': 'Digital Signature, Key Encipherment, Key Agreement',
            b'subjectAltName': 'DNS:example.com',
        }

        self.assertExtensions(cert, extensions)

    def test_no_subject(self):
        kwargs = get_cert_profile_kwargs()
        del kwargs['subject']
        cert = get_cert(self.ca, self.csr_pem, expires=720, algorithm='sha256',
                        subjectAltName=['example.com'], **kwargs)

        self.assertSubject(cert, [('CN', 'example.com')])

        # verify extensions
        self.assertExtensions(cert, {
            b'extendedKeyUsage': 'TLS Web Server Authentication',
            b'keyUsage': 'Digital Signature, Key Encipherment, Key Agreement',
            b'subjectAltName': 'DNS:example.com',
        })

    def test_no_names(self):
        kwargs = get_cert_profile_kwargs()
        del kwargs['subject']

        with self.assertRaises(ValueError):
            get_cert(self.ca, self.csr_pem, expires=720, algorithm='sha256', subjectAltName=[],
                     **kwargs)
        with self.assertRaises(ValueError):
            get_cert(self.ca, self.csr_pem, expires=720, algorithm='sha256', subjectAltName=None,
                     **kwargs)

    def test_cn_in_san(self):
        kwargs = get_cert_profile_kwargs()
        kwargs['subject']['CN'] = 'cn.example.com'
        cert = get_cert(self.ca, self.csr_pem, expires=720, algorithm='sha256',
                        subjectAltName=['example.com'], **kwargs)

        self.assertEqual(self.get_subject(cert)['CN'], 'cn.example.com')
        self.assertIn('subjectAltName', self.get_extensions(cert))
        self.assertEqual(['DNS:cn.example.com', 'DNS:example.com'], self.get_alt_names(cert))

        # try the same with no SAN at all
        cert = get_cert(self.ca, self.csr_pem, expires=720, algorithm='sha256', **kwargs)
        self.assertEqual(self.get_subject(cert)['CN'], 'cn.example.com')
        self.assertIn('subjectAltName', self.get_extensions(cert))
        self.assertEqual(['DNS:cn.example.com'], self.get_alt_names(cert))

    def test_cn_not_in_san(self):
        kwargs = get_cert_profile_kwargs()
        kwargs['subject']['CN'] = 'cn.example.com'
        kwargs['cn_in_san'] = False
        cert = get_cert(self.ca, self.csr_pem, expires=720, algorithm='sha256',
                        subjectAltName=['example.com'], **kwargs)
        self.assertEqual(self.get_subject(cert)['CN'], 'cn.example.com')
        self.assertIn('subjectAltName', self.get_extensions(cert))
        self.assertEqual(['DNS:example.com'], self.get_alt_names(cert))

    def test_no_san(self):
        kwargs = get_cert_profile_kwargs()
        kwargs['subject']['CN'] = 'cn.example.com'
        kwargs['cn_in_san'] = False
        cert = get_cert(self.ca, self.csr_pem, expires=720, algorithm='sha256', **kwargs)
        self.assertEqual(self.get_subject(cert)['CN'], 'cn.example.com')
        self.assertNotIn('subjectAltName', self.get_extensions(cert))

    def test_no_key_usage(self):
        kwargs = get_cert_profile_kwargs()
        del kwargs['keyUsage']
        cert = get_cert(self.ca, self.csr_pem, expires=720, algorithm='sha256',
                        subjectAltName=['example.com'], **kwargs)
        self.assertNotIn('keyUsage', self.get_extensions(cert))

    def test_no_ext_key_usage(self):
        kwargs = get_cert_profile_kwargs()
        del kwargs['extendedKeyUsage']
        cert = get_cert(self.ca, self.csr_pem, expires=720, algorithm='sha256',
                        subjectAltName=['example.com'], **kwargs)
        self.assertNotIn('extendedKeyUsage', self.get_extensions(cert))

    def test_crl(self):
        # get from the db to make sure that values do not influence other testcases
        ca = CertificateAuthority.objects.first()
        ca.crl_url = 'http://crl.example.com'

        kwargs = get_cert_profile_kwargs()
        cert = get_cert(ca, self.csr_pem, expires=720, algorithm='sha256',
                        subjectAltName=['example.com'], **kwargs)
        self.assertEqual(self.get_extensions(cert)['crlDistributionPoints'],
                         '\nFull Name:\n  URI:%s\n' % ca .crl_url)

        # test multiple URLs
        ca.crl_url = 'http://crl.example.com\nhttp://crl.example.org'
        kwargs = get_cert_profile_kwargs()
        cert = get_cert(ca, self.csr_pem, expires=720, algorithm='sha256',
                        subjectAltName=['example.com'], **kwargs)

        expected = '\nFull Name:\n  URI:%s\n\nFull Name:\n  URI:%s\n' % tuple(
            ca.crl_url.splitlines())
        self.assertEqual(self.get_extensions(cert)['crlDistributionPoints'], expected)

    def test_issuer_alt_name(self):
        ca = CertificateAuthority.objects.first()
        ca.issuer_alt_name = 'http://ian.example.com'

        kwargs = get_cert_profile_kwargs()
        cert = get_cert(ca, self.csr_pem, expires=720, algorithm='sha256',
                        subjectAltName=['example.com'], **kwargs)

        self.assertEqual(self.get_extensions(cert)['issuerAltName'], 'URI:%s' % ca.issuer_alt_name)

    def test_auth_info_access(self):
        ca = CertificateAuthority.objects.first()
        kwargs = get_cert_profile_kwargs()

        # test only with ocsp url
        ca.ocsp_url = 'http://ocsp.ca.example.com'
        cert = get_cert(ca, self.csr_pem, expires=720, algorithm='sha256',
                        subjectAltName=['example.com'], **kwargs)

        self.assertEqual(self.get_extensions(cert)['authorityInfoAccess'],
                         'OCSP - URI:%s\n' % ca.ocsp_url)

        # test with both ocsp_url and issuer_url
        ca.issuer_url = 'http://ca.example.com/ca.crt'
        cert = get_cert(ca, self.csr_pem, expires=720, algorithm='sha256',
                        subjectAltName=['example.com'], **kwargs)

        self.assertEqual(self.get_extensions(cert)['authorityInfoAccess'],
                         'OCSP - URI:%s\nCA Issuers - URI:%s\n' % (ca.ocsp_url, ca.issuer_url))

        # test only with issuer url
        ca.ocsp_url = None
        cert = get_cert(ca, self.csr_pem, expires=720, algorithm='sha256',
                        subjectAltName=['example.com'], **kwargs)

        self.assertEqual(self.get_extensions(cert)['authorityInfoAccess'],
                         'CA Issuers - URI:%s\n' % ca.issuer_url)

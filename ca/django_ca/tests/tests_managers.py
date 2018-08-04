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

from cryptography.hazmat.primitives import hashes

from ..models import Certificate
from ..models import CertificateAuthority
from ..subject import Subject
from ..utils import get_cert_profile_kwargs
from .base import DjangoCAWithCSRTestCase
from .base import override_tmpcadir


@override_tmpcadir(CA_PROFILES={}, CA_DEFAULT_SUBJECT={})
class GetCertTestCase(DjangoCAWithCSRTestCase):
    def assertExtensions(self, cert, expected):
        expected['basicConstraints'] = (True, 'CA:FALSE')
        expected['authorityKeyIdentifier'] = self.ca.authorityKeyIdentifier()

        if self.ca.issuer_alt_name:
            expected[b'issuerAltName'] = 'URI:%s' % self.ca.issuer_alt_name

        # TODO: Does not account for multiple CRLs yet
        if self.ca.crl_url:
            expected['crlDistributionPoints'] = '\nFull Name:\n  URI:%s\n' % self.ca.crl_url

        auth_info_access = ''
        if self.ca.ocsp_url:
            auth_info_access += 'OCSP - URI:%s\n' % self.ca.ocsp_url
        if self.ca.issuer_url:
            auth_info_access += 'CA Issuers - URI:%s\n' % self.ca.issuer_url
        if auth_info_access:
            expected[b'authorityInfoAccess'] = auth_info_access

        c = Certificate()
        c.x509 = cert
        exts = [e.oid._name for e in cert.extensions]
        exts = {name: getattr(c, name)() for name in exts}

        skid_critical, skid = exts.pop('subjectKeyIdentifier')
        self.assertFalse(skid_critical)
        self.assertEqual(len(skid), 59)

        self.assertEqual(exts, expected)

    def test_basic(self):
        kwargs = get_cert_profile_kwargs()
        kwargs['subject'] = Subject(kwargs['subject'])

        cert = Certificate.objects.init(
            self.ca, self.csr_pem, expires=self.expires(720), algorithm=hashes.SHA256(),
            subjectAltName=['example.com'], **kwargs)
        cert.full_clean()

        self.assertBasic(cert.x509)

        # verify subject
        expected_subject = [
            ('CN', 'example.com'),
        ]
        self.assertSubject(cert.x509, expected_subject)

        # verify extensions
        extensions = {
            'extendedKeyUsage': (False, ['serverAuth']),
            'keyUsage': (True, ['digitalSignature', 'keyAgreement', 'keyEncipherment']),
            'subjectAltName': (False, ['DNS:example.com']),
        }

        self.assertExtensions(cert.x509, extensions)

    def test_no_subject(self):
        kwargs = get_cert_profile_kwargs()
        del kwargs['subject']
        cert = Certificate.objects.init(
            self.ca, self.csr_pem, expires=self.expires(720), algorithm=hashes.SHA256(),
            subjectAltName=['example.com'], **kwargs)

        self.assertSubject(cert.x509, [('CN', 'example.com')])

        # verify extensions
        self.assertExtensions(cert.x509, {
            'extendedKeyUsage': (False, ['serverAuth']),
            'keyUsage': (True, ['digitalSignature', 'keyAgreement', 'keyEncipherment']),
            'subjectAltName': (False, ['DNS:example.com']),
        })

    def test_no_names(self):
        kwargs = get_cert_profile_kwargs()
        del kwargs['subject']

        with self.assertRaises(ValueError):
            Certificate.objects.init(
                self.ca, self.csr_pem, expires=self.expires(720), algorithm=hashes.SHA256(),
                subjectAltName=[], **kwargs)
        with self.assertRaises(ValueError):
            Certificate.objects.init(
                self.ca, self.csr_pem, expires=self.expires(720), algorithm=hashes.SHA256(),
                subjectAltName=None, **kwargs)

    def test_cn_in_san(self):
        kwargs = get_cert_profile_kwargs()
        kwargs['subject'] = Subject(kwargs['subject'])
        kwargs['subject']['CN'] = 'cn.example.com'
        cert = Certificate.objects.init(
            self.ca, self.csr_pem, expires=self.expires(720), algorithm=hashes.SHA256(),
            subjectAltName=['example.com'], **kwargs)

        self.assertEqual(self.get_subject(cert.x509)['CN'], 'cn.example.com')
        self.assertIn('subjectAltName', self.get_extensions(cert.x509))
        self.assertEqual(['DNS:cn.example.com', 'DNS:example.com'], self.get_alt_names(cert.x509))

        # try the same with no SAN at all
        cert = Certificate.objects.init(
            self.ca, self.csr_pem, expires=self.expires(720), algorithm=hashes.SHA256(), **kwargs)
        self.assertEqual(self.get_subject(cert.x509)['CN'], 'cn.example.com')
        self.assertIn('subjectAltName', self.get_extensions(cert.x509))
        self.assertEqual(['DNS:cn.example.com'], self.get_alt_names(cert.x509))

    def test_cn_not_in_san(self):
        kwargs = get_cert_profile_kwargs()
        kwargs['subject'] = Subject(kwargs['subject'])
        kwargs['subject']['CN'] = 'cn.example.com'
        kwargs['cn_in_san'] = False
        cert = Certificate.objects.init(
            self.ca, self.csr_pem, expires=self.expires(720), algorithm=hashes.SHA256(),
            subjectAltName=['example.com'], **kwargs)

        self.assertEqual(self.get_subject(cert.x509)['CN'], 'cn.example.com')
        self.assertIn('subjectAltName', self.get_extensions(cert.x509))
        self.assertEqual(['DNS:example.com'], self.get_alt_names(cert.x509))

    def test_no_san(self):
        kwargs = get_cert_profile_kwargs()
        kwargs['subject'] = Subject(kwargs['subject'])
        kwargs['subject']['CN'] = 'cn.example.com'
        kwargs['cn_in_san'] = False
        cert = Certificate.objects.init(
            self.ca, self.csr_pem, expires=self.expires(720), algorithm=hashes.SHA256(), **kwargs)
        self.assertEqual(self.get_subject(cert.x509)['CN'], 'cn.example.com')
        self.assertNotIn('subjectAltName', self.get_extensions(cert.x509))

    def test_no_key_usage(self):
        kwargs = get_cert_profile_kwargs()
        kwargs['subject'] = Subject(kwargs['subject'])
        del kwargs['keyUsage']
        cert = Certificate.objects.init(
            self.ca, self.csr_pem, expires=self.expires(720), algorithm=hashes.SHA256(),
            subjectAltName=['example.com'], **kwargs)
        self.assertNotIn('keyUsage', self.get_extensions(cert.x509))

    def test_no_ext_key_usage(self):
        kwargs = get_cert_profile_kwargs()
        kwargs['subject'] = Subject(kwargs['subject'])
        del kwargs['extendedKeyUsage']
        cert = Certificate.objects.init(
            self.ca, self.csr_pem, expires=self.expires(720), algorithm=hashes.SHA256(),
            subjectAltName=['example.com'], **kwargs)
        self.assertNotIn('extendedKeyUsage', self.get_extensions(cert.x509))

    def test_crl(self):
        # get from the db to make sure that values do not influence other testcases
        ca = CertificateAuthority.objects.first()
        ca.crl_url = 'http://crl.example.com'

        kwargs = get_cert_profile_kwargs()
        kwargs['subject'] = Subject(kwargs['subject'])
        cert = Certificate.objects.init(
            ca, self.csr_pem, expires=self.expires(720), algorithm=hashes.SHA256(),
            subjectAltName=['example.com'], **kwargs)
        self.assertEqual(self.get_extensions(cert.x509)['crlDistributionPoints'],
                         (False, ['Full Name: URI:%s' % ca .crl_url]))

        # test multiple URLs
        ca.crl_url = 'http://crl.example.com\nhttp://crl.example.org'
        kwargs = get_cert_profile_kwargs()
        kwargs['subject'] = Subject(kwargs['subject'])
        cert = Certificate.objects.init(
            ca, self.csr_pem, expires=self.expires(720), algorithm=hashes.SHA256(),
            subjectAltName=['example.com'], **kwargs)

        crl_a, crl_b = ca.crl_url.splitlines()
        expected = ['Full Name: URI:%s' % url for url in ca.crl_url.splitlines()]
        self.assertEqual(self.get_extensions(cert.x509)['crlDistributionPoints'], (False, expected))

    def test_issuer_alt_name(self):
        ca = CertificateAuthority.objects.first()
        ca.issuer_alt_name = 'http://ian.example.com'

        kwargs = get_cert_profile_kwargs()
        kwargs['subject'] = Subject(kwargs['subject'])
        cert = Certificate.objects.init(
            ca, self.csr_pem, expires=self.expires(720), algorithm=hashes.SHA256(),
            subjectAltName=['example.com'], **kwargs)

        self.assertEqual(self.get_extensions(cert.x509)['issuerAltName'],
                         (False, 'URI:%s' % ca.issuer_alt_name))

    def test_auth_info_access(self):
        ca = CertificateAuthority.objects.first()
        kwargs = get_cert_profile_kwargs()
        kwargs['subject'] = Subject(kwargs['subject'])

        # test only with ocsp url
        ca.ocsp_url = 'http://ocsp.ca.example.com'
        cert = Certificate.objects.init(
            ca, self.csr_pem, expires=self.expires(720), algorithm=hashes.SHA256(),
            subjectAltName=['example.com'], **kwargs)

        self.assertEqual(self.get_extensions(cert.x509)['authorityInfoAccess'],
                         (False, ['OCSP - URI:%s' % ca.ocsp_url]))

        # test with both ocsp_url and issuer_url
        ca.issuer_url = 'http://ca.example.com/ca.crt'
        cert = Certificate.objects.init(
            ca, self.csr_pem, expires=self.expires(720), algorithm=hashes.SHA256(),
            subjectAltName=['example.com'], **kwargs)

        self.assertEqual(self.get_extensions(cert.x509)['authorityInfoAccess'],
                         (False, ['OCSP - URI:%s' % ca.ocsp_url, 'CA Issuers - URI:%s' % ca.issuer_url]))

        # test only with issuer url
        ca.ocsp_url = None
        cert = Certificate.objects.init(
            ca, self.csr_pem, expires=self.expires(720), algorithm=hashes.SHA256(),
            subjectAltName=['example.com'], **kwargs)

        self.assertEqual(self.get_extensions(cert.x509)['authorityInfoAccess'],
                         (False, ['CA Issuers - URI:%s' % ca.issuer_url]))

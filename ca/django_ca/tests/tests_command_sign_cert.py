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
# see <http://www.gnu.org/licenses/>

import os
import stat
from datetime import datetime
from datetime import timedelta

from cryptography.hazmat.primitives.serialization import Encoding

from django.core.management.base import CommandError
from django.utils import six

from .. import ca_settings
from ..extensions import ExtendedKeyUsage
from ..extensions import KeyUsage
from ..extensions import SubjectAlternativeName
from ..extensions import TLSFeature
from ..models import Certificate
from ..models import CertificateAuthority
from ..signals import post_issue_cert
from ..signals import pre_issue_cert
from ..subject import Subject
from .base import DjangoCAWithCSRTestCase
from .base import child_pubkey
from .base import override_settings
from .base import override_tmpcadir

if six.PY2:
    import mock
else:
    from unittest import mock  # NOQA


@override_settings(CA_MIN_KEY_SIZE=1024, CA_PROFILES={}, CA_DEFAULT_SUBJECT={})
class SignCertTestCase(DjangoCAWithCSRTestCase):
    def test_from_stdin(self):
        stdin = six.StringIO(self.csr_pem)
        subject = Subject([('CN', 'example.com')])
        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd('sign_cert', subject=subject, stdin=stdin)
        self.assertEqual(stderr, '')
        self.assertEqual(pre.call_count, 1)

        cert = Certificate.objects.first()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertSubject(cert.x509, subject)
        self.assertEqual(stdout, 'Please paste the CSR:\n%s' % cert.pub)

        self.assertEqual(cert.key_usage, KeyUsage('critical,digitalSignature,keyAgreement,keyEncipherment'))
        self.assertEqual(cert.extended_key_usage, ExtendedKeyUsage('serverAuth'))
        self.assertEqual(cert.subject_alternative_name, SubjectAlternativeName('DNS:example.com'))
        self.assertIssuer(self.ca, cert)
        self.assertAuthorityKeyIdentifier(self.ca, cert)

    @override_settings(USE_TZ=True)
    def test_from_stdin_with_use_tz(self):
        self.test_from_stdin()

    def test_ecc_ca(self):
        stdin = six.StringIO(self.csr_pem)
        subject = Subject([('CN', 'ecc-signed.example.com')])
        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd('sign_cert', ca=self.ecc_ca, subject=subject, stdin=stdin)
        self.assertEqual(stderr, '')
        self.assertEqual(pre.call_count, 1)

        cert = Certificate.objects.first()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ecc_ca], cert)
        self.assertSubject(cert.x509, subject)
        self.assertEqual(stdout, 'Please paste the CSR:\n%s' % cert.pub)

        self.assertEqual(cert.key_usage, KeyUsage('critical,digitalSignature,keyAgreement,keyEncipherment'))
        self.assertEqual(cert.extended_key_usage, ExtendedKeyUsage('serverAuth'))
        self.assertEqual(cert.subject_alternative_name, SubjectAlternativeName('DNS:ecc-signed.example.com'))
        self.assertIssuer(self.ecc_ca, cert)
        self.assertAuthorityKeyIdentifier(self.ecc_ca, cert)

    @override_tmpcadir()
    def test_from_file(self):
        csr_path = os.path.join(ca_settings.CA_DIR, 'test.csr')
        with open(csr_path, 'w') as csr_stream:
            csr_stream.write(self.csr_pem)

        try:
            subject = Subject([('CN', 'example.com'), ('emailAddress', 'user@example.com')])
            with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
                stdout, stderr = self.cmd('sign_cert', subject=subject, csr=csr_path)
            self.assertEqual(stderr, '')
            self.assertEqual(pre.call_count, 1)

            cert = Certificate.objects.first()
            self.assertPostIssueCert(post, cert)
            self.assertSignature([self.ca], cert)

            self.assertSubject(cert.x509, subject)
            self.assertEqual(stdout, cert.pub)
            self.assertEqual(cert.key_usage,
                             KeyUsage('critical,digitalSignature,keyAgreement,keyEncipherment'))
            self.assertEqual(cert.extended_key_usage, ExtendedKeyUsage('serverAuth'))
            self.assertEqual(cert.subject_alternative_name, SubjectAlternativeName('DNS:example.com'))
        finally:
            os.remove(csr_path)

    @override_settings(USE_TZ=True)
    def test_from_file_with_tz(self):
        self.test_from_file()

    @override_tmpcadir()
    def test_to_file(self):
        out_path = os.path.join(ca_settings.CA_DIR, 'test.pem')
        stdin = six.StringIO(self.csr_pem)

        try:
            with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
                stdout, stderr = self.cmd('sign_cert', subject=Subject([('CN', 'example.com')]), out=out_path,
                                          stdin=stdin)
            self.assertEqual(pre.call_count, 1)

            cert = Certificate.objects.first()
            self.assertPostIssueCert(post, cert)
            self.assertSignature([self.ca], cert)
            self.assertEqual(stdout, 'Please paste the CSR:\n')
            self.assertEqual(stderr, '')

            self.assertIssuer(self.ca, cert)
            self.assertAuthorityKeyIdentifier(self.ca, cert)

            with open(out_path) as out_stream:
                from_file = out_stream.read()

            self.assertEqual(cert.pub, from_file)
        finally:
            if os.path.exists(out_path):
                os.remove(out_path)

    def test_no_dns_cn(self):
        # Use a CommonName that is *not* a valid DNSName. By default, this is added as a subjectAltName, which
        # should fail.

        stdin = six.StringIO(self.csr_pem)
        cn = 'foo bar'
        msg = r'^%s: Could not parse CommonName as subjectAltName\.$' % cn

        with self.assertRaisesRegex(CommandError, msg), self.assertSignal(pre_issue_cert) as pre, \
                self.assertSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd('sign_cert', subject=Subject([('CN', cn)]), cn_in_san=True,
                                      stdin=stdin)
        self.assertEqual(pre.call_count, 1)
        self.assertFalse(post.called)

    def test_cn_not_in_san(self):
        stdin = six.StringIO(self.csr_pem)
        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd('sign_cert', subject=Subject([('CN', 'example.net')]),
                                      cn_in_san=False, alt=['example.com'], stdin=stdin)
        self.assertEqual(pre.call_count, 1)

        cert = Certificate.objects.first()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertIssuer(self.ca, cert)
        self.assertAuthorityKeyIdentifier(self.ca, cert)
        self.assertSubject(cert.x509, [('CN', 'example.net')])
        self.assertEqual(stdout, 'Please paste the CSR:\n%s' % cert.pub)
        self.assertEqual(stderr, '')
        self.assertEqual(cert.subject_alternative_name, SubjectAlternativeName('DNS:example.com'))

    def test_no_san(self):
        # test with no subjectAltNames:
        stdin = six.StringIO(self.csr_pem)
        subject = Subject([('CN', 'example.net')])
        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd('sign_cert', subject=subject, cn_in_san=False, alt=[], stdin=stdin)
        self.assertEqual(pre.call_count, 1)

        cert = Certificate.objects.first()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertSubject(cert.x509, subject)
        self.assertIssuer(self.ca, cert)
        self.assertAuthorityKeyIdentifier(self.ca, cert)
        self.assertEqual(stdout, 'Please paste the CSR:\n%s' % cert.pub)
        self.assertEqual(stderr, '')
        self.assertIsNone(cert.subject_alternative_name)

    @override_settings(CA_DEFAULT_SUBJECT=[
        ('C', 'AT'),
        ('ST', 'Vienna'),
        ('L', 'Vienna'),
        ('O', 'MyOrg'),
        ('OU', 'MyOrgUnit'),
        ('CN', 'CommonName'),
        ('emailAddress', 'user@example.com'),
    ])
    def test_profile_subject(self):
        # just to make sure we actually have defaults
        self.assertEqual(next(t[1] for t in ca_settings._CA_DEFAULT_SUBJECT if t[0] == 'O'), 'MyOrg')
        self.assertEqual(next(t[1] for t in ca_settings._CA_DEFAULT_SUBJECT if t[0] == 'OU'), 'MyOrgUnit')

        # first, we only pass an subjectAltName, meaning that even the CommonName is used.
        stdin = six.StringIO(self.csr_pem)
        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd('sign_cert', cn_in_san=False, alt=['example.net'], stdin=stdin)
        self.assertEqual(pre.call_count, 1)

        cert = Certificate.objects.first()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertSubject(cert.x509, ca_settings._CA_DEFAULT_SUBJECT)
        self.assertIssuer(self.ca, cert)
        self.assertAuthorityKeyIdentifier(self.ca, cert)

        # replace subject fields via command-line argument:
        subject = Subject([
            ('C', 'US'),
            ('ST', 'California'),
            ('L', 'San Francisco'),
            ('O', 'MyOrg2'),
            ('OU', 'MyOrg2Unit2'),
            ('CN', 'CommonName2'),
            ('emailAddress', 'user@example.net'),
        ])
        stdin = six.StringIO(self.csr_pem)
        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            self.cmd('sign_cert', cn_in_san=False, alt=['example.net'], stdin=stdin, subject=subject)
        self.assertEqual(pre.call_count, 1)

        cert = Certificate.objects.get(cn='CommonName2')
        self.assertPostIssueCert(post, cert)
        self.assertSubject(cert.x509, subject)

        # set some empty values to see if we can remove subject fields:
        stdin = six.StringIO(self.csr_pem)
        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            subject = Subject([('C', ''), ('ST', ''), ('L', ''), ('O', ''), ('OU', ''), ('emailAddress', ''),
                               ('CN', 'empty')])
            self.cmd('sign_cert', cn_in_san=False, alt=['example.net'], stdin=stdin, subject=subject)
        self.assertEqual(pre.call_count, 1)

        cert = Certificate.objects.get(cn='empty')
        self.assertPostIssueCert(post, cert)
        self.assertSubject(cert.x509, [('CN', 'empty')])

    def test_extensions(self):
        stdin = six.StringIO(self.csr_pem)
        cmdline = [
            'sign_cert', '--subject=%s' % Subject([('CN', 'example.com')]),
            '--key-usage=critical,keyCertSign',
            '--ext-key-usage=clientAuth',
            '--alt=URI:https://example.net',
            '--tls-feature=OCSPMustStaple',
        ]

        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd_e2e(cmdline, stdin=stdin)
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(stderr, '')

        cert = Certificate.objects.first()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertSubject(cert.x509, [('CN', 'example.com')])
        self.assertEqual(stdout, 'Please paste the CSR:\n%s' % cert.pub)
        self.assertEqual(cert.key_usage, KeyUsage('critical,keyCertSign'))
        self.assertEqual(cert.extended_key_usage, ExtendedKeyUsage('clientAuth'))
        self.assertEqual(cert.subject_alternative_name,
                         SubjectAlternativeName('DNS:example.com,URI:https://example.net'))
        self.assertEqual(cert.tls_feature, TLSFeature('OCSPMustStaple'))

    @override_settings(CA_DEFAULT_SUBJECT={})
    def test_no_subject(self):
        # test with no subjectAltNames:
        stdin = six.StringIO(self.csr_pem)
        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd('sign_cert', alt=['example.com'], stdin=stdin)
        self.assertEqual(pre.call_count, 1)

        cert = Certificate.objects.first()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertSubject(cert.x509, [('CN', 'example.com')])
        self.assertEqual(stdout, 'Please paste the CSR:\n%s' % cert.pub)
        self.assertEqual(stderr, '')
        self.assertEqual(cert.subject_alternative_name, SubjectAlternativeName('DNS:example.com'))

    @override_tmpcadir(CA_DEFAULT_SUBJECT={})
    def test_with_password(self):
        password = b'testpassword'
        ca = self.create_ca('with password', password=password)
        self.assertIsNotNone(ca.key(password=password))

        ca = CertificateAuthority.objects.get(pk=ca.pk)

        # Giving no password raises a CommandError
        stdin = six.StringIO(self.csr_pem)
        with self.assertRaisesRegex(CommandError, '^Password was not given but private key is encrypted$'), \
                self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            self.cmd('sign_cert', ca=ca, alt=['example.com'], stdin=stdin)
        self.assertEqual(pre.call_count, 0)
        self.assertEqual(post.call_count, 0)

        # Pass a password
        stdin = six.StringIO(self.csr_pem)
        ca = CertificateAuthority.objects.get(pk=ca.pk)
        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd('sign_cert', ca=ca, alt=['example.com'], stdin=stdin, password=password)
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(post.call_count, 1)

        # Pass the wrong password
        stdin = six.StringIO(self.csr_pem)
        ca = CertificateAuthority.objects.get(pk=ca.pk)
        with self.assertRaisesRegex(CommandError, self.re_false_password), \
                self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            self.cmd('sign_cert', ca=ca, alt=['example.com'], stdin=stdin, password=b'wrong')
        self.assertFalse(pre.called)
        self.assertFalse(post.called)

    @override_tmpcadir(CA_DEFAULT_SUBJECT={})
    def test_unparseable(self):
        ca = self.create_ca('test')
        ca = CertificateAuthority.objects.get(pk=ca.pk)

        os.chmod(ca.private_key_path, stat.S_IWUSR | stat.S_IRUSR)
        with open(ca.private_key_path, 'w') as stream:
            stream.write('bogus')
        os.chmod(ca.private_key_path, stat.S_IRUSR)

        # Giving no password raises a CommandError
        stdin = six.StringIO(self.csr_pem)
        with self.assertRaisesRegex(CommandError, '^Could not deserialize key data.$'), \
                self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            self.cmd('sign_cert', ca=ca, alt=['example.com'], stdin=stdin)
        self.assertEqual(pre.call_count, 0)
        self.assertEqual(post.call_count, 0)

    @override_tmpcadir()
    def test_der_csr(self):
        csr_path = os.path.join(ca_settings.CA_DIR, 'test.csr')
        with open(csr_path, 'wb') as csr_stream:
            csr_stream.write(self.csr_der)

        try:
            subject = Subject([('CN', 'example.com'), ('emailAddress', 'user@example.com')])
            with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
                stdout, stderr = self.cmd('sign_cert', subject=subject, csr=csr_path, csr_format=Encoding.DER)
            self.assertEqual(pre.call_count, 1)
            self.assertEqual(stderr, '')

            cert = Certificate.objects.first()
            self.assertPostIssueCert(post, cert)
            self.assertSignature([self.ca], cert)

            self.assertSubject(cert.x509, subject)
            self.assertEqual(stdout, cert.pub)
            self.assertEqual(cert.key_usage,
                             KeyUsage('critical,digitalSignature,keyAgreement,keyEncipherment'))
            self.assertEqual(cert.extended_key_usage, ExtendedKeyUsage('serverAuth'))
            self.assertEqual(cert.subject_alternative_name, SubjectAlternativeName('DNS:example.com'))
        finally:
            os.remove(csr_path)

    def test_expiry_too_late(self):
        expires = self.ca.expires + timedelta(days=3)
        time_left = (self.ca.expires - datetime.now()).days
        stdin = six.StringIO(self.csr_pem)

        with self.assertRaisesRegex(
                CommandError,
                r'^Certificate would outlive CA, maximum expiry for this CA is {} days\.$'.format(time_left)
        ), self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            self.cmd('sign_cert', alt=['example.com'], expires=expires, stdin=stdin)
        self.assertFalse(pre.called)
        self.assertFalse(post.called)

    def test_no_cn_or_san(self):
        with self.assertRaisesRegex(
                CommandError, r'^Must give at least a CN in --subject or one or more --alt arguments\.$'), \
                self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            self.cmd('sign_cert', subject=Subject([('C', 'AT')]))
        self.assertFalse(pre.called)
        self.assertFalse(post.called)

    def test_wrong_format(self):
        stdin = six.StringIO(self.csr_pem)

        with self.assertRaisesRegex(CommandError, 'Unknown CSR format passed: foo$'), \
                self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            self.cmd('sign_cert', alt=['example.com'], csr_format='foo', stdin=stdin)
        self.assertEqual(pre.call_count, 1)
        self.assertFalse(post.called)


@override_settings(CA_MIN_KEY_SIZE=1024, CA_PROFILES={}, CA_DEFAULT_SUBJECT={})
class SignCertChildCATestCase(DjangoCAWithCSRTestCase):
    @classmethod
    def setUpClass(cls):
        super(SignCertChildCATestCase, cls).setUpClass()

        cls.child_ca = cls.load_ca(name='child', x509=child_pubkey)

    def test_from_stdin(self):
        stdin = six.StringIO(self.csr_pem)
        subject = Subject([('CN', 'example.com')])
        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd('sign_cert', ca=self.child_ca, subject=subject, stdin=stdin)
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(stderr, '')

        cert = Certificate.objects.first()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca, self.child_ca], cert)
        self.assertSubject(cert.x509, subject)
        self.assertEqual(stdout, 'Please paste the CSR:\n%s' % cert.pub)

        self.assertEqual(cert.key_usage, KeyUsage('critical,digitalSignature,keyAgreement,keyEncipherment'))
        self.assertEqual(cert.extended_key_usage, ExtendedKeyUsage('serverAuth'))
        self.assertEqual(cert.subject_alternative_name, SubjectAlternativeName('DNS:example.com'))
        self.assertIssuer(self.child_ca, cert)
        self.assertAuthorityKeyIdentifier(self.child_ca, cert)

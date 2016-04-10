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

from django.core.management.base import CommandError
from django.utils import six

from .. import ca_settings
from ..models import Certificate
from .base import DjangoCAWithCSRTestCase
from .base import override_settings
from .base import override_tmpcadir


@override_tmpcadir(CA_MIN_KEY_SIZE=1024, CA_PROFILES={}, CA_DEFAULT_SUBJECT={})
class SignCertTestCase(DjangoCAWithCSRTestCase):
    def test_from_stdin(self):
        stdin = six.StringIO(self.csr_pem)
        stdout, stderr = self.cmd('sign_cert', CN='example.com', stdin=stdin)
        self.assertEqual(stderr, '')

        cert = Certificate.objects.first()
        self.assertEqual(cert.x509.get_subject().get_components(), [(b'CN', b'example.com')])
        self.assertEqual(stdout, 'Please paste the CSR:\n%s' % cert.pub)

        self.assertEqual(cert.keyUsage(),
                         'critical,Digital Signature, Key Encipherment, Key Agreement')
        self.assertEqual(cert.extendedKeyUsage(), 'TLS Web Server Authentication')
        self.assertEqual(cert.subjectAltName(), 'DNS:example.com')

    def test_from_file(self):
        csr_path = os.path.join(ca_settings.CA_DIR, 'test.csr')
        with open(csr_path, 'w') as csr_stream:
            csr_stream.write(self.csr_pem)

        try:
            stdout, stderr = self.cmd('sign_cert', CN='example.com', E='user@example.com',
                                      csr=csr_path)
            self.assertEqual(stderr, '')

            cert = Certificate.objects.first()
            self.assertEqual(cert.x509.get_subject().get_components(),
                             [(b'CN', b'example.com'), (b'emailAddress', b'user@example.com')])
            self.assertEqual(stdout, cert.pub)

            self.assertEqual(cert.keyUsage(),
                             'critical,Digital Signature, Key Encipherment, Key Agreement')
            self.assertEqual(cert.extendedKeyUsage(), 'TLS Web Server Authentication')
            self.assertEqual(cert.subjectAltName(), 'DNS:example.com')
        finally:
            os.remove(csr_path)

    def test_to_file(self):
        out_path = os.path.join(ca_settings.CA_DIR, 'test.pem')
        stdin = six.StringIO(self.csr_pem)

        try:
            stdout, stderr = self.cmd('sign_cert', CN='example.com', out=out_path, stdin=stdin)
            cert = Certificate.objects.first()
            self.assertEqual(stdout, 'Please paste the CSR:\n')
            self.assertEqual(stderr, '')

            with open(out_path) as out_stream:
                from_file = out_stream.read()

            self.assertEqual(cert.pub, from_file)
        finally:
            if os.path.exists(out_path):
                os.remove(out_path)

    def test_cn_not_in_san(self):
        stdin = six.StringIO(self.csr_pem)
        stdout, stderr = self.cmd('sign_cert', CN='example.net', cn_in_san=False,
                                  alt=['example.com'], stdin=stdin)
        cert = Certificate.objects.first()
        self.assertEqual(cert.x509.get_subject().get_components(), [(b'CN', b'example.net')])
        self.assertEqual(stdout, 'Please paste the CSR:\n%s' % cert.pub)
        self.assertEqual(stderr, '')
        self.assertEqual(cert.subjectAltName(), 'DNS:example.com')

    def test_no_san(self):
        # test with no subjectAltNames:
        stdin = six.StringIO(self.csr_pem)
        stdout, stderr = self.cmd('sign_cert', CN='example.net', cn_in_san=False,
                                  alt=[], stdin=stdin)
        cert = Certificate.objects.first()
        self.assertEqual(cert.x509.get_subject().get_components(), [(b'CN', b'example.net')])
        self.assertEqual(stdout, 'Please paste the CSR:\n%s' % cert.pub)
        self.assertEqual(stderr, '')
        self.assertEqual(cert.subjectAltName(), '')

    @override_settings(CA_DEFAULT_SUBJECT={
        'C': 'AT',
        'ST': 'Vienna',
        'L': 'Vienna',
        'O': 'MyOrg',
        'OU': 'MyOrgUnit',
        'CN': 'CommonName',
        'emailAddress': 'user@example.com',
    })
    def test_profile_subject(self):
        # first, we only pass an subjectAltName, meaning that even the CommonName is used.
        stdin = six.StringIO(self.csr_pem)
        stdout, stderr = self.cmd('sign_cert', cn_in_san=False, alt=['example.net'], stdin=stdin)
        cert = Certificate.objects.first()
        self.assertSubject(cert.x509, ca_settings._CA_DEFAULT_SUBJECT)

        # replace subject fields via command-line argument:
        subject = {
            'C': 'US',
            'ST': 'California',
            'L': 'San Francisco',
            'O': 'MyOrg2',
            'OU': 'MyOrg2Unit2',
            'CN': 'CommonName2',
            'emailAddress': 'user@example.net',
        }
        stdin = six.StringIO(self.csr_pem)
        self.cmd('sign_cert', cn_in_san=False, alt=['example.net'], stdin=stdin,
                 C='US', ST='California', L='San Francisco', O='MyOrg2', OU='MyOrg2Unit2',
                 CN='CommonName2', E='user@example.net')
        cert = Certificate.objects.get(cn='CommonName2')
        self.assertSubject(cert.x509, subject)

        # set some empty values to see if we can remove subject fields:
        stdin = six.StringIO(self.csr_pem)
        self.cmd('sign_cert', cn_in_san=False, alt=['example.net'], stdin=stdin,
                 C='', ST='', L='', O='', OU='', CN='empty', E='')
        cert = Certificate.objects.get(cn='empty')
        self.assertSubject(cert.x509, {'CN': 'empty'})

    def test_extensions(self):
        stdin = six.StringIO(self.csr_pem)
        stdout, stderr = self.cmd('sign_cert', CN='example.com',
                                  key_usage='critical,keyCertSign',
                                  ext_key_usage='clientAuth',
                                  alt=['URI:https://example.net'],
                                  stdin=stdin)
        self.assertEqual(stderr, '')

        cert = Certificate.objects.first()
        self.assertEqual(cert.x509.get_subject().get_components(), [(b'CN', b'example.com')])
        self.assertEqual(stdout, 'Please paste the CSR:\n%s' % cert.pub)
        self.assertEqual(cert.keyUsage(), 'critical,Certificate Sign')
        self.assertEqual(cert.extendedKeyUsage(), 'TLS Web Client Authentication')
        self.assertEqual(cert.subjectAltName(), 'DNS:example.com, URI:https://example.net')

    @override_settings(CA_DEFAULT_SUBJECT={})
    def test_no_subject(self):
        # test with no subjectAltNames:
        stdin = six.StringIO(self.csr_pem)
        stdout, stderr = self.cmd('sign_cert', alt=['example.com'], stdin=stdin)
        cert = Certificate.objects.first()
        self.assertEqual(cert.x509.get_subject().get_components(), [(b'CN', b'example.com')])
        self.assertEqual(stdout, 'Please paste the CSR:\n%s' % cert.pub)
        self.assertEqual(stderr, '')
        self.assertEqual(cert.subjectAltName(), 'DNS:example.com')

    def test_no_cn_or_san(self):
        with self.assertRaises(CommandError):
            self.cmd('sign_cert', C='AT', OU='OrgUnit')

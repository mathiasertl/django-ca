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

import os
import unittest

from cryptography.hazmat.backends import default_backend
from cryptography.x509.extensions import UnrecognizedExtension
from cryptography.x509.oid import ObjectIdentifier

from django.core.exceptions import ValidationError
from django.test import TestCase

from ..extensions import BasicConstraints
from ..extensions import ExtendedKeyUsage
from ..extensions import IssuerAlternativeName
from ..extensions import KeyUsage
from ..extensions import SubjectAlternativeName
from ..models import Certificate
from ..models import Watcher
from .base import DjangoCAWithCertTestCase
from .base import cert2_pubkey
from .base import cert3_csr
from .base import cert3_pubkey
from .base import certs
from .base import child_pubkey
from .base import cryptography_version
from .base import ocsp_pubkey

try:
    import unittest.mock as mock
except ImportError:
    import mock


class TestWatcher(TestCase):
    def test_from_addr(self):
        mail = 'user@example.com'
        name = 'Firstname Lastname'

        w = Watcher.from_addr('%s <%s>' % (name, mail))
        self.assertEqual(w.mail, mail)
        self.assertEqual(w.name, name)

    def test_spaces(self):
        mail = 'user@example.com'
        name = 'Firstname Lastname'

        w = Watcher.from_addr('%s     <%s>' % (name, mail))
        self.assertEqual(w.mail, mail)
        self.assertEqual(w.name, name)

        w = Watcher.from_addr('%s<%s>' % (name, mail))
        self.assertEqual(w.mail, mail)
        self.assertEqual(w.name, name)

    def test_error(self):
        with self.assertRaises(ValidationError):
            Watcher.from_addr('foobar ')
        with self.assertRaises(ValidationError):
            Watcher.from_addr('foobar @')

    def test_update(self):
        mail = 'user@example.com'
        name = 'Firstname Lastname'
        newname = 'Newfirst Newlast'

        Watcher.from_addr('%s <%s>' % (name, mail))
        w = Watcher.from_addr('%s <%s>' % (newname, mail))
        self.assertEqual(w.mail, mail)
        self.assertEqual(w.name, newname)

    def test_output(self):
        mail = 'user@example.com'
        name = 'Firstname Lastname'

        w = Watcher(mail=mail)
        self.assertEqual(str(w), mail)

        w.name = name
        self.assertEqual(str(w), '%s <%s>' % (name, mail))


class CertificateTests(DjangoCAWithCertTestCase):
    def setUp(self):
        super(CertificateTests, self).setUp()
        # A certificate with all extensions, can do everything, etc
        self.ca.crl_url = 'https://ca.example.com/crl.der'
        self.full = self.create_cert(
            self.ca, cert3_csr, [('CN', 'all.example.com')],
            san=['dirname:/C=AT/CN=example.com', 'email:user@example.com', 'fd00::1'])

        self.ca2 = self.load_ca('child', child_pubkey, parent=self.ca)
        self.cert2 = self.load_cert(self.ca, cert2_pubkey)
        self.cert3 = self.load_cert(self.ca, cert3_pubkey)
        self.ocsp = self.load_cert(self.ca, ocsp_pubkey)

    def test_pathlen(self):
        self.assertEqual(self.ca.pathlen, 1)
        self.assertEqual(self.ca2.pathlen, 0)

    def test_dates(self):
        self.assertEqual(self.ca.expires, certs['root']['expires'])
        self.assertEqual(self.ca2.expires, certs['child']['expires'])
        self.assertEqual(self.cert.expires, certs['cert1']['expires'])
        self.assertEqual(self.cert2.expires, certs['cert2']['expires'])
        self.assertEqual(self.cert3.expires, certs['cert3']['expires'])
        self.assertEqual(self.ocsp.expires, certs['ocsp']['expires'])

        self.assertEqual(self.ca.valid_from, certs['root']['valid_from'])
        self.assertEqual(self.ca2.valid_from, certs['child']['valid_from'])
        self.assertEqual(self.cert.valid_from, certs['cert1']['valid_from'])
        self.assertEqual(self.cert2.valid_from, certs['cert2']['valid_from'])
        self.assertEqual(self.cert3.valid_from, certs['cert3']['valid_from'])
        self.assertEqual(self.ocsp.valid_from, certs['ocsp']['valid_from'])

    def test_max_pathlen(self):
        self.assertEqual(self.ca.max_pathlen, 1)
        self.assertEqual(self.ca2.pathlen, 0)

    def test_allows_intermediate(self):
        self.assertTrue(self.ca.allows_intermediate_ca, 1)
        self.assertFalse(self.ca2.allows_intermediate_ca, 0)

    def test_revocation(self):
        # Never really happens in real life, but should still be checked
        c = Certificate(revoked=False)

        with self.assertRaises(ValueError):
            c.get_revocation()

    def test_serial(self):
        self.assertEqual(self.ca.serial, certs['root']['serial'])
        self.assertEqual(self.ca2.serial, certs['child']['serial'])
        self.assertEqual(self.cert.serial, certs['cert1']['serial'])
        self.assertEqual(self.cert2.serial, certs['cert2']['serial'])
        self.assertEqual(self.cert3.serial, certs['cert3']['serial'])
        self.assertEqual(self.ocsp.serial, certs['ocsp']['serial'])

    def test_subjectAltName(self):
        self.assertEqual(self.ca.subject_alternative_name, certs['root']['san'])
        self.assertEqual(self.ca2.subject_alternative_name, certs['child']['san'])
        self.assertEqual(self.cert.subject_alternative_name, certs['cert1']['san'])
        self.assertEqual(self.cert2.subject_alternative_name, certs['cert2']['san'])
        self.assertEqual(self.cert3.subject_alternative_name, certs['cert3']['san'])

        self.assertEqual(
            self.full.subject_alternative_name,
            SubjectAlternativeName({'value': [
                'DNS:all.example.com',
                'dirname:/C=AT/CN=example.com',
                'email:user@example.com',
                'IP:fd00::1',
            ]}))

    def test_basicConstraints(self):
        self.assertEqual(self.ca.basic_constraints, BasicConstraints('critical,CA:TRUE,pathlen=1'))
        self.assertEqual(self.pwd_ca.basic_constraints, BasicConstraints('critical,CA:TRUE'))
        self.assertEqual(self.ecc_ca.basic_constraints, BasicConstraints('critical,CA:TRUE,pathlen=0'))

        self.assertEqual(self.cert.basic_constraints, BasicConstraints('critical,CA:FALSE'))
        self.assertEqual(self.cert_all.basic_constraints, BasicConstraints('critical,CA:FALSE'))
        self.assertIsNone(self.cert_no_ext.basic_constraints)
        self.assertEqual(self.cert2.basic_constraints, BasicConstraints('critical,CA:FALSE'))
        # accidentally used cert2 in cn/san
        self.assertEqual(self.cert3.basic_constraints, BasicConstraints('critical,CA:FALSE'))

    def test_issuerAltName(self):
        self.assertIsNone(self.ca.issuer_alternative_name)
        self.assertIsNone(self.pwd_ca.issuer_alternative_name)
        self.assertIsNone(self.ecc_ca.issuer_alternative_name)

        self.assertEqual(self.cert.issuer_alternative_name,
                         IssuerAlternativeName(certs['cert1']['issuer_alternative_name']))
        self.assertEqual(self.cert2.issuer_alternative_name,
                         IssuerAlternativeName(certs['cert2']['issuer_alternative_name']))
        self.assertEqual(self.cert3.issuer_alternative_name,
                         IssuerAlternativeName(certs['cert3']['issuer_alternative_name']))

    def test_keyUsage(self):
        self.assertEqual(self.ca.key_usage, KeyUsage('critical,cRLSign,keyCertSign'))
        self.assertEqual(self.ca2.key_usage, KeyUsage('critical,cRLSign,keyCertSign'))
        self.assertEqual(self.cert.key_usage,
                         KeyUsage('critical,digitalSignature,keyAgreement,keyEncipherment'))
        self.assertEqual(self.cert2.key_usage,
                         KeyUsage('critical,digitalSignature,keyAgreement,keyEncipherment'))
        self.assertEqual(self.cert3.key_usage,
                         KeyUsage('critical,digitalSignature,keyAgreement,keyEncipherment'))
        self.assertEqual(self.ocsp.key_usage,
                         KeyUsage('critical,digitalSignature,keyEncipherment,nonRepudiation'))

    def test_extendedKeyUsage(self):
        self.assertIsNone(self.ca.extended_key_usage)
        self.assertIsNone(self.ca2.extended_key_usage)
        self.assertEqual(self.cert.extended_key_usage, ExtendedKeyUsage('serverAuth'))
        self.assertEqual(self.cert2.extended_key_usage, ExtendedKeyUsage('serverAuth'))
        self.assertEqual(self.cert3.extended_key_usage, ExtendedKeyUsage('serverAuth'))
        self.assertEqual(self.ocsp.extended_key_usage, ExtendedKeyUsage('OCSPSigning'))

    def test_crlDistributionPoints(self):
        self.assertEqual(self.ca.crlDistributionPoints(), certs['root']['crl'])  # None
        self.assertEqual(self.ca2.crlDistributionPoints(), certs['child']['crl'])  # None
        self.assertEqual(self.cert.crlDistributionPoints(), certs['cert1']['crl'])
        self.assertEqual(self.cert2.crlDistributionPoints(), certs['cert2']['crl'])
        self.assertEqual(self.cert3.crlDistributionPoints(), certs['cert3']['crl'])
        self.assertEqual(self.ocsp.crlDistributionPoints(), certs['ocsp']['crl'])
        self.assertEqual(self.full.crlDistributionPoints(),
                         (False, ['Full Name: URI:https://ca.example.com/crl.der']))

    def test_digest(self):
        self.assertEqual(self.ca.get_digest('md5'), certs['root']['md5'])
        self.assertEqual(self.ca.get_digest('sha1'), certs['root']['sha1'])
        self.assertEqual(self.ca.get_digest('sha256'), certs['root']['sha256'])
        self.assertEqual(self.ca.get_digest('sha512'), certs['root']['sha512'])

        self.assertEqual(self.ca.get_digest('md5'), certs['child']['md5'])
        self.assertEqual(self.ca.get_digest('sha1'), certs['child']['sha1'])
        self.assertEqual(self.ca.get_digest('sha256'), certs['child']['sha256'])
        self.assertEqual(self.ca.get_digest('sha512'), certs['child']['sha512'])

        self.assertEqual(self.cert.get_digest('md5'), certs['cert1']['md5'])
        self.assertEqual(self.cert.get_digest('sha1'), certs['cert1']['sha1'])
        self.assertEqual(self.cert.get_digest('sha256'), certs['cert1']['sha256'])
        self.assertEqual(self.cert.get_digest('sha512'), certs['cert1']['sha512'])

        self.assertEqual(self.cert2.get_digest('md5'), certs['cert2']['md5'])
        self.assertEqual(self.cert2.get_digest('sha1'), certs['cert2']['sha1'])
        self.assertEqual(self.cert2.get_digest('sha256'), certs['cert2']['sha256'])
        self.assertEqual(self.cert2.get_digest('sha512'), certs['cert2']['sha512'])

        self.assertEqual(self.cert3.get_digest('md5'), certs['cert3']['md5'])
        self.assertEqual(self.cert3.get_digest('sha1'), certs['cert3']['sha1'])
        self.assertEqual(self.cert3.get_digest('sha256'), certs['cert3']['sha256'])
        self.assertEqual(self.cert3.get_digest('sha512'), certs['cert3']['sha512'])

    def test_authorityKeyIdentifier(self):
        self.assertEqual(self.ca.authority_key_identifier.as_text(), certs['root']['authKeyIdentifier'])
        self.assertEqual(self.ca2.authority_key_identifier.as_text(), certs['child']['authKeyIdentifier'])
        self.assertEqual(self.cert.authority_key_identifier.as_text(), certs['cert1']['authKeyIdentifier'])
        self.assertEqual(self.cert2.authority_key_identifier.as_text(), certs['cert2']['authKeyIdentifier'])
        self.assertEqual(self.cert3.authority_key_identifier.as_text(), certs['cert3']['authKeyIdentifier'])

    def test_nameConstraints(self):
        self.assertEqual(self.ca.nameConstraints(), None)

    def test_hpkp_pin(self):

        # get hpkp pins using
        #   openssl x509 -in cert1.pem -pubkey -noout \
        #       | openssl rsa -pubin -outform der \
        #       | openssl dgst -sha256 -binary | base64
        self.assertEqual(self.ca.hpkp_pin, certs['root']['hpkp'])
        self.assertEqual(self.ca2.hpkp_pin, certs['child']['hpkp'])
        self.assertEqual(self.cert.hpkp_pin, certs['cert1']['hpkp'])
        self.assertEqual(self.cert2.hpkp_pin, certs['cert2']['hpkp'])
        self.assertEqual(self.cert3.hpkp_pin, certs['cert3']['hpkp'])

    def test_contrib_multiple_ous_and_no_ext(self):
        name = 'multiple_ous_and_no_ext'
        _pem, pubkey = self.get_cert(os.path.join('contrib', '%s.pem' % name))
        cert = self.load_cert(self.ca, x509=pubkey)
        self.assertIsNone(cert.authorityInfoAccess())
        self.assertIsNone(cert.basic_constraints)
        self.assertIsNone(cert.subject_alternative_name)
        self.assertIsNone(cert.key_usage)
        self.assertIsNone(cert.extended_key_usage)
        self.assertIsNone(cert.subject_key_identifier)
        self.assertIsNone(cert.issuer_alternative_name)
        self.assertIsNone(cert.authority_key_identifier)
        self.assertIsNone(cert.tls_feature)
        self.assertIsNone(cert.certificatePolicies())
        self.assertIsNone(cert.signedCertificateTimestampList())

    @unittest.skipUnless(
        default_backend()._lib.CRYPTOGRAPHY_OPENSSL_110F_OR_GREATER,
        'test only makes sense with older libreSSL/OpenSSL versions that don\'t support SCT.')
    @unittest.skipUnless(cryptography_version >= (2, 3),
                         'test requires cryptography >= 2.3')
    def test_unsupported(self):
        # Test return value for older versions of OpenSSL

        name = 'letsencrypt_jabber_at'
        _pem, pubkey = self.get_cert(os.path.join('contrib', '%s.pem' % name))
        cert = self.load_cert(self.ca, x509=pubkey)

        value = UnrecognizedExtension(ObjectIdentifier('1.1.1.1'), b'foo')

        with mock.patch('cryptography.x509.extensions.Extension.value', value):
            self.assertEqual(cert.signedCertificateTimestampList(),
                             (False, ['Parsing requires OpenSSL 1.1.0f+']))

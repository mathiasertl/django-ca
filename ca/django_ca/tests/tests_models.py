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
from datetime import datetime

from freezegun import freeze_time

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.extensions import UnrecognizedExtension
from cryptography.x509.oid import ObjectIdentifier

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone

from .. import ca_settings
from ..extensions import AuthorityInformationAccess
from ..extensions import AuthorityKeyIdentifier
from ..extensions import BasicConstraints
from ..extensions import ExtendedKeyUsage
from ..extensions import IssuerAlternativeName
from ..extensions import KeyUsage
from ..extensions import SubjectAlternativeName
from ..extensions import SubjectKeyIdentifier
from ..models import Certificate
from ..models import Watcher
from .base import DjangoCAWithChildCATestCase
from .base import cert2_pubkey
from .base import cert3_csr
from .base import cert3_pubkey
from .base import certs
from .base import cryptography_version
from .base import ocsp_pubkey
from .base import override_settings
from .base import override_tmpcadir
from .base import multiple_ous_and_no_ext_pubkey
from .base import cloudflare_1_pubkey
from .base import letsencrypt_jabber_at_pubkey
from .base import godaddy_derstandardat_pubkey

try:
    import unittest.mock as mock
except ImportError:
    import mock

if ca_settings.CRYPTOGRAPHY_HAS_PRECERT_POISON:  # pragma: only cryptography>=2.4
    from ..extensions import PrecertPoison


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


class CertificateTests(DjangoCAWithChildCATestCase):
    def setUp(self):
        super(CertificateTests, self).setUp()
        self.ca.crl_url = 'https://ca.example.com/crl.der'

        self.cert2 = self.load_cert(self.ca, cert2_pubkey)
        self.cert3 = self.load_cert(self.ca, cert3_pubkey)
        self.ocsp = self.load_cert(self.ca, ocsp_pubkey)

        self.cert_multiple_ous_and_no_ext = self.load_cert(self.ca, multiple_ous_and_no_ext_pubkey)
        self.cert_cloudflare_1 = self.load_cert(self.ca, cloudflare_1_pubkey)
        self.cert_letsencrypt_jabber_at = self.load_cert(self.ca, letsencrypt_jabber_at_pubkey)
        self.cert_godaddy_derstandardat = self.load_cert(self.ca, godaddy_derstandardat_pubkey)

        self.certs += [
            self.cert2, self.cert3, self.ocsp,
            self.cert_multiple_ous_and_no_ext, self.cert_cloudflare_1,
            self.cert_letsencrypt_jabber_at, self.cert_godaddy_derstandardat,
        ]

    def assertExtension(self, name, expected):
        for cert in self.cas + self.certs:
            value = getattr(cert, name)
            exp = expected.get(cert)

            if exp is None:
                self.assertIsNone(value, cert)
            else:
                self.assertEqual(value, exp, cert)

    @override_tmpcadir()
    def test_key(self):
        log_msg = 'WARNING:django_ca.models:%s: CA uses absolute path. Use "manage.py migrate_ca" to update.'

        # NOTE: exclude pwd_ca for simplicity
        for ca in [self.ca, self.ecc_ca, self.child_ca]:
            self.assertTrue(ca.key_exists)
            self.assertIsNotNone(ca.key(None))

            # test a second tome to make sure we reload the key
            with mock.patch('django_ca.utils.read_file') as patched:
                self.assertIsNotNone(ca.key(None))
            patched.assert_not_called()

            ca._key = None  # so the key is reloaded
            ca.private_key_path = os.path.join(ca_settings.CA_DIR, ca.private_key_path)

            with self.assertLogs() as cm:
                self.assertTrue(ca.key_exists)
            self.assertEqual(cm.output, [log_msg % ca.serial, ])

            with self.assertLogs() as cm:
                self.assertIsNotNone(ca.key(None))
            self.assertEqual(cm.output, [log_msg % ca.serial, ])

            # Check again - here we have an already loaded key (also: no logging here anymore)
            # NOTE: assertLogs() fails if there are *no* log messages, so we cannot test that
            self.assertTrue(ca.key_exists)

    def test_pathlen(self):
        self.assertEqual(self.ca.pathlen, 1)
        self.assertIsNone(self.pwd_ca.pathlen)
        self.assertEqual(self.ecc_ca.pathlen, 0)
        self.assertEqual(self.child_ca.pathlen, 0)

    def test_dates(self):
        self.assertEqual(self.ca.expires, certs['root']['expires'])
        self.assertEqual(self.child_ca.expires, certs['child']['expires'])
        self.assertEqual(self.cert.expires, certs['cert1']['expires'])
        self.assertEqual(self.cert2.expires, certs['cert2']['expires'])
        self.assertEqual(self.cert3.expires, certs['cert3']['expires'])
        self.assertEqual(self.ocsp.expires, certs['ocsp']['expires'])

        self.assertEqual(self.ca.valid_from, certs['root']['valid_from'])
        self.assertEqual(self.child_ca.valid_from, certs['child']['valid_from'])
        self.assertEqual(self.cert.valid_from, certs['cert1']['valid_from'])
        self.assertEqual(self.cert2.valid_from, certs['cert2']['valid_from'])
        self.assertEqual(self.cert3.valid_from, certs['cert3']['valid_from'])
        self.assertEqual(self.ocsp.valid_from, certs['ocsp']['valid_from'])

    def test_max_pathlen(self):
        self.assertEqual(self.ca.max_pathlen, 1)
        self.assertEqual(self.child_ca.pathlen, 0)

    def test_allows_intermediate(self):
        self.assertTrue(self.ca.allows_intermediate_ca, 1)
        self.assertFalse(self.child_ca.allows_intermediate_ca, 0)

    def test_revocation(self):
        # Never really happens in real life, but should still be checked
        c = Certificate(revoked=False)

        with self.assertRaises(ValueError):
            c.get_revocation()

    @override_tmpcadir()
    def test_serial(self):
        self.assertEqual(self.ca.serial, certs['root']['serial'])
        self.assertEqual(self.child_ca.serial, certs['child']['serial'])
        self.assertEqual(self.cert.serial, certs['cert1']['serial'])
        self.assertEqual(self.cert2.serial, certs['cert2']['serial'])
        self.assertEqual(self.cert3.serial, certs['cert3']['serial'])
        self.assertEqual(self.ocsp.serial, certs['ocsp']['serial'])

    @override_tmpcadir()
    def test_subjectAltName(self):
        self.assertEqual(self.ca.subject_alternative_name, certs['root']['san'])
        self.assertEqual(self.child_ca.subject_alternative_name, certs['child']['san'])
        self.assertEqual(self.cert.subject_alternative_name, certs['cert1']['san'])
        self.assertEqual(self.cert2.subject_alternative_name, certs['cert2']['san'])
        self.assertEqual(self.cert3.subject_alternative_name, certs['cert3']['san'])

        full = self.create_cert(
            self.ca, cert3_csr, [('CN', 'all.example.com')],
            san=['dirname:/C=AT/CN=example.com', 'email:user@example.com', 'fd00::1'])

        self.assertEqual(
            full.subject_alternative_name,
            SubjectAlternativeName({'value': [
                'DNS:all.example.com',
                'dirname:/C=AT/CN=example.com',
                'email:user@example.com',
                'IP:fd00::1',
            ]}))

    @freeze_time("2019-02-03 15:43:12")
    def test_get_revocation_time(self):
        self.assertIsNone(self.cert.get_revocation_time())
        self.cert.revoke()

        with override_settings(USE_TZ=True):
            self.cert.revoked_date = timezone.now()
            self.assertEqual(self.cert.get_revocation_time(), datetime(2019, 2, 3, 15, 43, 12))

        with override_settings(USE_TZ=False):
            self.cert.revoked_date = timezone.now()
            self.assertEqual(self.cert.get_revocation_time(), datetime(2019, 2, 3, 15, 43, 12))

    @unittest.skipUnless(cryptography_version >= (2, 4), 'OCSP support was added in cryptography 2.4.')
    def test_get_revocation_reason(self):
        self.assertIsNone(self.cert.get_revocation_reason())

        for reason, _text in self.cert.REVOCATION_REASONS:
            self.cert.revoke(reason)
            self.assertIsInstance(self.cert.get_revocation_reason(), x509.ReasonFlags)
            #print(self.cert.revoked_reason, self.cert.get_revocation_reason())

    def test_ocsp_status(self):
        self.assertEqual(self.cert.ocsp_status, 'good')

        for reason, _text in self.cert.REVOCATION_REASONS:
            self.cert.revoke(reason)
            if reason == '':
                self.assertEqual(self.cert.ocsp_status, 'revoked')
            else:
                self.assertEqual(self.cert.ocsp_status, reason)

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
        self.assertEqual(self.child_ca.key_usage, KeyUsage('critical,cRLSign,keyCertSign'))
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
        self.assertIsNone(self.child_ca.extended_key_usage)
        self.assertEqual(self.cert.extended_key_usage, ExtendedKeyUsage('serverAuth'))
        self.assertEqual(self.cert2.extended_key_usage, ExtendedKeyUsage('serverAuth'))
        self.assertEqual(self.cert3.extended_key_usage, ExtendedKeyUsage('serverAuth'))
        self.assertEqual(self.ocsp.extended_key_usage, ExtendedKeyUsage('OCSPSigning'))

    def test_crlDistributionPoints(self):
        self.assertEqual(self.ca.crlDistributionPoints(), certs['root']['crl'])  # None
        self.assertEqual(self.child_ca.crlDistributionPoints(), certs['child']['crl'])  # None
        self.assertEqual(self.cert.crlDistributionPoints(), certs['cert1']['crl'])
        self.assertEqual(self.cert2.crlDistributionPoints(), certs['cert2']['crl'])
        self.assertEqual(self.cert3.crlDistributionPoints(), certs['cert3']['crl'])
        self.assertEqual(self.ocsp.crlDistributionPoints(), certs['ocsp']['crl'])

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
        self.assertEqual(self.child_ca.authority_key_identifier.as_text(),
                         certs['child']['authKeyIdentifier'])
        self.assertEqual(self.cert.authority_key_identifier.as_text(), certs['cert1']['authKeyIdentifier'])
        self.assertEqual(self.cert2.authority_key_identifier.as_text(), certs['cert2']['authKeyIdentifier'])
        self.assertEqual(self.cert3.authority_key_identifier.as_text(), certs['cert3']['authKeyIdentifier'])

    def test_hpkp_pin(self):
        # get hpkp pins using
        #   openssl x509 -in cert1.pem -pubkey -noout \
        #       | openssl rsa -pubin -outform der \
        #       | openssl dgst -sha256 -binary | base64
        self.assertEqual(self.ca.hpkp_pin, certs['root']['hpkp'])
        self.assertEqual(self.child_ca.hpkp_pin, certs['child']['hpkp'])
        self.assertEqual(self.cert.hpkp_pin, certs['cert1']['hpkp'])
        self.assertEqual(self.cert2.hpkp_pin, certs['cert2']['hpkp'])
        self.assertEqual(self.cert3.hpkp_pin, certs['cert3']['hpkp'])

    def test_contrib_multiple_ous_and_no_ext(self):
        cert = self.cert_multiple_ous_and_no_ext
        self.assertIsNone(cert.authority_information_access)
        self.assertIsNone(cert.authority_key_identifier)
        self.assertIsNone(cert.basic_constraints)
        self.assertIsNone(cert.extended_key_usage)
        self.assertIsNone(cert.issuer_alternative_name)
        self.assertIsNone(cert.key_usage)
        self.assertIsNone(cert.subject_alternative_name)
        self.assertIsNone(cert.subject_key_identifier)
        self.assertIsNone(cert.certificatePolicies())
        self.assertIsNone(cert.signedCertificateTimestampList())

    def test_contrib_le(self):
        cert = self.cert_letsencrypt_jabber_at
        self.assertEqual(cert.authority_information_access,
                         AuthorityInformationAccess({
                             'issuers': ['URI:http://cert.int-x3.letsencrypt.org/'],
                             'ocsp': ['URI:http://ocsp.int-x3.letsencrypt.org'],
                         }))
        self.assertEqual(cert.basic_constraints, BasicConstraints('critical,CA:FALSE'))
        self.assertEqual(cert.key_usage, KeyUsage('critical,digitalSignature,keyEncipherment'))
        self.assertEqual(cert.extended_key_usage, ExtendedKeyUsage('serverAuth,clientAuth'))
        self.assertEqual(cert.subject_key_identifier,
                         SubjectKeyIdentifier('97:AB:1D:D3:46:04:96:0F:45:DF:C3:FF:59:9D:B0:53:AC:73:79:2E'))
        self.assertIsNone(cert.issuer_alternative_name)
        self.assertEqual(
            cert.authority_key_identifier,
            AuthorityKeyIdentifier('A8:4A:6A:63:04:7D:DD:BA:E6:D1:39:B7:A6:45:65:EF:F3:A8:EC:A1')
        )
        self.assertEqual(cert.certificatePolicies(), (False, [
            'OID 2.23.140.1.2.1: None',
            'OID 1.3.6.1.4.1.44947.1.1.1: http://cps.letsencrypt.org, This Certificate '
            'may only be relied upon by Relying Parties and only in accordance with the '
            'Certificate Policy found at https://letsencrypt.org/repository/'
        ]))
        self.assertEqual(cert.signedCertificateTimestampList(), (False, [
            'Precertificate (v1): 2018-08-09 10:15:21.724000\n'
            '\n'
            '293c519654c83965baaa50fc5807d4b76fbf587a2972dca4c30cf4e54547f478',
            'Precertificate (v1): 2018-08-09 10:15:21.749000\n'
            '\n'
            'db74afeecb29ecb1feca3e716d2ce5b9aabb36f7847183c75d9d4f37b61fbf64'
        ]))

    def test_contrib_godaddy(self):
        cert = self.cert_godaddy_derstandardat
        self.assertEqual(cert.authority_information_access,
                         AuthorityInformationAccess({
                             'issuers': ['URI:http://certificates.godaddy.com/repository/gdig2.crt'],
                             'ocsp': ['URI:http://ocsp.godaddy.com/'],
                         }))
        self.assertEqual(cert.basic_constraints, BasicConstraints('critical,CA:FALSE'))
        self.assertEqual(cert.key_usage, KeyUsage('critical,digitalSignature,keyEncipherment'))
        self.assertEqual(cert.extended_key_usage, ExtendedKeyUsage('serverAuth,clientAuth'))
        self.assertEqual(cert.subject_key_identifier,
                         SubjectKeyIdentifier('36:97:AB:24:CF:50:2B:05:71:B1:4E:0A:4F:18:94:C1:FC:F9:4F:69'))
        self.assertIsNone(cert.issuer_alternative_name)
        self.assertEqual(
            cert.authority_key_identifier,
            AuthorityKeyIdentifier(':40:C2:BD:27:8E:CC:34:83:30:A2:33:D7:FB:6C:B3:F0:B4:2C:80:CE'))
        self.assertEqual(cert.certificatePolicies(), (False, [
            'OID 2.16.840.1.114413.1.7.23.1: http://certificates.godaddy.com/repository/',
            'OID 2.23.140.1.2.1: None',
        ]))
        self.assertIsNone(cert.signedCertificateTimestampList())

    def test_contrib_cloudflare(self):
        cert = self.cert_cloudflare_1
        self.assertEqual(
            cert.authority_information_access,
            AuthorityInformationAccess({
                'issuers': ['URI:http://crt.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crt'],
                'ocsp': ['URI:http://ocsp.comodoca4.com'],
            }))
        self.assertEqual(cert.basic_constraints, BasicConstraints('critical,CA:FALSE'))
        self.assertEqual(cert.key_usage, KeyUsage('critical,digitalSignature'))
        self.assertEqual(cert.extended_key_usage, ExtendedKeyUsage('serverAuth,clientAuth'))
        self.assertEqual(cert.subject_key_identifier,
                         SubjectKeyIdentifier('05:86:D8:B4:ED:A9:7E:23:EE:2E:E7:75:AA:3B:2C:06:08:2A:93:B2'))
        self.assertIsNone(cert.issuer_alternative_name, '')
        self.assertEqual(
            cert.authority_key_identifier,
            AuthorityKeyIdentifier('40:09:61:67:F0:BC:83:71:4F:DE:12:08:2C:6F:D4:D4:2B:76:3D:96')
        )
        self.assertEqual(cert.certificatePolicies(), (False, [
            'OID 1.3.6.1.4.1.6449.1.2.2.7: https://secure.comodo.com/CPS',
            'OID 2.23.140.1.2.1: None',
        ]))
        self.assertIsNone(cert.signedCertificateTimestampList())

    # Test seems to run fine with cryptography 2.2.
    #@unittest.skipUnless(cryptography_version >= (2, 3),
    #                     'test requires cryptography >= 2.3')
    @unittest.skipUnless(
        default_backend()._lib.CRYPTOGRAPHY_OPENSSL_110F_OR_GREATER,
        'test only makes sense with older libreSSL/OpenSSL versions that don\'t support SCT.')
    @override_tmpcadir()
    def test_unsupported(self):
        # Test return value for older versions of OpenSSL
        value = UnrecognizedExtension(ObjectIdentifier('1.1.1.1'), b'foo')

        with mock.patch('cryptography.x509.extensions.Extension.value', value):
            self.assertEqual(self.cert_letsencrypt_jabber_at.signedCertificateTimestampList(),
                             (False, ['Parsing requires OpenSSL 1.1.0f+']))

    def test_get_authority_key_identifier(self):
        self.assertEqual(self.ca.get_authority_key_identifier(), certs['root']['aki'])
        self.assertEqual(self.pwd_ca.get_authority_key_identifier(), certs['pwd_ca']['aki'])
        self.assertEqual(self.ecc_ca.get_authority_key_identifier(), certs['ecc_ca']['aki'])
        self.assertEqual(self.child_ca.get_authority_key_identifier(), certs['child']['aki'])

        # All CAs have a subject key identifier, so we mock that this exception is not present
        def side_effect(cls):
            raise x509.ExtensionNotFound('mocked', x509.SubjectKeyIdentifier.oid)

        with mock.patch('cryptography.x509.extensions.Extensions.get_extension_for_class',
                        side_effect=side_effect):
            self.assertEqual(self.child_ca.get_authority_key_identifier(), certs['child']['aki'])

    ###############################################
    # Test extensions for all loaded certificates #
    ###############################################
    def test_name_constraints(self):
        self.assertExtension('name_constraints', {
            self.child_ca: certs['child']['name_constraints'],
        })

    def test_ocsp_no_check(self):
        self.assertExtension('ocsp_no_check', {})

    @unittest.skipUnless(ca_settings.CRYPTOGRAPHY_HAS_PRECERT_POISON,
                         "This version of cryptography does not support PrecertPoison extension.")
    def test_precert_poison(self):
        self.assertExtension('precert_poison', {
            self.cert_cloudflare_1: PrecertPoison()
        })

    def test_tls_feature(self):
        self.assertExtension('tls_feature', {
            self.cert_all: certs['cert_all']['tls_feature'],
        })

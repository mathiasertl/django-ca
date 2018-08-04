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

from django.core.exceptions import ValidationError
from django.test import TestCase

from ..models import Certificate
from ..models import Watcher
from .base import DjangoCAWithCertTestCase
from .base import cert2_pubkey
from .base import cert3_csr
from .base import cert3_pubkey
from .base import certs
from .base import child_pubkey
from .base import ocsp_pubkey


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
    @classmethod
    def setUpClass(cls):
        super(CertificateTests, cls).setUpClass()

        # A certificate with all extensions, can do everything, etc
        cls.ca.crl_url = 'https://ca.example.com/crl.der'
        cls.full = cls.create_cert(
            cls.ca, cert3_csr, [('CN', 'all.example.com')],
            san=['dirname:/C=AT/CN=example.com', 'email:user@example.com', 'fd00::1'])

    def setUp(self):
        self.ca2 = self.load_ca('child', child_pubkey, parent=self.ca)
        self.cert2 = self.load_cert(self.ca, cert2_pubkey)
        self.cert3 = self.load_cert(self.ca, cert3_pubkey)
        self.ocsp = self.load_cert(self.ca, ocsp_pubkey)

    def test_pathlen(self):
        self.assertEqual(self.ca.pathlen, 1)
        self.assertEqual(self.ca2.pathlen, 0)

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
        self.assertEqual(self.ca.subjectAltName(), certs['root']['san'])
        self.assertEqual(self.ca2.subjectAltName(), certs['child']['san'])
        self.assertEqual(self.cert.subjectAltName(), certs['cert1']['san'])
        self.assertEqual(self.cert2.subjectAltName(), certs['cert2']['san'])
        self.assertEqual(self.cert3.subjectAltName(), certs['cert3']['san'])

        self.assertEqual(
            self.full.subjectAltName(),
            (False, [
                'DNS:all.example.com',
                'dirname:/C=AT/CN=example.com',
                'email:user@example.com',
                'IP:fd00::1',
            ]))

    def test_basicConstraints(self):
        self.assertEqual(self.ca.basicConstraints(), (True, 'CA:TRUE, pathlen:1'))
        self.assertEqual(self.cert.basicConstraints(), (True, 'CA:FALSE'))
        self.assertEqual(self.cert2.basicConstraints(), (True, 'CA:FALSE'))
        # accidentally used cert2 in cn/san
        self.assertEqual(self.cert3.basicConstraints(), (True, 'CA:FALSE'))

    def test_issuerAltName(self):
        self.assertEqual(self.cert.issuerAltName(), certs['cert1']['issuerAltName'])
        self.assertEqual(self.cert2.issuerAltName(), certs['cert2']['issuerAltName'])
        self.assertEqual(self.cert3.issuerAltName(), certs['cert3']['issuerAltName'])

    def test_keyUsage(self):
        self.assertEqual(self.ca.keyUsage(), (True, ['cRLSign', 'keyCertSign']))
        self.assertEqual(self.ca2.keyUsage(), (True, ['cRLSign', 'keyCertSign']))
        self.assertEqual(self.cert.keyUsage(),
                         (True, ['digitalSignature', 'keyAgreement', 'keyEncipherment']))
        self.assertEqual(self.cert2.keyUsage(),
                         (True, ['digitalSignature', 'keyAgreement', 'keyEncipherment']))
        self.assertEqual(self.cert3.keyUsage(),
                         (True, ['digitalSignature', 'keyAgreement', 'keyEncipherment']))
        self.assertEqual(self.ocsp.keyUsage(),
                         (True, ['digitalSignature', 'keyEncipherment', 'nonRepudiation']))

    def test_extendedKeyUsage(self):
        self.assertEqual(self.ca.extendedKeyUsage(), None)
        self.assertEqual(self.ca2.extendedKeyUsage(), None)
        self.assertEqual(self.cert.extendedKeyUsage(), (False, ['serverAuth']))
        self.assertEqual(self.cert2.extendedKeyUsage(), (False, ['serverAuth']))
        self.assertEqual(self.cert3.extendedKeyUsage(), (False, ['serverAuth']))
        self.assertEqual(self.ocsp.extendedKeyUsage(), (False, ['OCSPSigning']))

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
        self.assertEqual(self.ca.authorityKeyIdentifier(), certs['root']['authKeyIdentifier'])
        self.assertEqual(self.ca2.authorityKeyIdentifier(), certs['child']['authKeyIdentifier'])
        self.assertEqual(self.cert.authorityKeyIdentifier(), certs['cert1']['authKeyIdentifier'])
        self.assertEqual(self.cert2.authorityKeyIdentifier(), certs['cert2']['authKeyIdentifier'])
        self.assertEqual(self.cert3.authorityKeyIdentifier(), certs['cert3']['authKeyIdentifier'])

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

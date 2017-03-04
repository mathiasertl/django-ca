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
            cls.ca, cert3_csr, {'CN': 'all.example.com'},
            san=['dirname:/C=AT/CN=example.com', 'email:user@example.com', 'fd00::1'])

    def setUp(self):
        self.ca2 = self.load_ca('child', child_pubkey, parent=self.ca)
        self.cert2 = self.load_cert(self.ca, cert2_pubkey)
        self.cert3 = self.load_cert(self.ca, cert3_pubkey)
        self.ocsp = self.load_cert(self.ca, ocsp_pubkey)

    def test_revocation(self):
        # Never really happens in real life, but should still be checked
        c = Certificate(revoked=False)

        with self.assertRaises(ValueError):
            c.get_revocation()

    def test_subjectAltName(self):
        self.assertEqual(self.ca.subjectAltName(), 'DNS:ca.example.com')
        self.assertEqual(self.cert.subjectAltName(), 'DNS:cert1.example.com')
        self.assertEqual(self.cert2.subjectAltName(), 'DNS:cert2.example.com')
        # accidentally used cert2 in cn/san
        self.assertEqual(self.cert3.subjectAltName(), 'DNS:cert2.example.com')

        self.assertEqual(
            self.full.subjectAltName(),
            'DNS:all.example.com, dirname:/C=AT/CN=example.com, email:user@example.com, IP:fd00::1')

    def test_basicConstraints(self):
        self.assertEqual(self.ca.basicConstraints(), 'critical,CA:TRUE, pathlen:1')
        self.assertEqual(self.cert.basicConstraints(), 'critical,CA:FALSE')
        self.assertEqual(self.cert2.basicConstraints(), 'critical,CA:FALSE')
        # accidentally used cert2 in cn/san
        self.assertEqual(self.cert3.basicConstraints(), 'critical,CA:FALSE')

    def test_issuerAltName(self):
        self.assertEqual(self.cert.issuerAltName(), 'DNS:ca.example.com')
        self.assertEqual(self.cert2.issuerAltName(), 'DNS:ca.example.com')
        self.assertEqual(self.cert3.issuerAltName(), 'DNS:ca.example.com')

    def test_keyUsage(self):
        self.assertEqual(self.ca.keyUsage(), 'cRLSign,keyCertSign')
        self.assertEqual(self.ca2.keyUsage(), 'cRLSign,keyCertSign')
        self.assertEqual(self.cert.keyUsage(), 'critical,digitalSignature,keyAgreement,keyEncipherment')
        self.assertEqual(self.cert2.keyUsage(), 'critical,digitalSignature,keyAgreement,keyEncipherment')
        self.assertEqual(self.cert3.keyUsage(), 'critical,digitalSignature,keyAgreement,keyEncipherment')
        self.assertEqual(self.ocsp.keyUsage(), 'critical,digitalSignature,keyEncipherment,nonRepudiation')

    def test_extendedKeyUsage(self):
        self.assertEqual(self.ca.extendedKeyUsage(), '')
        self.assertEqual(self.ca2.extendedKeyUsage(), '')
        self.assertEqual(self.cert.extendedKeyUsage(), 'serverAuth')
        self.assertEqual(self.cert2.extendedKeyUsage(), 'serverAuth')
        self.assertEqual(self.cert3.extendedKeyUsage(), 'serverAuth')
        self.assertEqual(self.ocsp.extendedKeyUsage(), 'OCSPSigning')

    def test_crlDistributionPoints(self):
        self.assertEqual(self.ca.crlDistributionPoints(), '')
        self.assertEqual(self.ca2.crlDistributionPoints(), '')
        self.assertEqual(self.cert.crlDistributionPoints(), '')
        self.assertEqual(self.cert2.crlDistributionPoints(), '')
        self.assertEqual(self.cert3.crlDistributionPoints(), '')
        self.assertEqual(self.ocsp.crlDistributionPoints(), '')
        self.assertEqual(self.full.crlDistributionPoints(), 'Full Name: URI:https://ca.example.com/crl.der')

    def test_digest(self):
        self.assertEqual(self.ca.get_digest('md5'), 'E6:B7:97:E8:16:E6:D3:EC:4C:6C:3F:74:82:B2:8C:8E')
        self.assertEqual(self.ca.get_digest('sha1'),
                         'E9:7D:EF:50:6B:E2:D4:DE:B9:E1:00:71:38:20:63:7F:2A:FD:4F:D6')
        self.assertEqual(self.ca.get_digest('sha256'),
                         '80:16:34:7B:D9:96:E8:B9:E3:F4:D5:49:02:B1:3E:15:17:9D:46:CA:F3:96:A5:BA:27:1F:75:73:AC:37:DF:E3')  # NOQA
        self.assertEqual(self.ca.get_digest('sha512'), '99:B2:C5:00:D9:4E:17:77:D0:BB:FE:DC:07:98:00:A5:29:F6:8B:17:B2:9F:A1:38:D1:21:8A:D5:3A:9D:1B:02:F9:9D:4B:EE:B8:AA:D7:F5:DA:7E:D5:88:0C:C8:91:BC:3B:5F:ED:40:D1:5A:CB:CD:9F:C8:1F:7B:78:76:31:4A')  # NOQA

        self.assertEqual(self.ca2.get_digest('md5'), 'E9:EE:C3:65:47:73:73:28:7F:3E:40:C2:11:87:95:F9')
        self.assertEqual(self.ca2.get_digest('sha1'),
                         '4E:1E:A1:4D:6E:31:EF:2D:74:08:94:52:CE:B0:EC:CB:21:0C:DA:2F')
        self.assertEqual(self.ca2.get_digest('sha256'), '93:7B:E2:6F:68:35:91:8E:2A:7F:0D:63:80:1A:15:8A:CE:E4:6D:78:41:72:A9:2E:E6:CE:60:BC:20:C5:29:86')  # NOQA
        self.assertEqual(self.ca2.get_digest('sha512'), 'A5:44:E7:0D:19:F9:04:A0:EA:79:D5:3D:03:76:BD:FE:65:9B:C5:25:F2:F7:35:55:F4:DD:22:43:F5:C9:7D:67:C0:52:C9:CE:E3:6D:A0:DD:4E:C9:E8:A2:D4:A6:D7:49:DB:41:1C:EC:FF:E1:0C:3F:4B:E9:67:BD:DA:E3:DD:F4')  # NOQA

        self.assertEqual(self.cert.get_digest('md5'), '0C:B6:17:65:D3:A9:E7:49:87:06:EA:A3:7E:D4:9E:54')
        self.assertEqual(self.cert.get_digest('sha1'),
                         '47:B7:D3:A1:9E:02:5C:7B:E2:65:4E:28:2E:CF:13:5C:18:EC:6C:F8')
        self.assertEqual(self.cert.get_digest('sha256'), '6D:F9:F7:B9:24:D6:38:38:C5:97:88:85:FB:8B:EE:BB:6C:BF:DE:B4:EE:EF:C7:CA:E3:9F:79:8D:13:AC:62:78')  # NOQA
        self.assertEqual(self.cert.get_digest('sha512'), 'F4:16:BE:BD:8E:33:6A:79:0E:4B:ED:1C:52:10:8A:B3:AF:A1:6A:D9:FC:49:B0:B9:02:2B:ED:A3:91:15:6E:16:D6:31:5B:5E:47:8A:B3:7E:1B:C9:8E:45:6E:A0:BD:50:72:3D:60:20:67:93:B2:0E:7D:1A:36:9C:84:1D:AE:59')  # NOQA

        self.assertEqual(self.cert2.get_digest('md5'), '65:CE:08:5D:E6:DF:88:55:CF:38:83:30:96:EB:0D:22')
        self.assertEqual(self.cert2.get_digest('sha1'),
                         '73:51:1A:3A:AF:4F:01:5A:5D:AA:D1:BD:26:64:BE:FE:79:9F:71:91')
        self.assertEqual(self.cert2.get_digest('sha256'), '58:A3:75:B7:4B:A0:9D:ED:41:3C:7E:FE:AB:3B:BE:ED:3C:77:B3:BE:9F:F8:C4:3D:5E:AF:E5:C3:70:1F:10:14')  # NOQA
        self.assertEqual(self.cert2.get_digest('sha512'), '88:78:87:EE:D7:D1:43:E8:A4:B7:20:AC:14:B5:86:A8:97:2D:A3:5C:A8:F8:0A:64:49:70:4E:A5:8D:F3:D8:74:B0:84:6D:EB:00:C8:11:C8:12:AB:A7:65:44:DB:10:9C:8A:1B:51:D4:E9:65:02:3D:8A:83:F6:FE:A7:AB:42:45')  # NOQA

        self.assertEqual(self.cert3.get_digest('md5'), '4E:32:1B:2A:5D:2A:F8:84:FC:C1:F8:78:63:EC:68:F0')
        self.assertEqual(self.cert3.get_digest('sha1'),
                         'E7:74:DB:A6:01:15:6E:5E:3E:18:7C:20:14:59:4D:8D:93:F1:9A:72')
        self.assertEqual(self.cert3.get_digest('sha256'), '41:0B:41:6F:92:94:1D:3A:4E:2A:6D:A2:E5:66:47:0D:A7:43:D2:CE:E8:6D:65:44:77:B7:87:A3:3B:45:EB:21')  # NOQA
        self.assertEqual(self.cert3.get_digest('sha512'), '7F:73:5B:1B:54:F0:EC:91:DD:D0:3D:B4:09:07:2B:BD:5B:23:BA:59:EA:15:C1:34:57:14:65:DA:9F:6A:84:3C:2F:8D:01:80:52:72:B9:D2:12:3B:4C:EC:3D:2C:33:AA:D5:DE:AA:70:44:C2:60:13:51:8B:1E:98:37:E1:82:63')  # NOQA

    def test_authorityKeyIdentifier(self):
        self.assertEqual(self.cert.authorityKeyIdentifier(),
                         'keyid:6B:C8:CF:56:29:FC:00:55:DD:A5:ED:5A:55:B7:7C:65:49:AC:AD:B1\n')
        self.assertEqual(self.cert2.authorityKeyIdentifier(),
                         'keyid:6B:C8:CF:56:29:FC:00:55:DD:A5:ED:5A:55:B7:7C:65:49:AC:AD:B1\n')
        self.assertEqual(self.cert3.authorityKeyIdentifier(),
                         'keyid:6B:C8:CF:56:29:FC:00:55:DD:A5:ED:5A:55:B7:7C:65:49:AC:AD:B1\n')

    def test_nameConstraints(self):
        self.assertEqual(self.ca.nameConstraints(), '')

    def test_hpkp_pin(self):

        # get hpkp pins using
        #   openssl x509 -in cert1.pem -pubkey -noout \
        #       | openssl rsa -pubin -outform der \
        #       | openssl dgst -sha256 -binary | base64
        self.assertEqual(self.cert.hpkp_pin, '/W7D0lNdHVFrH/hzI16BPkhoojMVl5JmjEunZqXaEKI=')
        self.assertEqual(self.cert2.hpkp_pin, 'K8Kykt/NPbgrMs20gZ9vXpyBT8FQqa5QyRsEgNXQTZc=')
        self.assertEqual(self.cert3.hpkp_pin, 'wqXwnXNXwtIEXGx6j9x7Tg8zAnoiNjKbH1OKqumXCFg=')

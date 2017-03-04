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

from datetime import timedelta
from io import BytesIO

from cryptography.hazmat.primitives.serialization import Encoding

from django.core.management.base import CommandError
from django.utils import timezone

from ..models import Certificate
from ..models import Watcher
from .base import DjangoCAWithCertTestCase
from .base import override_tmpcadir


# TODO: Use verbatim strings instead of interpolating

@override_tmpcadir(CA_MIN_KEY_SIZE=1024, CA_PROFILES={}, CA_DEFAULT_SUBJECT={})
class ViewCertTestCase(DjangoCAWithCertTestCase):
    def _get_format(self, cert):
        return {
            'cn': cert.cn,
            'from': cert.not_before.strftime('%Y-%m-%d %H:%M'),
            'until': cert.not_after.strftime('%Y-%m-%d %H:%M'),
            'pub': cert.pub,
            'md5': cert.get_digest('md5'),
            'sha1': cert.get_digest('sha1'),
            'sha256': cert.get_digest('sha256'),
            'sha512': cert.get_digest('sha512'),
            'subjectKeyIdentifier': cert.subjectKeyIdentifier(),
            'authorityKeyIdentifier': cert.ca.subjectKeyIdentifier(),
            'hpkp': cert.hpkp_pin,
        }

    def test_basic(self):
        stdout, stderr = self.cmd('view_cert', self.cert.serial,
                                  stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stdout.decode('utf-8'), '''Common Name: %(cn)s
Valid from: %(from)s
Valid until: %(until)s
Status: Valid
subjectAltName:
    DNS:%(cn)s
Watchers:
Digest:
    md5: %(md5)s
    sha1: %(sha1)s
    sha256: %(sha256)s
    sha512: %(sha512)s
HPKP pin: %(hpkp)s

%(pub)s''' % self._get_format(self.cert))
        self.assertEqual(stderr, b'')

        # test with no pem but with extensions
        stdout, stderr = self.cmd('view_cert', self.cert.serial, no_pem=True, extensions=True,
                                  stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stdout.decode('utf-8'), '''Common Name: %(cn)s
Valid from: %(from)s
Valid until: %(until)s
Status: Valid
authorityKeyIdentifier:
    keyid:%(authorityKeyIdentifier)s
basicConstraints:
    CA:FALSE
extendedKeyUsage:
    TLS Web Server Authentication
issuerAltName:
    DNS:ca.example.com
keyUsage:
    Digital Signature, Key Encipherment, Key Agreement
subjectAltName:
    DNS:%(cn)s
subjectKeyIdentifier:
    %(subjectKeyIdentifier)s
Watchers:
Digest:
    md5: %(md5)s
    sha1: %(sha1)s
    sha256: %(sha256)s
    sha512: %(sha512)s
HPKP pin: %(hpkp)s
''' % self._get_format(self.cert))
        self.assertEqual(stderr, b'')

    def test_der(self):
        self.maxDiff = None
        stdout, stderr = self.cmd('view_cert', self.cert.serial, format=Encoding.DER,
                                  stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stdout, b'''Common Name: cert1.example.com
Valid from: 2016-05-15 19:32
Valid until: 2018-05-16 00:00
Status: Valid
subjectAltName:
    DNS:cert1.example.com
Watchers:
Digest:
    md5: 0C:B6:17:65:D3:A9:E7:49:87:06:EA:A3:7E:D4:9E:54
    sha1: 47:B7:D3:A1:9E:02:5C:7B:E2:65:4E:28:2E:CF:13:5C:18:EC:6C:F8
    sha256: 6D:F9:F7:B9:24:D6:38:38:C5:97:88:85:FB:8B:EE:BB:6C:BF:DE:B4:EE:EF:C7:CA:E3:9F:79:8D:13:AC:62:78
    sha512: F4:16:BE:BD:8E:33:6A:79:0E:4B:ED:1C:52:10:8A:B3:AF:A1:6A:D9:FC:49:B0:B9:02:2B:ED:A3:91:15:6E:16:D6:31:5B:5E:47:8A:B3:7E:1B:C9:8E:45:6E:A0:BD:50:72:3D:60:20:67:93:B2:0E:7D:1A:36:9C:84:1D:AE:59
HPKP pin: /W7D0lNdHVFrH/hzI16BPkhoojMVl5JmjEunZqXaEKI=

0\x82\x03,0\x82\x02\x95\xa0\x03\x02\x01\x02\x02\x10#\x14\xe2\xed_[I\x0f\xbb\xda\x14\x00J\xc8\xa1\x1b0\r\x06\t*\x86H\x86\xf7\r\x01\x01\r\x05\x000\x81\x871\x0b0\t\x06\x03U\x04\x06\x13\x02AT1\x0f0\r\x06\x03U\x04\x08\x0c\x06Vienna1\x0f0\r\x06\x03U\x04\x07\x0c\x06Vienna1\x0c0\n\x06\x03U\x04\n\x0c\x03Org1\x100\x0e\x06\x03U\x04\x0b\x0c\x07OrgUnit1\x170\x15\x06\x03U\x04\x03\x0c\x0eca.example.com1\x1d0\x1b\x06\t*\x86H\x86\xf7\r\x01\t\x01\x16\x0eca@example.com0"\x18\x0f20160515193200Z\x18\x0f20180516000000Z0k1\x0b0\t\x06\x03U\x04\x06\x13\x02AT1\x0f0\r\x06\x03U\x04\x08\x0c\x06Vienna1\x0f0\r\x06\x03U\x04\x07\x0c\x06Vienna1\x1e0\x1c\x06\x03U\x04\x0b\x0c\x15Fachschaft Informatik1\x1a0\x18\x06\x03U\x04\x03\x0c\x11cert1.example.com0\x81\x9f0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x81\x8d\x000\x81\x89\x02\x81\x81\x00\xe0;\xa7g\x9dB\x98\xbeD\x1e\x9fuN\xe0t\xee\xd6`Vv\x8e\xc4\r\xa10\x0b\x16\x9d\x85\x89?\xfeO\x93x\xdeogBt\xd1^\xb5T\x12\xd5\x86\x84\x0b\xc1I\xb4\xb3\xcd\xb7.v\x8eFm\x11\xb7B\tS\x98\xab\xa3O\xcc\xf9\x12L5x\x87\x98\xe2\xb9\x9f\x10\x8d\x1d\xb5d\x01z\xf2c\x17\xf0\xee7 G\xaf\x1a\xc9\x9f\xd7\x94\xd1\xa3\xa7\'\x86\x9c"\x10s-U\xc84IzH\xaaDD\x05J\xa3\x9bs\xc7\xe4\x99\x02\x03\x01\x00\x01\xa3\x81\xaf0\x81\xac0\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14XEU{N\xec\xce\xf4\xbe\xd0\xfeJ$\x84G\xffr3 \xb40\x1f\x06\x03U\x1d#\x04\x180\x16\x80\x14k\xc8\xcfV)\xfc\x00U\xdd\xa5\xedZU\xb7|eI\xac\xad\xb10\x0c\x06\x03U\x1d\x13\x01\x01\xff\x04\x020\x000\x0e\x06\x03U\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x03\xa80\x13\x06\x03U\x1d%\x04\x0c0\n\x06\x08+\x06\x01\x05\x05\x07\x03\x010\x1c\x06\x03U\x1d\x11\x04\x150\x13\x82\x11cert1.example.com0\x19\x06\x03U\x1d\x12\x04\x120\x10\x82\x0eca.example.com0\r\x06\t*\x86H\x86\xf7\r\x01\x01\r\x05\x00\x03\x81\x81\x00\x17\xb9\xaf\x8d\x9e\x8a\xa8\xb82t\xcb,\xe9tq\xf1\xc7\xca\x90\x82\xc5\x84\xce\xe6\xc1\xcbf\xfcs\n\x12\xbd\xf8\xe1\xed3\x94B\xd3\x92\xe1aZ\xb7\tN=\x97\x86\xb1]0\x9d\xf65B8o\xfc\xc8\xf876\t\xcebs\x19r\x9a\xd9g\xb1\xce@\x0e*\xecm\xa8\x0f\x92>\xce\x88\x81V\xbd\xd0\x12;]\xa0%\xfe\xb8\xf1\xb4\x8e\x13\x84F$Y\xb1]\xc2Yn\xa4\x89\xc4\x9b]\xcf\x8er\xc7\xd0\xd2\xa3\xf7\x18\x1e\xe5\x1f\xb9n
''')  # NOQA
        self.assertEqual(stderr, b'')

    def test_revoked(self):
        cert = Certificate.objects.get(serial=self.cert.serial)
        cert.revoked = True
        cert.save()
        stdout, stderr = self.cmd('view_cert', cert.serial, no_pem=True, stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stdout.decode('utf-8'), '''Common Name: %(cn)s
Valid from: %(from)s
Valid until: %(until)s
Status: Revoked
subjectAltName:
    DNS:%(cn)s
Watchers:
Digest:
    md5: %(md5)s
    sha1: %(sha1)s
    sha256: %(sha256)s
    sha512: %(sha512)s
HPKP pin: %(hpkp)s
''' % self._get_format(self.cert))
        self.assertEqual(stderr, b'')

    def test_expired(self):
        cert = Certificate.objects.get(serial=self.cert.serial)
        cert.expires = timezone.now() - timedelta(days=30)
        cert.save()

        stdout, stderr = self.cmd('view_cert', cert.serial, no_pem=True, stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stdout.decode('utf-8'), '''Common Name: %(cn)s
Valid from: %(from)s
Valid until: %(until)s
Status: Expired
subjectAltName:
    DNS:%(cn)s
Watchers:
Digest:
    md5: %(md5)s
    sha1: %(sha1)s
    sha256: %(sha256)s
    sha512: %(sha512)s
HPKP pin: %(hpkp)s
''' % self._get_format(self.cert))
        self.assertEqual(stderr, b'')

    def test_no_san_with_watchers(self):
        # test a cert with no subjectAltNames but with watchers.
        cert = self.create_cert(self.ca, self.csr_pem, {'CN': 'example.com'}, cn_in_san=False)
        watcher = Watcher.from_addr('user@example.com')
        cert.watchers.add(watcher)

        stdout, stderr = self.cmd('view_cert', cert.serial, no_pem=True, stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stdout.decode('utf-8'), '''Common Name: %(cn)s
Valid from: %(from)s
Valid until: %(until)s
Status: Valid
Watchers:
* user@example.com
Digest:
    md5: %(md5)s
    sha1: %(sha1)s
    sha256: %(sha256)s
    sha512: %(sha512)s
HPKP pin: %(hpkp)s
''' % self._get_format(cert))
        self.assertEqual(stderr, b'')

    def test_unknown_cert(self):
        with self.assertRaises(CommandError):
            self.cmd('view_cert', 'fooobar', no_pem=True)

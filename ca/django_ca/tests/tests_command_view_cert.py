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

from django.core.management.base import CommandError
from django.utils import timezone

from ..models import Certificate
from ..models import Watcher
from .base import DjangoCAWithCertTestCase
from .base import override_tmpcadir


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
        stdout, stderr = self.cmd('view_cert', self.cert.serial)
        self.assertEqual(stdout, '''Common Name: %(cn)s
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
        self.assertEqual(stderr, '')

        # test with no pem but with extensions
        stdout, stderr = self.cmd('view_cert', self.cert.serial, no_pem=True, extensions=True)
        self.assertEqual(stdout, '''Common Name: %(cn)s
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
        self.assertEqual(stderr, '')

    def test_revoked(self):
        cert = Certificate.objects.get(serial=self.cert.serial)
        cert.revoked = True
        cert.save()
        stdout, stderr = self.cmd('view_cert', cert.serial, no_pem=True)
        self.assertEqual(stdout, '''Common Name: %(cn)s
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
        self.assertEqual(stderr, '')

    def test_expired(self):
        cert = Certificate.objects.get(serial=self.cert.serial)
        cert.expires = timezone.now() - timedelta(days=30)
        cert.save()

        stdout, stderr = self.cmd('view_cert', cert.serial, no_pem=True)
        self.assertEqual(stdout, '''Common Name: %(cn)s
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
        self.assertEqual(stderr, '')

    def test_no_san_with_watchers(self):
        # test a cert with no subjectAltNames but with watchers.
        cert = self.create_cert(self.ca, self.csr_pem, {'CN': 'example.com'}, cn_in_san=False)
        watcher = Watcher.from_addr('user@example.com')
        cert.watchers.add(watcher)

        stdout, stderr = self.cmd('view_cert', cert.serial, no_pem=True)
        self.assertEqual(stdout, '''Common Name: %(cn)s
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

    def test_unknown_cert(self):
        with self.assertRaises(CommandError):
            self.cmd('view_cert', 'fooobar', no_pem=True)

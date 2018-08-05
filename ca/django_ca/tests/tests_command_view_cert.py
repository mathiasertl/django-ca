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
from django.utils.encoding import force_bytes

from ..models import Certificate
from ..models import Watcher
from .base import DjangoCAWithCertTestCase
from .base import certs
from .base import cloudflare_1_pubkey
from .base import multiple_ous_and_no_ext_pubkey
from .base import override_settings
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
            'san': cert.subjectAltName(),
        }

    def test_basic(self):
        stdout, stderr = self.cmd('view_cert', self.cert.serial, stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stdout.decode('utf-8'), '''Common Name: %(cn)s
Valid from: %(from)s
Valid until: %(until)s
Status: %(status)s
subjectAltName:
    * %(san_0)s
Watchers:
Digest:
    md5: %(md5)s
    sha1: %(sha1)s
    sha256: %(sha256)s
    sha512: %(sha512)s
HPKP pin: %(hpkp)s

%(pem)s''' % self.get_cert_context('cert1'))

        self.assertEqual(stderr, b'')

        # test with no pem but with extensions
        stdout, stderr = self.cmd('view_cert', self.cert.serial, no_pem=True, extensions=True,
                                  stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stdout.decode('utf-8'), '''Common Name: %(cn)s
Valid from: %(from)s
Valid until: %(until)s
Status: %(status)s
authorityInfoAccess:
    * %(authInfoAccess_0)s
    * %(authInfoAccess_1)s
authorityKeyIdentifier:
    %(authKeyIdentifier)s
basicConstraints (critical):
    CA:FALSE
cRLDistributionPoints:
    * %(crl_0)s
extendedKeyUsage:
    * serverAuth
issuerAltName:
    %(issuerAltName)s
keyUsage (critical):
    * %(keyUsage_0)s
    * %(keyUsage_1)s
    * %(keyUsage_2)s
subjectAltName:
    * %(san_0)s
subjectKeyIdentifier:
    %(subjectKeyIdentifier)s
Watchers:
Digest:
    md5: %(md5)s
    sha1: %(sha1)s
    sha256: %(sha256)s
    sha512: %(sha512)s
HPKP pin: %(hpkp)s
''' % self.get_cert_context('cert1'))
        self.assertEqual(stderr, b'')

    @override_settings(USE_TZ=True)
    def test_basic_with_use_tz(self):
        self.test_basic()

    def test_der(self):
        self.maxDiff = None
        stdout, stderr = self.cmd('view_cert', self.cert.serial, format=Encoding.DER,
                                  stdout=BytesIO(), stderr=BytesIO())
        expected = '''Common Name: %(cn)s
Valid from: %(from)s
Valid until: %(until)s
Status: %(status)s
subjectAltName:
    * %(san_0)s
Watchers:
Digest:
    md5: %(md5)s
    sha1: %(sha1)s
    sha256: %(sha256)s
    sha512: %(sha512)s
HPKP pin: %(hpkp)s

''' % self.get_cert_context('cert1')
        expected = force_bytes(expected) + certs['cert1']['der'] + b'\n'

        self.assertEqual(stdout, expected)
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
    * DNS:%(cn)s
Watchers:
Digest:
    md5: %(md5)s
    sha1: %(sha1)s
    sha256: %(sha256)s
    sha512: %(sha512)s
HPKP pin: %(hpkp)s
''' % certs['cert1'])
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
    * DNS:%(cn)s
Watchers:
Digest:
    md5: %(md5)s
    sha1: %(sha1)s
    sha256: %(sha256)s
    sha512: %(sha512)s
HPKP pin: %(hpkp)s
''' % certs['cert1'])
        self.assertEqual(stderr, b'')

    @override_settings(USE_TZ=True)
    def test_expired_with_use_tz(self):
        self.test_expired()

    def test_no_san_with_watchers(self):
        # test a cert with no subjectAltNames but with watchers.
        cert = self.create_cert(self.ca, self.csr_pem, [('CN', 'example.com')], cn_in_san=False)
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

    def test_contrib_multiple_ous_and_no_ext(self):
        self.maxDiff = None
        cert = self.load_cert(self.ca, x509=multiple_ous_and_no_ext_pubkey)
        stdout, stderr = self.cmd('view_cert', cert.serial, no_pem=True, extensions=True,
                                  stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b'')
        self.assertEqual(stdout.decode('utf-8'), '''Common Name: %(cn)s
Valid from: 1998-05-18 00:00
Valid until: 2028-08-01 23:59
Status: Valid
Watchers:
Digest:
    md5: A2:33:9B:4C:74:78:73:D4:6C:E7:C1:F3:8D:CB:5C:E9
    sha1: 85:37:1C:A6:E5:50:14:3D:CE:28:03:47:1B:DE:3A:09:E8:F8:77:0F
    sha256: 83:CE:3C:12:29:68:8A:59:3D:48:5F:81:97:3C:0F:91:95:43:1E:DA:37:CC:5E:36:43:0E:79:C7:A8:88:63:8B
    sha512: 86:20:07:9F:8B:06:80:43:44:98:F6:7A:A4:22:DE:7E:2B:33:10:9B:65:72:79:C4:EB:F3:F3:0F:66:C8:6E:89:1D:4C:6C:09:1C:83:45:D1:25:6C:F8:65:EB:9A:B9:50:8F:26:A8:85:AE:3A:E4:8A:58:60:48:65:BB:44:B6:CE
HPKP pin: AjyBzOjnxk+pQtPBUEhwfTXZu1uH9PVExb8bxWQ68vo=
''' % {'cn': ''})  # NOQA

    def test_contrib_cloudflare_1(self):
        self.maxDiff = None
        cert = self.load_cert(self.ca, x509=cloudflare_1_pubkey)
        stdout, stderr = self.cmd('view_cert', cert.serial, no_pem=True, extensions=True,
                                  stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b'')
        self.assertEqual(stdout.decode('utf-8'), '''Common Name: sni24142.cloudflaressl.com
Valid from: 2018-07-18 00:00
Valid until: 2019-01-24 23:59
Status: Valid
UnknownOID (critical):
    <ObjectIdentifier(oid=1.3.6.1.4.1.11129.2.4.3, name=Unknown OID)>
authorityInfoAccess:
    * CA Issuers - URI:http://crt.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crt
    * OCSP - URI:http://ocsp.comodoca4.com
authorityKeyIdentifier:
    keyid:40:09:61:67:F0:BC:83:71:4F:DE:12:08:2C:6F:D4:D4:2B:76:3D:96
basicConstraints (critical):
    CA:FALSE
cRLDistributionPoints:
    * Full Name: URI:http://crl.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crl
certificatePolicies:
    <ObjectIdentifier(oid=2.5.29.32, name=certificatePolicies)>
extendedKeyUsage:
    * serverAuth
    * clientAuth
keyUsage (critical):
    * digitalSignature
subjectAltName:
    * DNS:sni24142.cloudflaressl.com
    * DNS:*.animereborn.com
    * DNS:*.beglideas.ga
    * DNS:*.chroma.ink
    * DNS:*.chuckscleanings.ga
    * DNS:*.clipvuigiaitris.ga
    * DNS:*.cmvsjns.ga
    * DNS:*.competegraphs.ga
    * DNS:*.consoleprints.ga
    * DNS:*.copybreezes.ga
    * DNS:*.corphreyeds.ga
    * DNS:*.cyanigees.ga
    * DNS:*.dadpbears.ga
    * DNS:*.dahuleworldwides.ga
    * DNS:*.dailyopeningss.ga
    * DNS:*.daleylexs.ga
    * DNS:*.danajweinkles.ga
    * DNS:*.dancewthyogas.ga
    * DNS:*.darkmoosevpss.ga
    * DNS:*.daurat.com.ar
    * DNS:*.deltaberg.com
    * DNS:*.drjahanobgyns.ga
    * DNS:*.drunkgirliess.ga
    * DNS:*.duhiepkys.ga
    * DNS:*.dujuanjsqs.ga
    * DNS:*.dumbiseasys.ga
    * DNS:*.dumpsoftdrinkss.ga
    * DNS:*.dunhavenwoodss.ga
    * DNS:*.durabiliteas.ga
    * DNS:*.duxmangroups.ga
    * DNS:*.dvpdrivewayss.ga
    * DNS:*.dwellwizes.ga
    * DNS:*.dwwkouis.ga
    * DNS:*.entertastic.com
    * DNS:*.estudiogolber.com.ar
    * DNS:*.letsretro.team
    * DNS:*.maccuish.org.uk
    * DNS:*.madamsquiggles.com
    * DNS:*.sftw.ninja
    * DNS:*.spangenberg.io
    * DNS:*.timmutton.com.au
    * DNS:*.wyomingsexbook.com
    * DNS:*.ych.bid
    * DNS:animereborn.com
    * DNS:beglideas.ga
    * DNS:chroma.ink
    * DNS:chuckscleanings.ga
    * DNS:clipvuigiaitris.ga
    * DNS:cmvsjns.ga
    * DNS:competegraphs.ga
    * DNS:consoleprints.ga
    * DNS:copybreezes.ga
    * DNS:corphreyeds.ga
    * DNS:cyanigees.ga
    * DNS:dadpbears.ga
    * DNS:dahuleworldwides.ga
    * DNS:dailyopeningss.ga
    * DNS:daleylexs.ga
    * DNS:danajweinkles.ga
    * DNS:dancewthyogas.ga
    * DNS:darkmoosevpss.ga
    * DNS:daurat.com.ar
    * DNS:deltaberg.com
    * DNS:drjahanobgyns.ga
    * DNS:drunkgirliess.ga
    * DNS:duhiepkys.ga
    * DNS:dujuanjsqs.ga
    * DNS:dumbiseasys.ga
    * DNS:dumpsoftdrinkss.ga
    * DNS:dunhavenwoodss.ga
    * DNS:durabiliteas.ga
    * DNS:duxmangroups.ga
    * DNS:dvpdrivewayss.ga
    * DNS:dwellwizes.ga
    * DNS:dwwkouis.ga
    * DNS:entertastic.com
    * DNS:estudiogolber.com.ar
    * DNS:letsretro.team
    * DNS:maccuish.org.uk
    * DNS:madamsquiggles.com
    * DNS:sftw.ninja
    * DNS:spangenberg.io
    * DNS:timmutton.com.au
    * DNS:wyomingsexbook.com
    * DNS:ych.bid
subjectKeyIdentifier:
    05:86:D8:B4:ED:A9:7E:23:EE:2E:E7:75:AA:3B:2C:06:08:2A:93:B2
Watchers:
Digest:
    md5: D6:76:03:E9:4F:3B:B0:F1:F7:E3:A1:40:80:8E:F0:4A
    sha1: 71:BD:B8:21:80:BD:86:E8:E5:F4:2B:6D:96:82:B2:EF:19:53:ED:D3
    sha256: 1D:8E:D5:41:E5:FF:19:70:6F:65:86:A9:A3:6F:DF:DE:F8:A0:07:22:92:71:9E:F1:CD:F8:28:37:39:02:E0:A1
    sha512: FF:03:1B:8F:11:E8:A7:FF:91:4F:B9:97:E9:97:BC:77:37:C1:A7:69:86:F3:7C:E3:BB:BB:DF:A6:4F:0E:3C:C0:7F:B5:BC:CC:BD:0A:D5:EF:5F:94:55:E9:FF:48:41:34:B8:11:54:57:DD:90:85:41:2E:71:70:5E:FA:BA:E6:EA
HPKP pin: bkunFfRSda4Yhz7UlMUaalgj0Gcus/9uGVp19Hceczg=
''')  # NOQA

    def test_unknown_cert(self):
        with self.assertRaises(CommandError):
            self.cmd('view_cert', 'fooobar', no_pem=True)

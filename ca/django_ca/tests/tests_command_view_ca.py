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

from django.conf import settings

from ..models import CertificateAuthority
from .base import DjangoCAWithCATestCase
from .base import child_pubkey
from .base import override_tmpcadir


class ViewCATestCase(DjangoCAWithCATestCase):
    maxDiff = None

    def assertOutput(self, ca, stdout, san=''):
        status = 'enabled' if self.ca.enabled else 'disabled'
        if ca.children.all():
            children = '* Children:\n'
            for child in ca.children.all():
                children += '  * %s (%s)\n' % (child.name, child.serial)
            children = children.strip()
        else:
            children = '* Has no children.'

        if ca.parent is None:
            parent = '* Is a root CA.'
        else:
            parent = '* Parent: %s (%s)' % (ca.parent.name, ca.parent.serial)
        pathlen = 'unlimited' if ca.pathlen is None else ca.pathlen

        if san != '':
            san = '\nsubjectAltName:\n    DNS:%s' % san

        self.assertEqual(stdout, '''%s (%s):
* Serial: %s
* Path to private key:
  %s
%s
%s
* Distinguished Name: %s
* Maximum levels of sub-CAs (pathlen): %s
* HPKP pin: %s

X509 v3 certificate extensions for CA:
authorityKeyIdentifier:
    %s
basicConstraints:
    %s
keyUsage:
    critical,Certificate Sign, CRL Sign%s
subjectKeyIdentifier:
    %s

X509 v3 certificate extensions for signed certificates:
* Certificate Revokation List (CRL): None
* Issuer URL: None
* OCSP URL: None
* Issuer Alternative Name: None

%s''' % (ca.name, status, ca.serial, ca.private_key_path, parent, children, ca.distinguishedName(),
         pathlen, ca.hpkp_pin, ca.authorityKeyIdentifier().strip(), ca.basicConstraints(),
         san, ca.subjectKeyIdentifier(), ca.pub))

    def test_basic(self):
        stdout, stderr = self.cmd('view_ca', self.ca.serial)
        self.assertEqual(stdout, '''root (enabled):
* Serial: 35:DB:D2:AD:79:0A:4D:1F:B5:26:ED:5F:83:74:C0:C2
* Path to private key:
  /home/mati/git/mati/django-ca/ca/django_ca/tests/fixtures/root.key
* Is a root CA.
* Has no children.
* Distinguished Name: /C=AT/ST=Vienna/L=Vienna/O=Org/OU=OrgUnit/CN=ca.example.com/emailAddress=ca@example.com
* Maximum levels of sub-CAs (pathlen): 1
* HPKP pin: XmTZPvdKBPls+/JoVM98/8ASycc/9WMd3fgmbaN2rII=

X509 v3 certificate extensions for CA:
authorityKeyIdentifier:
    keyid:6B:C8:CF:56:29:FC:00:55:DD:A5:ED:5A:55:B7:7C:65:49:AC:AD:B1
basicConstraints:
    critical,CA:TRUE, pathlen:1
keyUsage:
    Certificate Sign, CRL Sign
subjectAltName:
    DNS:ca.example.com
subjectKeyIdentifier:
    6B:C8:CF:56:29:FC:00:55:DD:A5:ED:5A:55:B7:7C:65:49:AC:AD:B1

X509 v3 certificate extensions for signed certificates:
* Certificate Revokation List (CRL): None
* Issuer URL: None
* OCSP URL: None
* Issuer Alternative Name: None

-----BEGIN CERTIFICATE-----
MIIDFzCCAoCgAwIBAgIQNdvSrXkKTR+1Ju1fg3TAwjANBgkqhkiG9w0BAQ0FADCB
hzELMAkGA1UEBhMCQVQxDzANBgNVBAgMBlZpZW5uYTEPMA0GA1UEBwwGVmllbm5h
MQwwCgYDVQQKDANPcmcxEDAOBgNVBAsMB09yZ1VuaXQxFzAVBgNVBAMMDmNhLmV4
YW1wbGUuY29tMR0wGwYJKoZIhvcNAQkBFg5jYUBleGFtcGxlLmNvbTAiGA8yMDE2
MDUxMDE3NTYwMFoYDzIxMTYwNDE3MDAwMDAwWjCBhzELMAkGA1UEBhMCQVQxDzAN
BgNVBAgMBlZpZW5uYTEPMA0GA1UEBwwGVmllbm5hMQwwCgYDVQQKDANPcmcxEDAO
BgNVBAsMB09yZ1VuaXQxFzAVBgNVBAMMDmNhLmV4YW1wbGUuY29tMR0wGwYJKoZI
hvcNAQkBFg5jYUBleGFtcGxlLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC
gYEArdnr5gKSNJdxtjJJ49kpC4Yd79GcBEwhQeiRciGNdap/wbDl5Xff4EapLvP1
KMlXPyb6af2HVpCjuVSUjOtxzNgSOgLbWKYuuSaxzRvSS7ydXBMLJCJFTGFwul39
2U/zNO0JmDyd7Pk5trpqImpmSetSxRz5AL5mhxY2FNWkegUCAwEAAaN+MHwwEgYD
VR0TAQH/BAgwBgEB/wIBATALBgNVHQ8EBAMCAQYwHQYDVR0OBBYEFGvIz1Yp/ABV
3aXtWlW3fGVJrK2xMBkGA1UdEQQSMBCCDmNhLmV4YW1wbGUuY29tMB8GA1UdIwQY
MBaAFGvIz1Yp/ABV3aXtWlW3fGVJrK2xMA0GCSqGSIb3DQEBDQUAA4GBAIT/5guU
8uWiyQ6e3lRuuY4ioeaTOBI94Ygn1Dym328hVJfjsdFXHAP9Tfs2Sg3+Sj0CICnX
TzM06CLgrbfk/hQjU+H+dcfh5ahBH78MbytsAnzs8KlfBPnfeuLti3RnfXSkOAUZ
kbfhROu065IYOU0LmqufhP3IdGSeFtiw6nPw
-----END CERTIFICATE-----
''')
        self.assertEqual(stderr, '')

    def test_family(self):
        parent = CertificateAuthority.objects.get(name=self.ca.name)
        child = self.load_ca(name='child', x509=child_pubkey, parent=self.ca)

        stdout, stderr = self.cmd('view_ca', parent.serial)
        #self.assertOutput(parent, stdout, san='ca.example.com')
        self.assertEqual(stdout, '''root (enabled):
* Serial: 35:DB:D2:AD:79:0A:4D:1F:B5:26:ED:5F:83:74:C0:C2
* Path to private key:
  /home/mati/git/mati/django-ca/ca/django_ca/tests/fixtures/root.key
* Is a root CA.
* Children:
  * child (6A:A2:3D:F9:5A:4A:44:8A:9F:91:64:54:A2:0D:04:29)
* Distinguished Name: /C=AT/ST=Vienna/L=Vienna/O=Org/OU=OrgUnit/CN=ca.example.com/emailAddress=ca@example.com
* Maximum levels of sub-CAs (pathlen): 1
* HPKP pin: XmTZPvdKBPls+/JoVM98/8ASycc/9WMd3fgmbaN2rII=

X509 v3 certificate extensions for CA:
authorityKeyIdentifier:
    keyid:6B:C8:CF:56:29:FC:00:55:DD:A5:ED:5A:55:B7:7C:65:49:AC:AD:B1
basicConstraints:
    critical,CA:TRUE, pathlen:1
keyUsage:
    Certificate Sign, CRL Sign
subjectAltName:
    DNS:ca.example.com
subjectKeyIdentifier:
    6B:C8:CF:56:29:FC:00:55:DD:A5:ED:5A:55:B7:7C:65:49:AC:AD:B1

X509 v3 certificate extensions for signed certificates:
* Certificate Revokation List (CRL): None
* Issuer URL: None
* OCSP URL: None
* Issuer Alternative Name: None

-----BEGIN CERTIFICATE-----
MIIDFzCCAoCgAwIBAgIQNdvSrXkKTR+1Ju1fg3TAwjANBgkqhkiG9w0BAQ0FADCB
hzELMAkGA1UEBhMCQVQxDzANBgNVBAgMBlZpZW5uYTEPMA0GA1UEBwwGVmllbm5h
MQwwCgYDVQQKDANPcmcxEDAOBgNVBAsMB09yZ1VuaXQxFzAVBgNVBAMMDmNhLmV4
YW1wbGUuY29tMR0wGwYJKoZIhvcNAQkBFg5jYUBleGFtcGxlLmNvbTAiGA8yMDE2
MDUxMDE3NTYwMFoYDzIxMTYwNDE3MDAwMDAwWjCBhzELMAkGA1UEBhMCQVQxDzAN
BgNVBAgMBlZpZW5uYTEPMA0GA1UEBwwGVmllbm5hMQwwCgYDVQQKDANPcmcxEDAO
BgNVBAsMB09yZ1VuaXQxFzAVBgNVBAMMDmNhLmV4YW1wbGUuY29tMR0wGwYJKoZI
hvcNAQkBFg5jYUBleGFtcGxlLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC
gYEArdnr5gKSNJdxtjJJ49kpC4Yd79GcBEwhQeiRciGNdap/wbDl5Xff4EapLvP1
KMlXPyb6af2HVpCjuVSUjOtxzNgSOgLbWKYuuSaxzRvSS7ydXBMLJCJFTGFwul39
2U/zNO0JmDyd7Pk5trpqImpmSetSxRz5AL5mhxY2FNWkegUCAwEAAaN+MHwwEgYD
VR0TAQH/BAgwBgEB/wIBATALBgNVHQ8EBAMCAQYwHQYDVR0OBBYEFGvIz1Yp/ABV
3aXtWlW3fGVJrK2xMBkGA1UdEQQSMBCCDmNhLmV4YW1wbGUuY29tMB8GA1UdIwQY
MBaAFGvIz1Yp/ABV3aXtWlW3fGVJrK2xMA0GCSqGSIb3DQEBDQUAA4GBAIT/5guU
8uWiyQ6e3lRuuY4ioeaTOBI94Ygn1Dym328hVJfjsdFXHAP9Tfs2Sg3+Sj0CICnX
TzM06CLgrbfk/hQjU+H+dcfh5ahBH78MbytsAnzs8KlfBPnfeuLti3RnfXSkOAUZ
kbfhROu065IYOU0LmqufhP3IdGSeFtiw6nPw
-----END CERTIFICATE-----
''')
        self.assertEqual(stderr, '')

        stdout, stderr = self.cmd('view_ca', child.serial)
        subject = '/C=AT/ST=Vienna/L=Vienna/O=Org/OU=OrgUnit/CN=sub.ca.example.com/emailAddress=sub.ca@example.com'  # NOQA
        self.assertEqual(stdout, '''child (enabled):
* Serial: 6A:A2:3D:F9:5A:4A:44:8A:9F:91:64:54:A2:0D:04:29
* Path to private key:
  /home/mati/git/mati/django-ca/ca/django_ca/tests/fixtures/child.key
* Parent: root (35:DB:D2:AD:79:0A:4D:1F:B5:26:ED:5F:83:74:C0:C2)
* Has no children.
* Distinguished Name: %s
* Maximum levels of sub-CAs (pathlen): 0
* HPKP pin: zX54clL03NhaRzlm1R3JbCTvx9ddQgKcOceeVwgoTSw=

X509 v3 certificate extensions for CA:
authorityKeyIdentifier:
    keyid:6B:C8:CF:56:29:FC:00:55:DD:A5:ED:5A:55:B7:7C:65:49:AC:AD:B1
basicConstraints:
    critical,CA:TRUE, pathlen:0
keyUsage:
    Certificate Sign, CRL Sign
subjectAltName:
    DNS:sub.ca.example.com
subjectKeyIdentifier:
    EE:78:8B:01:C8:22:5D:4C:41:6A:DE:07:74:AA:C9:63:66:0A:92:EE

X509 v3 certificate extensions for signed certificates:
* Certificate Revokation List (CRL): None
* Issuer URL: None
* OCSP URL: None
* Issuer Alternative Name: None

-----BEGIN CERTIFICATE-----
MIIDLTCCApagAwIBAgIQaqI9+VpKRIqfkWRUog0EKTANBgkqhkiG9w0BAQ0FADCB
jzELMAkGA1UEBhMCQVQxDzANBgNVBAgMBlZpZW5uYTEPMA0GA1UEBwwGVmllbm5h
MQwwCgYDVQQKDANPcmcxEDAOBgNVBAsMB09yZ1VuaXQxGzAZBgNVBAMMEnN1Yi5j
YS5leGFtcGxlLmNvbTEhMB8GCSqGSIb3DQEJARYSc3ViLmNhQGV4YW1wbGUuY29t
MCIYDzIwMTYwNTEwMTgwMzAwWhgPMjExNjA0MTcwMDAwMDBaMIGPMQswCQYDVQQG
EwJBVDEPMA0GA1UECAwGVmllbm5hMQ8wDQYDVQQHDAZWaWVubmExDDAKBgNVBAoM
A09yZzEQMA4GA1UECwwHT3JnVW5pdDEbMBkGA1UEAwwSc3ViLmNhLmV4YW1wbGUu
Y29tMSEwHwYJKoZIhvcNAQkBFhJzdWIuY2FAZXhhbXBsZS5jb20wgZ8wDQYJKoZI
hvcNAQEBBQADgY0AMIGJAoGBAMvCSMjmOxI7wa8aqb9WbCS37dBYWDEY1+5ioQhZ
8FiyXOZZxNGVqn6Dt9TkikhTR9I4Rs3p2pyrMZZM63McFAWKyo//160RIvBwQOYM
9PpLuFZNx3In8/Fw5/GISgIsOF72jF1/VI1owLe/YShNuzwqzS7qQ5p/E4skUv3O
+25bAgMBAAGjgYMwgYAwEgYDVR0TAQH/BAgwBgEB/wIBADALBgNVHQ8EBAMCAQYw
HQYDVR0OBBYEFO54iwHIIl1MQWreB3SqyWNmCpLuMB0GA1UdEQQWMBSCEnN1Yi5j
YS5leGFtcGxlLmNvbTAfBgNVHSMEGDAWgBRryM9WKfwAVd2l7VpVt3xlSaytsTAN
BgkqhkiG9w0BAQ0FAAOBgQA6T7GffThrQKMyVq8Cf7Jb7dXrRw3EZgEfTpFND9C6
r2dgotB+5o5RVJkxQWs2i9XT2q10gXh76fgL3rUAF/nUzWkpD3htMETwDus6WmqF
IIBeA+G1PVe+gBRnKyXL7le66AihBU3lMmhhihW+6V43NkzB/F9essMZAF7e0/Pe
5A==
-----END CERTIFICATE-----
''' % subject)
        self.assertEqual(stderr, '')

    @override_tmpcadir()
    def test_no_pathlen(self):
        name = 'no-pathlen'
        kwargs = {
            'key_size': settings.CA_MIN_KEY_SIZE,
            'algorithm': 'sha256',
        }

        self.cmd('init_ca', name, '/C=AT/ST=Vienna/L=Vienna/O=Org/OU=OrgUnit/CN=%s' % name,
                 pathlen=False, **kwargs)

        ca = CertificateAuthority.objects.get(name=name)
        stdout, stderr = self.cmd('view_ca', ca.serial)
        self.assertOutput(ca, stdout)
        self.assertEqual(stderr, '')

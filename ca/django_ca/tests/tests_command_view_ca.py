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

from cryptography.hazmat.primitives import hashes

from django.conf import settings

from ..models import CertificateAuthority
from .base import DjangoCAWithCATestCase
from .base import certs
from .base import child_pubkey
from .base import override_settings
from .base import override_tmpcadir


class ViewCATestCase(DjangoCAWithCATestCase):
    def test_basic(self):
        stdout, stderr = self.cmd('view_ca', self.ca.serial)
        path = os.path.join(settings.FIXTURES_DIR, 'root.key')
        data = self.get_cert_context('root')
        data['path'] = path
        self.assertMultiLineEqual(stdout, '''root (enabled):
* Serial: %(serial)s
* Path to private key:
  %(path)s
* Is a root CA.
* Has no children.
* Distinguished Name: %(dn)s
* Maximum levels of sub-CAs (pathlen): 1
* HPKP pin: %(hpkp)s

X509 v3 certificate extensions for CA:
authorityKeyIdentifier:
    %(authKeyIdentifier)s
basicConstraints (critical):
    %(basicConstraints)s
keyUsage (critical):
    * %(keyUsage_0)s
    * %(keyUsage_1)s
subjectKeyIdentifier:
    %(subjectKeyIdentifier)s

X509 v3 certificate extensions for signed certificates:
* Certificate Revokation List (CRL): None
* Issuer URL: None
* OCSP URL: None
* Issuer Alternative Name: None

%(pem)s''' % data)
        self.assertEqual(stderr, '')

    @override_settings(USE_TZ=True)
    def test_basic_with_use_tz(self):
        self.test_basic()

    def test_family(self):
        parent = CertificateAuthority.objects.get(name=self.ca.name)
        child = self.load_ca(name='child', x509=child_pubkey, parent=self.ca)

        stdout, stderr = self.cmd('view_ca', parent.serial)
        data = self.get_cert_context('root')
        data['path'] = os.path.join(settings.FIXTURES_DIR, 'root.key')
        data['child_serial'] = certs['child']['serial']
        self.assertMultiLineEqual(stdout, '''root (enabled):
* Serial: %(serial)s
* Path to private key:
  %(path)s
* Is a root CA.
* Children:
  * child (%(child_serial)s)
* Distinguished Name: %(dn)s
* Maximum levels of sub-CAs (pathlen): 1
* HPKP pin: %(hpkp)s

X509 v3 certificate extensions for CA:
authorityKeyIdentifier:
    %(authKeyIdentifier)s
basicConstraints (critical):
    %(basicConstraints)s
keyUsage (critical):
    * %(keyUsage_0)s
    * %(keyUsage_1)s
subjectKeyIdentifier:
    %(subjectKeyIdentifier)s

X509 v3 certificate extensions for signed certificates:
* Certificate Revokation List (CRL): None
* Issuer URL: None
* OCSP URL: None
* Issuer Alternative Name: None

%(pem)s''' % data)
        self.assertEqual(stderr, '')

        stdout, stderr = self.cmd('view_ca', child.serial)
        data = self.get_cert_context('child')
        data['path'] = os.path.join(settings.FIXTURES_DIR, 'child.key')
        data['root_serial'] = certs['root']['serial']
        self.assertMultiLineEqual(stdout, '''child (enabled):
* Serial: %(serial)s
* Path to private key:
  %(path)s
* Parent: root (%(root_serial)s)
* Has no children.
* Distinguished Name: %(dn)s
* Maximum levels of sub-CAs (pathlen): 0
* HPKP pin: %(hpkp)s

X509 v3 certificate extensions for CA:
authorityKeyIdentifier:
    %(authKeyIdentifier)s
basicConstraints (critical):
    %(basicConstraints)s
keyUsage (critical):
    * %(keyUsage_0)s
    * %(keyUsage_1)s
subjectKeyIdentifier:
    %(subjectKeyIdentifier)s

X509 v3 certificate extensions for signed certificates:
* Certificate Revokation List (CRL): None
* Issuer URL: None
* OCSP URL: None
* Issuer Alternative Name: None

%(pem)s''' % data)
        self.assertEqual(stderr, '')

    @override_settings(USE_TZ=True)
    def test_family_with_use_tz(self):
        self.test_family()

    @override_tmpcadir()
    def test_no_pathlen(self):
        name = 'no-pathlen'
        kwargs = {
            'key_size': settings.CA_MIN_KEY_SIZE,
            'algorithm': hashes.SHA256(),
        }

        self.cmd('init_ca', name, '/C=AT/ST=Vienna/L=Vienna/O=Org/OU=OrgUnit/CN=%s' % name,
                 pathlen=None, **kwargs)

        ca = CertificateAuthority.objects.get(name=name)
        stdout, stderr = self.cmd('view_ca', ca.serial)

        context = {
            'path': ca.private_key_path,
            'serial': ca.serial,
            'dn': ca.distinguishedName(),
            'hpkp': ca.hpkp_pin,
            'authKeyIdentifier': ca.authorityKeyIdentifier()[1],
            'basicConstraints': ca.basicConstraints()[1],
            'keyUsage_0': ca.keyUsage()[1][0],
            'keyUsage_1': ca.keyUsage()[1][1],
            'subjectKeyIdentifier': ca.subjectKeyIdentifier()[1],
            'pem': ca.pub,
            'name': ca.name,
        }
        self.assertMultiLineEqual(stdout, '''%(name)s (enabled):
* Serial: %(serial)s
* Path to private key:
  %(path)s
* Is a root CA.
* Has no children.
* Distinguished Name: %(dn)s
* Maximum levels of sub-CAs (pathlen): unlimited
* HPKP pin: %(hpkp)s

X509 v3 certificate extensions for CA:
authorityKeyIdentifier:
    %(authKeyIdentifier)s
basicConstraints (critical):
    %(basicConstraints)s
keyUsage (critical):
    * %(keyUsage_0)s
    * %(keyUsage_1)s
subjectKeyIdentifier:
    %(subjectKeyIdentifier)s

X509 v3 certificate extensions for signed certificates:
* Certificate Revokation List (CRL): None
* Issuer URL: None
* OCSP URL: None
* Issuer Alternative Name: None

%(pem)s''' % context)
        self.assertEqual(stderr, '')

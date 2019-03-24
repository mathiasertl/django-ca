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

from cryptography.hazmat.primitives import hashes

from django.conf import settings

from ..models import CertificateAuthority
from .base import DjangoCAWithCATestCase
from .base import certs
from .base import child_pubkey
from .base import override_settings
from .base import override_tmpcadir


class ViewCATestCase(DjangoCAWithCATestCase):
    @override_tmpcadir()
    def test_basic(self):
        stdout, stderr = self.cmd('view_ca', self.ca.serial)
        data = self.get_cert_context('root')
        data['path'] = 'root.key'
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
AuthorityKeyIdentifier:
    %(authKeyIdentifier)s
BasicConstraints (critical):
    %(basicConstraints)s
KeyUsage (critical):
    * %(keyUsage_0)s
    * %(keyUsage_1)s
SubjectKeyIdentifier:
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

    @override_tmpcadir()
    def test_family(self):
        parent = CertificateAuthority.objects.get(name=self.ca.name)
        child = self.load_ca(name='child', x509=child_pubkey, parent=self.ca)

        stdout, stderr = self.cmd('view_ca', parent.serial)
        data = self.get_cert_context('root')
        data['path'] = 'root.key'
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
AuthorityKeyIdentifier:
    %(authKeyIdentifier)s
BasicConstraints (critical):
    %(basicConstraints)s
KeyUsage (critical):
    * %(keyUsage_0)s
    * %(keyUsage_1)s
SubjectKeyIdentifier:
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
        data['path'] = 'child.key'
        data['root_serial'] = certs['root']['serial']
        data['crl'] = certs['child']['crl'][1][0]
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
AuthorityInfoAccess:
    CA Issuers:
      * %(authInfoAccess_0)s
    OCSP:
      * %(authInfoAccess_1)s
AuthorityKeyIdentifier:
    %(authKeyIdentifier)s
BasicConstraints (critical):
    %(basicConstraints)s
cRLDistributionPoints:
    * %(crl)s
KeyUsage (critical):
    * %(keyUsage_0)s
    * %(keyUsage_1)s
NameConstraints (critical):
    Permitted:
      * DNS:.net
    Excluded:
      * DNS:.org
SubjectKeyIdentifier:
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
            'authKeyIdentifier': ca.authority_key_identifier.as_text(),
            'basicConstraints': ca.basic_constraints.as_text(),
            'subjectKeyIdentifier': ca.subject_key_identifier.as_text(),
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
AuthorityKeyIdentifier:
    %(authKeyIdentifier)s
BasicConstraints (critical):
    %(basicConstraints)s
KeyUsage (critical):
    * cRLSign
    * keyCertSign
SubjectKeyIdentifier:
    %(subjectKeyIdentifier)s

X509 v3 certificate extensions for signed certificates:
* Certificate Revokation List (CRL): None
* Issuer URL: None
* OCSP URL: None
* Issuer Alternative Name: None

%(pem)s''' % context)
        self.assertEqual(stderr, '')

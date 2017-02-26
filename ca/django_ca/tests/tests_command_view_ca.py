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
    def assertOutput(self, ca, stdout, san=''):
        self.maxDiff = None
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
    Certificate Sign, CRL Sign%s
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
        self.assertOutput(self.ca, stdout, san='ca.example.com')
        self.assertEqual(stderr, '')

    def test_family(self):
        parent = CertificateAuthority.objects.get(name=self.ca.name)
        child = self.load_ca(name='child', x509=child_pubkey, parent=self.ca)

        stdout, stderr = self.cmd('view_ca', parent.serial)
        self.assertOutput(parent, stdout, san='ca.example.com')
        self.assertEqual(stderr, '')

        stdout, stderr = self.cmd('view_ca', child.serial)
        self.assertOutput(child, stdout, san='sub.ca.example.com')
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

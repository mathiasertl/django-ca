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

from .. import ca_settings
from ..models import CertificateAuthority
from .base import DjangoCAWithCATestCase
from .base import override_tmpcadir


@override_tmpcadir(CA_MIN_KEY_SIZE=1024, CA_PROFILES={}, CA_DEFAULT_SUBJECT={})
class SignCertTestCase(DjangoCAWithCATestCase):
    def assertOutput(self, ca, stdout):
        status = 'enabled' if self.ca.enabled else 'disabled'
        path = os.path.join(ca_settings.CA_DIR, '%s.key' % ca.serial)
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

        self.assertEqual(stdout, '''%s (%s):
* Serial: %s
* Path to private key:
  %s
%s
%s
* Distinguished Name: %s
* Maximum levels of sub-CAs (pathlen): %s
* Certificate Revokation List (CRL): None
* Issuer URL: None
* OCSP URL: None
* Issuer Alternative Name: None
* HPKP pin: %s

%s''' % (ca.name, status, ca.serial, path, parent, children, ca.subject_str, pathlen,
         ca.hpkp_pin, ca.pub))

    def test_basic(self):
        stdout, stderr = self.cmd('view_ca', self.ca.serial)
        self.assertOutput(self.ca, stdout)
        self.assertEqual(stderr, '')

    def test_family(self):
        parent = CertificateAuthority.objects.get(name=self.ca.name)
        child = self.init_ca(name='Child CA', parent=self.ca, pathlen=False)

        stdout, stderr = self.cmd('view_ca', parent.serial)
        self.assertOutput(parent, stdout)
        self.assertEqual(stderr, '')

        stdout, stderr = self.cmd('view_ca', child.serial)
        self.assertOutput(child, stdout)
        self.assertEqual(stderr, '')

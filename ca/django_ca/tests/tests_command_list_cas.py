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

from ..models import CertificateAuthority
from .base import DjangoCAWithCATestCase
from .base import certs
from .base import child_pubkey
from .base import override_settings
from .base import override_tmpcadir


@override_tmpcadir(CA_MIN_KEY_SIZE=1024, CA_PROFILES={}, CA_DEFAULT_SUBJECT={})
class ListCertsTestCase(DjangoCAWithCATestCase):
    def test_basic(self):
        stdout, stderr = self.cmd('list_cas')
        self.assertEqual(stdout, '%s - %s\n%s - %s\n%s - %s\n' % (
            certs['root']['serial'], certs['root']['name'],
            certs['pwd_ca']['serial'], certs['pwd_ca']['name'],
            certs['ecc_ca']['serial'], certs['ecc_ca']['name'],
        ))
        self.assertEqual(stderr, '')

    @override_settings(USE_TZ=True)
    def test_basic_with_use_tz(self):
        self.test_basic()

    def test_disabled(self):
        ca = CertificateAuthority.objects.get(serial=self.ca.serial)
        ca.enabled = False
        ca.save()

        stdout, stderr = self.cmd('list_cas')
        self.assertEqual(stdout, '%s - %s (disabled)\n%s - %s\n%s - %s\n' % (
            certs['root']['serial'], certs['root']['name'],
            certs['pwd_ca']['serial'], certs['pwd_ca']['name'],
            certs['ecc_ca']['serial'], certs['ecc_ca']['name']))
        self.assertEqual(stderr, '')

    @override_settings(USE_TZ=True)
    def test_disabled_with_use_tz(self):
        self.test_disabled()

    def test_tree(self):
        stdout, stderr = self.cmd('list_cas', tree=True)
        self.assertEqual(stdout, '''%s - %s
%s - %s
%s - %s\n''' % (
            certs['root']['serial'], certs['root']['name'],
            certs['pwd_ca']['serial'], certs['pwd_ca']['name'],
            certs['ecc_ca']['serial'], certs['ecc_ca']['name'],
        ))
        self.assertEqual(stderr, '')

        # load intermediate ca
        self.child_ca = self.load_ca(name='child', x509=child_pubkey, parent=self.ca)
        stdout, stderr = self.cmd('list_cas', tree=True)
        self.assertEqual(stdout, '''%s - %s
└───%s - %s
%s - %s
%s - %s\n''' % (
            certs['root']['serial'], certs['root']['name'],
            certs['child']['serial'], certs['child']['name'],
            certs['pwd_ca']['serial'], certs['pwd_ca']['name'],
            certs['ecc_ca']['serial'], certs['ecc_ca']['name'],
        ))
        self.assertEqual(stderr, '')

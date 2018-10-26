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

from django.utils import timezone

from ..models import Certificate
from .base import DjangoCAWithChildCATestCase
from .base import override_settings
from .base import override_tmpcadir


@override_tmpcadir(CA_MIN_KEY_SIZE=1024, CA_PROFILES={}, CA_DEFAULT_SUBJECT={})
class ListCertsTestCase(DjangoCAWithChildCATestCase):
    def line(self, cert):
        if cert.revoked is True:
            info = 'revoked'
        else:
            word = 'expires'
            if cert.expires < timezone.now():
                word = 'expired'

            info = '%s: %s' % (word, cert.expires.strftime('%Y-%m-%d'))
        return '%s - %s (%s)' % (cert.serial, cert.cn, info)

    def assertCerts(self, *certs, **kwargs):
        stdout, stderr = self.cmd('list_certs', **kwargs)
        self.assertEqual(stdout, ''.join(['%s\n' % self.line(c) for c in certs]))
        self.assertEqual(stderr, '')

    def test_basic(self):
        self.assertCerts(self.cert, self.cert_all)

    @override_settings(USE_TZ=True)
    def test_basic_with_use_tz(self):
        # reload cert, otherwise self.cert is still the object created in setUp()
        self.cert = Certificate.objects.get(serial=self.cert.serial)
        self.cert_all = Certificate.objects.get(serial=self.cert_all.serial)
        self.test_basic()

    def test_expired(self):
        self.cert_all = Certificate.objects.get(serial=self.cert_all.serial)
        self.cert = Certificate.objects.get(serial=self.cert.serial)
        self.cert.expires = timezone.now() - timedelta(days=3)
        self.cert.save()

        self.assertCerts(self.cert_all)
        self.assertCerts(self.cert, self.cert_all, expired=True)

    @override_settings(USE_TZ=True)
    def test_expired_with_use_tz(self):
        self.test_expired()

    def test_revoked(self):
        self.cert.revoke()
        self.cert_all.revoke()

        self.assertCerts()
        self.assertCerts(self.cert, self.cert_all, revoked=True)

    def test_ca(self):
        self.assertCerts(self.cert, self.cert_all)
        self.assertCerts(self.cert, self.cert_all, ca=self.ca)
        self.assertCerts(ca=self.child_ca)

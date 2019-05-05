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

from freezegun import freeze_time

from django.utils import timezone

from .base import DjangoCAWithGeneratedCertsTestCase
from .base import override_settings
from .base import timestamps


@override_settings(CA_MIN_KEY_SIZE=1024, CA_PROFILES={}, CA_DEFAULT_SUBJECT={})
class ListCertsTestCase(DjangoCAWithGeneratedCertsTestCase):
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
        certs = sorted(certs, key=lambda c: c.expires)
        self.assertEqual(stdout, ''.join(['%s\n' % self.line(c) for c in certs]))
        self.assertEqual(stderr, '')

    @freeze_time(timestamps['everything_valid'])
    def test_basic(self):
        self.assertCerts(*self.certs.values())

    @freeze_time(timestamps['everything_expired'])
    def test_expired(self):
        self.assertCerts()
        self.assertCerts(*self.certs.values(), expired=True)

    @freeze_time(timestamps['everything_valid'])
    def test_revoked(self):
        cert = self.certs['root-cert']
        cert.revoke()

        self.assertCerts(*[c for c in self.certs.values() if c != cert])
        self.assertCerts(*self.certs.values(), revoked=True)

    @freeze_time(timestamps['everything_valid'])
    def test_ca(self):
        for name, ca in self.cas.items():
            self.assertCerts(*[c for c in self.certs.values() if c.ca == ca], ca=ca)


@override_settings(USE_TZ=True)
class ListCertsWithTZTestCase(ListCertsTestCase):
    pass

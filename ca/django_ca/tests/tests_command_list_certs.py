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

from .base import DjangoCAWithChildCATestCase
from .base import override_settings


@override_settings(CA_MIN_KEY_SIZE=1024, CA_PROFILES={}, CA_DEFAULT_SUBJECT={})
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
        certs = sorted(certs, key=lambda c: c.expires)
        self.assertEqual(stdout, ''.join(['%s\n' % self.line(c) for c in certs]))
        self.assertEqual(stderr, '')

    @freeze_time('2019-03-22')
    def test_basic(self):
        self.assertCerts(*[c for c in self.certs if c.expires > timezone.now()])

    @override_settings(USE_TZ=True)
    def test_basic_with_use_tz(self):
        # Refresh objects from db to add timezone to expires timestamp
        [c.refresh_from_db() for c in self.certs]
        self.test_basic()

    @freeze_time('2019-03-22')
    def test_expired(self):
        self.assertCerts(*[c for c in self.certs if c.expires > timezone.now()])
        self.assertCerts(*self.certs, expired=True)

    @override_settings(USE_TZ=True)
    def test_expired_with_use_tz(self):
        # Refresh objects from db to add timezone to expires timestamp
        [c.refresh_from_db() for c in self.certs]
        self.test_expired()

    @freeze_time('2019-03-22')
    def test_revoked(self):
        self.cert.revoke()
        self.cert_all.revoke()
        self.cert_no_ext.revoke()

        self.assertCerts(*[c for c in self.certs if c.expires > timezone.now() and c.revoked is False])
        self.assertCerts(*[c for c in self.certs if c.expires > timezone.now()], revoked=True)

    @freeze_time('2019-03-22')
    def test_ca(self):
        self.assertCerts(*[c for c in self.certs if c.expires > timezone.now()])
        self.assertCerts(*[c for c in self.certs if c.expires > timezone.now() and c.ca == self.ca],
                         ca=self.ca)
        self.assertCerts(ca=self.child_ca)  # child ca has no certs

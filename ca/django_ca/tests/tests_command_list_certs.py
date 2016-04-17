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

from django.core import mail
from django.core.management.base import CommandError
from django.utils import timezone

from ..models import Certificate
from ..models import Watcher
from .base import DjangoCAWithCertTestCase
from .base import override_tmpcadir


@override_tmpcadir(CA_MIN_KEY_SIZE=1024, CA_PROFILES={}, CA_DEFAULT_SUBJECT={})
class ViewCertTestCase(DjangoCAWithCertTestCase):
    def line(self, cert):
        if cert.revoked is True:
            info = 'revoked'
        else:
            word = 'expires'
            if cert.expires < timezone.now():
                word = 'expired'

            info = '%s: %s' % (word, cert.expires.strftime('%Y-%m-%d'))
        return '%s - %s (%s)' % (cert.serial, cert.cn, info)

    def test_basic(self):
        stdout, stderr = self.cmd('list_certs')
        self.assertEqual(stdout, '%s\n' % self.line(self.cert))
        self.assertEqual(stderr, '')

    def test_expired(self):
        cert = Certificate.objects.get(serial=self.cert.serial)
        cert.expires = timezone.now() - timedelta(days=3)
        cert.save()

        stdout, stderr = self.cmd('list_certs')
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')

        stdout, stderr = self.cmd('list_certs', expired=True)
        self.assertEqual(stdout, '%s\n' % self.line(cert))
        self.assertEqual(stderr, '')

    def test_revoked(self):
        cert = Certificate.objects.get(serial=self.cert.serial)
        cert.revoke()

        stdout, stderr = self.cmd('list_certs')
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')

        stdout, stderr = self.cmd('list_certs', revoked=True)
        self.assertEqual(stdout, '%s\n' % self.line(cert))
        self.assertEqual(stderr, '')

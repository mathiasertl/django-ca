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
from django.utils import timezone

from ..models import Certificate
from ..models import Watcher
from .base import DjangoCAWithCertTestCase
from .base import override_settings


@override_settings(CA_MIN_KEY_SIZE=1024, CA_PROFILES={}, CA_DEFAULT_SUBJECT={},
                   CA_NOTIFICATION_DAYS=[14, 7, 3, 1])
class ViewCertTestCase(DjangoCAWithCertTestCase):
    def test_no_certs(self):
        stdout, stderr = self.cmd('notify_expiring_certs')
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')
        self.assertEqual(len(mail.outbox), 0)

    def test_no_watchers(self):
        cert = Certificate.objects.get(serial=self.cert.serial)
        cert.expires = timezone.now() + timedelta(days=3)
        cert.save()

        stdout, stderr = self.cmd('notify_expiring_certs')
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')
        self.assertEqual(len(mail.outbox), 0)

    def test_one_watcher(self):
        cert = Certificate.objects.get(serial=self.cert.serial)
        cert.expires = timezone.now() + timedelta(days=3, minutes=1)
        timestamp = cert.expires.strftime('%Y-%m-%d')
        cert.save()

        email = 'user1@example.com'
        watcher = Watcher.from_addr('First Last <%s>' % email)
        cert.watchers.add(watcher)

        stdout, stderr = self.cmd('notify_expiring_certs')
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].subject,
                         'Certificate expiration for %s on %s' % (cert.cn, timestamp))
        self.assertEqual(mail.outbox[0].to, [email])

    def test_notification_days(self):
        now = timezone.now()

        cert = Certificate.objects.get(serial=self.cert.serial)
        email = 'user1@example.com'
        watcher = Watcher.from_addr('First Last <%s>' % email)
        cert.watchers.add(watcher)

        for i in reversed(range(0, 20)):
            cert = Certificate.objects.get(serial=self.cert.serial)
            cert.expires = now + timedelta(days=i)
            cert.save()

            stdout, stderr = self.cmd('notify_expiring_certs', days=14)
            self.assertEqual(stdout, '')
            self.assertEqual(stderr, '')

        self.assertEqual(len(mail.outbox), 4)

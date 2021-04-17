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

"""Test the notify_expiring_certs management command."""

from datetime import timedelta

from django.core import mail

from freezegun import freeze_time

from ..models import Watcher
from .base import DjangoCAWithGeneratedCertsTestCase
from .base import override_settings
from .base import timestamps
from .base_mixins import TestCaseMixin


@override_settings(CA_NOTIFICATION_DAYS=[14, 7, 3, 1])
class NotifyExpiringCertsTestCase(TestCaseMixin, DjangoCAWithGeneratedCertsTestCase):
    """Main test class for this command."""

    @freeze_time(timestamps["everything_valid"])
    def test_no_certs(self) -> None:
        """Try notificy command when all certs are still valid."""
        stdout, stderr = self.cmd("notify_expiring_certs")
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        self.assertEqual(len(mail.outbox), 0)

    @freeze_time(timestamps["ca_certs_expiring"])
    def test_no_watchers(self) -> None:
        """Try expiring certs, but with no watchers."""
        # certs have no watchers by default, so we get no mails
        stdout, stderr = self.cmd("notify_expiring_certs")
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        self.assertEqual(len(mail.outbox), 0)

    @freeze_time(timestamps["ca_certs_expiring"])
    def test_one_watcher(self) -> None:
        """Test one expiring certificate."""
        cert = self.certs["root-cert"]
        email = "user1@example.com"
        watcher = Watcher.from_addr("First Last <%s>" % email)
        cert.watchers.add(watcher)
        timestamp = cert.expires.strftime("%Y-%m-%d")

        stdout, stderr = self.cmd("notify_expiring_certs")
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].subject, "Certificate expiration for %s on %s" % (cert.cn, timestamp))
        self.assertEqual(mail.outbox[0].to, [email])

    def test_notification_days(self) -> None:
        """Test that user gets multiple notifications of expiring certs."""
        cert = self.certs["root-cert"]
        email = "user1@example.com"
        watcher = Watcher.from_addr("First Last <%s>" % email)
        cert.watchers.add(watcher)

        with freeze_time(cert.expires - timedelta(days=20)) as frozen_time:
            for _i in reversed(range(0, 20)):
                stdout, stderr = self.cmd("notify_expiring_certs", days=14)
                self.assertEqual(stdout, "")
                self.assertEqual(stderr, "")
                frozen_time.tick(timedelta(days=1))

        self.assertEqual(len(mail.outbox), 4)

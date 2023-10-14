# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU General
# Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca. If not, see
# <http://www.gnu.org/licenses/>.

"""Test the notify_expiring_certs management command."""

from datetime import timedelta

from django.core import mail
from django.test import TestCase, override_settings

from freezegun import freeze_time

from django_ca.models import Watcher
from django_ca.tests.base.constants import TIMESTAMPS
from django_ca.tests.base.mixins import TestCaseMixin


@override_settings(CA_NOTIFICATION_DAYS=[14, 7, 3, 1])
class NotifyExpiringCertsTestCase(TestCaseMixin, TestCase):
    """Main test class for this command."""

    load_cas = "__usable__"
    load_certs = "__usable__"

    @freeze_time(TIMESTAMPS["everything_valid"])
    def test_no_certs(self) -> None:
        """Try notify command when all certs are still valid."""
        stdout, stderr = self.cmd("notify_expiring_certs")
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        self.assertEqual(len(mail.outbox), 0)

    @freeze_time(TIMESTAMPS["ca_certs_expiring"])
    def test_no_watchers(self) -> None:
        """Try expiring certs, but with no watchers."""
        # certs have no watchers by default, so we get no mails
        stdout, stderr = self.cmd("notify_expiring_certs")
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        self.assertEqual(len(mail.outbox), 0)

    @freeze_time(TIMESTAMPS["ca_certs_expiring"])
    def test_one_watcher(self) -> None:
        """Test one expiring certificate."""
        email = "user1@example.com"
        watcher = Watcher.from_addr(f"First Last <{email}>")
        self.cert.watchers.add(watcher)
        timestamp = self.cert.expires.strftime("%Y-%m-%d")

        stdout, stderr = self.cmd("notify_expiring_certs")
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].subject, f"Certificate expiration for {self.cert.cn} on {timestamp}")
        self.assertEqual(mail.outbox[0].to, [email])

    def test_notification_days(self) -> None:
        """Test that user gets multiple notifications of expiring certs."""
        email = "user1@example.com"
        watcher = Watcher.from_addr(f"First Last <{email}>")
        self.cert.watchers.add(watcher)

        with freeze_time(self.cert.expires - timedelta(days=20)) as frozen_time:
            for _i in reversed(range(0, 20)):
                stdout, stderr = self.cmd("notify_expiring_certs", days=14)
                self.assertEqual(stdout, "")
                self.assertEqual(stderr, "")
                frozen_time.tick(timedelta(days=1))

        self.assertEqual(len(mail.outbox), 4)

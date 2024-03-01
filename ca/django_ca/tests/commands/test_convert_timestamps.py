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

"""Test the convert_timestamps management command."""

from django.test import TestCase, override_settings

from freezegun import freeze_time

from django_ca import ca_settings
from django_ca.models import AcmeAccount, AcmeAuthorization, AcmeChallenge, AcmeOrder
from django_ca.tests.base.assertions import assert_command_error
from django_ca.tests.base.constants import TIMESTAMPS
from django_ca.tests.base.mixins import TestCaseMixin
from django_ca.tests.base.utils import cmd

INPUT_PATH = "django_ca.management.commands.convert_timestamps.input"


@override_settings(USE_TZ=False)
@freeze_time(TIMESTAMPS["everything_valid"])
class ConvertTimestampsTestCase(TestCaseMixin, TestCase):
    """Test the convert_timestamps management command."""

    load_cas = ("root",)
    load_certs = ("root-cert",)

    def test_minimal_conversion(self) -> None:
        """Test conversion of objects with optional timestamps set to None."""
        acme_account = AcmeAccount.objects.create(ca=self.ca)
        acme_order = AcmeOrder.objects.create(account=acme_account)
        acme_auth = AcmeAuthorization.objects.create(order=acme_order)
        acme_challenge = AcmeChallenge.objects.create(auth=acme_auth)

        self.assertEqual(self.ca.created, TIMESTAMPS["everything_valid_naive"])
        self.assertEqual(self.cert.created, TIMESTAMPS["everything_valid_naive"])
        self.assertEqual(acme_account.created, TIMESTAMPS["everything_valid_naive"])
        self.assertEqual(
            acme_order.expires, TIMESTAMPS["everything_valid_naive"] + ca_settings.ACME_ORDER_VALIDITY
        )
        self.assertIsNone(acme_challenge.validated)

        with self.settings(USE_TZ=True), self.patch(INPUT_PATH, return_value="YES"):
            cmd("convert_timestamps")

            self.ca.refresh_from_db()
            self.cert.refresh_from_db()
            acme_account.refresh_from_db()
            acme_order.refresh_from_db()
            acme_challenge.refresh_from_db()

            self.assertEqual(self.ca.created, TIMESTAMPS["everything_valid"])
            self.assertEqual(self.cert.created, TIMESTAMPS["everything_valid"])
            self.assertEqual(acme_account.created, TIMESTAMPS["everything_valid"])
            self.assertEqual(
                acme_order.expires, TIMESTAMPS["everything_valid"] + ca_settings.ACME_ORDER_VALIDITY
            )
            self.assertIsNone(self.ca.revoked_date)
            self.assertIsNone(self.ca.compromised)
            self.assertIsNone(self.cert.revoked_date)
            self.assertIsNone(self.cert.compromised)
            self.assertIsNone(acme_order.not_before)
            self.assertIsNone(acme_order.not_after)
            self.assertIsNone(acme_challenge.validated)

    def test_full_conversion(self) -> None:
        """Test conversion with all optional timestamps set."""
        now = TIMESTAMPS["everything_valid_naive"]
        self.ca.revoked_date = now
        self.ca.compromised = now
        self.ca.save()
        self.cert.revoked_date = now
        self.cert.compromised = now
        self.cert.save()

        acme_account = AcmeAccount.objects.create(ca=self.ca)
        acme_order = AcmeOrder.objects.create(account=acme_account, not_before=now, not_after=now)
        acme_auth = AcmeAuthorization.objects.create(order=acme_order)
        acme_challenge = AcmeChallenge.objects.create(auth=acme_auth, validated=now)

        self.assertEqual(self.ca.created, TIMESTAMPS["everything_valid_naive"])
        self.assertEqual(self.ca.revoked_date, TIMESTAMPS["everything_valid_naive"])
        self.assertEqual(self.ca.compromised, TIMESTAMPS["everything_valid_naive"])
        self.assertEqual(self.cert.created, TIMESTAMPS["everything_valid_naive"])
        self.assertEqual(self.cert.revoked_date, TIMESTAMPS["everything_valid_naive"])
        self.assertEqual(self.cert.compromised, TIMESTAMPS["everything_valid_naive"])
        self.assertEqual(acme_account.created, TIMESTAMPS["everything_valid_naive"])
        self.assertEqual(
            acme_order.expires, TIMESTAMPS["everything_valid_naive"] + ca_settings.ACME_ORDER_VALIDITY
        )
        self.assertEqual(acme_order.not_before, now)
        self.assertEqual(acme_order.not_after, now)
        self.assertEqual(acme_challenge.validated, now)

        with self.settings(USE_TZ=True), self.patch(INPUT_PATH, return_value="YES"):
            cmd("convert_timestamps")

            self.ca.refresh_from_db()
            self.cert.refresh_from_db()
            acme_account.refresh_from_db()
            acme_order.refresh_from_db()
            acme_challenge.refresh_from_db()

            self.assertEqual(self.ca.created, TIMESTAMPS["everything_valid"])
            self.assertEqual(self.ca.revoked_date, TIMESTAMPS["everything_valid"])
            self.assertEqual(self.ca.compromised, TIMESTAMPS["everything_valid"])
            self.assertEqual(self.cert.created, TIMESTAMPS["everything_valid"])
            self.assertEqual(self.cert.revoked_date, TIMESTAMPS["everything_valid"])
            self.assertEqual(self.cert.compromised, TIMESTAMPS["everything_valid"])
            self.assertEqual(acme_account.created, TIMESTAMPS["everything_valid"])
            self.assertEqual(
                acme_order.expires, TIMESTAMPS["everything_valid"] + ca_settings.ACME_ORDER_VALIDITY
            )
            self.assertEqual(acme_order.not_before, TIMESTAMPS["everything_valid"])
            self.assertEqual(acme_order.not_after, TIMESTAMPS["everything_valid"])
            self.assertEqual(acme_challenge.validated, TIMESTAMPS["everything_valid"])

    def test_no_confirmation(self) -> None:
        """Test that nothing happens if the user doesn't give confirmation."""
        self.assertEqual(self.ca.created, TIMESTAMPS["everything_valid_naive"])
        with self.settings(USE_TZ=True), self.patch(INPUT_PATH, return_value="no"):
            out, err = cmd("convert_timestamps")
        self.assertIn("Aborting.", out)
        self.ca.refresh_from_db()
        self.assertEqual(self.ca.created, TIMESTAMPS["everything_valid_naive"])

    def test_use_tz_is_false(self) -> None:
        """Test error when USE_TZ=False."""
        with assert_command_error("This command requires that you have configured USE_TZ=True."):
            cmd("convert_timestamps")

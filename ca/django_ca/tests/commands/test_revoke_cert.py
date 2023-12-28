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

"""Test the revoke_cert management command."""
import re
from datetime import datetime, timedelta, timezone as tz
from typing import List, Optional

from django.test import TestCase
from django.utils import timezone

from django_ca.constants import ReasonFlags
from django_ca.models import Certificate
from django_ca.signals import post_revoke_cert, pre_revoke_cert
from django_ca.tests.base.mixins import TestCaseMixin


class RevokeCertTestCase(TestCaseMixin, TestCase):
    """Main test class for this command."""

    load_cas = ("root",)
    load_certs = ("root-cert",)

    def revoke(
        self,
        cert: Certificate,
        arguments: Optional[List[str]] = None,
        reason: str = ReasonFlags.unspecified.name,
    ) -> None:
        """Revoke a certificate and make the necessary assertions afterwards."""
        if arguments is None:
            arguments = []

        with self.mockSignal(pre_revoke_cert) as pre, self.mockSignal(post_revoke_cert) as post:
            stdout, stderr = self.cmd_e2e(["revoke_cert", cert.serial, *arguments])
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")

        cert.refresh_from_db()
        self.assertEqual(pre.call_count, 1)
        self.assertPostRevoke(post, cert)
        self.assertTrue(cert.revoked)
        self.assertTrue(cert.revoked_date is not None)
        self.assertEqual(cert.revoked_reason, reason)

    def test_no_arguments(self) -> None:
        """Test revoking without a reason."""
        self.assertFalse(self.cert.revoked)
        self.revoke(self.cert)

    def test_with_reason(self) -> None:
        """Test revoking with a reason."""
        self.assertFalse(self.cert.revoked)

        for reason in ReasonFlags:
            self.revoke(self.cert, ["--reason", reason.name], reason=reason.name)

            # un-revoke for next iteration of loop
            self.cert.revoked = False
            self.cert.revoked_date = None
            self.cert.revoked_reason = ""
            self.cert.save()

    def test_with_compromised(self) -> None:
        """Test revoking the certificate with a compromised date."""
        now = datetime.now(tz=tz.utc)
        self.revoke(self.cert, arguments=["--compromised", now.isoformat()])
        self.assertEqual(self.cert.compromised, now)

    def test_with_compromised_with_use_tz_is_false(self) -> None:
        """Test revoking the certificate with a compromised date with USE_TZ=False."""
        with self.settings(USE_TZ=False):
            now = datetime.now(tz=tz.utc)
            self.revoke(self.cert, arguments=["--compromised", now.isoformat()])
            self.assertEqual(self.cert.compromised, timezone.make_naive(now))

    def test_revoked(self) -> None:
        """Test revoking a cert that is already revoked."""
        self.assertFalse(self.cert.revoked)

        with self.mockSignal(pre_revoke_cert) as pre, self.mockSignal(post_revoke_cert) as post:
            self.cmd("revoke_cert", self.cert.serial)

        cert = Certificate.objects.get(serial=self.cert.serial)
        self.assertEqual(pre.call_count, 1)
        self.assertPostRevoke(post, cert)
        self.assertEqual(cert.revoked_reason, ReasonFlags.unspecified.name)

        with self.assertCommandError(
            rf"^{self.cert.serial}: Certificate is already revoked\.$"
        ), self.mockSignal(pre_revoke_cert) as pre, self.mockSignal(post_revoke_cert) as post:
            self.cmd("revoke_cert", self.cert.serial, reason=ReasonFlags.key_compromise)
        self.assertFalse(pre.called)
        self.assertFalse(post.called)

        cert = Certificate.objects.get(serial=self.cert.serial)
        self.assertTrue(cert.revoked)
        self.assertTrue(cert.revoked_date is not None)
        self.assertEqual(cert.revoked_reason, ReasonFlags.unspecified.name)

    def test_compromised_with_naive_datetime(self) -> None:
        """Test passing a naive datetime (which is an error)."""
        now = datetime.now()
        with self.assertCommandError(rf"{now.isoformat()}: Timestamp requires a timezone\."):
            self.cmd("revoke_cert", self.cert.serial, compromised=now)
        self.assertNotRevoked(self.cert)

    def test_compromised_with_future_datetime(self) -> None:
        """Test passing a datetime in the future (which is an error)."""
        now = datetime.now(tz=tz.utc).replace(microsecond=0) + timedelta(days=1)
        iso_format = re.escape(now.isoformat())  # tz-aware iso 8601 timestamp has regex special characters
        with self.assertCommandError(rf"{iso_format}: Timestamp must be in the past\."):
            self.cmd("revoke_cert", self.cert.serial, compromised=now)
        self.assertNotRevoked(self.cert)

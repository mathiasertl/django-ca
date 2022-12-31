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

"""Test the revoke_cert management command."""

from django.test import TestCase

from django_ca.constants import ReasonFlags
from django_ca.models import Certificate
from django_ca.signals import post_revoke_cert, pre_revoke_cert
from django_ca.tests.base.mixins import TestCaseMixin


class RevokeCertTestCase(TestCaseMixin, TestCase):
    """Main test class for this command."""

    load_cas = ("root",)
    load_certs = ("root-cert",)

    def test_no_reason(self) -> None:
        """Test revoking without a reason."""
        self.assertFalse(self.cert.revoked)

        with self.mockSignal(pre_revoke_cert) as pre, self.mockSignal(post_revoke_cert) as post:
            stdout, stderr = self.cmd("revoke_cert", self.cert.serial)
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")

        cert = Certificate.objects.get(serial=self.cert.serial)
        self.assertPostRevoke(post, cert)
        self.assertTrue(cert.revoked)
        self.assertTrue(cert.revoked_date is not None)
        self.assertEqual(cert.revoked_reason, ReasonFlags.unspecified.name)

    def test_with_reason(self) -> None:
        """Test revoking with a reason."""
        self.assertFalse(self.cert.revoked)

        for reason in ReasonFlags:
            with self.mockSignal(pre_revoke_cert) as pre, self.mockSignal(post_revoke_cert) as post:
                stdout, stderr = self.cmd_e2e(["revoke_cert", self.cert.serial, "--reason", reason.name])
            self.assertEqual(pre.call_count, 1)
            self.assertEqual(stdout, "")
            self.assertEqual(stderr, "")

            cert = Certificate.objects.get(serial=self.cert.serial)
            self.assertPostRevoke(post, cert)
            self.assertTrue(cert.revoked)
            self.assertTrue(cert.revoked_date is not None)
            self.assertEqual(cert.revoked_reason, reason.name)

            # unrevoke for next iteration of loop
            cert.revoked = False
            cert.revoked_date = None
            cert.revoked_reason = ""
            cert.save()

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

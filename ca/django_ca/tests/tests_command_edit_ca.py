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

"""Test the edit_ca management command."""

from django.test import TestCase

from .. import ca_settings
from ..models import CertificateAuthority
from .base import override_tmpcadir
from .base.mixins import TestCaseMixin


class EditCATestCase(TestCaseMixin, TestCase):
    """Test the edit_ca management command."""

    load_cas = ("root",)
    issuer = "https://issuer-test.example.org"
    ian = "http://ian-test.example.org"
    ocsp_url = "http://ocsp-test.example.org"
    crl = ["http://example.org/crl-test"]
    caa = "caa.example.com"
    website = "https://website.example.com"
    tos = "https://tos.example.com"

    def edit_ca(self, *args: str) -> None:
        """Shortcut for calling the edit_ca management command."""

        stdout, stderr = self.cmd_e2e(["edit_ca", self.ca.serial] + list(args))
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        self.ca.refresh_from_db()

    @override_tmpcadir()
    def test_basic(self) -> None:
        """Test command with e2e cli argument parsing."""

        crl = "\n".join(self.crl)
        stdout, stderr = self.cmd_e2e(
            [
                "edit_ca",
                self.ca.serial,
                f"--issuer-url={self.issuer}",
                f"--issuer-alt-name={self.ian}",
                f"--ocsp-url={self.ocsp_url}",
                f"--crl-url={crl}",
                f"--caa={self.caa}",
                f"--website={self.website}",
                f"--tos={self.tos}",
            ]
        )
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")

        ca = CertificateAuthority.objects.get(serial=self.ca.serial)
        self.assertEqual(ca.issuer_url, self.issuer)
        self.assertEqual(ca.issuer_alt_name, f"URI:{self.ian}")
        self.assertEqual(ca.ocsp_url, self.ocsp_url)
        self.assertEqual(ca.crl_url, "\n".join(self.crl))
        self.assertEqual(ca.caa_identity, self.caa)
        self.assertEqual(ca.website, self.website)
        self.assertEqual(ca.terms_of_service, self.tos)

    @override_tmpcadir()
    def test_enable_disable(self) -> None:
        """Test the enable/disable options."""
        self.assertTrue(self.ca.enabled)  # initial state

        self.edit_ca("--disable")
        self.assertFalse(self.ca.enabled)
        self.edit_ca("--enable")
        self.assertTrue(self.ca.enabled)

        with self.assertRaisesRegex(SystemExit, r"^2$") as excm:
            self.edit_ca("--enable", "--disable")
        self.assertEqual(excm.exception.args, (2,))
        self.assertTrue(self.ca.enabled)  # state unchanged

        # Try again, this time with a disabled state
        self.ca.enabled = False
        self.ca.save()
        with self.assertRaisesRegex(SystemExit, r"^2$") as excm:
            self.edit_ca("--enable", "--disable")
        self.assertEqual(excm.exception.args, (2,))
        self.assertFalse(self.ca.enabled)  # state unchanged

    @override_tmpcadir()
    def test_acme_arguments(self) -> None:
        """Test ACME arguments."""

        self.assertFalse(self.ca.acme_enabled)  # initial state
        self.assertEqual(self.ca.acme_profile, ca_settings.CA_DEFAULT_PROFILE)
        self.assertTrue(self.ca.acme_requires_contact)  # initial state

        self.edit_ca("--acme-enable", "--acme-contact-optional", "--acme-profile=client")
        self.assertTrue(self.ca.acme_enabled)
        self.assertEqual(self.ca.acme_profile, "client")
        self.assertFalse(self.ca.acme_requires_contact)

        # Try mutually exclusive arguments
        with self.assertRaisesRegex(SystemExit, r"^2$") as excm:
            self.edit_ca("--acme-enable", "--acme-disable")
        self.assertEqual(excm.exception.args, (2,))
        self.assertTrue(self.ca.acme_enabled)  # state unchanged

        with self.assertRaisesRegex(SystemExit, r"^2$") as excm:
            self.edit_ca("--acme-contact-optional", "--acme-contact-required")
        self.assertEqual(excm.exception.args, (2,))
        self.assertFalse(self.ca.acme_requires_contact)  # state unchanged

        # Try switching both settings
        self.edit_ca("--acme-disable", "--acme-contact-required")
        self.assertFalse(self.ca.acme_enabled)
        self.assertTrue(self.ca.acme_requires_contact)

        # Try mutually exclusive arguments again
        with self.assertRaisesRegex(SystemExit, r"^2$") as excm:
            self.edit_ca("--acme-enable", "--acme-disable")
        self.assertEqual(excm.exception.args, (2,))
        self.assertFalse(self.ca.acme_enabled)  # state unchanged

        with self.assertRaisesRegex(SystemExit, r"^2$") as excm:
            self.edit_ca("--acme-contact-optional", "--acme-contact-required")
        self.assertEqual(excm.exception.args, (2,))
        self.assertTrue(self.ca.acme_requires_contact)  # state unchanged

    @override_tmpcadir()
    def test_invalid_acme_profile(self) -> None:
        """Test setting an invalid ACME profile."""
        self.assertEqual(self.ca.acme_profile, ca_settings.CA_DEFAULT_PROFILE)

        with self.assertCommandError(r"^unknown-profile: Profile is not defined\.$"):
            self.cmd("edit_ca", self.ca.serial, acme_profile="unknown-profile")

        self.ca.refresh_from_db()
        self.assertEqual(self.ca.acme_profile, ca_settings.CA_DEFAULT_PROFILE)

    @override_tmpcadir(CA_ENABLE_ACME=False)
    def test_acme_disabled(self) -> None:
        """Test ACME arguments do not work when ACME support is disabled."""

        with self.assertRaisesRegex(SystemExit, r"^2$") as excm:
            self.edit_ca("--acme-enable")
        self.assertEqual(excm.exception.args, (2,))

        with self.assertRaisesRegex(SystemExit, r"^2$") as excm:
            self.edit_ca("--acme-contact-optional")
        self.assertEqual(excm.exception.args, (2,))

        with self.assertRaisesRegex(SystemExit, r"^2$") as excm:
            self.edit_ca("--acme-profile=foo")
        self.assertEqual(excm.exception.args, (2,))

    @override_tmpcadir()
    def test_enable(self) -> None:
        """Test enabling the CA."""
        ca = CertificateAuthority.objects.get(serial=self.ca.serial)
        ca.enabled = False
        ca.save()

        # we can also change nothing at all
        stdout, stderr = self.cmd("edit_ca", self.ca.serial, enabled=True, crl_url=None)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")

        ca = CertificateAuthority.objects.get(serial=self.ca.serial)
        self.assertEqual(ca.issuer_url, self.ca.issuer_url)
        self.assertEqual(ca.issuer_alt_name, self.ca.issuer_alt_name)
        self.assertEqual(ca.ocsp_url, self.ca.ocsp_url)
        self.assertEqual(ca.crl_url, self.ca.crl_url)
        self.assertTrue(ca.enabled)

        # disable it again
        stdout, stderr = self.cmd("edit_ca", self.ca.serial, enabled=False)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        ca = CertificateAuthority.objects.get(serial=self.ca.serial)
        self.assertFalse(ca.enabled)

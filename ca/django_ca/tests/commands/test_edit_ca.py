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

"""Test the edit_ca management command."""
from cryptography import x509

from django.test import TestCase

from django_ca import ca_settings
from django_ca.models import CertificateAuthority
from django_ca.tests.base.assertions import assert_command_error
from django_ca.tests.base.mixins import TestCaseMixin
from django_ca.tests.base.utils import (
    authority_information_access,
    cmd,
    cmd_e2e,
    crl_distribution_points,
    distribution_point,
    issuer_alternative_name,
    override_tmpcadir,
    uri,
)


class EditCATestCase(TestCaseMixin, TestCase):
    """Test the edit_ca management command."""

    load_cas = ("root",)
    issuer = "https://issuer-test.example.org"
    ian = "http://ian-test.example.org"
    ocsp_url = "http://ocsp-test.example.org"
    crl = ("http://example.org/crl-test",)
    caa = "caa.example.com"
    website = "https://website.example.com"
    tos = "https://tos.example.com"

    def edit_ca(self, *args: str) -> None:
        """Shortcut for calling the edit_ca management command."""
        stdout, stderr = cmd_e2e(["edit_ca", self.ca.serial, *args])
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        self.ca.refresh_from_db()

    @override_tmpcadir()
    def test_basic(self) -> None:
        """Test command with e2e cli argument parsing."""
        stdout, stderr = cmd_e2e(
            ["edit_ca", self.ca.serial, f"--caa={self.caa}", f"--website={self.website}", f"--tos={self.tos}"]
        )
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")

        ca = CertificateAuthority.objects.get(serial=self.ca.serial)
        self.assertEqual(ca.caa_identity, self.caa)
        self.assertEqual(ca.website, self.website)
        self.assertEqual(ca.terms_of_service, self.tos)

    @override_tmpcadir()
    def test_signing_extensions(self) -> None:
        """Test editing extensions used for signing certificates."""
        stdout, stderr = cmd_e2e(
            [
                "edit_ca",
                self.ca.serial,
                f"--sign-ca-issuer={self.issuer}",
                f"--sign-issuer-alternative-name={self.ian}",
                f"--sign-ocsp-responder={self.ocsp_url}",
                f"--sign-crl-full-name={self.crl[0]}",
                # Certificate Policies extension
                "--sign-policy-identifier=1.2.3",
                "--sign-certification-practice-statement=https://cps.example.com",
                "--sign-user-notice=explicit-text",
            ]
        )
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")

        ca: CertificateAuthority = CertificateAuthority.objects.get(serial=self.ca.serial)
        self.assertEqual(
            ca.sign_authority_information_access,
            authority_information_access(ocsp=[uri(self.ocsp_url)], ca_issuers=[uri(self.issuer)]),
        )
        self.assertEqual(ca.sign_issuer_alternative_name, issuer_alternative_name(uri(self.ian)))
        self.assertEqual(
            ca.sign_crl_distribution_points, crl_distribution_points(distribution_point([uri(self.crl[0])]))
        )

        # Certificate Policies extension
        self.assertEqual(
            ca.sign_certificate_policies,
            self.certificate_policies(
                x509.PolicyInformation(
                    policy_identifier=x509.ObjectIdentifier("1.2.3"),
                    policy_qualifiers=[
                        "https://cps.example.com",
                        x509.UserNotice(notice_reference=None, explicit_text="explicit-text"),
                    ],
                )
            ),
        )

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
        # Test initial state
        self.assertIs(self.ca.acme_enabled, False)
        self.assertIs(self.ca.acme_registration, True)
        self.assertEqual(self.ca.acme_profile, ca_settings.CA_DEFAULT_PROFILE)
        self.assertIs(self.ca.acme_requires_contact, True)

        # change all settings
        self.edit_ca(
            "--acme-enable",
            "--acme-disable-account-registration",
            "--acme-contact-optional",
            "--acme-profile=client",
        )
        self.assertIs(self.ca.acme_enabled, True)
        self.assertIs(self.ca.acme_registration, False)
        self.assertEqual(self.ca.acme_profile, "client")
        self.assertIs(self.ca.acme_requires_contact, False)

        # Try mutually exclusive arguments
        with self.assertRaisesRegex(SystemExit, r"^2$") as excm:
            self.edit_ca("--acme-enable", "--acme-disable")
        self.assertEqual(excm.exception.args, (2,))
        self.assertIs(self.ca.acme_enabled, True)  # state unchanged

        with self.assertRaisesRegex(SystemExit, r"^2$") as excm:
            self.edit_ca("--acme-contact-optional", "--acme-contact-required")
        self.assertEqual(excm.exception.args, (2,))
        self.assertIs(self.ca.acme_requires_contact, False)  # state unchanged

        # Try switching both settings
        self.edit_ca("--acme-disable", "--acme-contact-required")
        self.assertFalse(self.ca.acme_enabled)
        self.assertTrue(self.ca.acme_requires_contact)

        # Try mutually exclusive arguments again
        with self.assertRaisesRegex(SystemExit, r"^2$") as excm:
            self.edit_ca("--acme-enable", "--acme-disable")
        self.assertEqual(excm.exception.args, (2,))
        self.assertIs(self.ca.acme_enabled, False)  # state unchanged

        with self.assertRaisesRegex(SystemExit, r"^2$") as excm:
            self.edit_ca("--acme-contact-optional", "--acme-contact-required")
        self.assertEqual(excm.exception.args, (2,))
        self.assertIs(self.ca.acme_requires_contact, True)  # state unchanged

    @override_tmpcadir()
    def test_rest_api_arguments(self) -> None:
        """Test REST API arguments."""
        # Test initial state
        self.assertIs(self.ca.api_enabled, False)

        # change all settings
        self.edit_ca("--api-enable")
        self.assertIs(self.ca.api_enabled, True)

        # Try mutually exclusive arguments
        with self.assertRaisesRegex(SystemExit, r"^2$") as excm:
            self.edit_ca("--api-enable", "--api-disable")
        self.assertEqual(excm.exception.args, (2,))
        self.assertIs(self.ca.api_enabled, True)  # state unchanged

        # change all settings
        self.edit_ca("--api-disable")
        self.assertIs(self.ca.api_enabled, False)

    @override_tmpcadir()
    def test_ocsp_responder_arguments(self) -> None:
        """Test ACME arguments."""
        self.edit_ca("--ocsp-responder-key-validity=10", "--ocsp-response-validity=3600")

        self.assertEqual(self.ca.ocsp_responder_key_validity, 10)
        self.assertEqual(self.ca.ocsp_response_validity, 3600)

    @override_tmpcadir()
    def test_invalid_acme_profile(self) -> None:
        """Test setting an invalid ACME profile."""
        self.assertEqual(self.ca.acme_profile, ca_settings.CA_DEFAULT_PROFILE)

        with assert_command_error(r"^unknown-profile: Profile is not defined\.$"):
            cmd("edit_ca", self.ca.serial, acme_profile="unknown-profile")

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
        stdout, stderr = cmd("edit_ca", self.ca.serial, enabled=True)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")

        ca = CertificateAuthority.objects.get(serial=self.ca.serial)
        self.assertEqual(ca.sign_authority_information_access, self.ca.sign_authority_information_access)
        self.assertEqual(ca.sign_certificate_policies, self.ca.sign_certificate_policies)
        self.assertEqual(ca.sign_crl_distribution_points, self.ca.sign_crl_distribution_points)
        self.assertEqual(ca.sign_issuer_alternative_name, self.ca.sign_issuer_alternative_name)
        self.assertTrue(ca.enabled)

        # disable it again
        stdout, stderr = cmd("edit_ca", self.ca.serial, enabled=False)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        ca = CertificateAuthority.objects.get(serial=self.ca.serial)
        self.assertFalse(ca.enabled)

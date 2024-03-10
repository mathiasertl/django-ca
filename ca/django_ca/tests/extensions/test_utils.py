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

"""Test extension utility functions in django_ca.extensions.utils."""

from typing import Union
from unittest import TestCase

from cryptography import x509
from cryptography.x509.oid import CertificatePoliciesOID

from django_ca.extensions.utils import certificate_policies_is_simple


class CertificatePoliciesIsSimpleTestCase(TestCase):
    """Test the ``certificate_policies_is_simple`` function."""

    def assertIsSimple(self, *policies: x509.PolicyInformation) -> None:  # pylint: disable=invalid-name
        """Assert that a Certificate Policies extension with the given policies is simple."""
        self.assertTrue(certificate_policies_is_simple(self.certificate_policy(*policies)))

    def assertIsNotSimple(self, *policies: x509.PolicyInformation) -> None:  # pylint: disable=invalid-name
        """Assert that a Certificate Policies extension with the given policies is *not* simple."""
        self.assertFalse(certificate_policies_is_simple(self.certificate_policy(*policies)))

    def certificate_policy(self, *policies: x509.PolicyInformation) -> x509.CertificatePolicies:
        """Create a Certificate Policy object from the given policies."""
        return x509.CertificatePolicies(policies=policies)

    def policy_information(
        self,
        *policy_qualifiers: Union[str, x509.UserNotice],
        policy_identifier: x509.ObjectIdentifier = CertificatePoliciesOID.ANY_POLICY,
    ) -> x509.PolicyInformation:
        """Create a Policy Information object from the given policy qualifiers."""
        return x509.PolicyInformation(
            policy_identifier=policy_identifier, policy_qualifiers=policy_qualifiers
        )

    def test_simplest_certificate_policies(self) -> None:
        """Test the simplest policy possible."""
        self.assertIsSimple(
            x509.PolicyInformation(
                policy_identifier=CertificatePoliciesOID.ANY_POLICY, policy_qualifiers=None
            )
        )
        self.assertIsSimple(self.policy_information())

    def test_with_cps(self) -> None:
        """Test with a single certificate practice statement."""
        self.assertIsSimple(self.policy_information("https://cps.example.com"))

    def test_with_multiple_cps(self) -> None:
        """Test that multiple certificate practice statements are simple."""
        self.assertIsSimple(self.policy_information("https://cps.example.com/1", "https://cps.example.com/2"))

    def test_with_explicit_text(self) -> None:
        """Test a single explicit text is simple."""
        self.assertIsSimple(
            self.policy_information(x509.UserNotice(notice_reference=None, explicit_text="test"))
        )

    def test_with_multiple_explicit_text(self) -> None:
        """Test that multiple explicit texts are *not* simple."""
        self.assertIsNotSimple(
            self.policy_information(
                x509.UserNotice(notice_reference=None, explicit_text="test1"),
                x509.UserNotice(notice_reference=None, explicit_text="test2"),
            )
        )

    def test_with_notice_reference(self) -> None:
        """Test that a policy with a notice reference is *not* simple."""
        self.assertIsNotSimple(
            self.policy_information(
                x509.UserNotice(
                    notice_reference=x509.NoticeReference(organization="org", notice_numbers=[1]),
                    explicit_text=None,
                ),
            )
        )

    def test_multiple_policies(self) -> None:
        """Test that multiple policies are *not* simple."""
        self.assertIsNotSimple(self.policy_information(), self.policy_information())

    def test_simple_policy_with_everything(self) -> None:
        """Test a relatively complex policy with two CPS and an explicit text."""
        self.assertIsSimple(
            self.policy_information(
                "https://cps.example.com/1",
                "https://cps.example.com/2",
                x509.UserNotice(notice_reference=None, explicit_text="test1"),
            )
        )

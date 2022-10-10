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

# TYPEHINT NOTE: mypy-django typehints assertFieldOutput complete wrong.
# type: ignore

"""Test custom Django form fields."""

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from django.test import TestCase

from .. import fields
from .base.mixins import TestCaseMixin

D1 = "example.com"
D2 = "example.net"
D3 = "example.org"
DNS1 = x509.DNSName(D1)
DNS2 = x509.DNSName(D2)
DNS3 = x509.DNSName(D3)


class AuthorityInformationAccessField(TestCase, TestCaseMixin):
    """Tests for the AuthorityInformationAccessField."""

    def test_field_output(self) -> None:
        """Test field output."""
        self.assertFieldOutput(
            fields.AuthorityInformationAccessField,
            {
                (D1, "", False): self.authority_information_access([DNS1], [], critical=False),
                (D1, "", True): self.authority_information_access([DNS1], [], critical=True),
                ("", D1, False): self.authority_information_access([], [DNS1], critical=False),
                (D1, D2, True): self.authority_information_access([DNS1], [DNS2], critical=True),
                (D1, D2, False): self.authority_information_access([DNS1], [DNS2], critical=False),
                (f"{D1}\n{D3}", D2, True): self.authority_information_access(
                    [DNS1, DNS3], [DNS2], critical=True
                ),
                ("", "", True): None,
                ("", "", False): None,
            },
            {
                ("DNS:http://example.com", "", False): [
                    "Unparsable General Name: Could not parse DNS name: http://example.com"
                ],
            },
            empty_value=None,
        )


class CRLDistributionPointsTestCase(TestCase, TestCaseMixin):
    """Tests for the CRLDistributionPointsField."""

    def test_field_output(self) -> None:
        """Test field output."""

        for critical in [True, False]:
            self.assertFieldOutput(
                fields.CRLDistributionPointField,
                {
                    # fields: full_name, rdn, crl_issuer, reasons
                    (D1, "", "", (), critical): self.crl_distribution_points([DNS1], critical=critical),
                    (D2, "", "", (), critical): self.crl_distribution_points([DNS2], critical=critical),
                    # multiple full names:
                    (f"{D1}\n{D2}", "", "", (), critical): self.crl_distribution_points(
                        [DNS1, DNS2], critical=critical
                    ),
                    # relative distinguished name
                    ("", f"CN={D1}", "", (), critical): self.crl_distribution_points(
                        relative_name=x509.RelativeDistinguishedName(
                            [x509.NameAttribute(NameOID.COMMON_NAME, D1)]
                        ),
                        critical=critical,
                    ),
                    # crl issuer
                    (D1, "", f"{D2}", (), critical): self.crl_distribution_points(
                        [DNS1], crl_issuer=[DNS2], critical=critical
                    ),
                    (D1, "", f"{D2}\n{D3}", (), critical): self.crl_distribution_points(
                        [DNS1], crl_issuer=[DNS2, DNS3], critical=critical
                    ),
                    # include reasons
                    (
                        D1,
                        "",
                        "",
                        ("key_compromise", "certificate_hold"),
                        critical,
                    ): self.crl_distribution_points(
                        [DNS1],
                        reasons=frozenset(
                            [x509.ReasonFlags.key_compromise, x509.ReasonFlags.certificate_hold]
                        ),
                        critical=critical,
                    ),
                },
                {
                    (D1, f"CN={D2}", "", (), critical): [
                        "You cannot provide both full_name and relative_name."
                    ],
                },
                empty_value=None,
            )


class ExtendedKeyUsageFieldTestCase(TestCase, TestCaseMixin):
    """Tests for the ExtendedKeyUsageField."""

    def test_field_output(self) -> None:
        """Test field output."""
        self.assertFieldOutput(
            fields.ExtendedKeyUsageField,
            {
                (("serverAuth",), True): self.extended_key_usage(
                    ExtendedKeyUsageOID.SERVER_AUTH, critical=True
                ),
                (("clientAuth", "serverAuth",), True): self.extended_key_usage(
                    ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH, critical=True
                ),
            },
            {},
            empty_value=None,
        )


class OCSPNoCheckFieldTestCase(TestCase, TestCaseMixin):
    """Tests for the OCSPNoCheckField."""

    def test_field_output(self) -> None:
        """Test field output."""
        self.assertFieldOutput(
            fields.OCSPNoCheckField,
            {
                (True, True): self.ocsp_no_check(critical=True),
                (True, False): self.ocsp_no_check(critical=False),
                (False, False): None,
                (False, True): None,
            },
            {},
            empty_value=None,
        )


class TLSFeatureTestCase(TestCase, TestCaseMixin):
    """Tests for the TLSFeatureField."""

    def test_field_output(self) -> None:
        """Test field output."""
        self.assertFieldOutput(
            fields.TLSFeatureField,
            {
                ((), False): None,
                ((), True): None,
                (("status_request",), False): self.tls_feature(x509.TLSFeatureType.status_request),
                (("status_request", "status_request_v2"), False): self.tls_feature(
                    x509.TLSFeatureType.status_request, x509.TLSFeatureType.status_request_v2
                ),
                (("status_request",), True): self.tls_feature(
                    x509.TLSFeatureType.status_request, critical=True
                ),
                (("status_request", "status_request_v2"), True): self.tls_feature(
                    x509.TLSFeatureType.status_request, x509.TLSFeatureType.status_request_v2, critical=True
                ),
            },
            {},
            empty_value=None,
        )

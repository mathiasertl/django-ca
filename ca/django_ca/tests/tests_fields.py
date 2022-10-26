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

import typing

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

from django import forms
from django.core.exceptions import ValidationError
from django.test import TestCase

from .. import ca_settings, fields
from ..constants import REVOCATION_REASONS
from ..extensions.utils import KEY_USAGE_NAMES_MAPPING
from .base.mixins import TestCaseMixin

D1 = "example.com"
D2 = "example.net"
D3 = "example.org"
DNS1 = x509.DNSName(D1)
DNS2 = x509.DNSName(D2)
DNS3 = x509.DNSName(D3)


class FieldTestCaseMixin(TestCaseMixin):
    """Subclass of TestCaseMixin that adds a few form-field related fields."""

    field_class: typing.Type[forms.Field]

    def assertRequiredError(self, value) -> None:  # pylint: disable=invalid-name
        """Assert that the field raises a required error for the given value."""
        field = self.field_class(required=True)
        error_required = [field.error_messages["required"]]

        with self.assertRaises(ValidationError) as context_manager:
            field.clean(value)
        self.assertEqual(context_manager.exception.messages, error_required)


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


class CRLDistributionPointsTestCase(TestCase, FieldTestCaseMixin):
    """Tests for the CRLDistributionPointsField."""

    field_class = fields.CRLDistributionPointField

    def test_field_output(self) -> None:
        """Test field output."""

        for critical in [True, False]:
            self.assertFieldOutput(
                fields.CRLDistributionPointField,
                {
                    # fields: full_name, rdn, crl_issuer, reasons
                    ("", "", "", (), critical): None,  # not an error, this is not covered elsewhere
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
                    ("", "", "", ("key_compromise",), critical): [
                        "A DistributionPoint needs at least a full or relative name or a crl issuer."
                    ],
                },
                empty_value=None,
            )

    def test_rendering_empty_field(self) -> None:
        """Test rendering an empty field as HTML."""
        name = "field-name"
        field = self.field_class()
        html = field.widget.render(name, None)
        self.assertInHTML(
            f'<textarea name="{name}_0" cols="40" rows="3" class="django-ca-widget full-name"></textarea>',
            html,
        )
        self.assertInHTML(f'<input type="text" name="{name}_1" class="django-ca-widget relative-name">', html)
        self.assertInHTML(
            f'<textarea name="{name}_2" cols="40" rows="3" class="django-ca-widget crl-issuer"></textarea>',
            html,
        )
        for choice, text in REVOCATION_REASONS:
            self.assertInHTML(f'<option value="{choice}">{text}</option>', html)

    def test_rendering_full_field(self) -> None:
        """Test rendering an empty field as HTML."""
        name = "field-name"
        field = self.field_class()
        html = field.widget.render(
            name,
            self.crl_distribution_points(
                [DNS1],
                crl_issuer=[DNS2],
                reasons=frozenset([x509.ReasonFlags.key_compromise, x509.ReasonFlags.certificate_hold]),
            ),
        )
        self.assertInHTML(
            f'<textarea name="{name}_0" cols="40" rows="3" class="django-ca-widget full-name">'
            f"DNS:{D1}</textarea>",
            html,
        )
        self.assertInHTML(f'<input type="text" name="{name}_1" class="django-ca-widget relative-name">', html)
        self.assertInHTML('<option value="key_compromise" selected>Key compromised</option>', html)
        self.assertInHTML('<option value="certificate_hold" selected>On Hold</option>', html)
        self.assertInHTML(
            f'<textarea name="{name}_2" cols="40" rows="3" class="django-ca-widget crl-issuer">'
            f"DNS:{D2}</textarea>",
            html,
        )

    def test_rendering_relative_distinguished_name(self) -> None:
        """Test rendering a RelativeDistinguishedName."""
        name = "field-name"
        field = self.field_class()
        html = field.widget.render(
            name,
            self.crl_distribution_points(
                relative_name=x509.RelativeDistinguishedName([x509.NameAttribute(NameOID.COMMON_NAME, D1)]),
            ),
        )
        self.assertInHTML(
            f'<input type="text" name="{name}_1" value="CN={D1}" class="django-ca-widget relative-name">',
            html,
        )

    def test_rendering_mutltiple_dps(self) -> None:
        """Test rendering multiple distribution points (It's not supported yet)."""
        field = self.field_class()
        dpoint = x509.DistributionPoint(full_name=[DNS1], relative_name=None, reasons=None, crl_issuer=None)
        ext = x509.Extension(
            oid=ExtensionOID.CRL_DISTRIBUTION_POINTS,
            critical=False,
            value=x509.CRLDistributionPoints([dpoint, dpoint]),
        )

        with self.assertRaisesRegex(ValueError, r"^Only one DistributionPoint is supported at this time\.$"):
            field.widget.render("error", ext)


class GeneralNamesFieldTest(TestCase, FieldTestCaseMixin):
    """Tests for the GeneralNamesField."""

    field_class = fields.GeneralNamesField

    def test_field_output(self) -> None:
        """Test field output."""
        self.assertFieldOutput(
            fields.GeneralNamesField,
            {
                D1: [DNS1],
                D2: [DNS2],
                f"{D1}\n{D2}": [DNS1, DNS2],
                f"DNS:{D1}\nDNS:{D2}": [DNS1, DNS2],
                f"{D2}\n{D1}": [DNS2, DNS1],  # test order
                f"\n  {D1}  \n  \n  {D2}  \n  ": [DNS1, DNS2],
            },
            {
                "DNS:http://example.com": [
                    "Unparsable General Name: Could not parse DNS name: http://example.com"
                ],
            },
            empty_value=None,
        )

    def test_rendering(self) -> None:
        """Test rendering the field as HTML."""
        name = "field-name"
        field = self.field_class()
        self.assertInHTML(
            f'<textarea name="{name}" cols="40" rows="10" class="django-ca-widget"></textarea>',
            field.widget.render(name, None),
        )
        self.assertInHTML(
            f'<textarea name="{name}" cols="40" rows="10" class="django-ca-widget">DNS:{D1}</textarea>',
            field.widget.render(name, [DNS1]),
        )
        # assertInHTML() treats newline and space the same way, and we want to make sure we have a newline
        # separating the names.
        self.assertIn(f">\nDNS:{D1}\nDNS:{D2}</textarea>", field.widget.render(name, [DNS1, DNS2]))

    def test_whitespace(self) -> None:
        """Test that empty lines are completely ignored and return an empty value."""

        self.assertRequiredError("  ")
        self.assertRequiredError("\n")
        self.assertRequiredError("\n  \n")
        self.assertRequiredError("  \n")


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


class IssuerAlternativeNameFieldTestCase(TestCase, TestCaseMixin):
    """Tests for the IssuerAlternativeNameField."""

    def test_field_output(self) -> None:
        """Test field output."""
        self.assertFieldOutput(
            fields.IssuerAlternativeNameField,
            {
                (D1, True): self.issuer_alternative_name(DNS1, critical=True),
                (D1, False): self.issuer_alternative_name(DNS1, critical=False),
                ("", False): None,
                ("", True): None,
            },
            {},
            empty_value=None,
        )


class KeyUsageFieldTestCase(TestCase, FieldTestCaseMixin):
    """Tests for the KeyUsageField."""

    field_class = fields.KeyUsageField

    def test_field_output(self) -> None:
        """Test field output."""
        self.assertFieldOutput(
            fields.KeyUsageField,
            {
                (("crl_sign",), True): self.key_usage(crl_sign=True),
            },
            {},
            empty_value=None,
        )

    def test_rendering(self) -> None:
        """Test rendering the field as HTML."""
        name = "field-name"
        field = self.field_class()

        html = field.widget.render(name, None)
        for choice, text in self.field_class.choices:
            self.assertInHTML(f'<option value="{choice}">{text}</option>', html)

    def test_rendering_profiles(self) -> None:
        """Test rendering for all profiles."""
        field = self.field_class()

        for profile_name, profile in ca_settings.CA_PROFILES.items():
            choices = profile["extensions"]["key_usage"]["value"]
            choices = [KEY_USAGE_NAMES_MAPPING[choice] for choice in choices]

            ext = self.key_usage(**{choice: True for choice in choices})
            html = field.widget.render("unused", ext)

            for choice, text in self.field_class.choices:
                if choice in choices:
                    self.assertInHTML(f'<option value="{choice}" selected>{text}</option>', html)
                else:
                    self.assertInHTML(f'<option value="{choice}">{text}</option>', html)


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

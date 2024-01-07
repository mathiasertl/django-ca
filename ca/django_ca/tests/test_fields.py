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

# TYPEHINT NOTE: mypy-django typehints assertFieldOutput complete wrong.
# type: ignore

"""Test custom Django form fields."""
import html
import json
from typing import Any, Dict, List, Tuple, Type

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from django import forms
from django.core.exceptions import ValidationError
from django.test import TestCase

import pytest
from pytest_django.asserts import assertInHTML

from django_ca import ca_settings, fields
from django_ca.constants import KEY_USAGE_NAMES, REVOCATION_REASONS
from django_ca.tests.base.mixins import TestCaseMixin
from django_ca.tests.base.utils import (
    authority_information_access,
    crl_distribution_points,
    distribution_point,
    extended_key_usage,
    key_usage,
    ocsp_no_check,
    rdn,
    tls_feature,
)

D1 = "example.com"
D2 = "example.net"
D3 = "example.org"
DNS1 = x509.DNSName(D1)
DNS2 = x509.DNSName(D2)
DNS3 = x509.DNSName(D3)
SER_D1 = {"key": "DNS", "value": D1}
SER_D2 = {"key": "DNS", "value": D2}
SER_D3 = {"key": "DNS", "value": D3}

# common attributes in hidden key-value input field
HIDDEN_INPUT_ATTRS = 'type="hidden" data-key-key="key" data-value-key="value"'


class FieldTestCaseMixin(TestCaseMixin):
    """Subclass of TestCaseMixin that adds a few form-field related fields."""

    field_class: Type[forms.Field]

    def assertRequiredError(self, value) -> None:  # pylint: disable=invalid-name
        """Assert that the field raises a required error for the given value."""
        field = self.field_class(required=True)
        error_required = [field.error_messages["required"]]

        with self.assertRaises(ValidationError) as context_manager:
            field.clean(value)
        self.assertEqual(context_manager.exception.messages, error_required)


@pytest.mark.parametrize("critical", (True, False))
@pytest.mark.parametrize("required", (True, False))
@pytest.mark.parametrize(
    "field_class,extension_type",
    (
        (fields.IssuerAlternativeNameField, x509.IssuerAlternativeName),
        (fields.SubjectAlternativeNameField, x509.SubjectAlternativeName),
    ),
)
@pytest.mark.parametrize("value,general_names", (([SER_D1], [DNS1]), ([SER_D1, SER_D2], [DNS1, DNS2])))
def test_alternative_name_fields(
    critical: bool,
    required: bool,
    field_class: Type[fields.AlternativeNameField],
    extension_type: Type[x509.ExtensionType],
    value: Any,
    general_names: List[x509.GeneralName],
) -> None:
    """Test output for AlternativeName fields."""
    field = field_class(required=required)
    ext = x509.Extension(critical=critical, oid=extension_type.oid, value=extension_type(general_names))
    assert field.clean((json.dumps(value), critical)) == ext


@pytest.mark.parametrize("critical", (True, False))
@pytest.mark.parametrize("required", (True, False))
@pytest.mark.parametrize(
    "field_class,extension_type",
    (
        (fields.CRLDistributionPointField, x509.CRLDistributionPoints),
        (fields.FreshestCRLField, x509.FreshestCRL),
    ),
)
@pytest.mark.parametrize(
    "value,dpoint",
    (
        (([SER_D1], "", "", ()), distribution_point([DNS1])),
        (([SER_D1, SER_D2], "", "", ()), (distribution_point([DNS1, DNS2]))),
        (  # With RDN
            ([], f"CN={D1}", "", ()),
            (distribution_point(relative_name=rdn([(NameOID.COMMON_NAME, D1)]))),
        ),
        (  # test RDN order
            ([], f"C=AT,O=MyOrg,CN={D1}", "", ()),
            (
                distribution_point(
                    relative_name=rdn(
                        [
                            (NameOID.COUNTRY_NAME, "AT"),
                            (NameOID.ORGANIZATION_NAME, "MyOrg"),
                            (NameOID.COMMON_NAME, D1),
                        ]
                    )
                )
            ),
        ),
        (([SER_D1], "", [SER_D2], ()), distribution_point([DNS1], crl_issuer=[DNS2])),  # with CRL issuers
        (
            ([SER_D1], "", [SER_D2, SER_D3], ()),
            distribution_point([DNS1], crl_issuer=[DNS2, DNS3]),
        ),  # multiple
        (
            ([SER_D1], "", "", ("key_compromise", "certificate_hold")),
            distribution_point(
                [DNS1],
                reasons=frozenset([x509.ReasonFlags.key_compromise, x509.ReasonFlags.certificate_hold]),
            ),
        ),
    ),
)
def test_distribution_point_fields(
    critical: bool,
    required: bool,
    field_class: Type[fields.DistributionPointField],
    extension_type: Type[x509.ExtensionType],
    value: Tuple[List[Dict[str, Any]], str, List[Dict[str, Any]], Tuple[str, ...]],
    dpoint: x509.DistributionPoint,
) -> None:
    """Test fields.CRLDistributionPointField."""
    field = field_class(required=required)

    # Prepare field input
    full_name, relative_name, crl_issuers, reasons = value
    full_name = json.dumps(full_name)
    crl_issuers = json.dumps(crl_issuers)

    # Prepare expected value
    ext = x509.Extension(critical=critical, oid=extension_type.oid, value=extension_type([dpoint]))

    assert field.clean((full_name, relative_name, crl_issuers, reasons, critical)) == ext


@pytest.mark.parametrize("critical", (True, False))
@pytest.mark.parametrize("required", (True, False))
@pytest.mark.parametrize(
    "invalid,error",
    (
        (([SER_D1], f"CN={D1}", "", ()), r"You cannot provide both full_name and relative_name\."),
        (
            ([], "", "", ("key_compromise",)),
            r"A DistributionPoint needs at least a full or relative name or a crl issuer\.",
        ),
    ),
)
def test_crl_distribution_points_field_with_invalid_input(
    critical: bool,
    required: bool,
    invalid: Tuple[List[Dict[str, Any]], str, List[Dict[str, Any]], Tuple[str, ...]],
    error: str,
):
    """Test fields.CRLDistributionPointField with invalid input."""
    field = fields.CRLDistributionPointField(required=required)

    # Prepare field input
    full_name, relative_name, crl_issuers, reasons = invalid
    full_name = json.dumps(full_name)
    crl_issuers = json.dumps(crl_issuers)

    with pytest.raises(ValidationError, match=error):
        field.clean((full_name, relative_name, crl_issuers, reasons, critical))


@pytest.mark.parametrize("critical", (True, False))
@pytest.mark.parametrize("required", (True, False))
@pytest.mark.parametrize("value", (([], "", "", ()),))
def test_crl_distribution_points_field_with_empty_input(
    critical: bool,
    required: bool,
    value: Tuple[List[Dict[str, Any]], str, List[Dict[str, Any]], Tuple[str, ...]],
) -> None:
    """Test fields.CRLDistributionPointField with empty input."""
    field = fields.CRLDistributionPointField(required=required)
    assert field.clean((*value, critical)) is None

    # Test how the field is rendered
    name = "field-name"
    raw_html = field.widget.render(name, None)
    assertInHTML(
        f'<input name="{name}_0" value="" class="full-name key-value-data" {HIDDEN_INPUT_ATTRS}>', raw_html
    )
    assertInHTML(f'<input type="text" name="{name}_1" class="django-ca-widget relative-name">', raw_html)
    assertInHTML(
        f'<input name="{name}_2" value="" class="crl-issuer key-value-data" {HIDDEN_INPUT_ATTRS}>', raw_html
    )
    for choice, text in REVOCATION_REASONS:
        assertInHTML(f'<option value="{choice}">{text}</option>', raw_html)


def test_crl_distribution_points_field_rendering() -> None:
    """Test rendering of fields.CRLDistributionPointField with all values (but RDN)."""
    name = "field-name"
    field = fields.CRLDistributionPointField()
    reasons = frozenset([x509.ReasonFlags.key_compromise, x509.ReasonFlags.certificate_hold])
    raw_html = field.widget.render(
        name,
        crl_distribution_points(distribution_point([DNS1], crl_issuer=[DNS2], reasons=reasons)),
    )

    full_name_value = html.escape(json.dumps([SER_D1]))
    assertInHTML(
        f'<input name="{name}_0" value="{full_name_value}" class="full-name key-value-data" '
        f"{HIDDEN_INPUT_ATTRS}>",
        raw_html,
    )
    assertInHTML(f'<input type="text" name="{name}_1" class="django-ca-widget relative-name">', raw_html)
    assertInHTML('<option value="key_compromise" selected>Key compromised</option>', raw_html)
    assertInHTML('<option value="certificate_hold" selected>On Hold</option>', raw_html)
    crl_issuer_value = html.escape(json.dumps([SER_D2]))
    assertInHTML(
        f'<input name="{name}_2" value="{crl_issuer_value}" class="crl-issuer key-value-data" '
        f"{HIDDEN_INPUT_ATTRS}>",
        raw_html,
    )


def test_crl_distribution_points_field_rendering_with_rdn() -> None:
    """Test rendering of fields.CRLDistributionPointField with a RelativeDistinguishedName."""
    name = "field-name"
    field = fields.CRLDistributionPointField()
    ext = crl_distribution_points(distribution_point(relative_name=rdn([(NameOID.COMMON_NAME, D1)])))

    # Test how the field is rendered
    name = "field-name"
    raw_html = field.widget.render(name, ext)
    assertInHTML(
        f'<input name="{name}_0" value="[]" class="full-name key-value-data" {HIDDEN_INPUT_ATTRS}>', raw_html
    )
    assertInHTML(
        f'<input type="text" name="{name}_1" value="CN={D1}" class="django-ca-widget relative-name">',
        raw_html,
    )
    assertInHTML(
        f'<input name="{name}_2" value="[]" class="crl-issuer key-value-data" {HIDDEN_INPUT_ATTRS}>', raw_html
    )
    for choice, text in REVOCATION_REASONS:
        assertInHTML(f'<option value="{choice}">{text}</option>', raw_html)


def test_crl_distribution_points_field_rendering_with_multiple_dps() -> None:
    """Test rendering of fields.CRLDistributionPointField with multiple DistributionPoints."""
    name = "field-name"
    field = fields.CRLDistributionPointField()
    ext = crl_distribution_points(distribution_point([DNS1]), distribution_point([DNS2]))

    # Test how the field is rendered
    name = "field-name"
    raw_html = field.widget.render(name, ext)
    full_name_value = html.escape(json.dumps([SER_D1]))
    assertInHTML(
        f'<input name="{name}_0" value="{full_name_value}" class="full-name key-value-data" '
        f"{HIDDEN_INPUT_ATTRS}>",
        raw_html,
    )
    assertInHTML(f'<input type="text" name="{name}_1" class="django-ca-widget relative-name">', raw_html)
    assertInHTML(
        f'<input name="{name}_2" value="[]" class="crl-issuer key-value-data" {HIDDEN_INPUT_ATTRS}>', raw_html
    )
    for choice, text in REVOCATION_REASONS:
        assertInHTML(f'<option value="{choice}">{text}</option>', raw_html)


@pytest.mark.parametrize("critical", (True, False))
@pytest.mark.parametrize("required", (True, False))
@pytest.mark.parametrize(
    "ser_ca_issuers,ser_ocsp,ca_issuers,ocsp",
    (
        ((SER_D1,), (), (DNS1,), ()),
        ((), (SER_D2,), (), (DNS2,)),
        ((SER_D1,), (SER_D2,), (DNS1,), (DNS2,)),
        ((SER_D1, SER_D3), (SER_D2,), (DNS1, DNS3), (DNS2,)),
        ((SER_D1,), (SER_D2, SER_D3), (DNS1,), (DNS2, DNS3)),
    ),
)
def test_authority_information_access_field(
    critical: bool,
    required: bool,
    ser_ca_issuers: List[Dict[str, Any]],
    ser_ocsp: List[Dict[str, Any]],
    ca_issuers: List[x509.GeneralName],
    ocsp: List[x509.GeneralName],
) -> None:
    """Test AuthorityInformationAccessField field."""
    field = fields.AuthorityInformationAccessField(required=required)
    ext = authority_information_access(ca_issuers=ca_issuers, ocsp=ocsp, critical=critical)
    assert field.clean((json.dumps(ser_ca_issuers), json.dumps(ser_ocsp), critical)) == ext


@pytest.mark.parametrize("critical", (True, False))  # make sure that critical flag has no effect
@pytest.mark.parametrize("required", (True, False))
@pytest.mark.parametrize(
    "ser_ca_issuers,ser_ocsp",
    (("", ""), ("[]", "[]"), (None, None)),
)
def test_authority_information_access_field_with_empty_value(
    critical: bool, required: bool, ser_ca_issuers: str, ser_ocsp: str
) -> None:
    """Test AuthorityInformationAccessField field with an empty value."""
    field = fields.AuthorityInformationAccessField(required=required)
    assert field.clean((ser_ca_issuers, ser_ocsp, critical)) is None


@pytest.mark.parametrize(
    "ser_ca_issuers,ser_ocsp,error",
    (
        (({"key": "DNS", "value": "http://example.com"},), (), ""),
        (({"key": "IP", "value": "example.com"},), (), "example.com: Could not parse IP address"),
    ),
)
def test_authority_information_access_field_with_errors(
    ser_ca_issuers: str, ser_ocsp: str, error: str
) -> None:
    """Test AuthorityInformationAccessField field with an empty value."""
    field = fields.AuthorityInformationAccessField(required=True)

    with pytest.raises(ValidationError, match=error):
        field.clean((json.dumps(ser_ca_issuers), json.dumps(ser_ocsp), True))


class ExtendedKeyUsageFieldTestCase(TestCase, TestCaseMixin):
    """Tests for the ExtendedKeyUsageField."""

    def test_field_output(self) -> None:
        """Test field output."""
        self.assertFieldOutput(
            fields.ExtendedKeyUsageField,
            {
                ((ExtendedKeyUsageOID.SERVER_AUTH.dotted_string,), True): extended_key_usage(
                    ExtendedKeyUsageOID.SERVER_AUTH, critical=True
                ),
                (
                    (
                        ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string,
                        ExtendedKeyUsageOID.SERVER_AUTH.dotted_string,
                    ),
                    True,
                ): extended_key_usage(
                    ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH, critical=True
                ),
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
            {(("crl_sign",), True): key_usage(crl_sign=True)},
            {},
            empty_value=None,
        )

    def test_rendering(self) -> None:
        """Test rendering the field as HTML."""
        name = "field-name"
        field = self.field_class()

        raw_html = field.widget.render(name, None)
        for choice, text in self.field_class.choices:
            self.assertInHTML(f'<option value="{choice}">{text}</option>', raw_html)

    def test_rendering_profiles(self) -> None:
        """Test rendering for all profiles."""
        field = self.field_class()

        key_usage_choices = {v: k for k, v in KEY_USAGE_NAMES.items()}

        for profile in ca_settings.CA_PROFILES.values():
            choices = profile["extensions"]["key_usage"]["value"]
            choices = [key_usage_choices[choice] for choice in choices]

            ext = key_usage(**{choice: True for choice in choices})
            raw_html = field.widget.render("unused", ext)

            for choice, text in self.field_class.choices:
                if choice in choices:
                    self.assertInHTML(f'<option value="{choice}" selected>{text}</option>', raw_html)
                else:
                    self.assertInHTML(f'<option value="{choice}">{text}</option>', raw_html)


class OCSPNoCheckFieldTestCase(TestCase, TestCaseMixin):
    """Tests for the OCSPNoCheckField."""

    def test_field_output(self) -> None:
        """Test field output."""
        self.assertFieldOutput(
            fields.OCSPNoCheckField,
            {
                (True, True): ocsp_no_check(critical=True),
                (True, False): ocsp_no_check(critical=False),
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
                (("status_request",), False): tls_feature(x509.TLSFeatureType.status_request),
                (("status_request", "status_request_v2"), False): tls_feature(
                    x509.TLSFeatureType.status_request, x509.TLSFeatureType.status_request_v2
                ),
                (("status_request",), True): tls_feature(x509.TLSFeatureType.status_request, critical=True),
                (("status_request", "status_request_v2"), True): tls_feature(
                    x509.TLSFeatureType.status_request, x509.TLSFeatureType.status_request_v2, critical=True
                ),
            },
            {},
            empty_value=None,
        )

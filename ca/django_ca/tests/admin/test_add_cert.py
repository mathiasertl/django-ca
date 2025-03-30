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

"""Test cases for adding certificates via the admin interface."""

import json
from copy import deepcopy
from datetime import datetime, timedelta
from http import HTTPStatus
from typing import Any, Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import AuthorityInformationAccessOID, CertificatePoliciesOID, ExtensionOID, NameOID

from django.contrib.auth.models import User  # pylint: disable=imported-auth-user
from django.forms.boundfield import BoundField
from django.test import Client

import pytest
from _pytest.logging import LogCaptureFixture
from django_webtest import DjangoTestApp
from pytest_django.asserts import assertRedirects
from pytest_django.fixtures import SettingsWrapper
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement
from selenium.webdriver.support.select import Select
from selenium.webdriver.support.wait import WebDriverWait

from django_ca.conf import model_settings
from django_ca.constants import (
    END_ENTITY_CERTIFICATE_EXTENSION_KEYS,
    EXTENSION_DEFAULT_CRITICAL,
    HASH_ALGORITHM_NAMES,
    ExtendedKeyUsageOID,
)
from django_ca.fields import CertificateSigningRequestField
from django_ca.forms import CreateCertificateForm
from django_ca.models import Certificate, CertificateAuthority
from django_ca.profiles import Profile, profiles
from django_ca.pydantic.extensions import (
    EXTENSION_MODELS,
    AuthorityInformationAccessModel,
    CRLDistributionPointsModel,
)
from django_ca.tests.admin.assertions import assert_css
from django_ca.tests.admin.base import AddCertificateSeleniumTestCase, CertificateModelAdminTestCaseMixin
from django_ca.tests.base.assertions import (
    assert_authority_key_identifier,
    assert_count_equal,
    assert_create_cert_signals,
    assert_extensions,
    assert_post_issue_cert,
)
from django_ca.tests.base.constants import CERT_DATA, TIMESTAMPS
from django_ca.tests.base.testcases import SeleniumTestCase
from django_ca.tests.base.typehints import HttpResponse
from django_ca.tests.base.utils import (
    authority_information_access,
    basic_constraints,
    certificate_policies,
    cn,
    country,
    crl_distribution_points,
    distribution_point,
    dns,
    extended_key_usage,
    freshest_crl,
    issuer_alternative_name,
    key_usage,
    ocsp_no_check,
    override_tmpcadir,
    subject_alternative_name,
    subject_key_identifier,
    tls_feature,
    uri,
)
from django_ca.typehints import HashAlgorithms, SerializedPydanticExtension

CSR = CERT_DATA["root-cert"]["csr"]["parsed"].public_bytes(Encoding.PEM).decode("utf-8")
pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])]


def form_data(
    csr: str, ca: CertificateAuthority, hostname: str, algorithm: HashAlgorithms | Literal[""] = "SHA-256"
) -> dict[str, str | bool | int | list[str]]:
    """Get basic form data to submit to the admin interface."""
    crldp = CRLDistributionPointsModel.model_validate(ca.sign_crl_distribution_points).model_dump(
        mode="json"
    )["value"]
    aia = AuthorityInformationAccessModel.model_validate(ca.sign_authority_information_access).model_dump(
        mode="json"
    )["value"]
    ca_issuers = [
        ad["access_location"]
        for ad in aia
        if ad["access_method"] == AuthorityInformationAccessOID.CA_ISSUERS.dotted_string
    ]
    ocsp = [
        ad["access_location"]
        for ad in aia
        if ad["access_method"] == AuthorityInformationAccessOID.OCSP.dotted_string
    ]

    return {
        "csr": csr,
        "ca": ca.pk,
        "profile": "webserver",
        "subject": json.dumps(
            [
                {"oid": NameOID.COUNTRY_NAME.dotted_string, "value": "US"},
                {"oid": NameOID.COMMON_NAME.dotted_string, "value": hostname},
            ]
        ),
        "subject_alternative_name_0": json.dumps([{"type": "DNS", "value": hostname}]),
        "algorithm": algorithm,
        "not_after": ca.not_after.strftime("%Y-%m-%d"),
        "certificate_policies_0": "1.2.3",
        "certificate_policies_1": "https://cps.example.com",
        "certificate_policies_2": "explicit-text",
        "key_usage_0": ["digital_signature", "key_agreement"],
        "key_usage_1": True,
        "extended_key_usage_0": [
            ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string,
            ExtendedKeyUsageOID.SERVER_AUTH.dotted_string,
        ],
        "extended_key_usage_1": False,
        "tls_feature_0": ["status_request", "status_request_v2"],
        "tls_feature_1": False,
        "ocsp_no_check_0": True,
        "ocsp_no_check_1": False,
        "crl_distribution_points_0": json.dumps(crldp[0]["full_name"]),
        "crl_distribution_points_1": "",
        "crl_distribution_points_2": "",
        "crl_distribution_points_3": [],
        "crl_distribution_points_4": False,
        "authority_information_access_0": json.dumps(ca_issuers),
        "authority_information_access_1": json.dumps(ocsp),
        "authority_information_access_2": False,
    }


def get_add_response(client: Client) -> "HttpResponse":
    """Do a basic get request (to test CSS etc)."""
    response = client.get(Certificate.admin_add_url)
    assert response.status_code == HTTPStatus.OK
    templates = [t.name for t in response.templates]
    assert "admin/django_ca/certificate/change_form.html" in templates
    assert "admin/change_form.html" in templates
    assert_css(response, "django_ca/admin/css/base.css")
    assert_css(response, "django_ca/admin/css/certificateadmin.css")
    return response


def get_add_response_form(client: Client) -> CreateCertificateForm:
    """Just get the form returned in the add view response."""
    response = get_add_response(client)
    form = response.context["adminform"].form
    assert isinstance(form, CreateCertificateForm)
    return form


def assert_initial_field_value(form: CreateCertificateForm, field: str, value: Any) -> BoundField:
    """Assert an initial value in a form field."""
    bound_field = form.fields[field].get_bound_field(form, field)
    assert bound_field.initial == value
    return bound_field


class TestViewAddView:
    """Tests for simply viewing the add view (== view the form for adding a certificate)."""

    def test_with_rsa(
        self, admin_client: Client, usable_root: CertificateAuthority, usable_child: CertificateAuthority
    ) -> None:
        """Test with an RSA-based CA as default CA (algorithm should be ca algorithm)."""
        assert usable_child.not_after > usable_root.not_after  # assumption must hold for default value
        form = get_add_response_form(admin_client)
        assert_initial_field_value(form, "ca", usable_child)
        assert usable_child.algorithm is not None
        assert_initial_field_value(form, "algorithm", HASH_ALGORITHM_NAMES[type(usable_child.algorithm)])

    @pytest.mark.usefixtures("usable_ed448")
    def test_with_ed448(self, admin_client: Client) -> None:
        """Test with an Ed-based CA as default CA (algorithm should be empty)."""
        form = get_add_response_form(admin_client)
        assert_initial_field_value(form, "algorithm", "")

    def test_with_disabled_ca(
        self, admin_client: Client, usable_root: CertificateAuthority, usable_child: CertificateAuthority
    ) -> None:
        """Test disabling the default CA, check that the default has changed and is not selectable."""
        assert usable_child.not_after > usable_root.not_after  # assumption must hold for default value
        usable_child.enabled = False
        usable_child.save()

        form = get_add_response_form(admin_client)
        bound_field = assert_initial_field_value(form, "ca", usable_root)
        assert bound_field.field.choices == [(usable_root.pk, usable_root.name)]  # type: ignore[attr-defined]

    @pytest.mark.usefixtures("root")
    def test_with_no_usable_ca(self, admin_client: Client) -> None:
        """Test error when no usable CAs are configured."""
        response = admin_client.get(Certificate.admin_add_url)
        assert response.status_code == HTTPStatus.FORBIDDEN

    @pytest.mark.freeze_time(TIMESTAMPS["everything_expired"])
    @pytest.mark.usefixtures("usable_root")
    def test_change_view_with_expired_cas(self, admin_client: Client) -> None:
        """Test error when all CAs have expired."""
        response = admin_client.get(Certificate.admin_add_url)
        assert response.status_code == HTTPStatus.FORBIDDEN

    @pytest.mark.usefixtures("usable_root")
    def test_get_profiles(self, settings: SettingsWrapper, admin_client: Client) -> None:
        """Test get with a subject that explicitly sets an extension."""
        settings.CA_PROFILES = {"webserver": {"extensions": {"ocsp_no_check": {"critical": True}}}}
        form = get_add_response_form(admin_client)
        assert_initial_field_value(form, "ocsp_no_check", ocsp_no_check(critical=True))

    def test_with_unusable_default_ca(
        self,
        settings: SettingsWrapper,
        admin_client: Client,
        usable_root: CertificateAuthority,
        usable_child: CertificateAuthority,
    ) -> None:
        """Test that a usable CA is the initial value if the default is not usable."""
        settings.CA_DEFAULT_CA = usable_child.serial
        usable_child.enabled = False
        usable_child.save()
        form = get_add_response_form(admin_client)
        assert_initial_field_value(form, "ca", usable_root)

    def test_with_unusable_default_ca_with_unsable_private_key(
        self,
        settings: SettingsWrapper,
        admin_client: Client,
        usable_root: CertificateAuthority,
        usable_child: CertificateAuthority,
    ) -> None:
        """Test that a usable CA is the initial value if the default is not usable acc. to the key backend."""
        settings.CA_DEFAULT_CA = usable_child.serial
        usable_child.key_backend_options = {"path": "does-not-exist.key"}
        usable_child.save()
        form = get_add_response_form(admin_client)
        assert_initial_field_value(form, "ca", usable_root)


class TestSubmitAddView:
    """Tests for adding certificates via the admin interface."""

    def test_add(self, admin_client: Client, hostname: str, usable_root: CertificateAuthority) -> None:
        """Test to actually add a certificate."""
        with assert_create_cert_signals() as (pre, post):
            response = admin_client.post(
                Certificate.admin_add_url, data=form_data(CSR, usable_root, hostname)
            )
            assertRedirects(response, Certificate.admin_changelist_url)

        cert = Certificate.objects.get(cn=hostname)
        assert_post_issue_cert(post, cert)
        assert cert.pub.loaded.subject == x509.Name([country("US"), cn(hostname)])
        assert cert.issuer == usable_root.subject
        assert_extensions(
            cert,
            [
                extended_key_usage(ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH),
                key_usage(digital_signature=True, key_agreement=True),
                ocsp_no_check(),
                subject_alternative_name(dns(hostname)),
                tls_feature(x509.TLSFeatureType.status_request, x509.TLSFeatureType.status_request_v2),
                certificate_policies(
                    x509.PolicyInformation(
                        policy_identifier=x509.ObjectIdentifier("1.2.3"),
                        policy_qualifiers=[
                            "https://cps.example.com",
                            x509.UserNotice(notice_reference=None, explicit_text="explicit-text"),
                        ],
                    )
                ),
            ],
        )
        assert cert.ca == usable_root
        assert cert.csr.pem == CSR
        assert cert.profile == "webserver"

        # Some extensions are NOT set
        assert ExtensionOID.ISSUER_ALTERNATIVE_NAME not in cert.extensions

    def test_with_extension_disabled_in_profile(
        self,
        settings: SettingsWrapper,
        admin_client: Client,
        hostname: str,
        usable_root: CertificateAuthority,
    ) -> None:
        """Test adding extensions based on a profile where one extension is a None value."""
        settings.CA_PROFILES = {"webserver": {"extensions": {"ocsp_no_check": None}}}
        submit_data = {**form_data(CSR, usable_root, hostname), "ocsp_no_check_0": False}

        response = admin_client.post(Certificate.admin_add_url, data=submit_data)
        assertRedirects(response, Certificate.admin_changelist_url)

        cert = Certificate.objects.get(cn=hostname)
        assert ExtensionOID.OCSP_NO_CHECK not in cert.extensions, cert.extensions.keys()

    def test_empty_subject(
        self, admin_client: Client, hostname: str, usable_root: CertificateAuthority
    ) -> None:
        """Test passing an empty subject with a subject alternative name."""
        response = admin_client.post(
            Certificate.admin_add_url, data={**form_data(CSR, usable_root, hostname), "subject": ""}
        )
        assertRedirects(response, Certificate.admin_changelist_url)

        cert: Certificate = Certificate.objects.get(cn="")
        assert cert.subject == x509.Name([])
        assert cert.extensions[ExtensionOID.SUBJECT_ALTERNATIVE_NAME] == subject_alternative_name(
            dns(hostname)
        )

    def test_subject_with_multiple_org_units(
        self,
        settings: SettingsWrapper,
        admin_client: Client,
        hostname: str,
        usable_root: CertificateAuthority,
    ) -> None:
        """Test creating a certificate with multiple Org Units (which is allowed)."""
        settings.CA_DEFAULT_SUBJECT = tuple()
        with assert_create_cert_signals() as (pre, post):
            response = admin_client.post(
                Certificate.admin_add_url,
                data={
                    **form_data(CSR, usable_root, hostname),
                    "subject": json.dumps(
                        [
                            {"oid": NameOID.COUNTRY_NAME.dotted_string, "value": "US"},
                            {"oid": NameOID.ORGANIZATIONAL_UNIT_NAME.dotted_string, "value": "OU-1"},
                            {"oid": NameOID.ORGANIZATIONAL_UNIT_NAME.dotted_string, "value": "OU-2"},
                            {"oid": NameOID.COMMON_NAME.dotted_string, "value": hostname},
                        ]
                    ),
                },
            )
        assertRedirects(response, Certificate.admin_changelist_url)

        cert: Certificate = Certificate.objects.get(cn=hostname)
        assert_post_issue_cert(post, cert)
        assert cert.subject == x509.Name(
            [
                x509.NameAttribute(oid=NameOID.COUNTRY_NAME, value="US"),
                x509.NameAttribute(oid=NameOID.ORGANIZATIONAL_UNIT_NAME, value="OU-1"),
                x509.NameAttribute(oid=NameOID.ORGANIZATIONAL_UNIT_NAME, value="OU-2"),
                x509.NameAttribute(oid=NameOID.COMMON_NAME, value=hostname),
            ]
        )

    def test_add_no_common_name_and_no_subject_alternative_name(
        self, admin_client: Client, hostname: str, usable_root: CertificateAuthority
    ) -> None:
        """Test posting a subject with no common name and no subject alternative name."""
        cert_count = Certificate.objects.all().count()
        error_msg = "Subject Alternative Name is required if the subject does not contain a Common Name."

        with assert_create_cert_signals(False, False):
            response = admin_client.post(
                Certificate.admin_add_url,
                data={
                    **form_data(CSR, usable_root, hostname),
                    "subject": json.dumps([{"oid": NameOID.COUNTRY_NAME.dotted_string, "value": "AT"}]),
                    "subject_alternative_name_0": [],
                    "subject_alternative_name_1": True,
                },
            )
        assert response.status_code == HTTPStatus.OK
        assert response.context["adminform"].form.is_valid() is False
        assert response.context["adminform"].form.errors == {"subject_alternative_name": [error_msg]}
        assert cert_count == Certificate.objects.all().count()

    def test_subject_with_multiple_country_codes(
        self, admin_client: Client, hostname: str, usable_root: CertificateAuthority
    ) -> None:
        """Test creating a certificate with multiple country codes (which is not allowed)."""
        with assert_create_cert_signals(False, False):
            response = admin_client.post(
                Certificate.admin_add_url,
                data={
                    **form_data(CSR, usable_root, hostname),
                    "subject": json.dumps(
                        [
                            {"oid": NameOID.COUNTRY_NAME.dotted_string, "value": "US"},
                            {"oid": NameOID.COUNTRY_NAME.dotted_string, "value": "AT"},
                            {"oid": NameOID.COMMON_NAME.dotted_string, "value": hostname},
                        ]
                    ),
                },
            )
        assert response.context["adminform"].form.is_valid() is False

        msg = "Value error, attribute of type countryName must not occur more then once in a name."
        assert response.context["adminform"].form.errors == {"subject": [msg]}

    def test_subject_with_invalid_country_code(
        self, admin_client: Client, hostname: str, usable_root: CertificateAuthority
    ) -> None:
        """Test creating a certificate with an invalid country code."""
        with assert_create_cert_signals(False, False):
            response = admin_client.post(
                Certificate.admin_add_url,
                data={
                    **form_data(CSR, usable_root, hostname),
                    "subject": json.dumps(
                        [
                            {"oid": NameOID.COUNTRY_NAME.dotted_string, "value": "FOO"},
                            {"oid": NameOID.COMMON_NAME.dotted_string, "value": hostname},
                        ]
                    ),
                },
            )
        assert response.status_code == HTTPStatus.OK
        assert not response.context["adminform"].form.is_valid()
        assert response.context["adminform"].form.errors == {
            "subject": ["Value error, FOO: Must have exactly two characters"]
        }

    def test_add_no_key_usage(
        self, admin_client: Client, hostname: str, usable_root: CertificateAuthority
    ) -> None:
        """Test adding a cert with no (extended) key usage."""
        with assert_create_cert_signals():
            response = admin_client.post(
                Certificate.admin_add_url,
                data={**form_data(CSR, usable_root, hostname), "key_usage_0": []},
            )
        assertRedirects(response, Certificate.admin_changelist_url)

        cert = Certificate.objects.get(cn=hostname)
        assert ExtensionOID.KEY_USAGE not in cert.extensions  # KeyUsage is not set!

    def test_add_with_password(
        self,
        settings: SettingsWrapper,
        admin_client: Client,
        hostname: str,
        usable_pwd: CertificateAuthority,
    ) -> None:
        """Test adding with a password."""
        settings.CA_PASSWORDS = {}

        # first post without password
        with assert_create_cert_signals(False, False):
            response = admin_client.post(Certificate.admin_add_url, data=form_data(CSR, usable_pwd, hostname))
        assert response.context["adminform"].form.is_valid() is False
        assert response.context["adminform"].form.errors == {
            "password": ["Certificate authority is not usable."]
        }

        # now post with a wrong password
        with assert_create_cert_signals(False, False):
            response = admin_client.post(
                Certificate.admin_add_url, data={**form_data(CSR, usable_pwd, hostname), "password": "wrong"}
            )
        assert response.context["adminform"].form.is_valid() is False
        assert response.context["adminform"].form.errors == {
            "password": ["Certificate authority is not usable."]
        }

        # post with correct password!
        with assert_create_cert_signals() as (pre, post):
            response = admin_client.post(
                Certificate.admin_add_url,
                data={
                    **form_data(CSR, usable_pwd, hostname),
                    "password": CERT_DATA["pwd"]["password"].decode("utf-8"),
                },
            )
        assertRedirects(response, Certificate.admin_changelist_url)

        cert = Certificate.objects.get(cn=hostname)
        assert_post_issue_cert(post, cert)
        assert cert.pub.loaded.subject == x509.Name(
            [
                x509.NameAttribute(oid=NameOID.COUNTRY_NAME, value="US"),
                x509.NameAttribute(oid=NameOID.COMMON_NAME, value=hostname),
            ]
        )
        assert usable_pwd.subject == cert.issuer
        assert_authority_key_identifier(usable_pwd, cert)
        assert cert.ca == usable_pwd
        assert cert.csr.pem == CSR

        # Some extensions are not set
        assert ExtensionOID.ISSUER_ALTERNATIVE_NAME not in cert.extensions
        assert ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS not in cert.extensions

    def test_add_with_password_with_ca_passwords(
        self,
        settings: SettingsWrapper,
        admin_client: Client,
        hostname: str,
        usable_pwd: CertificateAuthority,
    ) -> None:
        """Test adding with a password with the CA_PASSWORDS setting."""
        settings.CA_PASSWORDS = {usable_pwd.serial: CERT_DATA["pwd"]["password"]}

        # post with correct password!
        with assert_create_cert_signals() as (pre, post):
            response = admin_client.post(Certificate.admin_add_url, data=form_data(CSR, usable_pwd, hostname))
        assertRedirects(response, Certificate.admin_changelist_url)

        cert = Certificate.objects.get(cn=hostname)
        assert_post_issue_cert(post, cert)
        assert cert.pub.loaded.subject == x509.Name([country("US"), cn(hostname)])
        assert usable_pwd.subject == cert.issuer
        assert_authority_key_identifier(usable_pwd, cert)
        assert cert.ca == usable_pwd
        assert cert.csr.pem == CSR

        # Some extensions are not set
        assert ExtensionOID.ISSUER_ALTERNATIVE_NAME not in cert.extensions
        assert ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS not in cert.extensions

        # Test that we can view the certificate
        response = admin_client.get(cert.admin_change_url)
        assert response.status_code == HTTPStatus.OK

    def test_invalid_csr(
        self, admin_client: Client, hostname: str, usable_root: CertificateAuthority
    ) -> None:
        """Test passing an unparsable CSR."""
        with assert_create_cert_signals(False, False):
            response = admin_client.post(
                Certificate.admin_add_url, data=form_data("whatever", usable_root, hostname)
            )
        assert response.status_code == HTTPStatus.OK
        assert not response.context["adminform"].form.is_valid()
        assert response.context["adminform"].form.errors == {
            "csr": [CertificateSigningRequestField.simple_validation_error]
        }

    def test_unparsable_csr(
        self, admin_client: Client, hostname: str, usable_root: CertificateAuthority
    ) -> None:
        """Test passing something that looks like a CSR but isn't.

        This is different from test_wrong_csr() because this passes our initial test, but cryptography itself
        fails to load the CSR.
        """
        with assert_create_cert_signals(False, False):
            response = admin_client.post(
                Certificate.admin_add_url,
                data=form_data(
                    "-----BEGIN CERTIFICATE REQUEST-----\nwrong-----END CERTIFICATE REQUEST-----",
                    usable_root,
                    hostname,
                ),
            )
        assert response.status_code == HTTPStatus.OK, response.content
        assert not response.context["adminform"].form.is_valid()

        # Not testing exact error message here, as it the one from cryptography. Instead, just check that
        # there is exactly one message for the "csr" field.
        form = response.context["adminform"].form
        assert len(form.errors) == 1, form.errors
        assert len(form.errors["csr"]) == 1, form.errors["csr"]

    def test_not_after_in_the_past(
        self, admin_client: Client, hostname: str, usable_root: CertificateAuthority
    ) -> None:
        """Test creating a cert that not_after in the past."""
        expires = datetime.now() - timedelta(days=3)

        with assert_create_cert_signals(False, False):
            response = admin_client.post(
                Certificate.admin_add_url,
                data={**form_data(CSR, usable_root, hostname), "not_after": expires.strftime("%Y-%m-%d")},
            )
        assert response.status_code == HTTPStatus.OK
        assert "Certificate cannot expire in the past." in response.content.decode("utf-8")
        assert not response.context["adminform"].form.is_valid()
        assert response.context["adminform"].form.errors == {
            "not_after": ["Certificate cannot expire in the past."]
        }

        with pytest.raises(Certificate.DoesNotExist):
            Certificate.objects.get(cn=hostname)

    def test_expires_too_late(
        self, admin_client: Client, hostname: str, usable_root: CertificateAuthority
    ) -> None:
        """Test that creating a cert that not_after after the CA not_after throws an error."""
        expires = usable_root.not_after + timedelta(days=3)
        correct_expires = usable_root.not_after.strftime("%Y-%m-%d")
        error = f"CA not_after on {correct_expires}, certificate must not expire after that."

        with assert_create_cert_signals(False, False):
            response = admin_client.post(
                Certificate.admin_add_url,
                data={**form_data(CSR, usable_root, hostname), "not_after": expires.strftime("%Y-%m-%d")},
            )
        assert response.status_code == HTTPStatus.OK
        assert error in response.content.decode("utf-8")
        assert not response.context["adminform"].form.is_valid()
        assert response.context["adminform"].form.errors == {"not_after": [error]}

        with pytest.raises(Certificate.DoesNotExist):
            Certificate.objects.get(cn=hostname)

    def test_invalid_signature_hash_algorithm_with_ed(
        self,
        admin_client: Client,
        hostname: str,
        usable_ed448: CertificateAuthority,
    ) -> None:
        """Test adding a certificate with an invalid signature hash algorithm."""
        csr = CERT_DATA["ed448-cert"]["csr"]["parsed"].public_bytes(Encoding.PEM).decode("utf-8")
        with assert_create_cert_signals(False, False):
            response = admin_client.post(
                Certificate.admin_add_url, data=form_data(csr, usable_ed448, hostname, "SHA-256")
            )
        assert not response.context["adminform"].form.is_valid(), response
        assert response.context["adminform"].form.errors == {
            "algorithm": ["Ed448-based certificate authorities do not use a signature hash algorithm."]
        }

    def test_invalid_signature_hash_algorithm_with_dsa(
        self, admin_client: Client, hostname: str, usable_dsa: CertificateAuthority
    ) -> None:
        """Test adding a certificate with an invalid signature hash algorithm."""
        # Test with DSA CA
        csr = CERT_DATA["dsa-cert"]["csr"]["parsed"].public_bytes(Encoding.PEM).decode("utf-8")
        with assert_create_cert_signals(False, False):
            response = admin_client.post(
                Certificate.admin_add_url, data=form_data(csr, usable_dsa, hostname, "SHA-512")
            )
        assert not response.context["adminform"].form.is_valid(), response
        assert response.context["adminform"].form.errors == {
            "algorithm": ["DSA-based certificate authorities require a SHA-256 signature hash algorithm."]
        }

    def test_invalid_signature_hash_algorithm_with_rsa(
        self, admin_client: Client, hostname: str, usable_root: CertificateAuthority
    ) -> None:
        """Test adding a certificate with an invalid signature hash algorithm."""
        with assert_create_cert_signals(False, False):
            response = admin_client.post(
                Certificate.admin_add_url, data=form_data(CSR, usable_root, hostname, "")
            )
        assert not response.context["adminform"].form.is_valid(), response
        assert response.context["adminform"].form.errors == {
            "algorithm": ["RSA-based certificate authorities require a signature hash algorithm."]
        }

    def test_certificate_policies_with_invalid_oid(
        self, admin_client: Client, hostname: str, usable_root: CertificateAuthority
    ) -> None:
        """Test posting a certificate policies extension with an invalid OID."""
        with assert_create_cert_signals(False, False):
            response = admin_client.post(
                Certificate.admin_add_url,
                data={
                    "csr": CSR,
                    "ca": usable_root.pk,
                    "profile": "webserver",
                    "subject": json.dumps(
                        [
                            {"oid": NameOID.COUNTRY_NAME.dotted_string, "value": "US"},
                            {"oid": NameOID.COMMON_NAME.dotted_string, "value": hostname},
                        ]
                    ),
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA-256",
                    "not_after": usable_root.not_after.strftime("%Y-%m-%d"),
                    "certificate_policies_0": "abc",
                },
            )
        assert response.status_code == HTTPStatus.OK
        assert not response.context["adminform"].form.is_valid()
        assert response.context["adminform"].form.errors == {
            "certificate_policies": ["abc: The given OID is invalid."]
        }

    def test_add_unusable_cas(
        self, admin_client: Client, hostname: str, usable_root: CertificateAuthority
    ) -> None:
        """Try adding with an unusable CA."""
        usable_root.key_backend_options = {"path": "not/exist/add-unusable-cas"}
        usable_root.save()

        with assert_create_cert_signals(False, False):
            response = admin_client.post(
                Certificate.admin_add_url, data=form_data(CSR, usable_root, hostname)
            )
        assert response.status_code == HTTPStatus.FORBIDDEN


@pytest.mark.selenium
class ProfileFieldSeleniumTestCase(CertificateModelAdminTestCaseMixin, SeleniumTestCase):
    """Some Selenium based test cases to test the client side javascript code."""

    load_cas = "__usable__"

    def get_expected(
        self, profile: Profile, oid: x509.ObjectIdentifier, default: Any = None
    ) -> SerializedPydanticExtension:
        """Get expected value for a given extension for the given profile."""
        model_class = EXTENSION_MODELS[oid]
        if oid in profile.extensions:
            model = model_class.model_validate(profile.extensions[oid])
            return model.model_dump()
        return {
            "type": END_ENTITY_CERTIFICATE_EXTENSION_KEYS[oid],
            "value": default,
            "critical": EXTENSION_DEFAULT_CRITICAL[oid],
        }

    def assertProfile(  # pylint: disable=invalid-name
        self,
        profile_name: str,
        ku_select: Select,
        ku_critical: WebElement,
        eku_select: Select,
        eku_critical: WebElement,
        tf_select: Select,
        tf_critical: WebElement,
    ) -> None:
        """Assert that the admin form equals the given profile."""
        profile = profiles[profile_name]

        ku_expected = self.get_expected(profile, ExtensionOID.KEY_USAGE, [])
        ku_selected = [o.get_attribute("value") for o in ku_select.all_selected_options]
        assert_count_equal(ku_expected["value"], ku_selected)
        assert ku_expected["critical"] == ku_critical.is_selected()

        eku_expected = self.get_expected(profile, ExtensionOID.EXTENDED_KEY_USAGE, [])
        eku_selected = [o.get_attribute("value") for o in eku_select.all_selected_options]
        assert_count_equal(eku_expected["value"], eku_selected)
        assert eku_expected["critical"] == eku_critical.is_selected()

        tf_selected = [o.get_attribute("value") for o in tf_select.all_selected_options]
        tf_expected = self.get_expected(profile, ExtensionOID.TLS_FEATURE, [])
        assert_count_equal(tf_expected.get("value", []), tf_selected)
        assert tf_expected.get("critical", False) == tf_critical.is_selected()

    def clear_form(
        self,
        ku_select: Select,
        ku_critical: WebElement,
        eku_select: Select,
        eku_critical: WebElement,
        tf_select: Select,
        tf_critical: WebElement,
    ) -> None:
        """Clear the form."""
        try:
            self.find("fieldset.collapsed h2 a.collapse-toggle").click()
        except NoSuchElementException:  # fieldset is already shown
            pass

        ku_select.deselect_all()
        eku_select.deselect_all()
        tf_select.deselect_all()

        if ku_critical.is_selected():
            ku_critical.click()
        if eku_critical.is_selected():
            eku_critical.click()
        if tf_critical.is_selected():
            tf_critical.click()

    @override_tmpcadir()
    def test_select_profile(self) -> None:
        """Test that selecting the profile modifies the extensions."""
        self.login()

        self.selenium.get(f"{self.live_server_url}{Certificate.admin_add_url}")

        # Open the collapsed fieldset to make sure that fields are in view
        self.find("fieldset.x509-extensions").click()

        select = Select(self.find("select#id_profile"))
        ku_select = Select(self.find("select#id_key_usage_0"))
        ku_critical = self.find("input#id_key_usage_1")
        eku_select = Select(self.find("select#id_extended_key_usage_0"))
        eku_critical = self.find("input#id_extended_key_usage_1")
        tf_select = Select(self.find("select#id_tls_feature_0"))
        tf_critical = self.find("input#id_tls_feature_1")

        # test that the default profile is preselected
        assert [model_settings.CA_DEFAULT_PROFILE] == [
            o.get_attribute("value") for o in select.all_selected_options
        ]

        # assert that the values from the default profile are preloaded
        self.assertProfile(
            model_settings.CA_DEFAULT_PROFILE,
            ku_select,
            ku_critical,
            eku_select,
            eku_critical,
            tf_select,
            tf_critical,
        )

        for option in select.options:
            # first, clear everything to make sure that the profile *sets* everything
            self.clear_form(ku_select, ku_critical, eku_select, eku_critical, tf_select, tf_critical)

            value = option.get_attribute("value")
            if not value:
                continue
            option.click()

            self.assertProfile(
                value, ku_select, ku_critical, eku_select, eku_critical, tf_select, tf_critical
            )

            # Set all options to make sure that selected values are *unset* too
            for ext_select in [ku_select, eku_select, tf_select]:
                for opt in ext_select.options:
                    ext_value = opt.get_attribute("value")
                    if not ext_value:  # should not happen, just to be sure (also makes mypy happy)
                        raise ValueError("option was not set.")

                    ext_select.select_by_value(ext_value)

            if not ku_critical.is_selected():
                ku_critical.click()
            if not eku_critical.is_selected():
                eku_critical.click()
            if not tf_critical.is_selected():
                tf_critical.click()

            # select empty element in profile select, then select profile again
            select.select_by_value(model_settings.CA_DEFAULT_PROFILE)
            self.clear_form(ku_select, ku_critical, eku_select, eku_critical, tf_select, tf_critical)
            option.click()

            # see that all the right things are selected
            self.assertProfile(
                value,
                ku_select,
                ku_critical,
                eku_select,
                eku_critical,
                tf_select,
                tf_critical,
            )


@pytest.mark.selenium
class SubjectFieldSeleniumTestCase(AddCertificateSeleniumTestCase):
    """Test the Subject input field."""

    def send_csr_keys(self, csr: x509.CertificateSigningRequest) -> None:
        """Send a CSR to the CSR input field. See inline comments for extra function rationale."""
        # IMPORTANT: Always strip CSRs, as send_keys() sends it character by character. If the CSR has a final
        #   newline, it sends the request twice. Since everything is asynchronous, the requests run in
        #   parallel, causing transient test errors, as documented here:
        #       https://docs.djangoproject.com/en/dev/topics/testing/tools/#liveservertestcase

        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode().strip()
        self.find("textarea#id_csr").send_keys(csr_pem)

    @override_tmpcadir(
        CA_PROFILES={
            "webserver": {"subject": [{"oid": "C", "value": "AT"}, {"oid": "ST", "value": "Vienna"}]}
        }
    )
    def test_subject_field(self) -> None:
        """Test core functionality of the subject field."""
        self.initialize()

        # Expected initial subject based on the CA_PROFILES setting set in the decorator
        expected_initial_subject = [
            {"oid": NameOID.COUNTRY_NAME.dotted_string, "value": "AT"},
            {"oid": NameOID.STATE_OR_PROVINCE_NAME.dotted_string, "value": "Vienna"},
        ]

        # Test the initial state
        assert self.value == expected_initial_subject
        assert self.displayed_value == expected_initial_subject

        # Add a row and confirm that it's initially empty and the field is thus not yet modified
        self.key_value_field.find_element(By.CLASS_NAME, "add-row-btn").click()
        self.assertNotModified()
        new_select = Select(self.key_value_list.find_elements(By.CSS_SELECTOR, "select")[-1])
        new_input = self.key_value_list.find_elements(By.CSS_SELECTOR, "input")[-1]
        assert new_select.all_selected_options == []
        assert new_input.get_attribute("value") == ""

        # Enter a value. This marks the field as modified, but the hidden input is *not* updated, as there is
        # no key/OID selected yet
        new_input.send_keys(self.hostname)
        self.assertModified()
        assert self.value == expected_initial_subject

        # Now select common name, and the subject is also updated
        new_select.select_by_value(NameOID.COMMON_NAME.dotted_string)
        new_subject = [
            *expected_initial_subject,
            {"oid": NameOID.COMMON_NAME.dotted_string, "value": self.hostname},
        ]
        assert self.value == new_subject
        assert self.displayed_value == new_subject  # just to be sure

        # Remove the second row, check the update
        self.key_value_list.find_elements(By.CSS_SELECTOR, ".remove-row-btn")[1].click()
        new_subject.pop(1)
        assert len(new_subject) == 2
        assert self.value == new_subject
        assert self.displayed_value == new_subject

    @override_tmpcadir()
    def test_csr_integration(self) -> None:
        """Test that pasting a CSR shows text next to subject input fields."""
        self.initialize()

        initial_subject = [
            {"oid": "2.5.4.6", "value": "AT"},
            {"oid": "2.5.4.8", "value": "Vienna"},
            {"oid": "2.5.4.7", "value": "Vienna"},
            {"oid": "2.5.4.10", "value": "Django CA"},
            {"oid": "2.5.4.11", "value": "Django CA Testsuite"},
        ]
        csr_subject = [
            {"oid": "2.5.4.6", "value": "AT"},
            {"oid": "2.5.4.8", "value": "csr.Vienna"},
            {"oid": "2.5.4.7", "value": "csr.Vienna"},
            {"oid": "2.5.4.10", "value": "csr.Example"},
            {"oid": "2.5.4.11", "value": "csr.Example OU"},
            {"oid": "2.5.4.3", "value": "csr.all-extensions.example.com"},
            {"oid": "1.2.840.113549.1.9.1", "value": "csr.user@example.com"},
        ]

        # Elements of the CSR chapter
        csr_subject_input_chapter = self.key_value_field.find_element(
            By.CSS_SELECTOR, ".subject-input-chapter.csr"
        )
        no_csr = self.key_value_field.find_element(By.CSS_SELECTOR, ".subject-input-chapter.csr .no-csr")
        has_content = self.key_value_field.find_element(
            By.CSS_SELECTOR, ".subject-input-chapter.csr .has-content"
        )
        no_content = self.key_value_field.find_element(
            By.CSS_SELECTOR, ".subject-input-chapter.csr .no-content"
        )

        # Check that the right parts of the CSR chapter is displayed
        assert no_csr.is_displayed() is True  # this is displayed as we haven't pasted a CSR
        assert has_content.is_displayed() is False
        assert no_content.is_displayed() is False

        # Send the CSR to the input field.
        self.send_csr_keys(CERT_DATA["all-extensions"]["csr"]["parsed"])

        # Make sure that the displayed subject has not changed
        self.assertNotModified()
        assert self.value == initial_subject

        # Wait for the CSR results to be fetched
        WebDriverWait(self.selenium, 3, poll_frequency=0.1).until(
            lambda driver: driver.find_element(By.ID, "id_csr").get_attribute("data-fetched") == "true",
            "data-fetched for CSR was not set.",
        )

        # check the JSON value from the chapter
        value: str = csr_subject_input_chapter.get_attribute("data-value")  # type: ignore[assignment]
        assert json.loads(value) == csr_subject

        # check that the right chapter is displayed
        assert no_csr.is_displayed() is False
        assert has_content.is_displayed() is True
        assert no_content.is_displayed() is False

        # Check the li element inside
        lis = has_content.find_elements(By.TAG_NAME, "li")
        assert len(lis) == len(csr_subject)
        assert lis[0].text == "countryName (C): AT"  # just testing the first one

        # Click the copy button and validate that the subject is set
        csr_subject_input_chapter.find_element(By.CSS_SELECTOR, ".copy-button").click()
        self.assertModified()
        assert self.value == csr_subject
        assert self.displayed_value == csr_subject

    @override_tmpcadir()
    def test_paste_csr_no_subject(self) -> None:
        """Test that pasting a CSR shows text next to subject input fields."""
        self.initialize()

        # Create a CSR with no subject
        key = CERT_DATA["all-extensions"]["key"]["parsed"]
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).sign(key, hashes.SHA256())

        # Elements of the CSR chapter
        csr_chapter = self.key_value_field.find_element(By.CSS_SELECTOR, ".subject-input-chapter.csr")
        no_csr = csr_chapter.find_element(By.CSS_SELECTOR, ".no-csr")
        has_content = csr_chapter.find_element(By.CSS_SELECTOR, ".has-content")
        no_content = csr_chapter.find_element(By.CSS_SELECTOR, ".no-content")

        # Send the CSR to the input field.
        self.send_csr_keys(csr)

        # Wait for the CSR results to be fetched
        WebDriverWait(self.selenium, 3, poll_frequency=0.1).until(
            lambda driver: driver.find_element(By.ID, "id_csr").get_attribute("data-fetched") == "true",
            "data-fetched for CSR was not set.",
        )

        # Check that the right parts of the CSR chapter is displayed
        assert no_csr.is_displayed() is False
        assert has_content.is_displayed() is False
        assert no_content.is_displayed() is True
        self.assertNotModified()

        # Click the clear button and validate that the subject is cleared
        csr_chapter.find_element(By.CSS_SELECTOR, ".clear-button").click()
        self.assertModified()
        assert self.value == []
        assert self.displayed_value == []

    @override_tmpcadir()
    def test_paste_csr_missing_delimiters(self) -> None:
        """Test that pasting a CSR shows text next to subject input fields."""
        self.initialize()

        csr: x509.CertificateSigningRequest = CERT_DATA["all-extensions"]["csr"]["parsed"]
        csr_field = self.find("textarea#id_csr")

        # Elements of the CSR chapter
        chapter = self.key_value_field.find_element(By.CSS_SELECTOR, ".subject-input-chapter.csr")
        no_csr = chapter.find_element(By.CSS_SELECTOR, ".no-csr")
        has_content = chapter.find_element(By.CSS_SELECTOR, ".has-content")
        no_content = chapter.find_element(By.CSS_SELECTOR, ".no-content")

        # send all but the first character to the CSR input field
        csr_field.send_keys(csr.public_bytes(Encoding.PEM).decode("ascii")[1:])

        # Check that the right parts of the CSR chapter is displayed
        assert no_csr.is_displayed() is True  # this is displayed as we haven't pasted a CSR
        assert has_content.is_displayed() is False
        assert no_content.is_displayed() is False
        self.assertNotModified()

    @override_tmpcadir()
    def test_paste_invalid_csr(self) -> None:
        """Test that pasting a CSR shows text next to subject input fields."""
        self.initialize()

        csr = self.find("textarea#id_csr")

        # Elements of the CSR chapter
        chapter = self.key_value_field.find_element(By.CSS_SELECTOR, ".subject-input-chapter.csr")
        no_csr = chapter.find_element(By.CSS_SELECTOR, ".no-csr")
        has_content = chapter.find_element(By.CSS_SELECTOR, ".has-content")
        no_content = chapter.find_element(By.CSS_SELECTOR, ".no-content")

        # send all but the first character to the CSR input field
        csr.send_keys("-----BEGIN CERTIFICATE REQUEST-----\nXXX\n-----END CERTIFICATE REQUEST-----")

        # Check that the right parts of the CSR chapter is displayed
        assert no_csr.is_displayed() is True  # this is displayed as we haven't pasted a CSR
        assert has_content.is_displayed() is False
        assert no_content.is_displayed() is False
        self.assertNotModified()

    @override_tmpcadir(
        CA_DEFAULT_PROFILE="webserver",
        CA_DEFAULT_SUBJECT=[],
        CA_PROFILES={
            "webserver": {
                "subject": [
                    {"oid": "C", "value": "AT"},
                    {"oid": "ST", "value": "Vienna"},
                    {"oid": "OU", "value": "webserver"},
                ]
            },
            "client": {
                "subject": [
                    {"oid": "C", "value": "AT"},
                    {"oid": "ST", "value": "Vienna"},
                    {"oid": "OU", "value": "client"},
                ]
            },
            "no-subject": {},
        },
    )
    def test_profile_integration(self) -> None:
        """Test core functionality of the subject field."""
        self.initialize()

        # Expected initial subject based on the CA_PROFILES setting set in the decorator
        webserver_subject = [
            {"oid": NameOID.COUNTRY_NAME.dotted_string, "value": "AT"},
            {"oid": NameOID.STATE_OR_PROVINCE_NAME.dotted_string, "value": "Vienna"},
            {"oid": NameOID.ORGANIZATIONAL_UNIT_NAME.dotted_string, "value": "webserver"},
        ]
        client_subject = [
            {"oid": NameOID.COUNTRY_NAME.dotted_string, "value": "AT"},
            {"oid": NameOID.STATE_OR_PROVINCE_NAME.dotted_string, "value": "Vienna"},
            {"oid": NameOID.ORGANIZATIONAL_UNIT_NAME.dotted_string, "value": "client"},
        ]

        # Elements of the profile chapter
        chapter = self.key_value_field.find_element(By.CSS_SELECTOR, ".subject-input-chapter.profile")
        has_content = chapter.find_element(By.CSS_SELECTOR, ".has-content")
        no_content = chapter.find_element(By.CSS_SELECTOR, ".no-content")

        # Test the initial state (webserver subject, since it's the default profile
        self.assertNotModified()
        self.assertChapterHasValue(chapter, webserver_subject)
        assert self.value == webserver_subject
        assert self.displayed_value == webserver_subject
        assert has_content.is_displayed() is True
        assert no_content.is_displayed() is False

        profile_select = Select(self.selenium.find_element(By.ID, "id_profile"))

        # Select the different profile. Since the field is not yet modified, new values are taken
        profile_select.select_by_value("client")
        self.assertNotModified()
        self.assertChapterHasValue(chapter, client_subject)
        assert self.value == client_subject
        assert self.displayed_value == client_subject
        assert has_content.is_displayed() is True
        assert no_content.is_displayed() is False

        # Change one field and check modification
        st_input = self.key_value_list.find_elements(By.CSS_SELECTOR, "input")[1]
        st_input.clear()
        st_input.send_keys("Styria")
        new_subject = deepcopy(client_subject)
        new_subject[1]["value"] = "Styria"
        self.assertModified()
        assert self.value == new_subject
        assert self.displayed_value == new_subject

        # Switch back to the old profile. Since you made changes, it's not automatically updated
        profile_select.select_by_value("webserver")
        self.assertModified()
        self.assertChapterHasValue(chapter, webserver_subject)
        assert self.value == new_subject
        assert self.displayed_value == new_subject

        # Copy the profile subject and check the state
        chapter.find_element(By.CLASS_NAME, "copy-button").click()
        self.assertNotModified()
        self.assertChapterHasValue(chapter, webserver_subject)
        assert self.value == webserver_subject
        assert self.displayed_value == webserver_subject
        assert has_content.is_displayed() is True
        assert no_content.is_displayed() is False

        # Modify subject again (so that we can check the modified flag of the clear button)
        st_input = self.key_value_list.find_elements(By.CSS_SELECTOR, "input")[1]
        st_input.clear()
        st_input.send_keys("Styria")
        new_subject[2]["value"] = "webserver"
        self.assertModified()
        assert self.value == new_subject
        assert self.displayed_value == new_subject

        # Switch to the profile with no subject and check the state
        profile_select.select_by_value("no-subject")
        self.assertModified()
        self.assertChapterHasValue(chapter, [])
        assert self.value == new_subject
        assert self.displayed_value == new_subject
        assert has_content.is_displayed() is False
        assert no_content.is_displayed() is True

        # Click the clear button
        chapter.find_element(By.CLASS_NAME, "clear-button").click()
        self.assertNotModified()
        self.assertChapterHasValue(chapter, [])
        assert self.value == []
        assert self.displayed_value == []


class TestAddCertificateWebTest:
    """Tests for adding certificates."""

    def test_only_ca_prefill(
        self,
        django_app: DjangoTestApp,
        admin_user: User,
        settings: SettingsWrapper,
        hostname: str,
        usable_root: CertificateAuthority,
    ) -> None:
        """Create a cert with an empty profile.

        This test shows that the values from the CA are prefilled correctly. If they were not, some fields
        would not show up in the signed certificate.
        """
        settings.CA_PROFILES = {"nothing": {}}
        settings.CA_DEFAULT_PROFILE = "nothing"
        # Make sure that the CA has field values set.
        # CertificateAuthority.objects.exclude(id=self.ca.id).delete()
        assert usable_root.sign_authority_information_access is not None
        assert usable_root.sign_crl_distribution_points is not None
        usable_root.sign_certificate_policies = certificate_policies(
            x509.PolicyInformation(
                policy_identifier=x509.ObjectIdentifier("1.2.3"),
                policy_qualifiers=[
                    "https://cps.example.com",
                    x509.UserNotice(notice_reference=None, explicit_text="explicit-text"),
                ],
            )
        )
        usable_root.sign_issuer_alternative_name = issuer_alternative_name(
            uri("http://issuer-alt-name.test-only-ca.example.com")
        )
        usable_root.save()

        response = django_app.get(Certificate.admin_add_url, user=admin_user.username)
        assert response.status_code == HTTPStatus.OK

        form = response.forms["certificate_form"]
        form["csr"] = CSR
        form["subject"] = json.dumps([{"oid": NameOID.COMMON_NAME.dotted_string, "value": hostname}])
        form["subject_alternative_name_0"] = json.dumps([{"type": "DNS", "value": hostname}])
        response = form.submit().follow()
        assert response.status_code == HTTPStatus.OK

        # Check that we get all the extensions from the CA
        cert: Certificate = Certificate.objects.get(cn=hostname)
        assert cert.ca == usable_root
        assert cert.sorted_extensions == [
            cert.ca.sign_authority_information_access,
            cert.ca.get_authority_key_identifier_extension(),
            basic_constraints(),
            cert.ca.sign_crl_distribution_points,
            usable_root.sign_certificate_policies,
            usable_root.sign_issuer_alternative_name,
            subject_alternative_name(dns(hostname)),
            subject_key_identifier(cert),
        ]

    def test_full_profile_prefill(
        self,
        django_app: DjangoTestApp,
        admin_user: User,
        settings: SettingsWrapper,
        hostname: str,
        usable_root: CertificateAuthority,
    ) -> None:
        """Create a cert with a full profile, which should mask any CA-specific values.

        This test shows that the values from the profile are prefilled correctly. If they were not, some
        fields would not show up in the signed certificate.
        """
        settings.CA_PROFILES = {
            "everything": {
                "extensions": {
                    "authority_information_access": {
                        "critical": False,
                        "value": [
                            {
                                "access_method": "ocsp",
                                "access_location": {
                                    "type": "URI",
                                    "value": "http://profile.ocsp.example.com",
                                },
                            },
                            {
                                "access_method": "ocsp",
                                "access_location": {
                                    "type": "URI",
                                    "value": "http://profile.ocsp-backup.example.com",
                                },
                            },
                            {
                                "access_method": "ca_issuers",
                                "access_location": {
                                    "type": "URI",
                                    "value": "http://profile.issuers.example.com",
                                },
                            },
                        ],
                    },
                    "certificate_policies": {
                        "critical": True,
                        "value": [
                            {
                                "policy_identifier": CertificatePoliciesOID.CPS_USER_NOTICE.dotted_string,
                                "policy_qualifiers": ["text1"],
                            },
                        ],
                    },
                    "crl_distribution_points": {
                        "critical": True,
                        "value": [
                            {
                                "full_name": [{"type": "URI", "value": "http://crl.profile.example.com"}],
                                "crl_issuer": [
                                    {"type": "URI", "value": "http://crl-issuer.profile.example.com"}
                                ],
                            },
                        ],
                    },
                    "extended_key_usage": {
                        "critical": True,
                        "value": ["clientAuth", "serverAuth"],
                    },
                    "freshest_crl": {
                        "critical": False,
                        "value": [
                            {
                                "full_name": [
                                    {"type": "URI", "value": "http://freshest-crl.profile.example.com"}
                                ],
                                "crl_issuer": [
                                    {
                                        "type": "URI",
                                        "value": "http://freshest-crl-issuer.profile.example.com",
                                    }
                                ],
                            }
                        ],
                    },
                    "issuer_alternative_name": {
                        "critical": True,
                        "value": [
                            {"type": "URI", "value": "http://ian1.example.com"},
                            {"type": "URI", "value": "http://ian2.example.com"},
                        ],
                    },
                    "key_usage": {
                        "critical": True,
                        "value": ["key_agreement", "key_cert_sign"],
                    },
                    "ocsp_no_check": {"critical": True},
                    "tls_feature": {"critical": True, "value": ["OCSPMustStaple"]},
                }
            }
        }

        settings.CA_DEFAULT_PROFILE = "everything"

        # Make sure that the CA has sign_* field values set.
        assert usable_root.sign_authority_information_access is not None
        assert usable_root.sign_crl_distribution_points is not None
        usable_root.sign_certificate_policies = certificate_policies(
            x509.PolicyInformation(
                policy_identifier=CertificatePoliciesOID.CPS_QUALIFIER, policy_qualifiers=None
            )
        )
        usable_root.sign_issuer_alternative_name = issuer_alternative_name(
            uri("http://issuer-alt-name.test-only-ca.example.com")
        )
        usable_root.save()

        response = django_app.get(Certificate.admin_add_url, user=admin_user.username)
        form = response.forms["certificate_form"]
        # default value for form field is on import time, so override settings does not change
        # profile field
        form["profile"] = "everything"
        form["csr"] = CSR
        form["subject"] = json.dumps([{"oid": NameOID.COMMON_NAME.dotted_string, "value": hostname}])
        response = form.submit().follow()
        assert response.status_code == 200

        # Check that we get all the extensions from the CA
        cert = Certificate.objects.get(cn=hostname)
        assert cert.profile == "everything"
        assert cert.sorted_extensions == [
            authority_information_access(
                ca_issuers=[uri("http://profile.issuers.example.com")],
                ocsp=[uri("http://profile.ocsp.example.com"), uri("http://profile.ocsp-backup.example.com")],
                critical=False,
            ),
            cert.ca.get_authority_key_identifier_extension(),
            basic_constraints(),
            crl_distribution_points(
                distribution_point(
                    full_name=[uri("http://crl.profile.example.com")],
                    crl_issuer=[uri("http://crl-issuer.profile.example.com")],
                ),
                critical=True,
            ),
            certificate_policies(
                x509.PolicyInformation(
                    policy_identifier=CertificatePoliciesOID.CPS_USER_NOTICE, policy_qualifiers=["text1"]
                ),
                critical=True,
            ),
            extended_key_usage(
                ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH, critical=True
            ),
            freshest_crl(
                distribution_point(
                    full_name=[uri("http://freshest-crl.profile.example.com")],
                    crl_issuer=[uri("http://freshest-crl-issuer.profile.example.com")],
                ),
                critical=False,
            ),
            issuer_alternative_name(
                uri("http://ian1.example.com"), uri("http://ian2.example.com"), critical=True
            ),
            key_usage(key_agreement=True, key_cert_sign=True),
            ocsp_no_check(critical=True),
            subject_key_identifier(cert),
            tls_feature(x509.TLSFeatureType.status_request, critical=True),
        ]

    @override_tmpcadir(
        CA_PROFILES={
            "everything": {
                "extensions": {
                    "crl_distribution_points": {
                        "critical": True,
                        "value": [
                            {
                                "full_name": [{"type": "URI", "value": "http://crl.profile.example.com"}],
                                "crl_issuer": [
                                    {"type": "URI", "value": "http://crl-issuer.profile.example.com"}
                                ],
                            },
                            {
                                "full_name": [{"type": "URI", "value": "http://crl2.profile.example.com"}],
                                "crl_issuer": [
                                    {"type": "URI", "value": "http://crl-issuer2.profile.example.com"}
                                ],
                            },
                        ],
                    },
                    "freshest_crl": {
                        "critical": False,
                        "value": [
                            {
                                "full_name": [
                                    {"type": "URI", "value": "http://freshest-crl.profile.example.com"}
                                ],
                                "crl_issuer": [
                                    {"type": "URI", "value": "http://freshest-crl-issuer.profile.example.com"}
                                ],
                            }
                        ],
                    },
                }
            }
        },
        CA_DEFAULT_PROFILE="everything",
    )
    def test_multiple_distribution_points(
        self,
        caplog: LogCaptureFixture,
        django_app: DjangoTestApp,
        admin_user: User,
        settings: SettingsWrapper,
        hostname: str,
        usable_root: CertificateAuthority,
    ) -> None:
        """Create a cert with a full profile, which should mask any CA-specific values.

        This test shows that the values from the profile are prefilled correctly. If they were not, some
        fields would not show up in the signed certificate.
        """
        settings.CA_PROFILES = {
            "everything": {
                "extensions": {
                    "crl_distribution_points": {
                        "critical": True,
                        "value": [
                            {
                                "full_name": [{"type": "URI", "value": "http://crl.profile.example.com"}],
                                "crl_issuer": [
                                    {"type": "URI", "value": "http://crl-issuer.profile.example.com"}
                                ],
                            },
                            {
                                "full_name": [{"type": "URI", "value": "http://crl2.profile.example.com"}],
                                "crl_issuer": [
                                    {"type": "URI", "value": "http://crl-issuer2.profile.example.com"}
                                ],
                            },
                        ],
                    },
                    "freshest_crl": {
                        "critical": False,
                        "value": [
                            {
                                "full_name": [
                                    {"type": "URI", "value": "http://freshest-crl.profile.example.com"}
                                ],
                                "crl_issuer": [
                                    {"type": "URI", "value": "http://freshest-crl-issuer.profile.example.com"}
                                ],
                            }
                        ],
                    },
                }
            }
        }
        settings.CA_DEFAULT_PROFILE = "everything"

        # Make sure that the CA has field values set.
        usable_root.sign_crl_distribution_points = None
        usable_root.sign_authority_information_access = None
        usable_root.save()

        response = django_app.get(Certificate.admin_add_url, user=admin_user.username)
        assert (
            "Received multiple DistributionPoints, only the first can be changed in the web interface."
            in caplog.text
        )

        form = response.forms["certificate_form"]
        # default value for form field is on import time, so override settings does not change
        # profile field
        form["profile"] = "everything"
        form["csr"] = CSR
        form["subject"] = json.dumps([{"oid": NameOID.COMMON_NAME.dotted_string, "value": hostname}])
        response = form.submit()
        response = response.follow()
        assert response.status_code == 200

        # Check that we get all the extensions from the CA
        cert: Certificate = Certificate.objects.get(cn=hostname)
        assert cert.profile == "everything"
        assert cert.sorted_extensions == [
            cert.ca.get_authority_key_identifier_extension(),
            basic_constraints(),
            x509.Extension(
                oid=ExtensionOID.CRL_DISTRIBUTION_POINTS,
                critical=True,
                value=x509.CRLDistributionPoints(
                    [
                        x509.DistributionPoint(
                            full_name=[uri("http://crl.profile.example.com")],
                            relative_name=None,
                            reasons=None,
                            crl_issuer=[uri("http://crl-issuer.profile.example.com")],
                        ),
                        x509.DistributionPoint(
                            full_name=[uri("http://crl2.profile.example.com")],
                            relative_name=None,
                            reasons=None,
                            crl_issuer=[uri("http://crl-issuer2.profile.example.com")],
                        ),
                    ]
                ),
            ),
            freshest_crl(
                distribution_point(
                    [uri("http://freshest-crl.profile.example.com")],
                    crl_issuer=[uri("http://freshest-crl-issuer.profile.example.com")],
                )
            ),
            subject_key_identifier(cert),
        ]

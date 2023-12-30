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

import html
import json
from copy import deepcopy
from datetime import datetime, timedelta, timezone as tz
from http import HTTPStatus
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID, NameOID

from django.test import TestCase

import pytest
from django_webtest import WebTestMixin
from freezegun import freeze_time
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement
from selenium.webdriver.support.select import Select
from selenium.webdriver.support.wait import WebDriverWait
from webtest import Checkbox, Hidden, Select as WebTestSelect, Submit

from django_ca import ca_settings
from django_ca.constants import EXTENSION_DEFAULT_CRITICAL, ExtendedKeyUsageOID
from django_ca.extensions import serialize_extension
from django_ca.fields import CertificateSigningRequestField
from django_ca.models import Certificate, CertificateAuthority
from django_ca.profiles import Profile, profiles
from django_ca.tests.admin.base import AddCertificateSeleniumTestCase, CertificateModelAdminTestCaseMixin
from django_ca.tests.base.assertions import assert_css
from django_ca.tests.base.constants import CERT_DATA, TIMESTAMPS
from django_ca.tests.base.testcases import SeleniumTestCase
from django_ca.tests.base.typehints import HttpResponse
from django_ca.tests.base.utils import (
    authority_information_access,
    basic_constraints,
    certificate_policies,
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
from django_ca.typehints import SerializedExtension
from django_ca.utils import ca_storage


@freeze_time(TIMESTAMPS["after_child"])
class AddCertificateTestCase(CertificateModelAdminTestCaseMixin, TestCase):
    """Tests for adding certificates."""

    load_cas = ("root", "child", "dsa", "ec", "ed25519", "ed448", "pwd")

    def setUp(self) -> None:
        super().setUp()
        self.default_expires = (datetime.now(tz=tz.utc) + self.expires(3)).strftime("%Y-%m-%d")
        self.default_subject = json.dumps(
            [
                {"key": NameOID.COUNTRY_NAME.dotted_string, "value": "US"},
                {"key": NameOID.COMMON_NAME.dotted_string, "value": self.hostname},
            ]
        )

    def add_cert(self, cname: str, ca: CertificateAuthority, algorithm: str = "SHA-256") -> None:
        """Add certificate based on given name with given CA."""
        csr = CERT_DATA["root-cert"]["csr"]["pem"]

        with self.assertCreateCertSignals() as (pre, post):
            response = self.client.post(
                self.add_url,
                data={
                    "csr": csr,
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": json.dumps(
                        [
                            {"key": NameOID.COUNTRY_NAME.dotted_string, "value": "US"},
                            {"key": NameOID.COMMON_NAME.dotted_string, "value": cname},
                        ]
                    ),
                    "subject_alternative_name_1": True,
                    "algorithm": algorithm,
                    "expires": ca.expires.strftime("%Y-%m-%d"),
                    "certificate_policies_0": "1.2.3",
                    "certificate_policies_1": "https://cps.example.com",
                    "certificate_policies_2": "explicit-text",
                    "key_usage_0": [
                        "digital_signature",
                        "key_agreement",
                    ],
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
                    "crl_distribution_points_0": ca.crl_url,
                    "crl_distribution_points_1": "",
                    "crl_distribution_points_2": "",
                    "crl_distribution_points_3": [],
                    "crl_distribution_points_4": False,
                    "authority_information_access_0": ca.issuer_url,
                    "authority_information_access_1": ca.ocsp_url,
                    "authority_information_access_2": False,
                },
            )
        self.assertRedirects(response, self.changelist_url)

        cert = Certificate.objects.get(cn=cname)
        self.assertPostIssueCert(post, cert)
        self.assertEqual(
            cert.pub.loaded.subject,
            x509.Name(
                [
                    x509.NameAttribute(oid=NameOID.COUNTRY_NAME, value="US"),
                    x509.NameAttribute(oid=NameOID.COMMON_NAME, value=cname),
                ]
            ),
        )
        self.assertIssuer(ca, cert)
        self.assertExtensions(
            cert,
            [
                extended_key_usage(ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH),
                key_usage(digital_signature=True, key_agreement=True),
                ocsp_no_check(),
                subject_alternative_name(dns(cname)),
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
        self.assertEqual(cert.ca, ca)
        self.assertEqual(cert.csr.pem, csr)
        self.assertEqual(cert.profile, "webserver")

        # Some extensions are not set
        self.assertNotIn(ExtensionOID.ISSUER_ALTERNATIVE_NAME, cert.x509_extensions)

        # Test that we can view the certificate
        response = self.client.get(cert.admin_change_url)
        self.assertEqual(response.status_code, HTTPStatus.OK)

    def _test_get(self) -> "HttpResponse":
        """Do a basic get request (to test CSS etc)."""
        response = self.client.get(self.add_url)
        self.assertEqual(response.status_code, HTTPStatus.OK)
        templates = [t.name for t in response.templates]
        self.assertIn("admin/django_ca/certificate/change_form.html", templates)
        self.assertIn("admin/change_form.html", templates)
        assert_css(response, "django_ca/admin/css/base.css")
        assert_css(response, "django_ca/admin/css/certificateadmin.css")
        return response

    @override_tmpcadir()
    def test_get(self) -> None:
        """Do a basic get request (to test CSS etc)."""
        self._test_get()

    # @override_settings(CA_PROFILES={}, CA_DEFAULT_SUBJECT=tuple())
    @override_tmpcadir(CA_DEFAULT_SUBJECT=tuple())
    def test_get_dict(self) -> None:
        """Test get with no profiles and no default subject."""
        self._test_get()

    @override_tmpcadir(CA_DEFAULT_SUBJECT=tuple())
    def test_ed448_ca(self) -> None:
        """Test tet with default hash algorithm as none."""
        CertificateAuthority.objects.exclude(name="ed448").delete()
        self._test_get()

    @override_tmpcadir()
    def test_default_ca_key_does_not_exist(self) -> None:
        """Do a basic get request (to test CSS etc)."""
        ca_storage.delete(self.ca.private_key_path)
        response = self.client.get(self.add_url)
        self.assertEqual(response.status_code, HTTPStatus.OK)

        form = response.context_data["adminform"].form  # type: ignore[attr-defined]  # false positive

        field = form.fields["ca"]
        bound_field = field.get_bound_field(form, "ca")
        self.assertNotEqual(bound_field.initial, self.ca)
        self.assertIsInstance(bound_field.initial, CertificateAuthority)

    @override_tmpcadir(CA_DEFAULT_CA=CERT_DATA["child"]["serial"])
    def test_cas_expired(self) -> None:
        """Do a basic get request (to test CSS etc)."""
        self.ca.enabled = False
        self.ca.save()

        with self.assertLogs() as logcm:
            response = self.client.get(self.add_url)
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(
            logcm.output,
            [f"ERROR:django_ca.admin:CA_DEFAULT_CA: {self.ca.serial} is disabled."],
        )

        form = response.context_data["adminform"].form  # type: ignore[attr-defined]  # false positive

        field = form.fields["ca"]
        bound_field = field.get_bound_field(form, "ca")
        self.assertNotEqual(bound_field.initial, self.ca)
        self.assertIsInstance(bound_field.initial, CertificateAuthority)

    @override_tmpcadir(
        CA_PROFILES={"webserver": {"extensions": {"ocsp_no_check": {"critical": True}}}},
        CA_DEFAULT_PROFILE="webserver",
    )
    def test_get_profiles(self) -> None:
        """Test get with no profiles and no default subject."""
        response = self._test_get()
        form = response.context_data["adminform"].form  # type: ignore[attr-defined]  # false positive

        field = form.fields["ocsp_no_check"]
        bound_field = field.get_bound_field(form, "ocsp_no_check")
        self.assertEqual(bound_field.initial, ocsp_no_check(critical=True))

    @override_tmpcadir(CA_DEFAULT_SUBJECT=tuple())
    def test_add(self) -> None:
        """Test to actually add a certificate."""
        self.add_cert("test-child-add.example.com", self.ca)
        self.add_cert("test-root-add.example.com", self.cas["root"])
        self.add_cert("test-dsa-add.example.com", self.cas["dsa"])
        self.add_cert("test-ec-add.example.com", self.cas["ec"])
        self.add_cert("test-ed25519-add.example.com", self.cas["ed25519"], algorithm="")
        self.add_cert("test-ed448-add.example.com", self.cas["ed448"], algorithm="")

    @override_tmpcadir()
    def test_empty_subject(self) -> None:
        """Test passing an empty subject with a subject alternative name."""
        ca = self.cas["root"]
        csr = CERT_DATA["root-cert"]["csr"]["pem"]

        with self.assertCreateCertSignals() as (pre, post):
            response = self.client.post(
                self.add_url,
                data={
                    "csr": csr,
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": "",
                    "subject_alternative_name_0": self.hostname,
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA-256",
                    "expires": ca.expires.strftime("%Y-%m-%d"),
                    "key_usage_0": [
                        "digital_signature",
                        "key_agreement",
                    ],
                    "key_usage_1": True,
                    "extended_key_usage_0": [
                        ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string,
                        ExtendedKeyUsageOID.SERVER_AUTH.dotted_string,
                    ],
                    "extended_key_usage_1": False,
                    "tls_feature_0": ["status_request", "status_request_v2"],
                    "tls_feature_1": False,
                },
            )
        self.assertRedirects(response, self.changelist_url)

        cert: Certificate = Certificate.objects.get(cn="")
        self.assertPostIssueCert(post, cert)
        self.assertEqual(cert.subject, x509.Name([]))
        self.assertEqual(
            cert.x509_extensions[ExtensionOID.SUBJECT_ALTERNATIVE_NAME],
            subject_alternative_name(dns(self.hostname)),
        )

    @override_tmpcadir(CA_DEFAULT_SUBJECT=tuple())
    def test_subject_with_multiple_org_units(self) -> None:
        """Test creating a certificate with multiple Org Units (which is allowed)."""
        ca = self.cas["root"]
        csr = CERT_DATA["root-cert"]["csr"]["pem"]

        with self.assertCreateCertSignals() as (pre, post):
            response = self.client.post(
                self.add_url,
                data={
                    "csr": csr,
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": json.dumps(
                        [
                            {"key": NameOID.COUNTRY_NAME.dotted_string, "value": "US"},
                            {"key": NameOID.ORGANIZATIONAL_UNIT_NAME.dotted_string, "value": "OU-1"},
                            {"key": NameOID.ORGANIZATIONAL_UNIT_NAME.dotted_string, "value": "OU-2"},
                            {"key": NameOID.COMMON_NAME.dotted_string, "value": self.hostname},
                        ]
                    ),
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA-256",
                    "expires": ca.expires.strftime("%Y-%m-%d"),
                    "key_usage_0": [],
                    "key_usage_1": True,
                    "extended_key_usage_0": [],
                    "extended_key_usage_1": False,
                    "tls_feature_0": [],
                    "tls_feature_1": False,
                },
            )
        self.assertRedirects(response, self.changelist_url)

        cert: Certificate = Certificate.objects.get(cn=self.hostname)
        self.assertPostIssueCert(post, cert)
        self.assertEqual(
            cert.subject,
            x509.Name(
                [
                    x509.NameAttribute(oid=NameOID.COUNTRY_NAME, value="US"),
                    x509.NameAttribute(oid=NameOID.ORGANIZATIONAL_UNIT_NAME, value="OU-1"),
                    x509.NameAttribute(oid=NameOID.ORGANIZATIONAL_UNIT_NAME, value="OU-2"),
                    x509.NameAttribute(oid=NameOID.COMMON_NAME, value=self.hostname),
                ]
            ),
        )
        self.assertEqual(
            cert.x509_extensions[ExtensionOID.SUBJECT_ALTERNATIVE_NAME],
            subject_alternative_name(dns(self.hostname)),
        )

    @override_tmpcadir(CA_DEFAULT_SUBJECT=tuple())
    def test_add_no_common_name_and_no_subject_alternative_name(self) -> None:
        """Test posting a subject with no common name and no subject alternative name."""
        ca = self.cas["root"]
        csr = CERT_DATA["root-cert"]["csr"]["pem"]
        cert_count = Certificate.objects.all().count()

        with self.assertCreateCertSignals(False, False):
            response = self.client.post(
                self.add_url,
                data={
                    "csr": csr,
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": json.dumps([{"key": NameOID.COUNTRY_NAME.dotted_string, "value": "AT"}]),
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA-256",
                    "expires": ca.expires.strftime("%Y-%m-%d"),
                    "key_usage_0": [
                        "digital_signature",
                        "key_agreement",
                    ],
                    "key_usage_1": True,
                    "extended_key_usage_0": [
                        ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string,
                        ExtendedKeyUsageOID.SERVER_AUTH.dotted_string,
                    ],
                    "extended_key_usage_1": False,
                    "tls_feature_0": ["status_request", "status_request_v2"],
                    "tls_feature_1": False,
                },
            )
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertFalse(response.context["adminform"].form.is_valid())
        self.assertEqual(
            response.context["adminform"].form.errors,
            {
                "subject_alternative_name": [
                    "Subject Alternative Name is required if the subject does not contain a Common Name."
                ]
            },
        )
        self.assertEqual(cert_count, Certificate.objects.all().count())

    @override_tmpcadir(CA_DEFAULT_SUBJECT=tuple())
    def test_subject_with_multiple_country_codes(self) -> None:
        """Test creating a certificate with multiple country codes (which is not allowed)."""
        ca = self.cas["root"]
        csr = CERT_DATA["root-cert"]["csr"]["pem"]

        with self.assertCreateCertSignals(False, False):
            response = self.client.post(
                self.add_url,
                data={
                    "csr": csr,
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": json.dumps(
                        [
                            {"key": NameOID.COUNTRY_NAME.dotted_string, "value": "US"},
                            {"key": NameOID.COUNTRY_NAME.dotted_string, "value": "AT"},
                            {"key": NameOID.COMMON_NAME.dotted_string, "value": self.hostname},
                        ]
                    ),
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA-256",
                    "expires": ca.expires.strftime("%Y-%m-%d"),
                    "key_usage_0": [],
                    "key_usage_1": True,
                    "extended_key_usage_0": [],
                    "extended_key_usage_1": False,
                    "tls_feature_0": [],
                    "tls_feature_1": False,
                },
            )
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertFalse(response.context["adminform"].form.is_valid())
        self.assertEqual(
            response.context["adminform"].form.errors,
            {"subject": ["countryName (C): Attribute cannot occur more then once."]},
        )

    @override_tmpcadir(CA_DEFAULT_SUBJECT=tuple())
    def test_subject_with_invalid_country_code(self) -> None:
        """Test creating a certificate with an invalid country code."""
        ca = self.cas["root"]
        csr = CERT_DATA["root-cert"]["csr"]["pem"]

        with self.assertCreateCertSignals(False, False):
            response = self.client.post(
                self.add_url,
                data={
                    "csr": csr,
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": json.dumps(
                        [
                            {"key": NameOID.COUNTRY_NAME.dotted_string, "value": "FOO"},
                            {"key": NameOID.COMMON_NAME.dotted_string, "value": self.hostname},
                        ]
                    ),
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA-256",
                    "expires": ca.expires.strftime("%Y-%m-%d"),
                    "key_usage_0": [],
                    "key_usage_1": True,
                    "extended_key_usage_0": [],
                    "extended_key_usage_1": False,
                    "tls_feature_0": [],
                    "tls_feature_1": False,
                },
            )
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertFalse(response.context["adminform"].form.is_valid())
        self.assertEqual(
            response.context["adminform"].form.errors,
            {"subject": ["Country name must be a 2 character country code"]},
        )

    @override_tmpcadir(CA_DEFAULT_SUBJECT=tuple())
    def test_add_no_key_usage(self) -> None:
        """Test adding a cert with no (extended) key usage."""
        ca = self.cas["root"]
        csr = CERT_DATA["root-cert"]["csr"]["pem"]
        cname = "test-add2.example.com"
        san = "test-san.example.com"

        with self.assertCreateCertSignals() as (pre, post):
            response = self.client.post(
                self.add_url,
                data={
                    "csr": csr,
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": json.dumps(
                        [
                            {"key": NameOID.COUNTRY_NAME.dotted_string, "value": "US"},
                            {"key": NameOID.COMMON_NAME.dotted_string, "value": cname},
                        ]
                    ),
                    "subject_alternative_name_0": san,
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA-256",
                    "expires": ca.expires.strftime("%Y-%m-%d"),
                    "key_usage_0": [],
                    "key_usage_1": False,
                    "extended_key_usage_0": [],
                    "extended_Key_usage_1": False,
                    "crl_distribution_points_0": ca.crl_url,
                    "crl_distribution_points_1": "",
                    "crl_distribution_points_2": "",
                    "crl_distribution_points_3": [],
                    "crl_distribution_points_4": False,
                    "authority_information_access_0": ca.issuer_url,
                    "authority_information_access_1": ca.ocsp_url,
                    "authority_information_access_2": False,
                },
            )
        self.assertRedirects(response, self.changelist_url)

        cert = Certificate.objects.get(cn=cname)
        self.assertPostIssueCert(post, cert)
        self.assertEqual(
            cert.pub.loaded.subject,
            x509.Name(
                [
                    x509.NameAttribute(oid=NameOID.COUNTRY_NAME, value="US"),
                    x509.NameAttribute(oid=NameOID.COMMON_NAME, value=cname),
                ]
            ),
        )
        self.assertIssuer(ca, cert)
        self.assertEqual(cert.ca, ca)
        self.assertEqual(cert.csr.pem, csr)

        # Some extensions are not set
        self.assertExtensions(cert, [subject_alternative_name(dns(san), dns(cname))])

        # Test that we can view the certificate
        response = self.client.get(cert.admin_change_url)
        self.assertEqual(response.status_code, HTTPStatus.OK)

    @override_tmpcadir(CA_DEFAULT_SUBJECT=tuple())
    def test_add_with_password(self) -> None:
        """Test adding with a password."""
        ca = self.cas["pwd"]
        csr = CERT_DATA["pwd-cert"]["csr"]["pem"]
        cname = "with-password.example.com"

        # first post without password
        with self.assertCreateCertSignals(False, False):
            response = self.client.post(
                self.add_url,
                data={
                    "csr": csr,
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": json.dumps(
                        [
                            {"key": NameOID.COUNTRY_NAME.dotted_string, "value": "US"},
                            {"key": NameOID.COMMON_NAME.dotted_string, "value": cname},
                        ]
                    ),
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA-256",
                    "expires": ca.expires.strftime("%Y-%m-%d"),
                    "key_usage_0": [
                        "digital_signature",
                        "key_agreement",
                    ],
                    "key_usage_1": True,
                    "extended_key_usage_0": [
                        ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string,
                        ExtendedKeyUsageOID.SERVER_AUTH.dotted_string,
                    ],
                    "extended_key_usage_1": False,
                },
            )
        self.assertFalse(response.context["adminform"].form.is_valid())
        self.assertEqual(
            response.context["adminform"].form.errors,
            {"password": ["Password was not given but private key is encrypted"]},
        )

        # now post with a false password
        with self.assertCreateCertSignals(False, False):
            response = self.client.post(
                self.add_url,
                data={
                    "csr": csr,
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": json.dumps(
                        [
                            {"key": NameOID.COUNTRY_NAME.dotted_string, "value": "US"},
                            {"key": NameOID.COMMON_NAME.dotted_string, "value": cname},
                        ]
                    ),
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA-256",
                    "expires": ca.expires.strftime("%Y-%m-%d"),
                    "key_usage_0": [
                        "digital_signature",
                        "key_agreement",
                    ],
                    "key_usage_1": True,
                    "extended_key_usage_0": [
                        ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string,
                        ExtendedKeyUsageOID.SERVER_AUTH.dotted_string,
                    ],
                    "extended_key_usage_1": False,
                    "password": "wrong",
                },
            )
        self.assertFalse(response.context["adminform"].form.is_valid())
        self.assertEqual(
            response.context["adminform"].form.errors,
            {"password": ["Could not decrypt private key - bad password?"]},
        )

        # post with correct password!
        with self.assertCreateCertSignals() as (pre, post):
            response = self.client.post(
                self.add_url,
                data={
                    "csr": csr,
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": json.dumps(
                        [
                            {"key": NameOID.COUNTRY_NAME.dotted_string, "value": "US"},
                            {"key": NameOID.COMMON_NAME.dotted_string, "value": cname},
                        ]
                    ),
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA-256",
                    "expires": ca.expires.strftime("%Y-%m-%d"),
                    "key_usage_0": [
                        "digital_signature",
                        "key_agreement",
                    ],
                    "key_usage_1": True,
                    "extended_key_usage_0": [
                        ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string,
                        ExtendedKeyUsageOID.SERVER_AUTH.dotted_string,
                    ],
                    "extended_key_usage_1": False,
                    "crl_distribution_points_0": ca.crl_url,
                    "crl_distribution_points_1": "",
                    "crl_distribution_points_2": "",
                    "crl_distribution_points_3": [],
                    "crl_distribution_points_4": False,
                    "authority_information_access_0": ca.issuer_url,
                    "authority_information_access_1": ca.ocsp_url,
                    "authority_information_access_2": False,
                    "password": CERT_DATA["pwd"]["password"].decode("utf-8"),
                },
            )
        self.assertRedirects(response, self.changelist_url)

        cert = Certificate.objects.get(cn=cname)
        self.assertPostIssueCert(post, cert)
        self.assertEqual(
            cert.pub.loaded.subject,
            x509.Name(
                [
                    x509.NameAttribute(oid=NameOID.COUNTRY_NAME, value="US"),
                    x509.NameAttribute(oid=NameOID.COMMON_NAME, value=cname),
                ]
            ),
        )
        self.assertIssuer(ca, cert)
        self.assertAuthorityKeyIdentifier(ca, cert)

        self.assertEqual(
            cert.x509_extensions[ExtensionOID.SUBJECT_ALTERNATIVE_NAME],
            subject_alternative_name(dns(cname)),
        )
        self.assertExtensions(
            cert,
            [
                subject_alternative_name(dns(cname)),
                key_usage(digital_signature=True, key_agreement=True),
                extended_key_usage(ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH),
            ],
        )
        self.assertEqual(cert.ca, ca)
        self.assertEqual(cert.csr.pem, csr)

        # Some extensions are not set
        self.assertNotIn(ExtensionOID.CERTIFICATE_POLICIES, cert.x509_extensions)
        self.assertNotIn(ExtensionOID.ISSUER_ALTERNATIVE_NAME, cert.x509_extensions)
        self.assertNotIn(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS, cert.x509_extensions)
        self.assertNotIn(ExtensionOID.TLS_FEATURE, cert.x509_extensions)

        # Test that we can view the certificate
        response = self.client.get(cert.admin_change_url)
        self.assertEqual(response.status_code, HTTPStatus.OK)

    @override_tmpcadir()
    def test_wrong_csr(self) -> None:
        """Test passing an unparsable CSR."""
        ca = self.cas["root"]
        cname = "test-add-wrong-csr.example.com"

        with self.assertCreateCertSignals(False, False):
            response = self.client.post(
                self.add_url,
                data={
                    "csr": "whatever",
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": json.dumps(
                        [
                            {"key": NameOID.COUNTRY_NAME.dotted_string, "value": "US"},
                            {"key": NameOID.COMMON_NAME.dotted_string, "value": cname},
                        ]
                    ),
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA-256",
                    "expires": ca.expires.strftime("%Y-%m-%d"),
                    "key_usage_0": [
                        "digital_signature",
                        "key_agreement",
                    ],
                    "key_usage_1": True,
                    "extended_key_usage_0": [
                        ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string,
                        ExtendedKeyUsageOID.SERVER_AUTH.dotted_string,
                    ],
                    "extended_key_usage_1": False,
                },
            )
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertFalse(response.context["adminform"].form.is_valid())
        self.assertEqual(
            response.context["adminform"].form.errors,
            {"csr": [CertificateSigningRequestField.simple_validation_error]},
        )

        with self.assertRaises(Certificate.DoesNotExist):
            Certificate.objects.get(cn=cname)

    @override_tmpcadir()
    def test_unparsable_csr(self) -> None:
        """Test passing something that looks like a CSR but isn't.

        This is different from test_wrong_csr() because this passes our initial test, but cryptography itself
        fails to load the CSR.
        """
        ca = self.cas["root"]
        cname = "test-add-wrong-csr.example.com"

        with self.assertCreateCertSignals(False, False):
            response = self.client.post(
                self.add_url,
                data={
                    "csr": "-----BEGIN CERTIFICATE REQUEST-----\nwrong-----END CERTIFICATE REQUEST-----",
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": json.dumps(
                        [
                            {"key": NameOID.COUNTRY_NAME.dotted_string, "value": "US"},
                            {"key": NameOID.COMMON_NAME.dotted_string, "value": cname},
                        ]
                    ),
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA-256",
                    "expires": ca.expires.strftime("%Y-%m-%d"),
                    "key_usage_0": [
                        "digital_signature",
                        "key_agreement",
                    ],
                    "key_usage_1": True,
                    "extended_key_usage_0": [
                        ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string,
                        ExtendedKeyUsageOID.SERVER_AUTH.dotted_string,
                    ],
                    "extended_key_usage_1": False,
                },
            )
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertFalse(response.context["adminform"].form.is_valid())

        # Not testing exact error message here, as it the one from cryptography. Instead, just check that
        # there is exactly one message for the "csr" field.
        self.assertEqual(len(response.context["adminform"].form.errors), 1)
        self.assertEqual(len(response.context["adminform"].form.errors["csr"]), 1)

        with self.assertRaises(Certificate.DoesNotExist):
            Certificate.objects.get(cn=cname)

    @override_tmpcadir()
    def test_expires_in_the_past(self) -> None:
        """Test creating a cert that expires in the past."""
        ca = self.cas["root"]
        csr = CERT_DATA["pwd-cert"]["csr"]["pem"]
        cname = "test-expires-in-the-past.example.com"
        expires = datetime.now() - timedelta(days=3)

        with self.assertCreateCertSignals(False, False):
            response = self.client.post(
                self.add_url,
                data={
                    "csr": csr,
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": json.dumps(
                        [
                            {"key": NameOID.COUNTRY_NAME.dotted_string, "value": "US"},
                            {"key": NameOID.COMMON_NAME.dotted_string, "value": cname},
                        ]
                    ),
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA-256",
                    "expires": expires.strftime("%Y-%m-%d"),
                    "key_usage_0": [
                        "digital_signature",
                        "key_agreement",
                    ],
                    "key_usage_1": True,
                    "extended_key_usage_0": [
                        ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string,
                        ExtendedKeyUsageOID.SERVER_AUTH.dotted_string,
                    ],
                    "extended_key_usage_1": False,
                },
            )
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertIn("Certificate cannot expire in the past.", response.content.decode("utf-8"))
        self.assertFalse(response.context["adminform"].form.is_valid())
        self.assertEqual(
            response.context["adminform"].form.errors, {"expires": ["Certificate cannot expire in the past."]}
        )

        with self.assertRaises(Certificate.DoesNotExist):
            Certificate.objects.get(cn=cname)

    @override_tmpcadir()
    def test_expires_too_late(self) -> None:
        """Test that creating a cert that expires after the CA expires throws an error."""
        ca = self.cas["root"]
        csr = CERT_DATA["pwd-cert"]["csr"]["pem"]
        cname = "test-expires-too-late.example.com"
        expires = ca.expires + timedelta(days=3)
        correct_expires = ca.expires.strftime("%Y-%m-%d")
        error = f"CA expires on {correct_expires}, certificate must not expire after that."

        with self.assertCreateCertSignals(False, False):
            response = self.client.post(
                self.add_url,
                data={
                    "csr": csr,
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": json.dumps(
                        [
                            {"key": NameOID.COUNTRY_NAME.dotted_string, "value": "US"},
                            {"key": NameOID.COMMON_NAME.dotted_string, "value": cname},
                        ]
                    ),
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA-256",
                    "expires": expires.strftime("%Y-%m-%d"),
                    "key_usage_0": [
                        "digital_signature",
                        "key_agreement",
                    ],
                    "key_usage_1": True,
                    "extended_key_usage_0": [
                        ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string,
                        ExtendedKeyUsageOID.SERVER_AUTH.dotted_string,
                    ],
                    "extended_key_usage_1": False,
                },
            )
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertIn(error, response.content.decode("utf-8"))
        self.assertFalse(response.context["adminform"].form.is_valid())
        self.assertEqual(response.context["adminform"].form.errors, {"expires": [error]})

        with self.assertRaises(Certificate.DoesNotExist):
            Certificate.objects.get(cn=cname)

    @override_tmpcadir()
    def test_invalid_cn_in_san(self) -> None:
        """Test error with a CommonName that is not parsable as SubjectAlternativeName, but check "CN in SAN".

        .. seealso:: https://github.com/mathiasertl/django-ca/issues/62
        """
        cname = "Foo Bar"
        error = "The CommonName cannot be parsed as general name. Either change the CommonName or do not include it."  # NOQA
        ca = self.cas["root"]
        csr = CERT_DATA["root-cert"]["csr"]["pem"]

        with self.assertCreateCertSignals(False, False):
            response = self.client.post(
                self.add_url,
                data={
                    "csr": csr,
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": json.dumps(
                        [
                            {"key": NameOID.COUNTRY_NAME.dotted_string, "value": "US"},
                            {"key": NameOID.COMMON_NAME.dotted_string, "value": cname},
                        ]
                    ),
                    "subject_alternative_name_1": True,  # cn_in_san
                    "algorithm": "SHA-256",
                    "expires": ca.expires.strftime("%Y-%m-%d"),
                    "key_usage_0": [
                        "digital_signature",
                        "key_agreement",
                    ],
                    "key_usage_1": True,
                    "extended_key_usage_0": [
                        ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string,
                        ExtendedKeyUsageOID.SERVER_AUTH.dotted_string,
                    ],
                    "extended_key_usage_1": False,
                    "tls_feature_0": ["status_request", "status_request_v2"],
                    "tls_feature_1": False,
                },
            )
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertIn(html.escape(error), response.content.decode("utf-8"))
        self.assertFalse(response.context["adminform"].form.is_valid())
        self.assertEqual(response.context["adminform"].form.errors, {"subject_alternative_name": [error]})

        with self.assertRaises(Certificate.DoesNotExist):
            Certificate.objects.get(cn=cname)

    @override_tmpcadir()
    def test_invalid_signature_hash_algorithm(self) -> None:
        """Test adding a certificate with an invalid signature hash algorithm."""
        # Test with Ed448 CA
        with self.assertCreateCertSignals(False, False):
            response = self.client.post(
                self.add_url,
                data={
                    "csr": CERT_DATA["ed448-cert"]["csr"]["pem"],
                    "ca": self.cas["ed448"].pk,
                    "profile": "webserver",
                    "subject_0": json.dumps(
                        [{"key": NameOID.COMMON_NAME.dotted_string, "value": self.hostname}]
                    ),
                    "algorithm": "SHA-256",  # this is what we test
                    "expires": self.default_expires,
                },
            )
        self.assertFalse(response.context["adminform"].form.is_valid(), response)
        self.assertEqual(
            response.context["adminform"].form.errors,
            {"algorithm": ["Ed448-based certificate authorities do not use a signature hash algorithm."]},
        )

        # Test with Ed25519 CA
        with self.assertCreateCertSignals(False, False):
            response = self.client.post(
                self.add_url,
                data={
                    "csr": CERT_DATA["ed25519-cert"]["csr"]["pem"],
                    "ca": self.cas["ed25519"].pk,
                    "profile": "webserver",
                    "subject_0": json.dumps(
                        [{"key": NameOID.COMMON_NAME.dotted_string, "value": self.hostname}]
                    ),
                    "algorithm": "SHA-256",  # this is what we test
                    "expires": self.default_expires,
                },
            )
        self.assertFalse(response.context["adminform"].form.is_valid(), response)
        self.assertEqual(
            response.context["adminform"].form.errors,
            {"algorithm": ["Ed25519-based certificate authorities do not use a signature hash algorithm."]},
        )

        # Test with DSA CA
        with self.assertCreateCertSignals(False, False):
            response = self.client.post(
                self.add_url,
                data={
                    "csr": CERT_DATA["dsa-cert"]["csr"]["pem"],
                    "ca": self.cas["dsa"].pk,
                    "profile": "webserver",
                    "subject_0": json.dumps(
                        [{"key": NameOID.COMMON_NAME.dotted_string, "value": self.hostname}]
                    ),
                    "algorithm": "SHA-512",  # this is what we test
                    "expires": self.default_expires,
                },
            )
        self.assertFalse(response.context["adminform"].form.is_valid(), response)
        self.assertEqual(
            response.context["adminform"].form.errors,
            {"algorithm": ["DSA-based certificate authorities require a SHA-256 signature hash algorithm."]},
        )

        # Test with RSA CA
        with self.assertCreateCertSignals(False, False):
            response = self.client.post(
                self.add_url,
                data={
                    "csr": CERT_DATA["root-cert"]["csr"]["pem"],
                    "ca": self.cas["root"].pk,
                    "profile": "webserver",
                    "subject_0": json.dumps(
                        [{"key": NameOID.COMMON_NAME.dotted_string, "value": self.hostname}]
                    ),
                    "algorithm": "",  # this is what we test
                    "expires": self.default_expires,
                },
            )
        self.assertFalse(response.context["adminform"].form.is_valid(), response)
        self.assertEqual(
            response.context["adminform"].form.errors,
            {"algorithm": ["RSA-based certificate authorities require a signature hash algorithm."]},
        )

    @override_tmpcadir(CA_DEFAULT_SUBJECT=tuple())
    def test_certificate_policies_with_invalid_oid(self) -> None:
        """Test posting a certificate policies extension with an invalid OID."""
        ca = self.cas["root"]
        csr = CERT_DATA["root-cert"]["csr"]["pem"]
        cert_count = Certificate.objects.all().count()

        with self.assertCreateCertSignals(False, False):
            response = self.client.post(
                self.add_url,
                data={
                    "csr": csr,
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": json.dumps(
                        [
                            {"key": NameOID.COUNTRY_NAME.dotted_string, "value": "US"},
                            {"key": NameOID.COMMON_NAME.dotted_string, "value": self.hostname},
                        ]
                    ),
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA-256",
                    "expires": ca.expires.strftime("%Y-%m-%d"),
                    "certificate_policies_0": "abc",
                },
            )
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertFalse(response.context["adminform"].form.is_valid())
        self.assertEqual(
            response.context["adminform"].form.errors,
            {"certificate_policies": ["abc: The given OID is invalid."]},
        )
        self.assertEqual(cert_count, Certificate.objects.all().count())

    def test_add_no_cas(self) -> None:
        """Test adding when all CAs are disabled."""
        ca = self.cas["root"]
        csr = CERT_DATA["pwd-cert"]["csr"]["pem"]
        CertificateAuthority.objects.update(enabled=False)
        response = self.client.get(self.add_url)
        self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)

        with self.assertCreateCertSignals(False, False):
            response = self.client.post(
                self.add_url,
                data={
                    "csr": csr,
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": "US",
                    "subject_5": "test-add-no-cas.example.com",
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA-256",
                    "expires": ca.expires.strftime("%Y-%m-%d"),
                    "key_usage_0": [
                        "digital_signature",
                        "key_agreement",
                    ],
                    "key_usage_1": True,
                    "extended_key_usage_0": [
                        "clientAuth",
                        "serverAuth",
                    ],
                    "extended_key_usage_1": False,
                },
            )
        self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)

    def test_add_unusable_cas(self) -> None:
        """Try adding with an unusable CA."""
        ca = self.cas["root"]
        csr = CERT_DATA["pwd-cert"]["csr"]["pem"]
        CertificateAuthority.objects.update(private_key_path="not/exist/add-unusable-cas")

        # check that we have some enabled CAs, just to make sure this test is really useful
        self.assertTrue(CertificateAuthority.objects.filter(enabled=True).exists())

        with self.assertCreateCertSignals(False, False):
            response = self.client.get(self.add_url)
        self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)

        with self.assertCreateCertSignals(False, False):
            response = self.client.post(
                self.add_url,
                data={
                    "csr": csr,
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": "US",
                    "subject_5": "test-add.example.com",
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA-256",
                    "expires": ca.expires.strftime("%Y-%m-%d"),
                    "key_usage_0": [
                        "digital_signature",
                        "key_agreement",
                    ],
                    "key_usage_1": True,
                    "extended_key_usage_0": [
                        "clientAuth",
                        "serverAuth",
                    ],
                    "extended_key_usage_1": False,
                },
            )
        self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)


@pytest.mark.selenium
class ProfileFieldSeleniumTestCase(CertificateModelAdminTestCaseMixin, SeleniumTestCase):
    """Some Selenium based test cases to test the client side javascript code."""

    load_cas = "__usable__"

    def get_expected(
        self, profile: Profile, oid: x509.ObjectIdentifier, default: Any = None
    ) -> SerializedExtension:
        """Get expected value for a given extension for the given profile."""
        if oid in profile.extensions:
            return serialize_extension(profile.extensions[oid])  # type: ignore[arg-type]
        return {"value": default, "critical": EXTENSION_DEFAULT_CRITICAL[oid]}

    def assertProfile(  # pylint: disable=invalid-name
        self,
        profile_name: str,
        ku_select: Select,
        ku_critical: WebElement,
        eku_select: Select,
        eku_critical: WebElement,
        tf_select: Select,
        tf_critical: WebElement,
        cn_in_san: WebElement,
    ) -> None:
        """Assert that the admin form equals the given profile."""
        profile = profiles[profile_name]

        ku_expected = self.get_expected(profile, ExtensionOID.KEY_USAGE, [])
        ku_selected = [o.get_attribute("value") for o in ku_select.all_selected_options]
        self.assertCountEqual(ku_expected["value"], ku_selected)
        self.assertEqual(ku_expected["critical"], ku_critical.is_selected())

        eku_expected = self.get_expected(profile, ExtensionOID.EXTENDED_KEY_USAGE, [])
        eku_selected = [o.get_attribute("value") for o in eku_select.all_selected_options]
        self.assertCountEqual(eku_expected["value"], eku_selected)
        self.assertEqual(eku_expected["critical"], eku_critical.is_selected())

        tf_selected = [o.get_attribute("value") for o in tf_select.all_selected_options]
        tf_expected = self.get_expected(profile, ExtensionOID.TLS_FEATURE, [])
        self.assertCountEqual(tf_expected.get("value", []), tf_selected)
        self.assertEqual(tf_expected.get("critical", False), tf_critical.is_selected())

        self.assertEqual(profile.cn_in_san, cn_in_san.is_selected())

    def clear_form(
        self,
        ku_select: Select,
        ku_critical: WebElement,
        eku_select: Select,
        eku_critical: WebElement,
        tf_select: Select,
        tf_critical: WebElement,
        cn_in_san: WebElement,
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
        if cn_in_san.is_selected():
            cn_in_san.click()

    @override_tmpcadir()
    def test_select_profile(self) -> None:
        """Test that selecting the profile modifies the extensions."""
        self.login()

        self.selenium.get(f"{self.live_server_url}{self.add_url}")
        select = Select(self.find("select#id_profile"))
        ku_select = Select(self.find("select#id_key_usage_0"))
        ku_critical = self.find("input#id_key_usage_1")
        eku_select = Select(self.find("select#id_extended_key_usage_0"))
        eku_critical = self.find("input#id_extended_key_usage_1")
        tf_select = Select(self.find("select#id_tls_feature_0"))
        tf_critical = self.find("input#id_tls_feature_1")

        cn_in_san = self.find("input#id_subject_alternative_name_1")

        # test that the default profile is preselected
        self.assertEqual(
            [ca_settings.CA_DEFAULT_PROFILE], [o.get_attribute("value") for o in select.all_selected_options]
        )

        # assert that the values from the default profile are preloaded
        self.assertProfile(
            ca_settings.CA_DEFAULT_PROFILE,
            ku_select,
            ku_critical,
            eku_select,
            eku_critical,
            tf_select,
            tf_critical,
            cn_in_san,
        )

        for option in select.options:
            # first, clear everything to make sure that the profile *sets* everything
            self.clear_form(
                ku_select,
                ku_critical,
                eku_select,
                eku_critical,
                tf_select,
                tf_critical,
                cn_in_san,
            )

            value = option.get_attribute("value")
            if not value:
                continue
            option.click()

            self.assertProfile(
                value,
                ku_select,
                ku_critical,
                eku_select,
                eku_critical,
                tf_select,
                tf_critical,
                cn_in_san,
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
            if not cn_in_san.is_selected():
                cn_in_san.click()

            # select empty element in profile select, then select profile again
            select.select_by_value(ca_settings.CA_DEFAULT_PROFILE)
            self.clear_form(
                ku_select,
                ku_critical,
                eku_select,
                eku_critical,
                tf_select,
                tf_critical,
                cn_in_san,
            )
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
                cn_in_san,
            )


@pytest.mark.selenium
class SubjectFieldSeleniumTestCase(AddCertificateSeleniumTestCase):
    """Test the Subject input field."""

    @override_tmpcadir(CA_PROFILES={"webserver": {"subject": [["C", "AT"], ["ST", "Vienna"]]}})
    def test_subject_field(self) -> None:
        """Test core functionality of the subject field."""
        self.initialize()

        # Expected initial subject based on the CA_PROFILES setting set in the decorator
        expected_initial_subject = [
            {"key": NameOID.COUNTRY_NAME.dotted_string, "value": "AT"},
            {"key": NameOID.STATE_OR_PROVINCE_NAME.dotted_string, "value": "Vienna"},
        ]

        # Test the initial state
        self.assertEqual(self.value, expected_initial_subject)
        self.assertEqual(self.displayed_value, expected_initial_subject)

        # Add a row and confirm that it's initially empty and the field is thus not yet modified
        self.key_value_field.find_element(By.CLASS_NAME, "add-row-btn").click()
        self.assertNotModified()
        new_select = Select(self.key_value_list.find_elements(By.CSS_SELECTOR, "select")[-1])
        new_input = self.key_value_list.find_elements(By.CSS_SELECTOR, "input")[-1]
        self.assertEqual(new_select.all_selected_options, [])
        self.assertEqual(new_input.get_attribute("value"), "")

        # Enter a value. This marks the field as modified, but the hidden input is *not* updated, as there is
        # no key/OID selected yet
        new_input.send_keys(self.hostname)
        self.assertModified()
        self.assertEqual(self.value, expected_initial_subject)

        # Now select common name, and the subject is also updated
        new_select.select_by_value(NameOID.COMMON_NAME.dotted_string)
        new_subject = [
            expected_initial_subject,
            *{"key": NameOID.COMMON_NAME.dotted_string, "value": self.hostname},
        ]
        self.assertEqual(self.value, new_subject)
        self.assertEqual(self.displayed_value, new_subject)  # just to be sure

        # Remove the second row, check the update
        self.key_value_list.find_elements(By.CSS_SELECTOR, ".remove-row-btn")[1].click()
        new_subject.pop(1)
        self.assertEqual(len(new_subject), 2)
        self.assertEqual(self.value, new_subject)
        self.assertEqual(self.displayed_value, new_subject)

    @override_tmpcadir()
    def test_csr_integration(self) -> None:
        """Test that pasting a CSR shows text next to subject input fields."""
        self.initialize()

        initial_subject = [
            {"key": "2.5.4.6", "value": "AT"},
            {"key": "2.5.4.8", "value": "Vienna"},
            {"key": "2.5.4.7", "value": "Vienna"},
            {"key": "2.5.4.10", "value": "Django CA"},
            {"key": "2.5.4.11", "value": "Django CA Testsuite"},
        ]
        csr_subject = [
            {"key": "2.5.4.6", "value": "AT"},
            {"key": "2.5.4.8", "value": "csr.Vienna"},
            {"key": "2.5.4.7", "value": "csr.Vienna"},
            {"key": "2.5.4.10", "value": "csr.Example"},
            {"key": "2.5.4.11", "value": "csr.Example OU"},
            {"key": "2.5.4.3", "value": "csr.all-extensions.example.com"},
            {"key": "1.2.840.113549.1.9.1", "value": "csr.user@example.com"},
        ]

        # Elements of the CSR chapter
        csr_chapter = self.key_value_field.find_element(By.CSS_SELECTOR, ".subject-input-chapter.csr")
        no_csr = self.key_value_field.find_element(By.CSS_SELECTOR, ".subject-input-chapter.csr .no-csr")
        has_content = self.key_value_field.find_element(
            By.CSS_SELECTOR, ".subject-input-chapter.csr .has-content"
        )
        no_content = self.key_value_field.find_element(
            By.CSS_SELECTOR, ".subject-input-chapter.csr .no-content"
        )

        # Check that the right parts of the CSR chapter is displayed
        self.assertIs(no_csr.is_displayed(), True)  # this is displayed as we haven't pasted a CSR
        self.assertIs(has_content.is_displayed(), False)
        self.assertIs(no_content.is_displayed(), False)

        cert = CERT_DATA["all-extensions"]
        csr = self.find("textarea#id_csr")
        csr.send_keys(cert["csr"]["pem"])

        # Make sure that the displayed subject has not changed
        self.assertNotModified()
        self.assertEqual(self.value, initial_subject)

        # check the JSON value from the chapter
        self.assertEqual(
            json.loads(csr_chapter.get_attribute("data-value")),  # type: ignore[arg-type]
            csr_subject,
        )

        # check that the right chapter is displayed
        self.assertIs(no_csr.is_displayed(), False)
        self.assertIs(has_content.is_displayed(), True)
        self.assertIs(no_content.is_displayed(), False)

        # Check the li element inside
        lis = has_content.find_elements(By.TAG_NAME, "li")
        self.assertEqual(len(lis), len(csr_subject))
        self.assertEqual(lis[0].text, "countryName (C): AT")  # just testing the first one

        # Click the copy button and validate that the subject is set
        csr_chapter.find_element(By.CSS_SELECTOR, ".copy-button").click()
        self.assertModified()
        self.assertEqual(self.value, csr_subject)
        self.assertEqual(self.displayed_value, csr_subject)

    @override_tmpcadir()
    def test_paste_csr_no_subject(self) -> None:
        """Test that pasting a CSR shows text next to subject input fields."""
        self.initialize()

        # Create a CSR with no subject
        key = CERT_DATA["all-extensions"]["key"]["parsed"]
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).sign(key, hashes.SHA256())
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

        # Elements of the CSR chapter
        csr_chapter = self.key_value_field.find_element(By.CSS_SELECTOR, ".subject-input-chapter.csr")
        no_csr = csr_chapter.find_element(By.CSS_SELECTOR, ".no-csr")
        has_content = csr_chapter.find_element(By.CSS_SELECTOR, ".has-content")
        no_content = csr_chapter.find_element(By.CSS_SELECTOR, ".no-content")

        # send all but the first character to the CSR input field
        self.find("textarea#id_csr").send_keys(csr_pem)

        # Wait for the CSR results to be fetched
        WebDriverWait(self.selenium, 2, poll_frequency=0.1).until(
            lambda driver: driver.find_element(By.ID, "id_csr").get_attribute("data-fetched") == "true",
            "data-fetched for CSR was not set.",
        )

        # Check that the right parts of the CSR chapter is displayed
        self.assertIs(no_csr.is_displayed(), False)
        self.assertIs(has_content.is_displayed(), False)
        self.assertIs(no_content.is_displayed(), True)
        self.assertNotModified()

        # Click the clear button and validate that the subject is cleared
        csr_chapter.find_element(By.CSS_SELECTOR, ".clear-button").click()
        self.assertModified()
        self.assertEqual(self.value, [])
        self.assertEqual(self.displayed_value, [])

    @override_tmpcadir()
    def test_paste_csr_missing_delimiters(self) -> None:
        """Test that pasting a CSR shows text next to subject input fields."""
        self.initialize()

        cert = CERT_DATA["all-extensions"]
        csr = self.find("textarea#id_csr")

        # Elements of the CSR chapter
        chapter = self.key_value_field.find_element(By.CSS_SELECTOR, ".subject-input-chapter.csr")
        no_csr = chapter.find_element(By.CSS_SELECTOR, ".no-csr")
        has_content = chapter.find_element(By.CSS_SELECTOR, ".has-content")
        no_content = chapter.find_element(By.CSS_SELECTOR, ".no-content")

        # send all but the first character to the CSR input field
        csr.send_keys(cert["csr"]["pem"][1:])

        # Check that the right parts of the CSR chapter is displayed
        self.assertIs(no_csr.is_displayed(), True)  # this is displayed as we haven't pasted a CSR
        self.assertIs(has_content.is_displayed(), False)
        self.assertIs(no_content.is_displayed(), False)
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
        self.assertIs(no_csr.is_displayed(), True)  # this is displayed as we haven't pasted a CSR
        self.assertIs(has_content.is_displayed(), False)
        self.assertIs(no_content.is_displayed(), False)
        self.assertNotModified()

    @override_tmpcadir(
        CA_DEFAULT_PROFILE="webserver",
        CA_DEFAULT_SUBJECT=[],
        CA_PROFILES={
            "webserver": {"subject": [["C", "AT"], ["ST", "Vienna"], ["OU", "webserver"]]},
            "client": {"subject": [["C", "AT"], ["ST", "Vienna"], ["OU", "client"]]},
            "no-subject": {},
        },
    )
    def test_profile_integration(self) -> None:
        """Test core functionality of the subject field."""
        self.initialize()

        # Expected initial subject based on the CA_PROFILES setting set in the decorator
        webserver_subject = [
            {"key": NameOID.COUNTRY_NAME.dotted_string, "value": "AT"},
            {"key": NameOID.STATE_OR_PROVINCE_NAME.dotted_string, "value": "Vienna"},
            {"key": NameOID.ORGANIZATIONAL_UNIT_NAME.dotted_string, "value": "webserver"},
        ]
        client_subject = [
            {"key": NameOID.COUNTRY_NAME.dotted_string, "value": "AT"},
            {"key": NameOID.STATE_OR_PROVINCE_NAME.dotted_string, "value": "Vienna"},
            {"key": NameOID.ORGANIZATIONAL_UNIT_NAME.dotted_string, "value": "client"},
        ]

        # Elements of the profile chapter
        chapter = self.key_value_field.find_element(By.CSS_SELECTOR, ".subject-input-chapter.profile")
        has_content = chapter.find_element(By.CSS_SELECTOR, ".has-content")
        no_content = chapter.find_element(By.CSS_SELECTOR, ".no-content")

        # Test the initial state (webserver subject, since it's the default profile
        self.assertNotModified()
        self.assertChapterHasValue(chapter, webserver_subject)
        self.assertEqual(self.value, webserver_subject)
        self.assertEqual(self.displayed_value, webserver_subject)
        self.assertIs(has_content.is_displayed(), True)
        self.assertIs(no_content.is_displayed(), False)

        profile_select = Select(self.selenium.find_element(By.ID, "id_profile"))

        # Select the different profile. Since the field is not yet modified, new values are taken
        profile_select.select_by_value("client")
        self.assertNotModified()
        self.assertChapterHasValue(chapter, client_subject)
        self.assertEqual(self.value, client_subject)
        self.assertEqual(self.displayed_value, client_subject)
        self.assertIs(has_content.is_displayed(), True)
        self.assertIs(no_content.is_displayed(), False)

        # Change one field and check modification
        st_input = self.key_value_list.find_elements(By.CSS_SELECTOR, "input")[1]
        st_input.clear()
        st_input.send_keys("Styria")
        new_subject = deepcopy(client_subject)
        new_subject[1]["value"] = "Styria"
        self.assertModified()
        self.assertEqual(self.value, new_subject)
        self.assertEqual(self.displayed_value, new_subject)

        # Switch back to the old profile. Since you made changes, it's not automatically updated
        profile_select.select_by_value("webserver")
        self.assertModified()
        self.assertChapterHasValue(chapter, webserver_subject)
        self.assertEqual(self.value, new_subject)
        self.assertEqual(self.displayed_value, new_subject)

        # Copy the profile subject and check the state
        chapter.find_element(By.CLASS_NAME, "copy-button").click()
        self.assertNotModified()
        self.assertChapterHasValue(chapter, webserver_subject)
        self.assertEqual(self.value, webserver_subject)
        self.assertEqual(self.displayed_value, webserver_subject)
        self.assertIs(has_content.is_displayed(), True)
        self.assertIs(no_content.is_displayed(), False)

        # Modify subject again (so that we can check the modified flag of the clear button)
        st_input = self.key_value_list.find_elements(By.CSS_SELECTOR, "input")[1]
        st_input.clear()
        st_input.send_keys("Styria")
        new_subject[2]["value"] = "webserver"
        self.assertModified()
        self.assertEqual(self.value, new_subject)
        self.assertEqual(self.displayed_value, new_subject)

        # Switch to the profile with no subject and check the state
        profile_select.select_by_value("no-subject")
        self.assertModified()
        self.assertChapterHasValue(chapter, [])
        self.assertEqual(self.value, new_subject)
        self.assertEqual(self.displayed_value, new_subject)
        self.assertIs(has_content.is_displayed(), False)
        self.assertIs(no_content.is_displayed(), True)

        # Click the clear button
        chapter.find_element(By.CLASS_NAME, "clear-button").click()
        self.assertNotModified()
        self.assertChapterHasValue(chapter, [])
        self.assertEqual(self.value, [])
        self.assertEqual(self.displayed_value, [])


@freeze_time(TIMESTAMPS["everything_valid"])
class AddCertificateWebTestTestCase(CertificateModelAdminTestCaseMixin, WebTestMixin, TestCase):
    """Tests for adding certificates."""

    load_cas = ("root", "child")

    @override_tmpcadir()
    def test_empty_form_and_empty_cert(self) -> None:
        """Test submitting an empty form, then filling it with values and submitting it."""
        response = self.app.get(self.add_url, user=self.user.username)
        form = response.forms["certificate_form"]
        for _key, field_list in form.fields.items():
            for field in field_list:
                if isinstance(field, (Hidden, Submit)):
                    continue
                if isinstance(field, Checkbox):
                    field.checked = False
                elif isinstance(field, WebTestSelect):
                    continue  # just annoying to handle
                else:
                    field.value = ""
        response = form.submit()
        self.assertEqual(response.status_code, 200)

        # Fill in the bare minimum fields
        form = response.forms["certificate_form"]
        form["csr"] = CERT_DATA["child-cert"]["csr"]["pem"]
        form["subject_0"] = json.dumps(
            [{"key": NameOID.COMMON_NAME.dotted_string, "value": "test-empty-form.example.com"}]
        )
        now = datetime.now(tz=tz.utc).replace(tzinfo=None)
        form["expires"] = (now + timedelta(days=10)).strftime("%Y-%m-%d")

        # Submit the form
        response = form.submit().follow()
        self.assertEqual(response.status_code, 200)
        cert = Certificate.objects.get(cn="test-empty-form.example.com")

        # Cert has minimal extensions, since we cleared the form earlier
        self.assertEqual(
            cert.sorted_extensions,
            [
                cert.ca.get_authority_key_identifier_extension(),
                basic_constraints(),
                subject_key_identifier(cert),
            ],
        )

    @override_tmpcadir(
        CA_PROFILES={
            "webserver": {
                "extensions": {"subject_alternative_name": {"value": ["example.com"]}, "ocsp_no_check": None}
            }
        },
    )
    def test_none_extension_and_subject_alternative_name_extension(self) -> None:
        """Test how saving the model behaves when profile has None-extension or SubjectAlternativeName."""
        response = self.app.get(self.add_url, user=self.user.username)
        form = response.forms["certificate_form"]
        form["csr"] = CERT_DATA["child-cert"]["csr"]["pem"]
        form["subject_0"] = json.dumps([{"key": NameOID.COMMON_NAME.dotted_string, "value": self.hostname}])
        response = form.submit().follow()
        self.assertEqual(response.status_code, 200)

        cert = Certificate.objects.get(cn=self.hostname)
        self.assertEqual(
            cert.sorted_extensions,
            [
                authority_information_access(
                    ca_issuers=[uri(self.ca.issuer_url)], ocsp=[uri(self.ca.ocsp_url)]
                ),
                cert.ca.get_authority_key_identifier_extension(),
                basic_constraints(),
                crl_distribution_points(distribution_point(full_name=[uri(self.ca.crl_url)])),
                subject_alternative_name(dns(self.hostname)),
                subject_key_identifier(cert),
            ],
        )

    @override_tmpcadir(CA_PROFILES={"nothing": {}}, CA_DEFAULT_PROFILE="nothing")
    def test_only_ca_prefill(self) -> None:
        """Create a cert with an empty profile.

        This test shows that the values from the CA are prefilled correctly. If they were not, some fields
        would not show up in the signed certificate.
        """
        # Make sure that the CA has field values set.
        cn = "test-only-ca.example.com"
        self.ca.crl_url = "http://crl.test-only-ca.example.com"
        self.ca.issuer_url = "http://issuer.test-only-ca.example.com"
        self.ca.ocsp_url = "http://ocsp.test-only-ca.example.com"
        self.ca.issuer_alt_name = "http://issuer-alt-name.test-only-ca.example.com"
        self.ca.sign_certificate_policies = self.certificate_policies(
            x509.PolicyInformation(
                policy_identifier=x509.ObjectIdentifier("1.2.3"),
                policy_qualifiers=[
                    "https://cps.example.com",
                    x509.UserNotice(notice_reference=None, explicit_text="explicit-text"),
                ],
            )
        )
        self.ca.save()

        response = self.app.get(self.add_url, user=self.user.username)
        form = response.forms["certificate_form"]
        form["csr"] = CERT_DATA["child-cert"]["csr"]["pem"]
        form["subject_0"] = json.dumps([{"key": NameOID.COMMON_NAME.dotted_string, "value": cn}])
        response = form.submit().follow()
        self.assertEqual(response.status_code, 200)

        # Check that we get all the extensions from the CA
        cert = Certificate.objects.get(cn="test-only-ca.example.com")
        self.assertEqual(
            cert.sorted_extensions,
            [
                authority_information_access(
                    ca_issuers=[uri(self.ca.issuer_url)], ocsp=[uri(self.ca.ocsp_url)]
                ),
                cert.ca.get_authority_key_identifier_extension(),
                basic_constraints(),
                crl_distribution_points(distribution_point(full_name=[uri(self.ca.crl_url)])),
                self.ca.sign_certificate_policies,
                issuer_alternative_name(uri(self.ca.issuer_alt_name)),
                subject_alternative_name(dns(cn)),
                subject_key_identifier(cert),
            ],
        )

    @override_tmpcadir(
        CA_PROFILES={
            "everything": {
                "extensions": {
                    "authority_information_access": {
                        "critical": False,
                        "value": {
                            "ocsp": [
                                "http://profile.ocsp.example.com",
                                "http://profile.ocsp-backup.example.com",
                            ],
                            "issuers": ["http://profile.issuers.example.com"],
                        },
                    },
                    "certificate_policies": {
                        "critical": True,
                        "value": [
                            {
                                "policy_identifier": "2.5.29.32.0",
                                "policy_qualifiers": ["text1"],
                            },
                        ],
                    },
                    "crl_distribution_points": {
                        "critical": True,
                        "value": [
                            {
                                "full_name": ["http://crl.profile.example.com"],
                                "crl_issuer": ["http://crl-issuer.profile.example.com"],
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
                                "full_name": ["http://freshest-crl.profile.example.com"],
                                "crl_issuer": ["http://freshest-crl-issuer.profile.example.com"],
                            }
                        ],
                    },
                    "issuer_alternative_name": {
                        "critical": True,
                        "value": ["http://ian1.example.com", "http://ian2.example.com"],
                    },
                    "key_usage": {
                        "critical": True,
                        "value": ["key_agreement", "key_cert_sign"],
                    },
                    "ocsp_no_check": {"critical": True, "value": True},
                    "tls_feature": {"critical": True, "value": ["OCSPMustStaple"]},
                }
            }
        },
        CA_DEFAULT_PROFILE="everything",
    )
    def test_full_profile_prefill(self) -> None:
        """Create a cert with a full profile, which should mask any CA-specific values.

        This test shows that the values from the profile are prefilled correctly. If they were not, some
        fields would not show up in the signed certificate.
        """
        # Make sure that the CA has field values set.
        cn = "test-only-ca.example.com"
        self.ca.crl_url = "http://crl.test-only-ca.example.com"
        self.ca.issuer_url = "http://issuer.test-only-ca.example.com"
        self.ca.ocsp_url = "http://ocsp.test-only-ca.example.com"
        self.ca.issuer_alt_name = "http://issuer-alt-name.test-only-ca.example.com"
        self.ca.save()

        response = self.app.get(self.add_url, user=self.user.username)
        form = response.forms["certificate_form"]
        # default value for form field is on import time, so override settings does not change
        # profile field
        form["profile"] = "everything"
        form["csr"] = CERT_DATA["child-cert"]["csr"]["pem"]
        form["subject_0"] = json.dumps([{"key": NameOID.COMMON_NAME.dotted_string, "value": cn}])
        response = form.submit().follow()
        self.assertEqual(response.status_code, 200)

        # Check that we get all the extensions from the CA
        cert = Certificate.objects.get(cn="test-only-ca.example.com")
        self.assertEqual(cert.profile, "everything")
        self.maxDiff = None
        self.assertEqual(
            cert.sorted_extensions,
            [
                authority_information_access(
                    ca_issuers=[uri("http://profile.issuers.example.com")],
                    ocsp=[
                        uri("http://profile.ocsp.example.com"),
                        uri("http://profile.ocsp-backup.example.com"),
                    ],
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
                        policy_identifier=x509.ObjectIdentifier("2.5.29.32.0"), policy_qualifiers=["text1"]
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
                subject_alternative_name(dns(cn)),
                subject_key_identifier(cert),
                tls_feature(x509.TLSFeatureType.status_request, critical=True),
            ],
        )

    @override_tmpcadir(
        CA_PROFILES={
            "everything": {
                "extensions": {
                    "crl_distribution_points": {
                        "critical": True,
                        "value": [
                            {
                                "full_name": ["http://crl.profile.example.com"],
                                "crl_issuer": ["http://crl-issuer.profile.example.com"],
                            },
                            {
                                "full_name": ["http://crl2.profile.example.com"],
                                "crl_issuer": ["http://crl-issuer2.profile.example.com"],
                            },
                        ],
                    },
                    "freshest_crl": {
                        "critical": False,
                        "value": [
                            {
                                "full_name": ["http://freshest-crl.profile.example.com"],
                                "crl_issuer": ["http://freshest-crl-issuer.profile.example.com"],
                            }
                        ],
                    },
                }
            }
        },
        CA_DEFAULT_PROFILE="everything",
    )
    def test_multiple_distribution_points(self) -> None:
        """Create a cert with a full profile, which should mask any CA-specific values.

        This test shows that the values from the profile are prefilled correctly. If they were not, some
        fields would not show up in the signed certificate.
        """
        # Make sure that the CA has field values set.
        cn = "test-only-ca.example.com"
        self.ca.crl_url = ""
        self.ca.issuer_url = ""
        self.ca.ocsp_url = ""
        self.ca.issuer_alt_name = ""
        self.ca.save()

        with self.assertLogs("django_ca") as logcm:
            response = self.app.get(self.add_url, user=self.user.username)
        self.assertEqual(
            logcm.output,
            [
                "WARNING:django_ca.widgets:Received multiple DistributionPoints, only the first can be "
                "changed in the web interface."
            ],
        )
        form = response.forms["certificate_form"]
        # default value for form field is on import time, so override settings does not change
        # profile field
        form["profile"] = "everything"
        form["csr"] = CERT_DATA["child-cert"]["csr"]["pem"]
        form["subject_0"] = json.dumps([{"key": NameOID.COMMON_NAME.dotted_string, "value": cn}])
        response = form.submit()
        response = response.follow()
        self.assertEqual(response.status_code, 200)

        # Check that we get all the extensions from the CA
        cert = Certificate.objects.get(cn="test-only-ca.example.com")
        self.assertEqual(cert.profile, "everything")
        self.assertEqual(
            cert.sorted_extensions,
            [
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
                self.freshest_crl(
                    [uri("http://freshest-crl.profile.example.com")],
                    crl_issuer=[uri("http://freshest-crl-issuer.profile.example.com")],
                    critical=False,
                ),
                subject_alternative_name(dns(cn)),
                subject_key_identifier(cert),
            ],
        )

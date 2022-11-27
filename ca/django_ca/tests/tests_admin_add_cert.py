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

"""Test cases for adding certificates via the admin interface."""

import html
import typing
import unittest
from datetime import datetime, timedelta
from http import HTTPStatus

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from django.conf import settings
from django.http.response import HttpResponse
from django.test import TestCase

from django_webtest import WebTestMixin
from freezegun import freeze_time
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement
from selenium.webdriver.support.select import Select
from webtest import Checkbox, Hidden
from webtest import Select as WebTestSelect
from webtest import Submit

from .. import ca_settings
from ..constants import OID_DEFAULT_CRITICAL
from ..extensions import serialize_extension
from ..extensions.utils import ExtendedKeyUsageOID
from ..fields import CertificateSigningRequestField
from ..models import Certificate, CertificateAuthority
from ..profiles import Profile, profiles
from ..signals import post_issue_cert, pre_issue_cert
from ..typehints import SerializedExtension
from ..utils import MULTIPLE_OIDS, NAME_OID_MAPPINGS, ca_storage, x509_name
from .base import certs, dns, override_tmpcadir, timestamps, uri
from .base.testcases import SeleniumTestCase
from .tests_admin import CertificateModelAdminTestCaseMixin


@freeze_time(timestamps["after_child"])
class AddCertificateTestCase(CertificateModelAdminTestCaseMixin, TestCase):
    """Tests for adding certificates."""

    load_cas = (
        "root",
        "child",
        "pwd",
        "ecc",
    )

    def add_cert(self, cname: str, ca: CertificateAuthority) -> None:
        """Add certificate based on given name with given CA."""
        csr = certs["root-cert"]["csr"]["pem"]

        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            response = self.client.post(
                self.add_url,
                data={
                    "csr": csr,
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": "US",
                    "subject_5": cname,
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA256",
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
        self.assertEqual(pre.call_count, 1)

        cert = Certificate.objects.get(cn=cname)
        self.assertPostIssueCert(post, cert)
        self.assertEqual(cert.pub.loaded.subject, x509_name([("C", "US"), ("CN", cname)]))
        self.assertIssuer(ca, cert)
        self.assertExtensions(
            cert,
            [
                self.extended_key_usage(ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH),
                self.key_usage(digital_signature=True, key_agreement=True),
                self.ocsp_no_check(),
                self.subject_alternative_name(dns(cname)),
                self.tls_feature(x509.TLSFeatureType.status_request, x509.TLSFeatureType.status_request_v2),
            ],
        )
        self.assertEqual(cert.ca, ca)
        self.assertEqual(cert.csr.pem.strip(), csr)
        self.assertEqual(cert.profile, "webserver")

        # Some extensions are not set
        self.assertIsNone(cert.issuer_alternative_name)

        # Test that we can view the certificate
        response = self.client.get(cert.admin_change_url)
        self.assertEqual(response.status_code, HTTPStatus.OK)

    def _test_get(self) -> HttpResponse:
        """Do a basic get request (to test CSS etc)."""
        response = self.client.get(self.add_url)
        self.assertEqual(response.status_code, HTTPStatus.OK)
        templates = [t.name for t in response.templates]
        self.assertIn("admin/django_ca/certificate/change_form.html", templates)
        self.assertIn("admin/change_form.html", templates)
        self.assertCSS(response, "django_ca/admin/css/base.css")
        self.assertCSS(response, "django_ca/admin/css/certificateadmin.css")
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

    @override_tmpcadir(CA_DEFAULT_CA=certs["child"]["serial"])
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
        self.assertEqual(bound_field.initial, self.ocsp_no_check(critical=True))

    @override_tmpcadir(CA_DEFAULT_SUBJECT=tuple())
    def test_add(self) -> None:
        """Test to actually add a certificate."""
        self.add_cert("test-child-add.example.com", self.ca)
        self.add_cert("test-root-add.example.com", self.cas["root"])
        self.add_cert("test-ecc-add.example.com", self.cas["ecc"])

    @override_tmpcadir()
    def test_required_subject(self) -> None:
        """Test that we have to enter a complete subject value."""
        ca = self.cas["root"]
        csr = certs["root-cert"]["csr"]["pem"]
        cert_count = Certificate.objects.all().count()

        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            response = self.client.post(
                self.add_url,
                data={
                    "csr": csr,
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": "US",
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA256",
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
                    "tls_feature_0": ["status_request", "status_request_v2"],
                    "tls_feature_1": False,
                },
            )
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertFalse(response.context["adminform"].form.is_valid())
        self.assertEqual(response.context["adminform"].form.errors, {"subject": ["Enter a complete value."]})
        self.assertEqual(cert_count, Certificate.objects.all().count())

    @override_tmpcadir()
    def test_empty_subject(self) -> None:
        """Test passing an empty subject."""
        ca = self.cas["root"]
        csr = certs["root-cert"]["csr"]["pem"]
        cert_count = Certificate.objects.all().count()

        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            response = self.client.post(
                self.add_url,
                data={
                    "csr": csr,
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": "",
                    "subject_1": "",
                    "subject_2": "",
                    "subject_3": "",
                    "subject_4": "",
                    "subject_5": "",
                    "subject_6": "",
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA256",
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
                    "tls_feature_0": ["status_request", "status_request_v2"],
                    "tls_feature_1": False,
                },
            )
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertFalse(response.context["adminform"].form.is_valid())
        self.assertEqual(response.context["adminform"].form.errors, {"subject": ["This field is required."]})
        self.assertEqual(cert_count, Certificate.objects.all().count())

    @override_tmpcadir(CA_DEFAULT_SUBJECT=tuple())
    def test_add_no_common_name(self) -> None:
        """Test posting no common name but some other name components."""

        ca = self.cas["root"]
        csr = certs["root-cert"]["csr"]["pem"]
        cert_count = Certificate.objects.all().count()

        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            response = self.client.post(
                self.add_url,
                data={
                    "csr": csr,
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": "AT",
                    "subject_1": "",
                    "subject_2": "",
                    "subject_3": "",
                    "subject_4": "",
                    "subject_5": "",
                    "subject_6": "",
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA256",
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
                    "tls_feature_0": ["status_request", "status_request_v2"],
                    "tls_feature_1": False,
                },
            )
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertFalse(response.context["adminform"].form.is_valid())
        self.assertEqual(response.context["adminform"].form.errors, {"subject": ["Enter a complete value."]})
        self.assertEqual(cert_count, Certificate.objects.all().count())

    @override_tmpcadir(CA_DEFAULT_SUBJECT=tuple())
    def test_add_no_key_usage(self) -> None:
        """Test adding a cert with no (extended) key usage."""
        ca = self.cas["root"]
        csr = certs["root-cert"]["csr"]["pem"]
        cname = "test-add2.example.com"
        san = "test-san.example.com"

        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            response = self.client.post(
                self.add_url,
                data={
                    "csr": csr,
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": "US",
                    "subject_5": cname,
                    "subject_alternative_name_0": san,
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA256",
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
        self.assertEqual(pre.call_count, 1)
        self.assertRedirects(response, self.changelist_url)

        cert = Certificate.objects.get(cn=cname)
        self.assertPostIssueCert(post, cert)
        self.assertEqual(cert.pub.loaded.subject, x509_name([("C", "US"), ("CN", cname)]))
        self.assertIssuer(ca, cert)
        self.assertEqual(cert.ca, ca)
        self.assertEqual(cert.csr.pem.strip(), csr)

        # Some extensions are not set
        self.assertExtensions(cert, [self.subject_alternative_name(dns(san), dns(cname))])

        # Test that we can view the certificate
        response = self.client.get(cert.admin_change_url)
        self.assertEqual(response.status_code, HTTPStatus.OK)

    @override_tmpcadir(CA_DEFAULT_SUBJECT=tuple())
    def test_add_with_password(self) -> None:
        """Test adding with a password."""
        ca = self.cas["pwd"]
        csr = certs["pwd-cert"]["csr"]["pem"]
        cname = "with-password.example.com"

        # first post without password
        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            response = self.client.post(
                self.add_url,
                data={
                    "csr": csr,
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": "US",
                    "subject_5": cname,
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA256",
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
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertFalse(response.context["adminform"].form.is_valid())
        self.assertEqual(
            response.context["adminform"].form.errors,
            {"password": ["Password was not given but private key is encrypted"]},
        )

        # now post with a false password
        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            response = self.client.post(
                self.add_url,
                data={
                    "csr": csr,
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": "US",
                    "subject_5": cname,
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA256",
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
                    "password": "wrong",
                },
            )
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertFalse(response.context["adminform"].form.is_valid())
        self.assertEqual(
            response.context["adminform"].form.errors,
            {"password": ["Could not decrypt private key - bad password?"]},
        )

        # post with correct password!
        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            response = self.client.post(
                self.add_url,
                data={
                    "csr": csr,
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": "US",
                    "subject_5": cname,
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA256",
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
                    "crl_distribution_points_0": ca.crl_url,
                    "crl_distribution_points_1": "",
                    "crl_distribution_points_2": "",
                    "crl_distribution_points_3": [],
                    "crl_distribution_points_4": False,
                    "authority_information_access_0": ca.issuer_url,
                    "authority_information_access_1": ca.ocsp_url,
                    "authority_information_access_2": False,
                    "password": certs["pwd"]["password"].decode("utf-8"),
                },
            )
        self.assertEqual(pre.call_count, 1)
        self.assertRedirects(response, self.changelist_url)

        cert = Certificate.objects.get(cn=cname)
        self.assertPostIssueCert(post, cert)
        self.assertEqual(cert.pub.loaded.subject, x509_name([("C", "US"), ("CN", cname)]))
        self.assertIssuer(ca, cert)
        self.assertAuthorityKeyIdentifier(ca, cert)

        self.assertEqual(
            cert.x509_extensions[ExtensionOID.SUBJECT_ALTERNATIVE_NAME],
            self.subject_alternative_name(dns(cname)),
        )
        self.assertExtensions(
            cert,
            [
                self.subject_alternative_name(dns(cname)),
                self.key_usage(digital_signature=True, key_agreement=True),
                self.extended_key_usage(ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH),
            ],
        )
        self.assertEqual(cert.ca, ca)
        self.assertEqual(cert.csr.pem.strip(), csr)

        # Some extensions are not set
        self.assertIsNone(cert.certificate_policies)
        self.assertIsNone(cert.issuer_alternative_name)
        self.assertIsNone(cert.precertificate_signed_certificate_timestamps)
        self.assertIsNone(cert.tls_feature)

        # Test that we can view the certificate
        response = self.client.get(cert.admin_change_url)
        self.assertEqual(response.status_code, HTTPStatus.OK)

    @override_tmpcadir()
    def test_wrong_csr(self) -> None:
        """Test passing an unparseable CSR."""
        ca = self.cas["root"]
        cname = "test-add-wrong-csr.example.com"

        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            response = self.client.post(
                self.add_url,
                data={
                    "csr": "whatever",
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": "US",
                    "subject_5": cname,
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA256",
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
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertFalse(response.context["adminform"].form.is_valid())
        self.assertEqual(
            response.context["adminform"].form.errors,
            {"csr": [CertificateSigningRequestField.simple_validation_error]},
        )

        with self.assertRaises(Certificate.DoesNotExist):
            Certificate.objects.get(cn=cname)

    @override_tmpcadir()
    def test_unparseable_csr(self) -> None:
        """Test passing something that looks like a CSR but isn't.

        This is different from test_wrong_csr() because this passes our initial test, but cryptography itself
        fails to load the CSR.
        """
        ca = self.cas["root"]
        cname = "test-add-wrong-csr.example.com"

        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            response = self.client.post(
                self.add_url,
                data={
                    "csr": "-----BEGIN CERTIFICATE REQUEST-----\nwrong-----END CERTIFICATE REQUEST-----",
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": "US",
                    "subject_5": cname,
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA256",
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
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertFalse(response.context["adminform"].form.is_valid())

        # Not testing exact error message here, as it the one from cryptography. Instead, just check that
        # there is exactly one message for the "csr" field.
        self.assertEqual(len(response.context["adminform"].form.errors), 1)
        self.assertEqual(len(response.context["adminform"].form.errors["csr"]), 1)

        with self.assertRaises(Certificate.DoesNotExist):
            Certificate.objects.get(cn=cname)

    @override_tmpcadir()
    def test_wrong_algorithm(self) -> None:
        """Test selecting an unknown algorithm."""
        ca = self.cas["root"]
        csr = certs["pwd-cert"]["csr"]["pem"]
        cname = "test-add-wrong-algo.example.com"

        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            response = self.client.post(
                self.add_url,
                data={
                    "csr": csr,
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": "US",
                    "subject_5": cname,
                    "subject_alternative_name_1": True,
                    "algorithm": "wrong algo",
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
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertEqual(response.status_code, HTTPStatus.OK)

        self.assertFalse(response.context["adminform"].form.is_valid())
        self.assertEqual(
            response.context["adminform"].form.errors,
            {"algorithm": ["Select a valid choice. wrong algo is not one of the available choices."]},
        )

        with self.assertRaises(Certificate.DoesNotExist):
            Certificate.objects.get(cn=cname)

    @override_tmpcadir()
    def test_expires_in_the_past(self) -> None:
        """Test creating a cert that expires in the past."""
        ca = self.cas["root"]
        csr = certs["pwd-cert"]["csr"]["pem"]
        cname = "test-expires-in-the-past.example.com"
        expires = datetime.now() - timedelta(days=3)

        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            response = self.client.post(
                self.add_url,
                data={
                    "csr": csr,
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": "US",
                    "subject_5": cname,
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA256",
                    "expires": expires.strftime("%Y-%m-%d"),
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
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
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
        csr = certs["pwd-cert"]["csr"]["pem"]
        cname = "test-expires-too-late.example.com"
        expires = ca.expires + timedelta(days=3)
        correct_expires = ca.expires.strftime("%Y-%m-%d")
        error = f"CA expires on {correct_expires}, certificate must not expire after that."

        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            response = self.client.post(
                self.add_url,
                data={
                    "csr": csr,
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": "US",
                    "subject_5": cname,
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA256",
                    "expires": expires.strftime("%Y-%m-%d"),
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
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertIn(error, response.content.decode("utf-8"))
        self.assertFalse(response.context["adminform"].form.is_valid())
        self.assertEqual(response.context["adminform"].form.errors, {"expires": [error]})

        with self.assertRaises(Certificate.DoesNotExist):
            Certificate.objects.get(cn=cname)

    @override_tmpcadir()
    def test_invalid_cn_in_san(self) -> None:
        """Test that if you submit a CommonName that is not parseable as SubjectAlternativeName, but check "CN
        in SAN", an error is thrown.

        .. seealso:: https://github.com/mathiasertl/django-ca/issues/62
        """
        cname = "Foo Bar"
        error = "The CommonName cannot be parsed as general name. Either change the CommonName or do not include it."  # NOQA
        ca = self.cas["root"]
        csr = certs["root-cert"]["csr"]["pem"]

        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            response = self.client.post(
                self.add_url,
                data={
                    "csr": csr,
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": "US",
                    "subject_5": cname,
                    "subject_alternative_name_1": True,  # cn_in_san
                    "algorithm": "SHA256",
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
                    "tls_feature_0": ["status_request", "status_request_v2"],
                    "tls_feature_1": False,
                },
            )
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertIn(html.escape(error), response.content.decode("utf-8"))
        self.assertFalse(response.context["adminform"].form.is_valid())
        self.assertEqual(response.context["adminform"].form.errors, {"subject_alternative_name": [error]})

        with self.assertRaises(Certificate.DoesNotExist):
            Certificate.objects.get(cn=cname)

    def test_add_no_cas(self) -> None:
        """Test adding when all CAs are disabled."""
        ca = self.cas["root"]
        csr = certs["pwd-cert"]["csr"]["pem"]
        CertificateAuthority.objects.update(enabled=False)
        response = self.client.get(self.add_url)
        self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)

        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            response = self.client.post(
                self.add_url,
                data={
                    "csr": csr,
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": "US",
                    "subject_5": "test-add-no-cas.example.com",
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA256",
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
        self.assertFalse(pre.called)
        self.assertFalse(post.called)

    def test_add_unusable_cas(self) -> None:
        """Try adding with an unusable CA."""
        ca = self.cas["root"]
        csr = certs["pwd-cert"]["csr"]["pem"]
        CertificateAuthority.objects.update(private_key_path="not/exist/add-unusable-cas")

        # check that we have some enabled CAs, just to make sure this test is really useful
        self.assertTrue(CertificateAuthority.objects.filter(enabled=True).exists())

        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            response = self.client.get(self.add_url)
        self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)
        self.assertFalse(pre.called)
        self.assertFalse(post.called)

        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            response = self.client.post(
                self.add_url,
                data={
                    "csr": csr,
                    "ca": ca.pk,
                    "profile": "webserver",
                    "subject_0": "US",
                    "subject_5": "test-add.example.com",
                    "subject_alternative_name_1": True,
                    "algorithm": "SHA256",
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
        self.assertFalse(pre.called)
        self.assertFalse(post.called)


@unittest.skipIf(settings.SKIP_SELENIUM_TESTS, "Selenium tests skipped.")
class AddCertificateSeleniumTestCase(CertificateModelAdminTestCaseMixin, SeleniumTestCase):
    """Some Selenium based test cases to test the client side javascript code."""

    load_cas = "__usable__"

    def get_expected(
        self, profile: Profile, oid: x509.ObjectIdentifier, default: typing.Any = None
    ) -> SerializedExtension:
        """Get expected value for a given extension for the given profile."""
        if oid in profile.extensions:
            return serialize_extension(profile.extensions[oid])  # type: ignore[arg-type]
        return {"value": default, "critical": OID_DEFAULT_CRITICAL[oid]}

    def assertProfile(  # pylint: disable=invalid-name,too-many-locals
        self,
        profile_name: str,
        ku_select: Select,
        ku_critical: WebElement,
        eku_select: Select,
        eku_critical: WebElement,
        tf_select: Select,
        tf_critical: WebElement,
        subject: typing.Dict[str, WebElement],
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

        for key, field in subject.items():
            oid = NAME_OID_MAPPINGS[key]
            value = field.get_attribute("value")

            # OIDs that can occur multiple times are stored as list in subject, so we wrap it
            attrs = [attr.value for attr in profile.subject.get_attributes_for_oid(oid)]
            if not attrs:
                attrs = [""]
            if NAME_OID_MAPPINGS[key] in MULTIPLE_OIDS:
                self.assertEqual([value], attrs)
            else:
                self.assertEqual(value, attrs[0])

    def clear_form(
        self,
        ku_select: Select,
        ku_critical: WebElement,
        eku_select: Select,
        eku_critical: WebElement,
        tf_select: Select,
        tf_critical: WebElement,
        subject: typing.Dict[str, WebElement],
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
        for field in subject.values():
            field.clear()

    @override_tmpcadir()
    def test_paste_csr_test(self) -> None:
        """Test that pasting a CSR shows text next to subject input fields."""
        self.login()

        self.selenium.get(f"{self.live_server_url}{self.add_url}")

        cert = certs["all-extensions"]
        csr = self.find("textarea#id_csr")
        csr.send_keys(cert["csr"]["pem"])

        subject_fields = {
            "C": self.find(".field-subject #country"),
            "ST": self.find(".field-subject #state"),
            "L": self.find(".field-subject #location"),
            "O": self.find(".field-subject #organization"),
            "OU": self.find(".field-subject #organizational-unit"),
            "CN": self.find(".field-subject #commonname"),
            "emailAddress": self.find(".field-subject #e-mail"),
        }

        for key, elem in subject_fields.items():
            input_elem = elem.find_element(By.CSS_SELECTOR, "input")
            csr_copy = elem.find_element(By.CSS_SELECTOR, ".from-csr-copy")
            from_csr = elem.find_element(By.CSS_SELECTOR, ".from-csr-value")
            self.assertEqual(from_csr.text, cert["csr_subject"][key])

            # click the 'copy' button
            csr_copy.click()

            self.assertEqual(from_csr.text, input_elem.get_attribute("value"))

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

        subject_fields = {
            "C": self.find(".field-subject #country input"),
            "ST": self.find(".field-subject #state input"),
            "L": self.find(".field-subject #location input"),
            "O": self.find(".field-subject #organization input"),
            "OU": self.find(".field-subject #organizational-unit input"),
            "CN": self.find(".field-subject #commonname input"),
            "emailAddress": self.find(".field-subject #e-mail input"),
        }
        cn_in_san = self.find("input#id_subject_alternative_name_1")

        # test that the default profile is preselected
        self.assertEqual(
            [ca_settings.CA_DEFAULT_PROFILE], [o.get_attribute("value") for o in select.all_selected_options]
        )

        # assert that the values from the default profile are pre-loaded
        self.assertProfile(
            ca_settings.CA_DEFAULT_PROFILE,
            ku_select,
            ku_critical,
            eku_select,
            eku_critical,
            tf_select,
            tf_critical,
            subject_fields,
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
                subject_fields,
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
                subject_fields,
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

            for field in subject_fields.values():
                field.clear()
                field.send_keys("testdata")

            # select empty element in profile select, then select profile again
            select.select_by_value(ca_settings.CA_DEFAULT_PROFILE)
            self.clear_form(
                ku_select,
                ku_critical,
                eku_select,
                eku_critical,
                tf_select,
                tf_critical,
                subject_fields,
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
                subject_fields,
                cn_in_san,
            )


@freeze_time(timestamps["everything_valid"])
class AddCertificateWebTestTestCase(CertificateModelAdminTestCaseMixin, WebTestMixin, TestCase):
    """Tests for adding certificates."""

    load_cas = ("root", "child")

    @override_tmpcadir()
    def test_empty_form_and_empty_cert(self) -> None:
        """Test submitting an empty form, then filling it with values and submitting it."""
        response = self.app.get(self.add_url, user=self.user.username)
        form = response.forms["certificate_form"]
        for key, field_list in form.fields.items():
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
        form["csr"] = certs["child-cert"]["csr"]["pem"]
        form["subject_5"] = "test-empty-form.example.com"
        form["expires"] = (datetime.utcnow() + timedelta(days=10)).strftime("%Y-%m-%d")

        # Submit the form
        response = form.submit().follow()
        self.assertEqual(response.status_code, 200)
        cert = Certificate.objects.get(cn="test-empty-form.example.com")

        # Cert has minimal extensions, since we cleared the form  earlier
        self.assertEqual(
            cert.sorted_extensions,
            [
                cert.ca.get_authority_key_identifier_extension(),
                self.basic_constraints(),
                self.subject_key_identifier(cert),
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
        form["csr"] = certs["child-cert"]["csr"]["pem"]
        form["subject_5"] = self.hostname
        response = form.submit().follow()
        self.assertEqual(response.status_code, 200)

        cert = Certificate.objects.get(cn=self.hostname)
        self.assertEqual(
            cert.sorted_extensions,
            [
                self.authority_information_access(
                    ca_issuers=[uri(self.ca.issuer_url)],  # type: ignore[arg-type]
                    ocsp=[uri(self.ca.ocsp_url)],  # type: ignore[arg-type]
                ),
                cert.ca.get_authority_key_identifier_extension(),
                self.basic_constraints(),
                self.crl_distribution_points(full_name=[uri(self.ca.crl_url)]),
                self.subject_alternative_name(dns(self.hostname)),
                self.subject_key_identifier(cert),
            ],
        )

    @override_tmpcadir(CA_PROFILES={"nothing": {}}, CA_DEFAULT_PROFILE="nothing")
    def test_only_ca_prefill(self) -> None:
        """Create a cert with an empty profile.

        This test shows that the values from the CA are prefilled correctly. If they where not, some
        of the fields would not show up in the signed certificate.
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
        form["csr"] = certs["child-cert"]["csr"]["pem"]
        form["subject_5"] = cn
        response = form.submit().follow()
        self.assertEqual(response.status_code, 200)

        # Check that we get all the extensions from the CA
        cert = Certificate.objects.get(cn="test-only-ca.example.com")
        self.assertEqual(
            cert.sorted_extensions,
            [
                self.authority_information_access(
                    ca_issuers=[uri(self.ca.issuer_url)], ocsp=[uri(self.ca.ocsp_url)]
                ),
                cert.ca.get_authority_key_identifier_extension(),
                self.basic_constraints(),
                self.crl_distribution_points(full_name=[uri(self.ca.crl_url)]),
                self.issuer_alternative_name(uri(self.ca.issuer_alt_name)),
                self.subject_alternative_name(dns(cn)),
                self.subject_key_identifier(cert),
            ],
        )

    @override_tmpcadir(
        CA_PROFILES={
            "everything": {
                "extensions": {
                    "authority_information_access": {
                        "critical": True,  # NOTE: Yes, this is an RFC 5280 violation
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
                        "critical": True,
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

        This test shows that the values from the profile are prefilled correctly. If they where not, some
        of the fields would not show up in the signed certificate.
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
        form["csr"] = certs["child-cert"]["csr"]["pem"]
        form["subject_5"] = cn
        response = form.submit().follow()
        self.assertEqual(response.status_code, 200)

        # Check that we get all the extensions from the CA
        cert = Certificate.objects.get(cn="test-only-ca.example.com")
        self.assertEqual(cert.profile, "everything")
        self.assertEqual(
            cert.sorted_extensions,
            [
                self.authority_information_access(
                    ca_issuers=[uri("http://profile.issuers.example.com")],
                    ocsp=[
                        uri("http://profile.ocsp.example.com"),
                        uri("http://profile.ocsp-backup.example.com"),
                    ],
                    critical=True,
                ),
                cert.ca.get_authority_key_identifier_extension(),
                self.basic_constraints(),
                self.crl_distribution_points(
                    full_name=[uri("http://crl.profile.example.com")],
                    crl_issuer=[uri("http://crl-issuer.profile.example.com")],
                    critical=True,
                ),
                x509.Extension(
                    oid=ExtensionOID.CERTIFICATE_POLICIES,
                    critical=True,
                    value=x509.CertificatePolicies(
                        [
                            x509.PolicyInformation(
                                policy_identifier=x509.ObjectIdentifier("2.5.29.32.0"),
                                policy_qualifiers=["text1"],
                            )
                        ]
                    ),
                ),
                self.extended_key_usage(
                    ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH, critical=True
                ),
                self.freshest_crl(
                    [uri("http://freshest-crl.profile.example.com")],
                    crl_issuer=[uri("http://freshest-crl-issuer.profile.example.com")],
                    critical=True,
                ),
                self.issuer_alternative_name(
                    uri("http://ian1.example.com"), uri("http://ian2.example.com"), critical=True
                ),
                self.key_usage(key_agreement=True, key_cert_sign=True),
                self.ocsp_no_check(critical=True),
                self.subject_alternative_name(dns(cn)),
                self.subject_key_identifier(cert),
                self.tls_feature(x509.TLSFeatureType.status_request, critical=True),
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
                        "critical": True,
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

        This test shows that the values from the profile are prefilled correctly. If they where not, some
        of the fields would not show up in the signed certificate.
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
        form["csr"] = certs["child-cert"]["csr"]["pem"]
        form["subject_5"] = cn
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
                self.basic_constraints(),
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
                    critical=True,
                ),
                self.subject_alternative_name(dns(cn)),
                self.subject_key_identifier(cert),
            ],
        )

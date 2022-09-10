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
from datetime import datetime
from datetime import timedelta
from http import HTTPStatus

from cryptography import x509

from django.conf import settings
from django.test import TestCase

from freezegun import freeze_time
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement
from selenium.webdriver.support.select import Select

from .. import ca_settings
from ..extensions import BasicConstraints
from ..extensions import ExtendedKeyUsage
from ..extensions import Extension
from ..extensions import KeyUsage
from ..extensions import SubjectAlternativeName
from ..extensions import TLSFeature
from ..extensions.utils import ExtendedKeyUsageOID
from ..fields import CertificateSigningRequestField
from ..models import Certificate
from ..models import CertificateAuthority
from ..profiles import Profile
from ..profiles import profiles
from ..signals import post_issue_cert
from ..signals import pre_issue_cert
from ..typehints import ExtensionTypeTypeVar
from ..typehints import ParsableValue
from ..typehints import SerializedExtension
from ..typehints import SerializedValue
from ..utils import MULTIPLE_OIDS
from ..utils import NAME_OID_MAPPINGS
from ..utils import x509_name
from .base import certs
from .base import override_settings
from .base import override_tmpcadir
from .base import timestamps
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
                        "digitalSignature",
                        "keyAgreement",
                    ],
                    "key_usage_1": True,
                    "extended_key_usage_0": [
                        "clientAuth",
                        "serverAuth",
                    ],
                    "extended_key_usage_1": False,
                    "tls_feature_0": ["OCSPMustStaple", "MultipleCertStatusRequest"],
                    "tls_feature_1": False,
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
                self.subject_alternative_name(x509.DNSName(cname)),
                self.tls_feature(x509.TLSFeatureType.status_request_v2, x509.TLSFeatureType.status_request),
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

    @override_tmpcadir()
    def test_get(self) -> None:
        """Do a basic get request (to test CSS etc)."""
        response = self.client.get(self.add_url)
        self.assertEqual(response.status_code, HTTPStatus.OK)
        templates = [t.name for t in response.templates]
        self.assertIn("admin/django_ca/certificate/change_form.html", templates)
        self.assertIn("admin/change_form.html", templates)
        self.assertCSS(response, "django_ca/admin/css/base.css")
        self.assertCSS(response, "django_ca/admin/css/certificateadmin.css")

    @override_settings(CA_PROFILES={}, CA_DEFAULT_SUBJECT=tuple())
    def test_get_dict(self) -> None:
        """Test get with no profiles and no default subject."""
        self.test_get()

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
                        "digitalSignature",
                        "keyAgreement",
                    ],
                    "key_usage_1": True,
                    "extended_key_usage_0": [
                        "clientAuth",
                        "serverAuth",
                    ],
                    "extended_key_usage_1": False,
                    "tls_feature_0": ["OCSPMustStaple", "MultipleCertStatusRequest"],
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
                        "digitalSignature",
                        "keyAgreement",
                    ],
                    "key_usage_1": True,
                    "extended_key_usage_0": [
                        "clientAuth",
                        "serverAuth",
                    ],
                    "extended_key_usage_1": False,
                    "tls_feature_0": ["OCSPMustStaple", "MultipleCertStatusRequest"],
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
                        "digitalSignature",
                        "keyAgreement",
                    ],
                    "key_usage_1": True,
                    "extended_key_usage_0": [
                        "clientAuth",
                        "serverAuth",
                    ],
                    "extended_key_usage_1": False,
                    "tls_feature_0": ["OCSPMustStaple", "MultipleCertStatusRequest"],
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
        self.assertExtensions(cert, [self.subject_alternative_name(x509.DNSName(san), x509.DNSName(cname))])

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
                        "digitalSignature",
                        "keyAgreement",
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
                        "digitalSignature",
                        "keyAgreement",
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
                        "digitalSignature",
                        "keyAgreement",
                    ],
                    "key_usage_1": True,
                    "extended_key_usage_0": [
                        "clientAuth",
                        "serverAuth",
                    ],
                    "extended_key_usage_1": False,
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
        self.assertEqual(cert.subject_alternative_name, SubjectAlternativeName({"value": [f"DNS:{cname}"]}))
        self.assertEqual(cert.basic_constraints, BasicConstraints({"critical": True, "value": {"ca": False}}))
        self.assertEqual(
            cert.key_usage, KeyUsage({"critical": True, "value": ["digitalSignature", "keyAgreement"]})
        )
        self.assertEqual(cert.extended_key_usage, ExtendedKeyUsage({"value": ["clientAuth", "serverAuth"]}))
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
                        "digitalSignature",
                        "keyAgreement",
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
                        "digitalSignature",
                        "keyAgreement",
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
                        "digitalSignature",
                        "keyAgreement",
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
                        "digitalSignature",
                        "keyAgreement",
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
                        "digitalSignature",
                        "keyAgreement",
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
                        "digitalSignature",
                        "keyAgreement",
                    ],
                    "key_usage_1": True,
                    "extended_key_usage_0": [
                        "clientAuth",
                        "serverAuth",
                    ],
                    "extended_key_usage_1": False,
                    "tls_feature_0": ["OCSPMustStaple", "MultipleCertStatusRequest"],
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
                        "digitalSignature",
                        "keyAgreement",
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
                        "digitalSignature",
                        "keyAgreement",
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
        self,
        profile: Profile,
        extension_class: typing.Type[Extension[ExtensionTypeTypeVar, ParsableValue, SerializedValue]],
        default: typing.Any = None,
    ) -> SerializedExtension:
        """Get expected value for a given extension for the given profile."""
        if extension_class.key in profile.extensions:
            return profile.extensions[extension_class.key].serialize()
        return {"value": default, "critical": extension_class.default_critical}

    def assertProfile(  # pylint: disable=invalid-name
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

        ku_expected = self.get_expected(profile, KeyUsage, [])
        ku_selected = [o.get_attribute("value") for o in ku_select.all_selected_options]
        self.assertCountEqual(ku_expected["value"], ku_selected)
        self.assertEqual(ku_expected["critical"], ku_critical.is_selected())

        eku_expected = self.get_expected(profile, ExtendedKeyUsage, [])
        eku_selected = [o.get_attribute("value") for o in eku_select.all_selected_options]
        self.assertCountEqual(eku_expected["value"], eku_selected)
        self.assertEqual(eku_expected["critical"], eku_critical.is_selected())

        tf_selected = [o.get_attribute("value") for o in tf_select.all_selected_options]
        tf_expected = self.get_expected(profile, TLSFeature, [])
        self.assertCountEqual(tf_expected.get("value", []), tf_selected)
        self.assertEqual(tf_expected.get("critical", False), tf_critical.is_selected())

        self.assertEqual(profile.cn_in_san, cn_in_san.is_selected())

        for key, field in subject.items():
            value = field.get_attribute("value")

            # OIDs that can occur multiple times are stored as list in subject, so we wrap it
            if NAME_OID_MAPPINGS[key] in MULTIPLE_OIDS:
                self.assertEqual([value], profile.subject.get(key, ""))
            else:
                self.assertEqual(value, profile.subject.get(key, ""))

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
            input_elem = elem.find_element(By.CSS_SELECTOR, "input")  # type: ignore[var-annotated]
            csr_copy = elem.find_element(By.CSS_SELECTOR, ".from-csr-copy")  # type: ignore[var-annotated]
            from_csr = elem.find_element(By.CSS_SELECTOR, ".from-csr-value")  # type: ignore[var-annotated]
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

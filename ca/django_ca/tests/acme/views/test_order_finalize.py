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

"""Test AcmeOrderFinalizeView."""

from http import HTTPStatus
from unittest import mock
from unittest.mock import patch

import acme
import josepy as jose
import pyrfc3339

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import hashes
from OpenSSL.crypto import X509Req

from django.test import TransactionTestCase, override_settings
from django.urls import reverse, reverse_lazy

from freezegun import freeze_time

from django_ca.acme.messages import CertificateRequest
from django_ca.models import AcmeAccount, AcmeAuthorization, AcmeOrder, CertificateAuthority
from django_ca.tasks import acme_issue_certificate
from django_ca.tests.acme.views.assertions import assert_acme_problem, assert_acme_response
from django_ca.tests.acme.views.base import AcmeWithAccountViewTestCaseMixin
from django_ca.tests.base.constants import CERT_DATA, FIXTURES_DIR, TIMESTAMPS
from django_ca.tests.base.typehints import HttpResponse
from django_ca.tests.base.utils import dns, override_tmpcadir


def assert_bad_csr(response: "HttpResponse", message: str, ca: CertificateAuthority) -> None:
    """Assert a badCSR error."""
    assert_acme_problem(response, "badCSR", ca=ca, status=HTTPStatus.BAD_REQUEST, message=message)


@freeze_time(TIMESTAMPS["everything_valid"])
class AcmeOrderFinalizeViewTestCase(
    AcmeWithAccountViewTestCaseMixin[CertificateRequest], TransactionTestCase
):
    """Test retrieving a challenge."""

    slug = "92MPyl7jm0zw"
    url = reverse_lazy(
        "django_ca:acme-order-finalize", kwargs={"serial": CERT_DATA["root"]["serial"], "slug": slug}
    )

    def setUp(self) -> None:
        super().setUp()

        # Create a CSR based on root-cert
        # NOTE: certbot CSRs have an empty subject
        self.csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([]))
            .add_extension(x509.SubjectAlternativeName([dns(self.hostname)]), critical=False)
            .sign(CERT_DATA["root-cert"]["key"]["parsed"], hashes.SHA256())
        )

        self.order = AcmeOrder.objects.create(
            account=self.account, status=AcmeOrder.STATUS_READY, slug=self.slug
        )
        self.order.add_authorizations(
            [acme.messages.Identifier(typ=acme.messages.IDENTIFIER_FQDN, value=self.hostname)]
        )
        self.authz = AcmeAuthorization.objects.get(order=self.order, value=self.hostname)
        self.authz.status = AcmeAuthorization.STATUS_VALID
        self.authz.save()

    def get_message(  # type: ignore[override]
        self, csr: x509.CertificateSigningRequest
    ) -> CertificateRequest:
        """Get a message for the given cryptography CSR object."""
        req = X509Req.from_cryptography(csr)
        return CertificateRequest(csr=jose.util.ComparableX509(req))

    @property
    def message(self) -> CertificateRequest:
        """Default message to send to the server."""
        return self.get_message(self.csr)

    @override_tmpcadir()
    def test_basic(self, accept_naive: bool = False) -> None:
        """Basic test for creating an account via ACME."""
        with patch("django_ca.acme.views.run_task") as mockcm:
            resp = self.acme(self.url, self.message, kid=self.kid)
        assert resp.status_code == HTTPStatus.OK, resp.content
        assert_acme_response(resp, self.ca)

        order = AcmeOrder.objects.get(pk=self.order.pk)
        cert = order.acmecertificate
        assert mockcm.call_args_list == [mock.call(acme_issue_certificate, acme_certificate_pk=cert.pk)]

        assert resp.json() == {
            "authorizations": [f"http://{self.SERVER_NAME}{self.authz.acme_url}"],
            "expires": pyrfc3339.generate(order.expires, accept_naive=accept_naive),
            "identifiers": [{"type": "dns", "value": self.hostname}],
            "status": "processing",
        }

    @override_settings(USE_TZ=False)
    def test_basic_without_tz(self) -> None:
        """Basic test without timezone support."""
        self.test_basic(True)

    @override_tmpcadir()
    def test_unknown_key_backend(self) -> None:
        """Test that the frontend does not need to know about the backend."""
        self.ca.key_backend_alias = "unknown"
        self.ca.save()

        with patch("django_ca.acme.views.run_task") as mockcm:
            resp = self.acme(self.url, self.message, kid=self.kid)
        assert resp.status_code == HTTPStatus.OK, resp.content
        assert_acme_response(resp, self.ca)

        order = AcmeOrder.objects.get(pk=self.order.pk)
        cert = order.acmecertificate
        assert mockcm.call_args_list == [mock.call(acme_issue_certificate, acme_certificate_pk=cert.pk)]

        assert resp.json() == {
            "authorizations": [f"http://{self.SERVER_NAME}{self.authz.acme_url}"],
            "expires": pyrfc3339.generate(order.expires, accept_naive=False),
            "identifiers": [{"type": "dns", "value": self.hostname}],
            "status": "processing",
        }

    @override_tmpcadir()
    def test_not_found(self) -> None:
        """Test an order that does not exist."""
        url = reverse("django_ca:acme-order-finalize", kwargs={"serial": self.ca.serial, "slug": "foo"})
        with patch("django_ca.acme.views.run_task") as mockcm:
            resp = self.acme(url, self.message, kid=self.kid)
        mockcm.assert_not_called()
        self.assertUnauthorized(resp, "You are not authorized to perform this request.")

    @override_tmpcadir()
    def test_wrong_account(self) -> None:
        """Test an order for a different account."""
        account = AcmeAccount.objects.create(
            ca=self.ca, terms_of_service_agreed=True, slug="def", kid="kid", pem="bar", thumbprint="foo"
        )
        self.order.account = account
        self.order.save()

        with patch("django_ca.acme.views.run_task") as mockcm:
            resp = self.acme(self.url, self.message, kid=self.kid)
        mockcm.assert_not_called()
        self.assertUnauthorized(resp, "You are not authorized to perform this request.")

    @override_tmpcadir()
    def test_not_ready(self) -> None:
        """Test an order that is not yet ready."""
        self.order.status = AcmeOrder.STATUS_INVALID
        self.order.save()

        with patch("django_ca.acme.views.run_task") as mockcm:
            resp = self.acme(self.url, self.message, kid=self.kid)
        mockcm.assert_not_called()
        self.assertAcmeProblem(
            resp, "orderNotReady", status=HTTPStatus.FORBIDDEN, message="This order is not yet ready."
        )

    @override_tmpcadir()
    def test_invalid_auth(self) -> None:
        """Test an order where one of the authentications is not valid."""
        self.authz.status = AcmeAuthorization.STATUS_INVALID
        self.authz.save()

        with patch("django_ca.acme.views.run_task") as mockcm:
            resp = self.acme(self.url, self.message, kid=self.kid)
        mockcm.assert_not_called()
        self.assertAcmeProblem(
            resp, "orderNotReady", status=HTTPStatus.FORBIDDEN, message="This order is not yet ready."
        )

    @override_tmpcadir()
    def test_csr_invalid_signature(self) -> None:
        """Test posting a CSR with an invalid signature."""
        # create property mock for CSR object.
        # We mock parse_acme_csr below because the actual class returned depends on the backend in use
        csr_mock = mock.MagicMock()
        # attach to type: https://docs.python.org/3/library/unittest.mock.html#unittest.mock.PropertyMock
        type(csr_mock).is_signature_valid = mock.PropertyMock(return_value=False)

        with (
            patch("django_ca.acme.views.run_task") as mockcm,
            patch("django_ca.acme.views.parse_acme_csr", return_value=csr_mock),
        ):
            resp = self.acme(self.url, self.message, kid=self.kid)
        mockcm.assert_not_called()
        assert_bad_csr(resp, "CSR signature is not valid.", self.ca)

    @override_tmpcadir()
    def test_csr_bad_algorithm(self) -> None:
        """Test posting a CSR with a bad algorithm."""
        with open(FIXTURES_DIR / "md5.csr.pem", "rb") as stream:
            signed_csr = x509.load_pem_x509_csr(stream.read())

        with patch("django_ca.acme.views.run_task") as mockcm:
            resp = self.acme(self.url, self.get_message(signed_csr), kid=self.kid)
        mockcm.assert_not_called()
        assert_bad_csr(resp, "md5: Insecure hash algorithm.", self.ca)

        with open(FIXTURES_DIR / "sha1.csr.pem", "rb") as stream:
            signed_csr = x509.load_pem_x509_csr(stream.read())

        with patch("django_ca.acme.views.run_task") as mockcm:
            resp = self.acme(self.url, self.get_message(signed_csr), kid=self.kid)
        mockcm.assert_not_called()
        assert_bad_csr(resp, "sha1: Insecure hash algorithm.", self.ca)

    @override_tmpcadir()
    def test_csr_valid_subject(self) -> None:
        """Test posting a CSR where the CommonName was in the order."""
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, self.hostname),
                    ]
                )
            )
            .add_extension(x509.SubjectAlternativeName([dns(self.hostname)]), critical=False)
            .sign(CERT_DATA["root-cert"]["key"]["parsed"], hashes.SHA256())
        )

        with patch("django_ca.acme.views.run_task") as mockcm:
            resp = self.acme(self.url, self.get_message(csr), kid=self.kid)
        assert resp.status_code == HTTPStatus.OK, resp.content
        assert_acme_response(resp, self.ca)

        order = AcmeOrder.objects.get(pk=self.order.pk)
        cert = order.acmecertificate
        assert mockcm.call_args_list == [mock.call(acme_issue_certificate, acme_certificate_pk=cert.pk)]
        assert resp.json() == {
            "authorizations": [f"http://{self.SERVER_NAME}{self.authz.acme_url}"],
            "expires": pyrfc3339.generate(order.expires, accept_naive=True),
            "identifiers": [{"type": "dns", "value": self.hostname}],
            "status": "processing",
        }

    @override_tmpcadir()
    def test_csr_subject_no_cn(self) -> None:
        """Test posting a CSR that has a subject but no common name."""
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COUNTRY_NAME, "AT"),
                    ]
                )
            )
            .add_extension(x509.SubjectAlternativeName([dns(self.hostname)]), critical=False)
            .sign(CERT_DATA["root-cert"]["key"]["parsed"], hashes.SHA256())
        )

        with patch("django_ca.acme.views.run_task") as mockcm:
            resp = self.acme(self.url, self.get_message(csr), kid=self.kid)
        assert resp.status_code == HTTPStatus.OK, resp.content
        assert_acme_response(resp, self.ca)

        order = AcmeOrder.objects.get(pk=self.order.pk)
        cert = order.acmecertificate
        assert mockcm.call_args_list == [mock.call(acme_issue_certificate, acme_certificate_pk=cert.pk)]

        assert resp.json() == {
            "authorizations": [f"http://{self.SERVER_NAME}{self.authz.acme_url}"],
            "expires": pyrfc3339.generate(order.expires, accept_naive=True),
            "identifiers": [{"type": "dns", "value": self.hostname}],
            "status": "processing",
        }

    @override_tmpcadir()
    def test_csr_subject_no_domain(self) -> None:
        """Test posting a CSR where the CommonName is not a domain name."""
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, "user@example.com"),
                    ]
                )
            )
            .add_extension(x509.SubjectAlternativeName([dns(self.hostname)]), critical=False)
            .sign(CERT_DATA["root-cert"]["key"]["parsed"], hashes.SHA256())
        )

        with patch("django_ca.acme.views.run_task") as mockcm:
            resp = self.acme(self.url, self.get_message(csr), kid=self.kid)
        mockcm.assert_not_called()
        assert_bad_csr(resp, "CommonName was not in order.", self.ca)

    @override_tmpcadir()
    def test_csr_subject_not_in_order(self) -> None:
        """Test posting a CSR where the CommonName was not in the order."""
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, "example.net"),
                    ]
                )
            )
            .add_extension(x509.SubjectAlternativeName([dns(self.hostname)]), critical=False)
            .sign(CERT_DATA["root-cert"]["key"]["parsed"], hashes.SHA256())
        )

        with patch("django_ca.acme.views.run_task") as mockcm:
            resp = self.acme(self.url, self.get_message(csr), kid=self.kid)
        mockcm.assert_not_called()
        assert_bad_csr(resp, "CommonName was not in order.", self.ca)

    @override_tmpcadir()
    def test_csr_no_san(self) -> None:
        """Test posting a CSR with no SubjectAlternativeName extension."""
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([]))
            .sign(CERT_DATA["root-cert"]["key"]["parsed"], hashes.SHA256())
        )

        with patch("django_ca.acme.views.run_task") as mockcm:
            resp = self.acme(self.url, self.get_message(csr), kid=self.kid)
        mockcm.assert_not_called()
        assert_bad_csr(resp, "No subject alternative names found in CSR.", self.ca)

    @override_tmpcadir()
    def test_csr_different_names(self) -> None:
        """Test posting a CSR with different names in the SubjectAlternativeName extension."""
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([]))
            .add_extension(
                x509.SubjectAlternativeName([dns(self.hostname), dns("example.net")]),
                critical=False,
            )
            .sign(CERT_DATA["root-cert"]["key"]["parsed"], hashes.SHA256())
        )

        with patch("django_ca.acme.views.run_task") as mockcm:
            resp = self.acme(self.url, self.get_message(csr), kid=self.kid)
        mockcm.assert_not_called()
        assert_bad_csr(resp, "Names in CSR do not match.", self.ca)

    @override_tmpcadir()
    def test_unparsable_csr(self) -> None:
        """Test passing a completely unparsable CSR."""
        with (
            patch("django_ca.acme.views.run_task") as mockcm,
            patch("django_ca.acme.views.AcmeOrderFinalizeView.message_cls.encode", side_effect=[b"foo"]),
            self.assertLogs(),
        ):
            resp = self.acme(self.url, self.message, kid=self.kid)
        mockcm.assert_not_called()
        assert_bad_csr(resp, "Unable to parse CSR.", self.ca)

    @override_tmpcadir()
    def test_csr_invalid_version(self) -> None:
        """Test passing a completely unparsable CSR."""
        # It's difficult to create a CSR with an invalid version, so we just mock the parsing function raising
        # the exception instead.
        with (
            patch("django_ca.acme.views.run_task") as mockcm,
            patch("django_ca.acme.views.parse_acme_csr", side_effect=x509.InvalidVersion("foo", 42)),
        ):
            resp = self.acme(self.url, self.message, kid=self.kid)
        mockcm.assert_not_called()
        assert_bad_csr(resp, "Invalid CSR version.", self.ca)

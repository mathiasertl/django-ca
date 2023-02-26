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

import os
import typing
from http import HTTPStatus
from unittest import mock

import acme
import josepy as jose
import pyrfc3339
from OpenSSL.crypto import X509Req

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import hashes

from django.conf import settings
from django.test import TransactionTestCase, override_settings
from django.urls import reverse, reverse_lazy

from freezegun import freeze_time

from django_ca.acme.messages import CertificateRequest
from django_ca.models import AcmeAccount, AcmeAuthorization, AcmeOrder
from django_ca.tasks import acme_issue_certificate
from django_ca.tests.acme.views.base import AcmeWithAccountViewTestCaseMixin
from django_ca.tests.base import certs, dns, override_tmpcadir, timestamps

if typing.TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse as HttpResponse


@freeze_time(timestamps["everything_valid"])
class AcmeOrderFinalizeViewTestCase(
    AcmeWithAccountViewTestCaseMixin[CertificateRequest], TransactionTestCase
):
    """Test retrieving a challenge."""

    slug = "92MPyl7jm0zw"
    url = reverse_lazy(
        "django_ca:acme-order-finalize", kwargs={"serial": certs["root"]["serial"], "slug": slug}
    )

    def setUp(self) -> None:
        super().setUp()

        # Create a CSR based on root-cert
        # NOTE: certbot CSRs have an empty subject
        self.csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([]))
            .add_extension(x509.SubjectAlternativeName([dns(self.hostname)]), critical=False)
            .sign(certs["root-cert"]["key"]["parsed"], hashes.SHA256())
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

    def assertBadCSR(self, resp: "HttpResponse", message: str) -> None:  # pylint: disable=invalid-name
        """Assert a badCSR error."""
        self.assertAcmeProblem(resp, "badCSR", status=HTTPStatus.BAD_REQUEST, message=message)

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
    def test_basic(self, accept_naive: bool = True) -> None:
        """Basic test for creating an account via ACME."""

        with self.patch("django_ca.acme.views.run_task") as mockcm:
            resp = self.acme(self.url, self.message, kid=self.kid)
        self.assertEqual(resp.status_code, HTTPStatus.OK, resp.content)
        self.assertAcmeResponse(resp)

        order = AcmeOrder.objects.get(pk=self.order.pk)
        cert = order.acmecertificate
        self.assertEqual(
            mockcm.call_args_list, [mock.call(acme_issue_certificate, acme_certificate_pk=cert.pk)]
        )
        self.assertEqual(
            resp.json(),
            {
                "authorizations": [f"http://{self.SERVER_NAME}{self.authz.acme_url}"],
                "expires": pyrfc3339.generate(order.expires, accept_naive=accept_naive),
                "identifiers": [{"type": "dns", "value": self.hostname}],
                "status": "processing",
            },
        )

    @override_settings(USE_TZ=True)
    def test_basic_with_tz(self) -> None:
        """Basic test with USE_TZ=True."""
        self.test_basic(False)

    @override_tmpcadir()
    def test_not_found(self) -> None:
        """Test an order that does not exist."""
        url = reverse("django_ca:acme-order-finalize", kwargs={"serial": self.ca.serial, "slug": "foo"})
        with self.patch("django_ca.acme.views.run_task") as mockcm:
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

        with self.patch("django_ca.acme.views.run_task") as mockcm:
            resp = self.acme(self.url, self.message, kid=self.kid)
        mockcm.assert_not_called()
        self.assertUnauthorized(resp, "You are not authorized to perform this request.")

    @override_tmpcadir()
    def test_not_ready(self) -> None:
        """Test an order that is not yet ready."""

        self.order.status = AcmeOrder.STATUS_INVALID
        self.order.save()

        with self.patch("django_ca.acme.views.run_task") as mockcm:
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

        with self.patch("django_ca.acme.views.run_task") as mockcm:
            resp = self.acme(self.url, self.message, kid=self.kid)
        mockcm.assert_not_called()
        self.assertAcmeProblem(
            resp, "orderNotReady", status=HTTPStatus.FORBIDDEN, message="This order is not yet ready."
        )

    @override_tmpcadir()
    def test_csr_invalid_signature(self) -> None:
        """Test posting a CSR with an invalid signature"""

        # create property mock for CSR object.
        # We mock parse_acme_csr below because the actual class returned depends on the backend in use
        csr_mock = mock.MagicMock()
        # attach to type: https://docs.python.org/3/library/unittest.mock.html#unittest.mock.PropertyMock
        type(csr_mock).is_signature_valid = mock.PropertyMock(return_value=False)

        with self.patch("django_ca.acme.views.run_task") as mockcm, self.patch(
            "django_ca.acme.views.parse_acme_csr", return_value=csr_mock
        ):
            resp = self.acme(self.url, self.message, kid=self.kid)
        mockcm.assert_not_called()
        self.assertBadCSR(resp, "CSR signature is not valid.")

    @override_tmpcadir()
    def test_csr_bad_algorithm(self) -> None:
        """Test posting a CSR with a bad algorithm."""

        with open(os.path.join(settings.FIXTURES_DIR, "md5.csr.pem"), "rb") as stream:
            signed_csr = x509.load_pem_x509_csr(stream.read())

        with self.patch("django_ca.acme.views.run_task") as mockcm:
            resp = self.acme(self.url, self.get_message(signed_csr), kid=self.kid)
        mockcm.assert_not_called()
        self.assertBadCSR(resp, "md5: Insecure hash algorithm.")

        with open(os.path.join(settings.FIXTURES_DIR, "sha1.csr.pem"), "rb") as stream:
            signed_csr = x509.load_pem_x509_csr(stream.read())

        with self.patch("django_ca.acme.views.run_task") as mockcm:
            resp = self.acme(self.url, self.get_message(signed_csr), kid=self.kid)
        mockcm.assert_not_called()
        self.assertBadCSR(resp, "sha1: Insecure hash algorithm.")

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
            .sign(certs["root-cert"]["key"]["parsed"], hashes.SHA256())
        )

        with self.patch("django_ca.acme.views.run_task") as mockcm:
            resp = self.acme(self.url, self.get_message(csr), kid=self.kid)
        self.assertEqual(resp.status_code, HTTPStatus.OK, resp.content)
        self.assertAcmeResponse(resp)

        order = AcmeOrder.objects.get(pk=self.order.pk)
        cert = order.acmecertificate
        self.assertEqual(
            mockcm.call_args_list, [mock.call(acme_issue_certificate, acme_certificate_pk=cert.pk)]
        )
        self.assertEqual(
            resp.json(),
            {
                "authorizations": [f"http://{self.SERVER_NAME}{self.authz.acme_url}"],
                "expires": pyrfc3339.generate(order.expires, accept_naive=True),
                "identifiers": [{"type": "dns", "value": self.hostname}],
                "status": "processing",
            },
        )

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
            .sign(certs["root-cert"]["key"]["parsed"], hashes.SHA256())
        )

        with self.patch("django_ca.acme.views.run_task") as mockcm:
            resp = self.acme(self.url, self.get_message(csr), kid=self.kid)
        self.assertEqual(resp.status_code, HTTPStatus.OK, resp.content)
        self.assertAcmeResponse(resp)

        order = AcmeOrder.objects.get(pk=self.order.pk)
        cert = order.acmecertificate
        self.assertEqual(
            mockcm.call_args_list, [mock.call(acme_issue_certificate, acme_certificate_pk=cert.pk)]
        )
        self.assertEqual(
            resp.json(),
            {
                "authorizations": [f"http://{self.SERVER_NAME}{self.authz.acme_url}"],
                "expires": pyrfc3339.generate(order.expires, accept_naive=True),
                "identifiers": [{"type": "dns", "value": self.hostname}],
                "status": "processing",
            },
        )

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
            .sign(certs["root-cert"]["key"]["parsed"], hashes.SHA256())
        )

        with self.patch("django_ca.acme.views.run_task") as mockcm:
            resp = self.acme(self.url, self.get_message(csr), kid=self.kid)
        mockcm.assert_not_called()
        self.assertBadCSR(resp, "CommonName was not in order.")

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
            .sign(certs["root-cert"]["key"]["parsed"], hashes.SHA256())
        )

        with self.patch("django_ca.acme.views.run_task") as mockcm:
            resp = self.acme(self.url, self.get_message(csr), kid=self.kid)
        mockcm.assert_not_called()
        self.assertBadCSR(resp, "CommonName was not in order.")

    @override_tmpcadir()
    def test_csr_no_san(self) -> None:
        """Test posting a CSR with no SubjectAlternativeName extension."""

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([]))
            .sign(certs["root-cert"]["key"]["parsed"], hashes.SHA256())
        )

        with self.patch("django_ca.acme.views.run_task") as mockcm:
            resp = self.acme(self.url, self.get_message(csr), kid=self.kid)
        mockcm.assert_not_called()
        self.assertBadCSR(resp, "No subject alternative names found in CSR.")

    @override_tmpcadir()
    def test_csr_different_names(self) -> None:
        """Test posting a CSR with different names in the SubjectAlternativeName extesion."""

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([]))
            .add_extension(
                x509.SubjectAlternativeName([dns(self.hostname), dns("example.net")]),
                critical=False,
            )
            .sign(certs["root-cert"]["key"]["parsed"], hashes.SHA256())
        )

        with self.patch("django_ca.acme.views.run_task") as mockcm:
            resp = self.acme(self.url, self.get_message(csr), kid=self.kid)
        mockcm.assert_not_called()
        self.assertBadCSR(resp, "Names in CSR do not match.")

    @override_tmpcadir()
    def test_unparsable_csr(self) -> None:
        """Test passing a completely unparsable CSR."""

        with self.patch("django_ca.acme.views.run_task") as mockcm, self.patch(
            "django_ca.acme.views.AcmeOrderFinalizeView.message_cls.encode", side_effect=[b"foo"]
        ), self.assertLogs():
            resp = self.acme(self.url, self.message, kid=self.kid)
        mockcm.assert_not_called()
        self.assertBadCSR(resp, "Unable to parse CSR.")

    @override_tmpcadir()
    def test_csr_invalid_version(self) -> None:
        """Test passing a completely unparsable CSR."""

        # It's difficult to create a CSR with an invalid version, so we just mock the parsing function raising
        # the exception instead.
        with self.patch("django_ca.acme.views.run_task") as mockcm, self.patch(
            "django_ca.acme.views.parse_acme_csr", side_effect=x509.InvalidVersion("foo", 42)
        ):
            resp = self.acme(self.url, self.message, kid=self.kid)
        mockcm.assert_not_called()
        self.assertBadCSR(resp, "Invalid CSR version.")

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

# pylint: disable=redefined-outer-name

from http import HTTPStatus
from unittest import mock
from unittest.mock import patch

import josepy as jose
import pyrfc3339

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import hashes
from OpenSSL.crypto import X509Req

from django.test import Client
from django.urls import reverse

import pytest
from pytest_django.fixtures import SettingsWrapper

from django_ca.acme.messages import CertificateRequest
from django_ca.models import AcmeAccount, AcmeAuthorization, AcmeOrder, CertificateAuthority
from django_ca.tasks import acme_issue_certificate
from django_ca.tests.acme.views.assertions import (
    assert_acme_problem,
    assert_acme_response,
    assert_unauthorized,
)
from django_ca.tests.acme.views.base import AcmeWithAccountViewTestCaseMixin
from django_ca.tests.acme.views.constants import HOST_NAME, SERVER_NAME
from django_ca.tests.acme.views.utils import acme_request
from django_ca.tests.base.constants import CERT_DATA, FIXTURES_DIR, TIMESTAMPS
from django_ca.tests.base.typehints import CaptureOnCommitCallbacks, HttpResponse
from django_ca.tests.base.utils import dns, root_reverse

# ACME views require a currently valid certificate authority
pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])]

# Create a CSR based on root-cert
# NOTE: certbot CSRs have an empty subject
CSR = (
    x509.CertificateSigningRequestBuilder()
    .subject_name(x509.Name([]))
    .add_extension(x509.SubjectAlternativeName([dns(HOST_NAME)]), critical=False)
    .sign(CERT_DATA["root-cert"]["key"]["parsed"], hashes.SHA256())
)


@pytest.fixture
def order(order: AcmeOrder) -> AcmeOrder:
    """Override the module-level fixture to set the status to ready."""
    order.status = AcmeOrder.STATUS_READY
    order.save()
    return order


@pytest.fixture
def authz(authz: AcmeAuthorization) -> AcmeAuthorization:
    """Override the module-level fixture to set the status to valid."""
    authz.status = AcmeAuthorization.STATUS_VALID
    authz.save()
    return authz


@pytest.fixture
def url(order: AcmeOrder) -> str:
    """URL under test."""
    return root_reverse("acme-order-finalize", slug=order.slug)


@pytest.fixture
def message() -> CertificateRequest:
    """Default message sent to the server."""
    req = X509Req.from_cryptography(CSR)
    return CertificateRequest(csr=jose.util.ComparableX509(req))


def assert_bad_csr(response: "HttpResponse", message: str, ca: CertificateAuthority) -> None:
    """Assert a badCSR error."""
    assert_acme_problem(response, "badCSR", ca=ca, status=HTTPStatus.BAD_REQUEST, message=message)


@pytest.mark.parametrize("use_tz", (True, False))
def test_basic(
    settings: SettingsWrapper,
    django_capture_on_commit_callbacks: CaptureOnCommitCallbacks,
    client: Client,
    url: str,
    message: CertificateRequest,
    usable_root: CertificateAuthority,
    order: AcmeOrder,
    authz: AcmeAuthorization,
    kid: str | None,
    use_tz: bool,
) -> None:
    """Basic test for creating an account via ACME."""
    settings.USE_TZ = use_tz
    with (
        patch("django_ca.acme.views.run_task") as mockcm,
        django_capture_on_commit_callbacks(execute=True) as callbacks,
    ):
        resp = acme_request(client, url, usable_root, message, kid=kid)
    assert resp.status_code == HTTPStatus.OK, resp.content
    assert_acme_response(resp, usable_root)
    assert len(callbacks) == 1

    order = AcmeOrder.objects.get(pk=order.pk)
    cert = order.acmecertificate
    assert mockcm.call_args_list == [mock.call(acme_issue_certificate, acme_certificate_pk=cert.pk)]

    assert resp.json() == {
        "authorizations": [f"http://{SERVER_NAME}{authz.acme_url}"],
        "expires": pyrfc3339.generate(order.expires, accept_naive=not use_tz),
        "identifiers": [{"type": "dns", "value": HOST_NAME}],
        "status": "processing",
    }


def test_unknown_key_backend(
    django_capture_on_commit_callbacks: CaptureOnCommitCallbacks,
    client: Client,
    url: str,
    message: CertificateRequest,
    usable_root: CertificateAuthority,
    order: AcmeOrder,
    authz: AcmeAuthorization,
    kid: str | None,
) -> None:
    """Test that the frontend does not need to know about the backend."""
    usable_root.key_backend_alias = "unknown"
    usable_root.save()

    with (
        patch("django_ca.acme.views.run_task") as mockcm,
        django_capture_on_commit_callbacks(execute=True) as callbacks,
    ):
        resp = acme_request(client, url, usable_root, message, kid=kid)
    assert resp.status_code == HTTPStatus.OK, resp.content
    assert_acme_response(resp, usable_root)
    assert len(callbacks) == 1

    order = AcmeOrder.objects.get(pk=order.pk)
    cert = order.acmecertificate
    assert mockcm.call_args_list == [mock.call(acme_issue_certificate, acme_certificate_pk=cert.pk)]

    assert resp.json() == {
        "authorizations": [f"http://{SERVER_NAME}{authz.acme_url}"],
        "expires": pyrfc3339.generate(order.expires, accept_naive=False),
        "identifiers": [{"type": "dns", "value": HOST_NAME}],
        "status": "processing",
    }


@pytest.mark.usefixtures("account")
def test_not_found(
    django_capture_on_commit_callbacks: CaptureOnCommitCallbacks,
    client: Client,
    message: CertificateRequest,
    root: CertificateAuthority,
    kid: str | None,
) -> None:
    """Test an order that does not exist."""
    url = reverse("django_ca:acme-order-finalize", kwargs={"serial": root.serial, "slug": "foo"})
    with (
        patch("django_ca.acme.views.run_task") as mockcm,
        django_capture_on_commit_callbacks(execute=True) as callbacks,
    ):
        resp = acme_request(client, url, root, message, kid=kid)
    assert len(callbacks) == 0
    mockcm.assert_not_called()
    assert_unauthorized(resp, root, "You are not authorized to perform this request.")


def test_wrong_account(
    django_capture_on_commit_callbacks: CaptureOnCommitCallbacks,
    client: Client,
    url: str,
    message: CertificateRequest,
    root: CertificateAuthority,
    order: AcmeOrder,
    kid: str | None,
) -> None:
    """Test an order for a different account."""
    account = AcmeAccount.objects.create(
        ca=root, terms_of_service_agreed=True, slug="def", kid="kid", pem="bar", thumbprint="foo"
    )
    order.account = account
    order.save()

    with (
        patch("django_ca.acme.views.run_task") as mockcm,
        django_capture_on_commit_callbacks(execute=True) as callbacks,
    ):
        resp = acme_request(client, url, root, message, kid=kid)
    assert len(callbacks) == 0
    mockcm.assert_not_called()
    assert_unauthorized(resp, root, "You are not authorized to perform this request.")


def test_not_ready(
    django_capture_on_commit_callbacks: CaptureOnCommitCallbacks,
    client: Client,
    url: str,
    message: CertificateRequest,
    root: CertificateAuthority,
    order: AcmeOrder,
    kid: str | None,
) -> None:
    """Test an order that is not yet ready."""
    order.status = AcmeOrder.STATUS_INVALID
    order.save()

    with (
        patch("django_ca.acme.views.run_task") as mockcm,
        django_capture_on_commit_callbacks(execute=True) as callbacks,
    ):
        resp = acme_request(client, url, root, message, kid=kid)
    assert len(callbacks) == 0
    mockcm.assert_not_called()
    assert_acme_problem(
        resp,
        "orderNotReady",
        status=HTTPStatus.FORBIDDEN,
        message="This order is not yet ready.",
        ca=root,
    )


def test_invalid_auth(
    django_capture_on_commit_callbacks: CaptureOnCommitCallbacks,
    client: Client,
    url: str,
    message: CertificateRequest,
    root: CertificateAuthority,
    authz: AcmeAuthorization,
    kid: str | None,
) -> None:
    """Test an order where one of the authentications is not valid."""
    authz.status = AcmeAuthorization.STATUS_INVALID
    authz.save()

    with (
        patch("django_ca.acme.views.run_task") as mockcm,
        django_capture_on_commit_callbacks(execute=True) as callbacks,
    ):
        resp = acme_request(client, url, root, message, kid=kid)
    assert len(callbacks) == 0
    mockcm.assert_not_called()
    assert_acme_problem(
        resp,
        "orderNotReady",
        status=HTTPStatus.FORBIDDEN,
        message="This order is not yet ready.",
        ca=root,
    )


def test_csr_invalid_signature(
    django_capture_on_commit_callbacks: CaptureOnCommitCallbacks,
    client: Client,
    url: str,
    message: CertificateRequest,
    root: CertificateAuthority,
    kid: str | None,
) -> None:
    """Test posting a CSR with an invalid signature."""
    # create property mock for CSR object.
    # We mock parse_acme_csr below because the actual class returned depends on the backend in use
    csr_mock = mock.MagicMock()
    # attach to type: https://docs.python.org/3/library/unittest.mock.html#unittest.mock.PropertyMock
    type(csr_mock).is_signature_valid = mock.PropertyMock(return_value=False)

    with (
        patch("django_ca.acme.views.run_task") as mockcm,
        patch("django_ca.acme.views.parse_acme_csr", return_value=csr_mock),
        django_capture_on_commit_callbacks(execute=True) as callbacks,
    ):
        resp = acme_request(client, url, root, message, kid=kid)
    assert len(callbacks) == 0
    mockcm.assert_not_called()
    assert_bad_csr(resp, "CSR signature is not valid.", ca=root)


def test_csr_bad_algorithm(
    django_capture_on_commit_callbacks: CaptureOnCommitCallbacks,
    client: Client,
    url: str,
    root: CertificateAuthority,
    kid: str | None,
) -> None:
    """Test posting a CSR with a bad algorithm."""
    with open(FIXTURES_DIR / "md5.csr.pem", "rb") as stream:
        signed_csr = x509.load_pem_x509_csr(stream.read())

    req = X509Req.from_cryptography(signed_csr)
    message = CertificateRequest(csr=jose.util.ComparableX509(req))
    with (
        patch("django_ca.acme.views.run_task") as mockcm,
        django_capture_on_commit_callbacks() as callbacks,
    ):
        resp = acme_request(client, url, root, message, kid=kid)
    assert len(callbacks) == 0
    mockcm.assert_not_called()
    assert_bad_csr(resp, "md5: Insecure hash algorithm.", ca=root)

    with open(FIXTURES_DIR / "sha1.csr.pem", "rb") as stream:
        signed_csr = x509.load_pem_x509_csr(stream.read())
    req = X509Req.from_cryptography(signed_csr)
    message = CertificateRequest(csr=jose.util.ComparableX509(req))

    with (
        patch("django_ca.acme.views.run_task") as mockcm,
        django_capture_on_commit_callbacks(execute=True) as callbacks,
    ):
        resp = acme_request(client, url, root, message, kid=kid)
    assert len(callbacks) == 0
    mockcm.assert_not_called()
    assert_bad_csr(resp, "sha1: Insecure hash algorithm.", ca=root)


def test_csr_valid_subject(
    django_capture_on_commit_callbacks: CaptureOnCommitCallbacks,
    client: Client,
    url: str,
    root: CertificateAuthority,
    order: AcmeOrder,
    authz: AcmeAuthorization,
    kid: str | None,
) -> None:
    """Test posting a CSR where the CommonName was in the order."""
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, HOST_NAME),
                ]
            )
        )
        .add_extension(x509.SubjectAlternativeName([dns(HOST_NAME)]), critical=False)
        .sign(CERT_DATA["root-cert"]["key"]["parsed"], hashes.SHA256())
    )

    req = X509Req.from_cryptography(csr)
    message = CertificateRequest(csr=jose.util.ComparableX509(req))
    with (
        patch("django_ca.acme.views.run_task") as mockcm,
        django_capture_on_commit_callbacks(execute=True) as callbacks,
    ):
        resp = acme_request(client, url, root, message, kid=kid)
    assert len(callbacks) == 1
    assert resp.status_code == HTTPStatus.OK, resp.content
    assert_acme_response(resp, root)

    order.refresh_from_db()
    cert = order.acmecertificate
    assert mockcm.call_args_list == [mock.call(acme_issue_certificate, acme_certificate_pk=cert.pk)]
    assert resp.json() == {
        "authorizations": [f"http://{SERVER_NAME}{authz.acme_url}"],
        "expires": pyrfc3339.generate(order.expires),
        "identifiers": [{"type": "dns", "value": HOST_NAME}],
        "status": "processing",
    }


def test_csr_subject_no_cn(
    django_capture_on_commit_callbacks: CaptureOnCommitCallbacks,
    client: Client,
    url: str,
    root: CertificateAuthority,
    authz: AcmeAuthorization,
    order: AcmeOrder,
    kid: str | None,
) -> None:
    """Test posting a CSR that has a subject but no common name."""
    csr_builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "AT")]))
        .add_extension(x509.SubjectAlternativeName([dns(HOST_NAME)]), critical=False)
    )
    csr = csr_builder.sign(CERT_DATA["root-cert"]["key"]["parsed"], hashes.SHA256())
    req = X509Req.from_cryptography(csr)
    message = CertificateRequest(csr=jose.util.ComparableX509(req))

    with (
        patch("django_ca.acme.views.run_task") as mockcm,
        django_capture_on_commit_callbacks(execute=True) as callbacks,
    ):
        resp = acme_request(client, url, root, message, kid=kid)
    assert len(callbacks) == 1
    assert resp.status_code == HTTPStatus.OK, resp.content
    assert_acme_response(resp, root)

    cert = order.acmecertificate
    assert mockcm.call_args_list == [mock.call(acme_issue_certificate, acme_certificate_pk=cert.pk)]

    assert resp.json() == {
        "authorizations": [f"http://{SERVER_NAME}{authz.acme_url}"],
        "expires": pyrfc3339.generate(order.expires),
        "identifiers": [{"type": "dns", "value": HOST_NAME}],
        "status": "processing",
    }


def test_csr_subject_no_domain(
    django_capture_on_commit_callbacks: CaptureOnCommitCallbacks,
    client: Client,
    url: str,
    root: CertificateAuthority,
    kid: str | None,
) -> None:
    """Test posting a CSR where the CommonName is not a domain name."""
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "user@example.com")]))
        .add_extension(x509.SubjectAlternativeName([dns(HOST_NAME)]), critical=False)
        .sign(CERT_DATA["root-cert"]["key"]["parsed"], hashes.SHA256())
    )
    req = X509Req.from_cryptography(csr)
    message = CertificateRequest(csr=jose.util.ComparableX509(req))

    with (
        patch("django_ca.acme.views.run_task") as mockcm,
        django_capture_on_commit_callbacks(execute=True) as callbacks,
    ):
        resp = acme_request(client, url, root, message, kid=kid)
    assert len(callbacks) == 0
    mockcm.assert_not_called()
    assert_bad_csr(resp, "CommonName was not in order.", ca=root)


def test_csr_subject_not_in_order(
    django_capture_on_commit_callbacks: CaptureOnCommitCallbacks,
    client: Client,
    url: str,
    root: CertificateAuthority,
    kid: str | None,
) -> None:
    """Test posting a CSR where the CommonName was not in the order."""
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.net")]))
        .add_extension(x509.SubjectAlternativeName([dns(HOST_NAME)]), critical=False)
        .sign(CERT_DATA["root-cert"]["key"]["parsed"], hashes.SHA256())
    )
    req = X509Req.from_cryptography(csr)
    message = CertificateRequest(csr=jose.util.ComparableX509(req))

    with (
        patch("django_ca.acme.views.run_task") as mockcm,
        django_capture_on_commit_callbacks(execute=True) as callbacks,
    ):
        resp = acme_request(client, url, root, message, kid=kid)
    assert len(callbacks) == 0
    mockcm.assert_not_called()
    assert_bad_csr(resp, "CommonName was not in order.", root)


def test_csr_no_san(
    django_capture_on_commit_callbacks: CaptureOnCommitCallbacks,
    client: Client,
    url: str,
    root: CertificateAuthority,
    kid: str | None,
) -> None:
    """Test posting a CSR with no SubjectAlternativeName extension."""
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([]))
        .sign(CERT_DATA["root-cert"]["key"]["parsed"], hashes.SHA256())
    )
    req = X509Req.from_cryptography(csr)
    message = CertificateRequest(csr=jose.util.ComparableX509(req))

    with (
        patch("django_ca.acme.views.run_task") as mockcm,
        django_capture_on_commit_callbacks(execute=True) as callbacks,
    ):
        resp = acme_request(client, url, root, message, kid=kid)
    assert len(callbacks) == 0
    mockcm.assert_not_called()
    assert_bad_csr(resp, "No subject alternative names found in CSR.", root)


def test_csr_different_names(
    django_capture_on_commit_callbacks: CaptureOnCommitCallbacks,
    client: Client,
    url: str,
    root: CertificateAuthority,
    kid: str | None,
) -> None:
    """Test posting a CSR with different names in the SubjectAlternativeName extension."""
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([]))
        .add_extension(
            x509.SubjectAlternativeName([dns(HOST_NAME), dns("example.net")]),
            critical=False,
        )
        .sign(CERT_DATA["root-cert"]["key"]["parsed"], hashes.SHA256())
    )
    req = X509Req.from_cryptography(csr)
    message = CertificateRequest(csr=jose.util.ComparableX509(req))

    with (
        patch("django_ca.acme.views.run_task") as mockcm,
        django_capture_on_commit_callbacks(execute=True) as callbacks,
    ):
        resp = acme_request(client, url, root, message, kid=kid)
    assert len(callbacks) == 0
    mockcm.assert_not_called()
    assert_bad_csr(resp, "Names in CSR do not match.", root)


def test_unparsable_csr(
    django_capture_on_commit_callbacks: CaptureOnCommitCallbacks,
    client: Client,
    url: str,
    message: CertificateRequest,
    root: CertificateAuthority,
    kid: str | None,
) -> None:
    """Test passing a completely unparsable CSR."""
    with (
        patch("django_ca.acme.views.run_task") as mockcm,
        patch("django_ca.acme.views.AcmeOrderFinalizeView.message_cls.encode", side_effect=[b"foo"]),
        django_capture_on_commit_callbacks(execute=True) as callbacks,
    ):
        resp = acme_request(client, url, root, message, kid=kid)
    assert len(callbacks) == 0
    mockcm.assert_not_called()
    assert_bad_csr(resp, "Unable to parse CSR.", root)


def test_csr_invalid_version(
    django_capture_on_commit_callbacks: CaptureOnCommitCallbacks,
    client: Client,
    root: CertificateAuthority,
    url: str,
    message: CertificateRequest,
    kid: str | None,
) -> None:
    """Test passing a completely unparsable CSR."""
    # It's difficult to create a CSR with an invalid version, so we just mock the parsing function raising
    # the exception instead.
    with (
        patch("django_ca.acme.views.run_task") as mockcm,
        patch("django_ca.acme.views.parse_acme_csr", side_effect=x509.InvalidVersion("foo", 42)),
        django_capture_on_commit_callbacks(execute=True) as callbacks,
    ):
        resp = acme_request(client, url, root, message, kid=kid)
    assert len(callbacks) == 0
    mockcm.assert_not_called()
    assert_bad_csr(resp, "Invalid CSR version.", root)


class TestAcmeOrderFinalizeView(AcmeWithAccountViewTestCaseMixin[CertificateRequest]):
    """Test retrieving a challenge."""

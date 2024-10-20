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

"""Test ACME related views."""

import abc
import typing
from collections.abc import Iterator
from http import HTTPStatus
from typing import Optional, Union
from unittest import mock

import acme
import acme.jws
import josepy as jose

from django.test import Client

import pytest
from _pytest.logging import LogCaptureFixture
from pytest_django.fixtures import SettingsWrapper

from django_ca.models import AcmeAccount, CertificateAuthority
from django_ca.tests.acme.views.assertions import (
    assert_acme_problem,
    assert_malformed,
    assert_unauthorized,
)
from django_ca.tests.acme.views.utils import absolute_acme_uri, acme_request, get_nonce
from django_ca.tests.base.mixins import TestCaseMixin

MessageTypeVar = typing.TypeVar("MessageTypeVar", bound=jose.json_util.JSONObjectWithFields)


class AcmeBaseViewTestCaseMixin(TestCaseMixin, typing.Generic[MessageTypeVar]):
    """Base class with test cases for all views."""

    post_as_get = False
    requires_kid = True

    def test_internal_server_error(
        self,
        caplog: LogCaptureFixture,
        client: Client,
        url: str,
        message: MessageTypeVar,
        root: CertificateAuthority,
    ) -> None:
        """Test raising an uncaught exception -> Internal server error."""
        view = "django.views.generic.base.View.dispatch"
        msg = f"{url} mock-exception"
        with mock.patch(view, side_effect=Exception(msg)):
            resp = acme_request(client, url, root, message, nonce=b"foo")

        assert resp.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
        assert resp.json() == {
            "detail": "Internal server error",
            "status": HTTPStatus.INTERNAL_SERVER_ERROR,
            "type": "urn:ietf:params:acme:error:serverInternal",
        }
        assert msg in caplog.text

    def test_unknown_nonce(
        self,
        client: Client,
        url: str,
        message: MessageTypeVar,
        root: CertificateAuthority,
        kid: Optional[str],
    ) -> None:
        """Test sending an unknown nonce."""
        resp = acme_request(client, url, root, message, nonce=b"foo", kid=kid)
        assert_malformed(resp, root, "Bad or invalid nonce.", typ="badNonce")

    def test_duplicate_nonce(
        self,
        client: Client,
        url: str,
        message: Union[bytes, MessageTypeVar],
        root: CertificateAuthority,
        kid: Optional[str],
    ) -> None:
        """Test sending a nonce twice."""
        nonce = get_nonce(client, root)
        acme_request(client, url, root, message, nonce=nonce, kid=kid)
        resp1 = acme_request(client, url, root, message, nonce=nonce, kid=kid)
        assert_malformed(resp1, root, "Bad or invalid nonce.", typ="badNonce")

    def test_disabled_acme(
        self,
        settings: SettingsWrapper,
        client: Client,
        url: str,
        message: MessageTypeVar,
        root: CertificateAuthority,
    ) -> None:
        """Test that we get HTTP 404 if ACME is disabled."""
        settings.CA_ENABLE_ACME = False
        resp = acme_request(client, url, root, message, nonce=b"foo")
        assert resp.status_code == HTTPStatus.NOT_FOUND, resp.content

    def test_invalid_content_type(
        self, client: Client, url: str, message: MessageTypeVar, root: CertificateAuthority
    ) -> None:
        """Test that any request with an invalid Content-Type header is an error.

        .. seealso:: RFC 8555, 6.2
        """
        resp = acme_request(client, url, root, message, post_kwargs={"content_type": "FOO"})
        assert_acme_problem(
            resp,
            "malformed",
            status=HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
            message="Requests must use the application/jose+json content type.",
            ca=root,
        )

    def test_jwk_and_kid(
        self, client: Client, url: str, message: MessageTypeVar, root: CertificateAuthority
    ) -> None:
        """Test sending both a jwk and a kid, which are supposed to be mutually exclusive."""
        sign = acme.jws.Signature.sign

        def sign_mock(*args, **kwargs):  # type: ignore[no-untyped-def]
            """Mock function to set include_jwk to true."""
            kwargs["include_jwk"] = True
            return sign(*args, **kwargs)

        with self.patch("acme.jws.Signature.sign", spec_set=True, side_effect=sign_mock):
            resp = acme_request(client, url, root, message, kid="foo")
        assert_malformed(resp, root, "jwk and kid are mutually exclusive.")

    def test_invalid_ca(
        self, client: Client, url: str, message: MessageTypeVar, root: CertificateAuthority
    ) -> None:
        """Test a request where the CA cannot be found."""
        root.acme_enabled = False
        root.save()
        resp = acme_request(client, url, root, message)
        assert_acme_problem(
            resp,
            "not-found",
            status=HTTPStatus.NOT_FOUND,
            message="The requested CA cannot be found.",
            ca=root,
        )

    def test_wrong_jwk_or_kid(
        self,
        client: Client,
        url: str,
        message: MessageTypeVar,
        root: CertificateAuthority,
        kid: Optional[str],
        account_slug: str,
    ) -> None:
        """Send a KID where a JWK is required and vice versa."""
        expected = "Request requires a full JWK key."
        if self.requires_kid:
            self.requires_kid = False
            expected = "Request requires a JWK key ID."
            kid = None
        else:
            kid = absolute_acme_uri(":acme-account", serial=root.serial, slug=account_slug)

        resp = acme_request(client, url, root, message, kid=kid)
        assert_malformed(resp, root, expected)

    def test_invalid_jws(
        self,
        client: Client,
        url: str,
        message: MessageTypeVar,
        root: CertificateAuthority,
        kid: Optional[str],
    ) -> None:
        """Test invalid JWS signature."""
        with self.patch("acme.jws.JWS.verify", return_value=False) as verify_mock:
            resp = acme_request(client, url, root, message, kid=kid)

        assert_malformed(resp, root, "JWS signature invalid.")
        verify_mock.assert_called_once()

        # function might also raise an exception
        with self.patch("acme.jws.JWS.verify", side_effect=Exception("foo")) as verify_mock:
            resp = acme_request(client, url, root, message, kid=kid)
        assert_malformed(resp, root, "JWS signature invalid.")
        verify_mock.assert_called_once()

    def test_neither_jwk_nor_kid(
        self, client: Client, url: str, message: MessageTypeVar, root: CertificateAuthority
    ) -> None:
        """Test sending neither a jwk and a kid."""
        sign = acme.jws.Signature.sign

        def sign_mock(*args, **kwargs):  # type: ignore[no-untyped-def]
            """Mock function so that JWS has neither jwk nor kid."""
            kwargs.pop("kid")
            kwargs["include_jwk"] = False
            return sign(*args, **kwargs)

        with self.patch("acme.jws.Signature.sign", spec_set=True, side_effect=sign_mock):
            resp = acme_request(client, url, root, message, kid="foo")
        assert_malformed(resp, root, "JWS contained neither key nor key ID.")

    def test_invalid_json(self, client: Client, url: str, root: CertificateAuthority) -> None:
        """Test sending invalid JSON to the server."""
        resp = client.post(url, "{", content_type="application/jose+json")
        assert_malformed(resp, root, "Could not parse JWS token.")

    def test_wrong_url(
        self,
        client: Client,
        url: str,
        message: MessageTypeVar,
        root: CertificateAuthority,
        kid: Optional[str],
    ) -> None:
        """Test sending the wrong URL."""
        with self.patch("django.http.request.HttpRequest.build_absolute_uri", return_value="foo"):
            resp = acme_request(client, url, root, message, kid=kid)
        assert_unauthorized(resp, root, "URL does not match.", link_relations={"index": "foo"})

    def test_payload_in_post_as_get(
        self,
        client: Client,
        url: str,
        root: CertificateAuthority,
        kid: Optional[str],
    ) -> None:
        """Test sending a payload to a post-as-get request."""
        if not self.post_as_get:
            return

        # just some bogus data
        message = acme.messages.Registration(contact=("user@example.com",), terms_of_service_agreed=True)
        resp = acme_request(client, url, root, message, kid=kid)
        assert_malformed(resp, root, "Non-empty payload in get-as-post request.")


@pytest.mark.usefixtures("account")
class AcmeWithAccountViewTestCaseMixin(
    AcmeBaseViewTestCaseMixin[MessageTypeVar], typing.Generic[MessageTypeVar], metaclass=abc.ABCMeta
):
    """Mixin that also adds accounts to the database."""

    @pytest.fixture
    def main_account(self, account: AcmeAccount) -> Iterator[AcmeAccount]:
        """Return the main account to be used for this test case.

        This is overwritten by the revocation test case.
        """
        return account

    def test_deactivated_account(
        self,
        client: Client,
        url: str,
        message: MessageTypeVar,
        root: CertificateAuthority,
        kid: str,
        main_account: AcmeAccount,
    ) -> None:
        """Test request with a deactivated account."""
        main_account.status = AcmeAccount.STATUS_DEACTIVATED
        main_account.save()
        response = acme_request(client, url, root, message, kid=kid)
        assert_unauthorized(response, root, "Account has been deactivated.")

    def test_tos_not_agreed_account(
        self,
        client: Client,
        url: str,
        message: MessageTypeVar,
        root: CertificateAuthority,
        kid: str,
        main_account: AcmeAccount,
    ) -> None:
        """Test request with a deactivated account."""
        main_account.ca.terms_of_service = "http://tos.example.com"
        main_account.ca.save()

        main_account.terms_of_service_agreed = False
        main_account.save()
        resp = acme_request(client, url, root, message, kid=kid)
        assert_unauthorized(resp, root, "Account did not agree to the terms of service.")

    def test_unknown_account(
        self, client: Client, url: str, message: MessageTypeVar, root: CertificateAuthority
    ) -> None:
        """Test doing request with an unknown kid."""
        resp = acme_request(client, url, root, message, kid="unknown")
        assert_unauthorized(resp, root, "Account not found.")

    def test_unusable_account(
        self,
        client: Client,
        url: str,
        message: MessageTypeVar,
        root: CertificateAuthority,
        kid: str,
        main_account: AcmeAccount,
    ) -> None:
        """Test doing a request with an unusable account."""
        main_account.status = AcmeAccount.STATUS_REVOKED
        main_account.save()

        resp = acme_request(client, url, root, message, kid=kid)
        assert_unauthorized(resp, root, "Account not usable.")

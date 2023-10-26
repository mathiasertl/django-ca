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
import json
import typing
from contextlib import contextmanager
from http import HTTPStatus
from typing import Any, Dict, Iterator, Optional, Tuple, Type, Union
from unittest import mock

import acme
import acme.jws
import josepy as jose
from requests.utils import parse_header_links

from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from django.urls import reverse

from django_ca.acme.responses import AcmeResponseUnauthorized
from django_ca.models import AcmeAccount, CertificateAuthority, acme_slug
from django_ca.tests.base.constants import CERT_DATA
from django_ca.tests.base.mixins import TestCaseMixin
from django_ca.tests.base.utils import mock_slug, override_tmpcadir

MessageTypeVar = typing.TypeVar("MessageTypeVar", bound=jose.json_util.JSONObjectWithFields)

if typing.TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse as HttpResponse


class AcmeTestCaseMixin(TestCaseMixin):
    """TestCase mixin with various common utility functions."""

    hostname = "example.com"  # what we want a certificate for
    SERVER_NAME = "example.com"

    # NOTE: PEM here is the same as AcmeAccount.pem when this cert is used for account registration
    PEM = (
        CERT_DATA["root-cert"]["key"]["parsed"]
        .public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode("utf-8")
        .strip()
    )
    thumbprint = "kqtZjXqX07HbrRg220VoINzqF9QXsfIkQava3PdWM8o"
    ACCOUNT_ONE_CONTACT = "mailto:one@example.com"
    CHILD_PEM = (
        CERT_DATA["child-cert"]["key"]["parsed"]
        .public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode("utf-8")
        .strip()
    )
    CHILD_THUMBPRINT = "ux-66bpJQiyeDduTWQZHgkB4KJWK0kSdPOabnFiitFM"
    ACCOUNT_TWO_CONTACT = "mailto:two@example.net"

    load_cas: Tuple[str, ...] = ("root",)
    load_certs: Tuple[str, ...] = ("root-cert",)

    def setUp(self) -> None:
        super().setUp()
        self.ca.acme_enabled = True
        self.ca.save()
        self.client.defaults["SERVER_NAME"] = self.SERVER_NAME

    def absolute_uri(self, name: str, hostname: Optional[str] = None, **kwargs: Any) -> str:
        """Override to set a default for `hostname`."""
        if not hostname:  # pragma: no branch
            hostname = self.SERVER_NAME
        return super().absolute_uri(name, hostname=hostname, **kwargs)

    # NOINSPECTION NOTE: PyCharm does not detect mixins as a TestCase
    # noinspection PyPep8Naming
    def assertAcmeProblem(  # pylint: disable=invalid-name
        self,
        response: "HttpResponse",
        typ: str,
        status: int,
        message: str,
        ca: Optional[CertificateAuthority] = None,
        link_relations: Optional[Dict[str, str]] = None,
        regex: bool = False,
    ) -> None:
        """Assert that an HTTP response confirms to an ACME problem report.

        .. seealso:: `RFC 8555, section 8 <https://tools.ietf.org/html/rfc8555#section-6.7>`_
        """
        link_relations = link_relations or {}
        self.assertEqual(response["Content-Type"], "application/problem+json")
        self.assertLinkRelations(response, ca=ca, **link_relations)
        data = response.json()
        self.assertEqual(data["type"], f"urn:ietf:params:acme:error:{typ}", f"detail={data['detail']}")
        self.assertEqual(data["status"], status)
        if regex:
            self.assertRegex(data["detail"], message)
        else:
            self.assertEqual(data["detail"], message)
        self.assertIn("Replay-Nonce", response)

    # NOINSPECTION NOTE: PyCharm does not detect mixins as a TestCase
    # noinspection PyPep8Naming
    def assertAcmeResponse(  # pylint: disable=invalid-name
        self,
        response: "HttpResponse",
        ca: Optional[CertificateAuthority] = None,
        link_relations: Optional[Dict[str, str]] = None,
    ) -> None:
        """Assert basic Acme Response properties (Content-Type & Link header)."""
        link_relations = link_relations or {}
        self.assertLinkRelations(response, ca=ca, **link_relations)
        self.assertEqual(response["Content-Type"], "application/json")

    # NOINSPECTION NOTE: PyCharm does not detect mixins as a TestCase
    # noinspection PyPep8Naming
    def assertLinkRelations(  # pylint: disable=invalid-name
        self, response: "HttpResponse", ca: Optional[CertificateAuthority] = None, **kwargs: str
    ) -> None:
        """Assert Link relations for a given request."""
        if ca is None:  # pragma: no branch
            ca = self.ca

        directory = reverse("django_ca:acme-directory", kwargs={"serial": ca.serial})
        kwargs.setdefault("index", response.wsgi_request.build_absolute_uri(directory))

        expected = [{"rel": k, "url": v} for k, v in kwargs.items()]
        actual = parse_header_links(response["Link"])
        self.assertEqual(expected, actual)

    # NOINSPECTION NOTE: PyCharm does not detect mixins as a TestCase
    # noinspection PyPep8Naming
    def assertMalformed(  # pylint: disable=invalid-name
        self, resp: "HttpResponse", message: str = "", typ: str = "malformed", **kwargs: Any
    ) -> None:
        """Assert an unauthorized response."""
        self.assertAcmeProblem(resp, typ=typ, status=HTTPStatus.BAD_REQUEST, message=message, **kwargs)

    # NOINSPECTION NOTE: PyCharm does not detect mixins as a TestCase
    # noinspection PyPep8Naming
    def assertUnauthorized(  # pylint: disable=invalid-name
        self, resp: "HttpResponse", message: str = AcmeResponseUnauthorized.message, **kwargs: Any
    ) -> None:
        """Assert an unauthorized response."""
        self.assertAcmeProblem(
            resp, "unauthorized", status=HTTPStatus.UNAUTHORIZED, message=message, **kwargs
        )

    def get_nonce(self, ca: Optional[CertificateAuthority] = None) -> bytes:
        """Get a nonce with an actual request.

        Returns
        -------
        nonce : bytes
            The decoded bytes of the nonce.
        """
        if ca is None:  # pragma: no branch
            ca = self.ca

        url = reverse("django_ca:acme-new-nonce", kwargs={"serial": ca.serial})
        response = self.client.head(url)
        self.assertEqual(response.status_code, HTTPStatus.OK, response.content)
        return jose.json_util.decode_b64jose(response["replay-nonce"])

    @contextmanager
    def mock_slug(self) -> Iterator[str]:
        """Mock random slug generation, yields the static value."""
        with mock_slug() as slug:
            yield slug

    def post(
        self, url: str, data: Any, content_type: str = "application/jose+json", **extra: str
    ) -> "HttpResponse":
        """Make a post request with some ACME specific default data."""
        return self.client.post(
            url,
            json.dumps(data),
            content_type=content_type,
            follow=False,
            secure=False,
            **extra,  # type: ignore[arg-type]  # mypy 1.4.1 confuses this with header arg
        )


class AcmeBaseViewTestCaseMixin(AcmeTestCaseMixin, typing.Generic[MessageTypeVar]):
    """Base class with test cases for all views."""

    post_as_get = False
    requires_kid = True
    message_cls: Type[MessageTypeVar]
    view_name: str

    # NOINSPECTION NOTE: PyCharm does not detect mixins as a TestCase
    # noinspection PyAttributeOutsideInit
    def setUp(self) -> None:
        super().setUp()
        self.account_slug = acme_slug()
        self.child_account_slug = acme_slug()
        self.kid = self.absolute_uri(":acme-account", serial=self.ca.serial, slug=self.account_slug)
        self.child_kid = self.absolute_uri(
            ":acme-account", serial=self.ca.serial, slug=self.child_account_slug
        )

    @property
    @abc.abstractmethod
    def url(self) -> str:
        """Property providing a single URL under test."""

    def acme(
        self,
        uri: str,
        msg: Union[jose.json_util.JSONObjectWithFields, bytes],
        cert: Optional[CertificateIssuerPrivateKeyTypes] = None,
        kid: Optional[str] = None,
        nonce: Optional[bytes] = None,
        payload_cb: Optional[typing.Callable[[Dict[Any, Any]], Dict[Any, Any]]] = None,
        post_kwargs: Optional[Dict[str, str]] = None,
    ) -> "HttpResponse":
        """Do a generic ACME request.

        The `payload_cb` parameter is an optional callback that will receive the message data before being
        serialized to JSON.
        """
        if nonce is None:
            nonce = self.get_nonce()
        if cert is None:
            cert = typing.cast(
                CertificateIssuerPrivateKeyTypes, CERT_DATA[self.load_certs[0]]["key"]["parsed"]
            )
        if post_kwargs is None:
            post_kwargs = {}

        comparable = jose.util.ComparableRSAKey(cert)  # type: ignore[arg-type] # could also be DSA/EC key
        key = jose.jwk.JWKRSA(key=comparable)

        if isinstance(msg, jose.json_util.JSONObjectWithFields):
            payload = msg.to_json()
            if payload_cb is not None:
                payload = payload_cb(payload)
            payload = json.dumps(payload).encode("utf-8")
        else:
            payload = msg

        if self.requires_kid and kid is None:
            kid = self.kid

        jws = acme.jws.JWS.sign(
            payload, key, jose.jwa.RS256, nonce=nonce, url=self.absolute_uri(uri), kid=kid
        )
        return self.post(uri, jws.to_json(), **post_kwargs)

    def get_message(self, **kwargs: Any) -> Union[bytes, MessageTypeVar]:
        """Return a  message that can be sent to the server successfully.

        This function is used by test cases that want to get a useful message and manipulate it in some way so
        that it violates the ACME spec.
        """
        if self.post_as_get:
            return b""

        return self.message_cls(**kwargs)

    def get_url(self, **kwargs: Any) -> str:
        """Get a URL for this view with the given kwargs."""
        return reverse(f"django_ca:{self.view_name}", kwargs=kwargs)

    @property
    def message(self) -> Union[bytes, MessageTypeVar]:
        """Property for sending the default message."""
        return self.get_message()

    @override_tmpcadir()
    def test_internal_server_error(self) -> None:
        """Test raising an uncaught exception -> Internal server error."""
        view = "django.views.generic.base.View.dispatch"
        msg = f"{self.url} mock-exception"
        with mock.patch(view, side_effect=Exception(msg)), self.assertLogs() as logcm:
            resp = self.acme(self.url, self.message, nonce=b"foo")

        self.assertEqual(resp.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
        self.assertEqual(
            resp.json(),
            {
                "detail": "Internal server error",
                "status": HTTPStatus.INTERNAL_SERVER_ERROR,
                "type": "urn:ietf:params:acme:error:serverInternal",
            },
        )
        self.assertEqual(len(logcm.output), 1)
        self.assertIn(msg, logcm.output[0])

    @override_tmpcadir()
    def test_unknown_nonce(self) -> None:
        """Test sending an unknown nonce."""
        resp = self.acme(self.url, self.message, nonce=b"foo")
        self.assertMalformed(resp, "Bad or invalid nonce.", typ="badNonce")

    @override_tmpcadir()
    def test_duplicate_nonce(self) -> None:
        """Test sending a nonce twice."""
        nonce = self.get_nonce()
        self.acme(self.url, self.message, nonce=nonce)
        resp1 = self.acme(self.url, self.message, nonce=nonce)
        self.assertMalformed(resp1, "Bad or invalid nonce.", typ="badNonce")

    @override_tmpcadir(CA_ENABLE_ACME=False)
    def test_disabled_acme(self) -> None:
        """Test that we get HTTP 404 if ACME is disabled."""
        resp = self.acme(self.url, self.message, nonce=b"foo")
        self.assertEqual(resp.status_code, HTTPStatus.NOT_FOUND)

    @override_tmpcadir()
    def test_invalid_content_type(self) -> None:
        """Test that any request with an invalid Content-Type header is an error.

        .. seealso:: RFC 8555, 6.2
        """
        resp = self.acme(self.url, self.message, post_kwargs={"content_type": "FOO"})
        self.assertAcmeProblem(
            resp,
            "malformed",
            status=HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
            message="Requests must use the application/jose+json content type.",
        )

    @override_tmpcadir()
    def test_jwk_and_kid(self) -> None:
        """Test sending both a jwk and a kid, which are supposed to be mutually exclusive."""
        sign = acme.jws.Signature.sign

        def sign_mock(*args, **kwargs):  # type: ignore[no-untyped-def]
            """Mock function to set include_jwk to true."""
            kwargs["include_jwk"] = True
            return sign(*args, **kwargs)

        with self.patch("acme.jws.Signature.sign", spec_set=True, side_effect=sign_mock):
            resp = self.acme(self.url, self.message, kid="foo")
        self.assertMalformed(resp, "jwk and kid are mutually exclusive.")

    @override_tmpcadir()
    def test_invalid_ca(self) -> None:
        """Test a request where the CA cannot be found."""
        CertificateAuthority.objects.all().update(acme_enabled=False)
        resp = self.acme(self.url, self.message)
        self.assertAcmeProblem(
            resp, "not-found", status=HTTPStatus.NOT_FOUND, message="The requested CA cannot be found."
        )

    @override_tmpcadir()
    def test_wrong_jwk_or_kid(self) -> None:
        """Send a KID where a JWK is required and vice-versa."""
        kid: Optional[str] = self.kid
        expected = "Request requires a full JWK key."
        if self.requires_kid:
            self.requires_kid = False
            expected = "Request requires a JWK key ID."
            kid = None

        self.assertMalformed(self.acme(self.url, self.message, kid=kid), expected)

    @override_tmpcadir()
    def test_invalid_jws(self) -> None:
        """Test invalid JWS signature."""
        kid = self.kid if self.requires_kid else None
        with self.patch("acme.jws.JWS.verify", return_value=False) as verify_mock:
            self.assertMalformed(self.acme(self.url, self.message, kid=kid), "JWS signature invalid.")
        verify_mock.assert_called_once()

        # function might also raise an exception
        with self.patch("acme.jws.JWS.verify", side_effect=Exception("foo")) as verify_mock:
            self.assertMalformed(self.acme(self.url, self.message, kid=kid), "JWS signature invalid.")
        verify_mock.assert_called_once()

    @override_tmpcadir()
    def test_neither_jwk_nor_kid(self) -> None:
        """Test sending neither a jwk and a kid."""
        sign = acme.jws.Signature.sign

        def sign_mock(*args, **kwargs):  # type: ignore[no-untyped-def]
            """Mock function so that JWS has neither jwk nor kid."""
            kwargs.pop("kid")
            kwargs["include_jwk"] = False
            return sign(*args, **kwargs)

        with self.patch("acme.jws.Signature.sign", spec_set=True, side_effect=sign_mock):
            resp = self.acme(self.url, self.message, kid="foo")
        self.assertMalformed(resp, "JWS contained neither key nor key ID.")

    def test_invalid_json(self) -> None:
        """Test sending invalid JSON to the server."""
        resp = self.client.post(self.url, "{", content_type="application/jose+json")
        self.assertMalformed(resp, "Could not parse JWS token.")

    @override_tmpcadir()
    def test_wrong_url(self) -> None:
        """Test sending the wrong URL."""
        kid = self.kid if self.requires_kid else None
        with self.patch("django.http.request.HttpRequest.build_absolute_uri", return_value="foo"):
            if self.post_as_get:
                resp = self.acme(self.url, b"", kid=kid)
            else:
                resp = self.acme(self.url, self.message, kid=kid)
        self.assertUnauthorized(resp, "URL does not match.", link_relations={"index": "foo"})

    @override_tmpcadir()
    def test_payload_in_post_as_get(self) -> None:
        """Test sending a payload to a post-as-get request."""
        if not self.post_as_get:
            return

        # just some bogus data
        message = acme.messages.Registration(contact=("user@example.com",), terms_of_service_agreed=True)
        resp = self.acme(self.url, message, kid=self.kid)
        self.assertMalformed(resp, "Non-empty payload in get-as-post request.")


class AcmeWithAccountViewTestCaseMixin(
    AcmeBaseViewTestCaseMixin[MessageTypeVar], typing.Generic[MessageTypeVar], metaclass=abc.ABCMeta
):
    """Mixin that also adds accounts to the database."""

    # NOINSPECTION NOTE: PyCharm does not detect mixins as a TestCase
    # noinspection PyAttributeOutsideInit
    def setUp(self) -> None:
        super().setUp()
        self.account = AcmeAccount.objects.create(
            ca=self.ca,
            contact=self.ACCOUNT_ONE_CONTACT,
            terms_of_service_agreed=True,
            slug=self.account_slug,
            kid=self.kid,
            pem=self.PEM,
            thumbprint=self.thumbprint,
        )
        self.account2 = AcmeAccount.objects.create(
            ca=self.ca,
            contact=self.ACCOUNT_TWO_CONTACT,
            terms_of_service_agreed=True,
            slug=self.child_account_slug,
            kid=self.child_kid,
            pem=self.CHILD_PEM,
            thumbprint=self.CHILD_THUMBPRINT,
        )

    @property
    def main_account(self) -> AcmeAccount:
        """Return the main account to be used for this test case."""
        return self.account

    @override_tmpcadir()
    def test_deactivated_account(self) -> None:
        """Test request with a deactivated account."""
        self.main_account.status = AcmeAccount.STATUS_DEACTIVATED
        self.main_account.save()
        response = self.acme(self.url, self.message, kid=self.kid)
        self.assertUnauthorized(response, "Account has been deactivated.")

    @override_tmpcadir()
    def test_tos_not_agreed_account(self) -> None:
        """Test request with a deactivated account."""
        self.main_account.ca.terms_of_service = "http://tos.example.com"
        self.main_account.ca.save()

        self.main_account.terms_of_service_agreed = False
        self.main_account.save()
        response = self.acme(self.url, self.message, kid=self.kid)
        self.assertUnauthorized(response, "Account did not agree to the terms of service.")

    @override_tmpcadir()
    def test_unknown_account(self) -> None:
        """Test doing request with an unknown kid."""
        self.assertUnauthorized(self.acme(self.url, self.message, kid="unknown"), "Account not found.")

    @override_tmpcadir()
    def test_unusable_account(self) -> None:
        """Test doing a request with an unusable account."""
        self.main_account.status = AcmeAccount.STATUS_REVOKED
        self.main_account.save()
        self.assertUnauthorized(self.acme(self.url, self.message, kid=self.kid), "Account not usable.")

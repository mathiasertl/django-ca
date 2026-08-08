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

"""Tests for the ACME key-change view (RFC 8555, section 7.3.5)."""

# pylint: disable=redefined-outer-name  # because of fixtures

import json
from http import HTTPStatus
from typing import Any
from unittest import mock

import acme.jws
import josepy as jose

from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from django.test import Client

import pytest
from pytest_django.fixtures import Settings

from django_ca.models import AcmeAccount, CertificateAuthority, acme_slug as make_slug
from django_ca.tests.acme.views.assertions import assert_acme_response, assert_malformed
from django_ca.tests.acme.views.base import AcmeWithAccountViewTestCaseMixin
from django_ca.tests.acme.views.constants import THUMBPRINT
from django_ca.tests.acme.views.utils import absolute_acme_uri, get_nonce
from django_ca.tests.base.constants import CERT_DATA, TIMESTAMPS
from django_ca.tests.base.utils import root_reverse

pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])]

# The default (old) account key is CERT_DATA["root-cert"]["key"]["parsed"].
# We use CERT_DATA["child-cert"]["key"]["parsed"] as the new key.
NEW_KEY: CertificateIssuerPrivateKeyTypes = CERT_DATA["child-cert"]["key"]["parsed"]
NEW_PEM = (
    NEW_KEY.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("utf-8").strip()
)
NEW_THUMBPRINT = "aS2gDDmKA0OrhZDSLUDqBucaF6yYOXkrBbU2GdhU7LE"


def _make_new_jwk(new_key: CertificateIssuerPrivateKeyTypes = NEW_KEY) -> jose.jwk.JWKRSA:
    """Return a josepy JWK wrapping the new account key."""
    comparable = jose.util.ComparableRSAKey(new_key)  # type: ignore[arg-type]
    return jose.jwk.JWKRSA(key=comparable)


def key_change_request(  # pylint: disable=too-many-locals  # noqa: PLR0913,PLR0917
    client: Client,
    url: str,
    ca: CertificateAuthority,
    kid: str,
    account_url: str,
    old_key: CertificateIssuerPrivateKeyTypes | None = None,
    new_key: CertificateIssuerPrivateKeyTypes = NEW_KEY,
    inner_url: str | None = None,
    inner_nonce: bytes | None = None,
    inner_alg: jose.jwa.JWASignature = jose.jwa.RS256,
    payload_cb: Any = None,
) -> Any:
    """Build and send a key-change ACME request.

    The outer JWS is signed by *old_key* (defaults to the standard test key) and the inner JWS is signed
    by *new_key* using *inner_alg* (defaults to RS256). ``inner_url`` defaults to ``url`` (the key-change
    URL), matching the outer URL.
    """
    nonce = get_nonce(client, ca)
    if old_key is None:
        old_key = CERT_DATA["root-cert"]["key"]["parsed"]
    if inner_url is None:
        inner_url = absolute_acme_uri(url)

    old_comparable = jose.util.ComparableRSAKey(old_key)  # type: ignore[arg-type]
    old_jwk = jose.jwk.JWKRSA(key=old_comparable)

    new_jwk = _make_new_jwk(new_key)
    old_public_jwk = jose.jwk.JWKRSA(key=old_comparable.public_key())

    # Build inner payload
    inner_payload: dict[str, Any] = {
        "account": account_url,
        "oldKey": old_public_jwk.to_json(),
    }
    if payload_cb is not None:
        inner_payload = payload_cb(inner_payload)
    inner_payload_bytes = json.dumps(inner_payload).encode("utf-8")

    # Build inner JWS signed with new key; URL must equal the key-change URL.
    inner_jws = acme.jws.JWS.sign(
        inner_payload_bytes,
        new_jwk,
        inner_alg,
        nonce=inner_nonce,
        url=inner_url,
        kid=None,
    )

    # Build outer JWS signed with old key; payload is the serialized inner JWS.
    outer_payload = json.dumps(inner_jws.to_json()).encode("utf-8")
    outer_jws = acme.jws.JWS.sign(
        outer_payload,
        old_jwk,
        jose.jwa.RS256,
        nonce=nonce,
        url=absolute_acme_uri(url),
        kid=kid,
    )

    return client.post(
        url,
        json.dumps(outer_jws.to_json()),
        content_type="application/jose+json",
        follow=False,
        secure=False,
    )


@pytest.fixture
def url() -> str:
    """URL fixture for the key-change endpoint."""
    return root_reverse("acme-key-change")


@pytest.fixture
def message() -> bytes:
    """Dummy message fixture satisfying the AcmeBaseViewTestCaseMixin interface.

    The key-change view parses the payload directly as a JWS instead of an ACME message, so we supply a
    minimal post-as-get empty-payload bytes here to satisfy shared base-class tests that call
    ``acme_request()``.
    """
    return b""


@pytest.fixture
def kid(root: CertificateAuthority, account_slug: str) -> str:
    """Full KID URL for the test account."""
    return absolute_acme_uri(":acme-account", serial=root.serial, slug=account_slug)


# ---------------------------------------------------------------------------
# Successful key rollover
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("account")
def test_basic(client: Client, url: str, root: CertificateAuthority, kid: str, account_slug: str) -> None:
    """Happy-path: successful key rollover updates pem and thumbprint."""
    account_url = absolute_acme_uri(":acme-account", serial=root.serial, slug=account_slug)
    resp = key_change_request(client, url, root, kid, account_url)
    assert resp.status_code == HTTPStatus.OK, resp.content
    assert_acme_response(resp, root)

    account = AcmeAccount.objects.get(slug=account_slug)
    assert account.pem == NEW_PEM
    assert account.thumbprint == NEW_THUMBPRINT

    assert resp.json() == {
        "contact": ["mailto:one@example.com"],
        "orders": absolute_acme_uri(":acme-account-orders", serial=root.serial, slug=account_slug),
        "status": "valid",
    }


# ---------------------------------------------------------------------------
# Conflict: new key already in use
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("account")
def test_new_key_already_in_use(
    client: Client,
    url: str,
    root: CertificateAuthority,
    kid: str,
    account_slug: str,
) -> None:
    """409 Conflict when the new key is already registered for a different account."""
    other_slug = make_slug()
    other_kid = absolute_acme_uri(":acme-account", serial=root.serial, slug=other_slug)
    AcmeAccount.objects.create(
        ca=root,
        contact="",
        terms_of_service_agreed=True,
        slug=other_slug,
        kid=other_kid,
        pem=NEW_PEM,
        thumbprint=NEW_THUMBPRINT,
    )

    account_url = absolute_acme_uri(":acme-account", serial=root.serial, slug=account_slug)
    resp = key_change_request(client, url, root, kid, account_url)
    assert resp.status_code == HTTPStatus.CONFLICT, resp.content
    assert resp.json()["type"] == "urn:ietf:params:acme:error:malformed"
    assert resp["Location"] == other_kid

    # Original account key must be unchanged.
    account = AcmeAccount.objects.get(slug=account_slug)
    assert account.thumbprint == THUMBPRINT


# ---------------------------------------------------------------------------
# Inner JWS validation errors
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("account")
def test_invalid_inner_jws(client: Client, url: str, root: CertificateAuthority, kid: str) -> None:
    """Malformed response when the outer payload cannot be parsed as a JWS."""
    nonce = get_nonce(client, root)
    old_key = CERT_DATA["root-cert"]["key"]["parsed"]
    old_comparable = jose.util.ComparableRSAKey(old_key)
    old_jwk = jose.jwk.JWKRSA(key=old_comparable)

    # Build outer JWS with a plain-text (non-JWS) payload.
    outer_jws = acme.jws.JWS.sign(
        b"not-a-jws",
        old_jwk,
        jose.jwa.RS256,
        nonce=nonce,
        url=absolute_acme_uri(url),
        kid=kid,
    )
    resp = client.post(url, json.dumps(outer_jws.to_json()), content_type="application/jose+json")
    assert_malformed(resp, root, "Could not parse inner JWS.")


@pytest.mark.usefixtures("account")
def test_inner_jws_no_jwk(
    client: Client, url: str, root: CertificateAuthority, kid: str, account_slug: str
) -> None:
    """Malformed when inner JWS uses KID instead of JWK."""
    account_url = absolute_acme_uri(":acme-account", serial=root.serial, slug=account_slug)
    nonce = get_nonce(client, root)
    old_key = CERT_DATA["root-cert"]["key"]["parsed"]
    old_comparable = jose.util.ComparableRSAKey(old_key)
    old_jwk = jose.jwk.JWKRSA(key=old_comparable)

    inner_payload = json.dumps({"account": account_url, "oldKey": {}}).encode()
    # Sign inner JWS with kid (not JWK) to trigger the "must use JWK" error.
    inner_jws = acme.jws.JWS.sign(
        inner_payload,
        old_jwk,
        jose.jwa.RS256,
        nonce=None,
        url=absolute_acme_uri(url),
        kid=kid,
    )
    outer_payload = json.dumps(inner_jws.to_json()).encode()
    outer_jws = acme.jws.JWS.sign(
        outer_payload,
        old_jwk,
        jose.jwa.RS256,
        nonce=nonce,
        url=absolute_acme_uri(url),
        kid=kid,
    )
    resp = client.post(url, json.dumps(outer_jws.to_json()), content_type="application/jose+json")
    assert_malformed(resp, root, "Inner JWS must use JWK for the new key.")


@pytest.mark.usefixtures("account")
def test_inner_jws_wrong_url(
    client: Client, url: str, root: CertificateAuthority, kid: str, account_slug: str
) -> None:
    """Malformed when inner JWS URL does not match the key-change URL."""
    account_url = absolute_acme_uri(":acme-account", serial=root.serial, slug=account_slug)
    resp = key_change_request(client, url, root, kid, account_url, inner_url="http://example.com/wrong")
    assert_malformed(resp, root, 'Inner JWS MUST have the same "url" header parameter as the outer JWS.')


@pytest.mark.usefixtures("account")
def test_inner_jws_with_nonce(
    client: Client, url: str, root: CertificateAuthority, kid: str, account_slug: str
) -> None:
    """Malformed when inner JWS includes a nonce."""
    account_url = absolute_acme_uri(":acme-account", serial=root.serial, slug=account_slug)
    resp = key_change_request(client, url, root, kid, account_url, inner_nonce=b"foobar")
    assert_malformed(resp, root, 'Inner JWS MUST omit the "nonce" header parameter.')


@pytest.mark.usefixtures("account")
def test_inner_jws_disallowed_algorithm(
    client: Client,
    url: str,
    root: CertificateAuthority,
    kid: str,
    account_slug: str,
    settings: Settings,
) -> None:
    """Malformed when the inner JWS uses an algorithm not in the allowlist."""
    # RS256 is allowed (for the outer JWS to pass); PS256 is not.
    settings.CA_ACME_JWS_SIGNATURE_ALGORITHMS = ("RS256",)
    account_url = absolute_acme_uri(":acme-account", serial=root.serial, slug=account_slug)
    resp = key_change_request(client, url, root, kid, account_url, inner_alg=jose.jwa.PS256)
    assert_malformed(resp, root, "Inner JWS algorithm 'PS256' is not allowed.")


@pytest.mark.usefixtures("account")
def test_inner_jws_wrong_account(client: Client, url: str, root: CertificateAuthority, kid: str) -> None:
    """Malformed when 'account' in inner payload doesn't match the requesting account."""
    resp = key_change_request(client, url, root, kid, account_url="http://example.com/wrong-account")
    assert_malformed(resp, root, "'account' in inner JWS does not match requesting account.")


@pytest.mark.usefixtures("account")
def test_inner_jws_wrong_old_key(
    client: Client, url: str, root: CertificateAuthority, kid: str, account_slug: str
) -> None:
    """Malformed when 'oldKey' in inner payload doesn't match account's current key."""
    account_url = absolute_acme_uri(":acme-account", serial=root.serial, slug=account_slug)
    # Put the *new* key as oldKey → mismatch with actual account key.
    new_comparable = jose.util.ComparableRSAKey(NEW_KEY)  # type: ignore[arg-type]
    wrong_old_jwk = jose.jwk.JWKRSA(key=new_comparable.public_key())

    def payload_cb(payload: dict[str, Any]) -> dict[str, Any]:
        payload["oldKey"] = wrong_old_jwk.to_json()
        return payload

    resp = key_change_request(client, url, root, kid, account_url, payload_cb=payload_cb)
    assert_malformed(resp, root, "'oldKey' does not match current account key.")


@pytest.mark.usefixtures("account")
def test_inner_payload_missing_account(
    client: Client, url: str, root: CertificateAuthority, kid: str, account_slug: str
) -> None:
    """Malformed when inner payload is missing the 'account' field."""
    account_url = absolute_acme_uri(":acme-account", serial=root.serial, slug=account_slug)

    def payload_cb(payload: dict[str, Any]) -> dict[str, Any]:
        del payload["account"]
        return payload

    resp = key_change_request(client, url, root, kid, account_url, payload_cb=payload_cb)
    assert_malformed(resp, root, "Inner payload missing 'account' field.")


@pytest.mark.usefixtures("account")
def test_inner_payload_missing_old_key(
    client: Client, url: str, root: CertificateAuthority, kid: str, account_slug: str
) -> None:
    """Malformed when inner payload is missing the 'oldKey' field."""
    account_url = absolute_acme_uri(":acme-account", serial=root.serial, slug=account_slug)

    def payload_cb(payload: dict[str, Any]) -> dict[str, Any]:
        del payload["oldKey"]
        return payload

    resp = key_change_request(client, url, root, kid, account_url, payload_cb=payload_cb)
    assert_malformed(resp, root, "Inner payload missing 'oldKey' field.")


@pytest.mark.usefixtures("account")
def test_inner_jws_signature_invalid(
    client: Client, url: str, root: CertificateAuthority, kid: str, account_slug: str
) -> None:
    """Malformed when inner JWS signature verification fails."""
    account_url = absolute_acme_uri(":acme-account", serial=root.serial, slug=account_slug)
    with mock.patch("acme.jws.JWS.verify", side_effect=[True, False]):
        resp = key_change_request(client, url, root, kid, account_url)
    assert_malformed(resp, root, "Inner JWS signature invalid.")


# ---------------------------------------------------------------------------
# Base-class generic ACME request tests (content-type, nonce, etc.)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("account")
class TestAcmeKeyChangeView(AcmeWithAccountViewTestCaseMixin[jose.json_util.JSONObjectWithFields]):
    """Run shared ACME view tests against the key-change endpoint."""

    post_as_get = False
    requires_kid = True

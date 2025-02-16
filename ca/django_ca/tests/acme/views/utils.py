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

"""Utility functions for ACME."""

import json
from collections.abc import Callable
from http import HTTPStatus
from typing import Any, cast

import acme.jws
import josepy as jose

from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes

from django.test import Client
from django.urls import reverse

from django_ca.models import CertificateAuthority
from django_ca.tests.acme.views.constants import SERVER_NAME
from django_ca.tests.base.constants import CERT_DATA
from django_ca.tests.base.typehints import HttpResponse


def absolute_acme_uri(path: str, **kwargs: Any) -> str:
    """Override to set a default for `hostname`."""
    if path.startswith(":"):
        path = reverse(f"django_ca{path}", kwargs=kwargs)
    return f"http://{SERVER_NAME}{path}"


def get_nonce(client: Client, ca: CertificateAuthority) -> bytes:
    """Get a nonce with an actual request.

    Returns
    -------
    nonce : bytes
        The decoded bytes of the nonce.
    """
    url = reverse("django_ca:acme-new-nonce", kwargs={"serial": ca.serial})
    response = client.head(url)
    assert response.status_code == HTTPStatus.OK, response.content
    return jose.json_util.decode_b64jose(response["replay-nonce"])


def acme_post(
    client: Client, url: str, data: Any, content_type: str = "application/jose+json", **extra: str
) -> "HttpResponse":
    """Make a post request with some ACME specific default data."""
    return client.post(
        url,
        json.dumps(data),
        content_type=content_type,
        follow=False,
        secure=False,
        **extra,  # type: ignore[arg-type]  # mypy 1.4.1 confuses this with header arg
    )


def acme_request(
    client: Client,
    uri: str,
    ca: CertificateAuthority,
    msg: jose.json_util.JSONObjectWithFields | bytes,
    cert: CertificateIssuerPrivateKeyTypes | None = None,
    kid: str | None = None,
    nonce: bytes | None = None,
    payload_cb: Callable[[dict[Any, Any]], dict[Any, Any]] | None = None,
    post_kwargs: dict[str, str] | None = None,
) -> "HttpResponse":
    """Do a generic ACME request.

    The `payload_cb` parameter is an optional callback that will receive the message data before being
    serialized to JSON.
    """
    if nonce is None:
        nonce = get_nonce(client, ca)
    if cert is None:
        cert = cast(CertificateIssuerPrivateKeyTypes, CERT_DATA["root-cert"]["key"]["parsed"])
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

    jws = acme.jws.JWS.sign(payload, key, jose.jwa.RS256, nonce=nonce, url=absolute_acme_uri(uri), kid=kid)
    return acme_post(client, uri, jws.to_json(), **post_kwargs)

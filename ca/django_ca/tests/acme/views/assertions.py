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

"""Assertions for ACME views."""

import re
from typing import TYPE_CHECKING, Optional

from requests.utils import parse_header_links

from django.urls import reverse

from django_ca.models import CertificateAuthority

if TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse as HttpResponse


def assert_link_relations(response: "HttpResponse", ca: CertificateAuthority, **kwargs: str) -> None:
    """Assert Link relations for a given request."""
    directory = reverse("django_ca:acme-directory", kwargs={"serial": ca.serial})
    kwargs.setdefault("index", response.wsgi_request.build_absolute_uri(directory))

    expected = [{"rel": k, "url": v} for k, v in kwargs.items()]
    actual = parse_header_links(response["Link"])
    assert expected == actual


def assert_acme_problem(
    response: "HttpResponse",
    typ: str,
    status: int,
    message: str,
    ca: CertificateAuthority,
    link_relations: Optional[dict[str, str]] = None,
    regex: bool = False,
) -> None:
    """Assert that an HTTP response confirms to an ACME problem report.

    .. seealso:: `RFC 8555, section 8 <https://tools.ietf.org/html/rfc8555#section-6.7>`_
    """
    link_relations = link_relations or {}
    assert response["Content-Type"] == "application/problem+json", response.content
    assert_link_relations(response, ca=ca, **link_relations)
    data = response.json()
    assert data["type"] == f"urn:ietf:params:acme:error:{typ}", f"detail={data['detail']}"
    assert data["status"] == status
    if regex:
        assert re.search(message, data["detail"])
    else:
        assert data["detail"] == message
    assert "Replay-Nonce" in response


def assert_acme_response(
    response: "HttpResponse",
    ca: CertificateAuthority,
    link_relations: Optional[dict[str, str]] = None,
) -> None:
    """Assert basic Acme Response properties (Content-Type & Link header)."""
    link_relations = link_relations or {}
    assert_link_relations(response, ca, **link_relations)
    assert response["Content-Type"] == "application/json"

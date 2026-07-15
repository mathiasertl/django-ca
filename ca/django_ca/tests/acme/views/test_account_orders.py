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

"""Tests for the account orders list endpoint (RFC 8555, section 7.1.2.1)."""

# pylint: disable=redefined-outer-name  # because of fixtures

from http import HTTPStatus

import josepy as jose

from django.test import Client

import pytest

from django_ca.acme.views import AcmeAccountOrdersView
from django_ca.models import AcmeAccount, AcmeOrder, CertificateAuthority, acme_slug
from django_ca.tests.acme.views.assertions import assert_acme_response, assert_malformed, assert_unauthorized
from django_ca.tests.acme.views.base import AcmeWithAccountViewTestCaseMixin
from django_ca.tests.acme.views.constants import SERVER_NAME
from django_ca.tests.acme.views.utils import absolute_acme_uri, acme_request
from django_ca.tests.base.constants import TIMESTAMPS
from django_ca.tests.base.utils import root_reverse

# ACME views require a currently valid certificate authority.
pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])]


@pytest.fixture
def url(account: AcmeAccount) -> str:
    """URL under test."""
    return root_reverse("acme-account-orders", slug=account.slug)


@pytest.fixture
def message() -> bytes:
    """Empty bytestring — this is a POST-as-GET request."""
    return b""


# ---------------------------------------------------------------------------
# Happy-path tests
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("account")
def test_no_orders(client: Client, url: str, root: CertificateAuthority, kid: str) -> None:
    """Account with no orders returns an empty list."""
    resp = acme_request(client, url, root, b"", kid=kid)
    assert resp.status_code == HTTPStatus.OK, resp.content
    assert_acme_response(resp, root)
    assert resp.json() == {"orders": []}


@pytest.mark.usefixtures("account")
def test_basic(client: Client, url: str, root: CertificateAuthority, kid: str, order: AcmeOrder) -> None:
    """Account with one order returns that order's URL."""
    resp = acme_request(client, url, root, b"", kid=kid)
    assert resp.status_code == HTTPStatus.OK, resp.content
    assert_acme_response(resp, root)
    assert resp.json() == {"orders": [f"http://{SERVER_NAME}{order.acme_url}"]}


@pytest.mark.usefixtures("account")
def test_multiple_orders(
    client: Client, url: str, root: CertificateAuthority, kid: str, account: AcmeAccount
) -> None:
    """Multiple orders are all returned, most-recently-created first."""
    order1 = AcmeOrder.objects.create(account=account)
    order2 = AcmeOrder.objects.create(account=account)
    order3 = AcmeOrder.objects.create(account=account)

    resp = acme_request(client, url, root, b"", kid=kid)
    assert resp.status_code == HTTPStatus.OK, resp.content
    assert_acme_response(resp, root)
    # Most-recently-created (highest PK) first.
    assert resp.json() == {
        "orders": [
            f"http://{SERVER_NAME}{order3.acme_url}",
            f"http://{SERVER_NAME}{order2.acme_url}",
            f"http://{SERVER_NAME}{order1.acme_url}",
        ]
    }


@pytest.mark.usefixtures("account")
def test_invalid_orders_excluded(
    client: Client, url: str, root: CertificateAuthority, kid: str, account: AcmeAccount
) -> None:
    """RFC 8555 §7.1.2.1: invalid orders SHOULD NOT be included."""
    valid_order = AcmeOrder.objects.create(account=account, status=AcmeOrder.STATUS_VALID)
    AcmeOrder.objects.create(account=account, status=AcmeOrder.STATUS_INVALID)

    resp = acme_request(client, url, root, b"", kid=kid)
    assert resp.status_code == HTTPStatus.OK, resp.content
    assert resp.json() == {"orders": [f"http://{SERVER_NAME}{valid_order.acme_url}"]}


@pytest.mark.usefixtures("account")
def test_other_account_orders_excluded(
    client: Client,
    url: str,
    root: CertificateAuthority,
    kid: str,
    account: AcmeAccount,
) -> None:
    """Orders belonging to a different account are not visible."""
    own_order = AcmeOrder.objects.create(account=account)

    other_slug = acme_slug()
    other_kid = absolute_acme_uri(":acme-account", serial=root.serial, slug=other_slug)
    other_account = AcmeAccount.objects.create(
        ca=root,
        contact="",
        terms_of_service_agreed=True,
        slug=other_slug,
        kid=other_kid,
        pem=account.pem,
        thumbprint=acme_slug(),
    )
    AcmeOrder.objects.create(account=other_account)

    resp = acme_request(client, url, root, b"", kid=kid)
    assert resp.status_code == HTTPStatus.OK, resp.content
    assert resp.json() == {"orders": [f"http://{SERVER_NAME}{own_order.acme_url}"]}


# ---------------------------------------------------------------------------
# Pagination tests
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("account")
def test_pagination_first_page(
    client: Client, url: str, root: CertificateAuthority, kid: str, account: AcmeAccount
) -> None:
    """When there are more orders than page_size, first page includes a Link:next header."""
    page_size = AcmeAccountOrdersView._page_size  # pylint: disable=protected-access
    orders = [AcmeOrder.objects.create(account=account) for _ in range(page_size + 1)]

    resp = acme_request(client, url, root, b"", kid=kid)
    assert resp.status_code == HTTPStatus.OK, resp.content

    data = resp.json()
    assert len(data["orders"]) == page_size
    # Most-recently-created (highest PK) order is first; the oldest (orders[0]) falls on page 2.
    assert data["orders"][0] == f"http://{SERVER_NAME}{orders[-1].acme_url}"
    assert data["orders"][-1] == f"http://{SERVER_NAME}{orders[1].acme_url}"

    # The Link header must contain a "next" relation.
    link = resp["Link"]
    assert 'rel="next"' in link
    assert f"cursor={orders[0].pk}" in link


@pytest.mark.usefixtures("account")
def test_pagination_second_page(
    client: Client, url: str, root: CertificateAuthority, kid: str, account: AcmeAccount
) -> None:
    """Following the next-page cursor returns the remaining orders without a further next link."""
    page_size = AcmeAccountOrdersView._page_size  # pylint: disable=protected-access
    orders = [AcmeOrder.objects.create(account=account) for _ in range(page_size + 1)]
    oldest = orders[0]

    # Fetch second page by passing the cursor (PK of the last item on page 1 = orders[1]).
    cursor_url = url + f"?cursor={orders[1].pk}"
    resp = acme_request(client, cursor_url, root, b"", kid=kid)
    assert resp.status_code == HTTPStatus.OK, resp.content

    data = resp.json()
    assert data["orders"] == [f"http://{SERVER_NAME}{oldest.acme_url}"]

    # No further next link because this is the last page.
    link = resp["Link"]
    assert 'rel="next"' not in link


@pytest.mark.usefixtures("account")
def test_pagination_invalid_cursor(client: Client, url: str, root: CertificateAuthority, kid: str) -> None:
    """An invalid cursor value returns 400 Malformed."""
    bad_url = url + "?cursor=not-an-integer"
    resp = acme_request(client, bad_url, root, b"", kid=kid)
    assert resp.status_code == HTTPStatus.BAD_REQUEST, resp.content
    assert_malformed(resp, root, "Invalid pagination cursor.")


# ---------------------------------------------------------------------------
# Authorization / access-control tests
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("account")
def test_wrong_account_slug(client: Client, root: CertificateAuthority, kid: str) -> None:
    """Authenticated account must match the slug in the URL (RFC 8555 §10.5)."""
    wrong_url = root_reverse("acme-account-orders", slug=acme_slug())
    resp = acme_request(client, wrong_url, root, b"", kid=kid)
    assert_unauthorized(resp, root)


# ---------------------------------------------------------------------------
# Base-class generic ACME request tests (content-type, nonce, etc.)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("account")
class TestAcmeAccountOrdersView(AcmeWithAccountViewTestCaseMixin[jose.json_util.JSONObjectWithFields]):
    """Run shared ACME view tests against the account-orders endpoint."""

    post_as_get = True
    requires_kid = True

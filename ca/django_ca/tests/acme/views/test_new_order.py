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

"""Test creating a new order."""

# pylint: disable=redefined-outer-name  # because of fixtures

from datetime import timedelta, timezone as tz
from http import HTTPStatus
from typing import Any

import acme
import acme.jws
import pyrfc3339

from django.test import Client
from django.utils import timezone

import pytest
from pytest_django.fixtures import SettingsWrapper

from django_ca.acme.messages import NewOrder
from django_ca.conf import model_settings
from django_ca.models import AcmeAccount, AcmeAuthorization, AcmeOrder, CertificateAuthority
from django_ca.tests.acme.views.assertions import assert_malformed
from django_ca.tests.acme.views.base import AcmeWithAccountViewTestCaseMixin
from django_ca.tests.acme.views.constants import SERVER_NAME
from django_ca.tests.acme.views.utils import absolute_acme_uri, acme_request
from django_ca.tests.base.constants import TIMESTAMPS
from django_ca.tests.base.utils import mock_slug, root_reverse

# ACME views require a currently valid certificate authority
now = TIMESTAMPS["everything_valid"]  # just a shortcut
pytestmark = [pytest.mark.freeze_time(now)]


@pytest.fixture
def url() -> str:
    """URL under test."""
    return root_reverse("acme-new-order")


@pytest.fixture
def message() -> NewOrder:
    """Default message sent to the server."""
    return NewOrder(identifiers=[{"type": "dns", "value": SERVER_NAME}])


@pytest.mark.parametrize("use_tz", (True, False))
def test_basic(
    settings: SettingsWrapper,
    client: Client,
    url: str,
    message: NewOrder,
    root: CertificateAuthority,
    account: AcmeAccount,
    kid: str,
    use_tz: bool,
) -> None:
    """Basic test for creating an account via ACME."""
    settings.USE_TZ = use_tz

    with mock_slug() as slug:
        resp = acme_request(client, url, root, message, kid=kid)
    assert resp.status_code == HTTPStatus.CREATED, resp.content

    expires = timezone.now() + model_settings.CA_ACME_ORDER_VALIDITY
    assert resp.json() == {
        "authorizations": [absolute_acme_uri(":acme-authz", serial=root.serial, slug=slug)],
        "expires": pyrfc3339.generate(expires, accept_naive=not use_tz),
        "finalize": absolute_acme_uri(":acme-order-finalize", serial=root.serial, slug=slug),
        "identifiers": [{"type": "dns", "value": SERVER_NAME}],
        "status": "pending",
    }

    order = AcmeOrder.objects.get(account=account)
    assert order.account == account
    assert order.slug == slug
    assert order.status == "pending"
    assert order.expires == expires
    assert order.not_before is None
    assert order.not_after is None

    # Test the autogenerated AcmeAuthorization object
    authz = order.authorizations.all()
    assert len(authz) == 1
    assert authz[0].order == order
    assert authz[0].type == "dns"
    assert authz[0].value == SERVER_NAME
    assert authz[0].status == AcmeAuthorization.STATUS_PENDING
    assert authz[0].wildcard is False


@pytest.mark.parametrize("use_tz", (True, False))
def test_not_before_not_after(
    settings: SettingsWrapper,
    client: Client,
    url: str,
    root: CertificateAuthority,
    account: AcmeAccount,
    kid: str,
    use_tz: bool,
) -> None:
    """Test the notBefore/notAfter properties."""
    settings.USE_TZ = use_tz

    not_before = timezone.now() + timedelta(seconds=10)
    not_after = timezone.now() + timedelta(days=3)

    if timezone.is_naive(not_before):
        not_before = timezone.make_aware(not_before, timezone=tz.utc)
    if timezone.is_naive(not_after):
        not_after = timezone.make_aware(not_after, timezone=tz.utc)

    msg = NewOrder(
        identifiers=[{"type": "dns", "value": SERVER_NAME}], not_before=not_before, not_after=not_after
    )

    with mock_slug() as slug:
        resp = acme_request(client, url, root, msg, kid=kid)
    assert resp.status_code == HTTPStatus.CREATED, resp.content

    expires = timezone.now() + model_settings.CA_ACME_ORDER_VALIDITY
    assert resp.json() == {
        "authorizations": [absolute_acme_uri(":acme-authz", serial=root.serial, slug=slug)],
        "expires": pyrfc3339.generate(expires, accept_naive=not use_tz),
        "finalize": absolute_acme_uri(":acme-order-finalize", serial=root.serial, slug=slug),
        "identifiers": [{"type": "dns", "value": SERVER_NAME}],
        "status": "pending",
        "notBefore": pyrfc3339.generate(not_before, accept_naive=not use_tz),
        "notAfter": pyrfc3339.generate(not_after, accept_naive=not use_tz),
    }

    order = AcmeOrder.objects.get(account=account)
    assert order.account == account
    assert order.slug == slug
    assert order.status == "pending"
    assert order.expires == expires

    if use_tz:
        assert order.not_before == not_before
        assert order.not_after == not_after
    else:
        assert order.not_before == timezone.make_naive(not_before)
        assert order.not_after == timezone.make_naive(not_after)

    # Test the autogenerated AcmeAuthorization object
    authz = order.authorizations.all()
    assert len(authz) == 1
    assert authz[0].order == order
    assert authz[0].type == "dns"
    assert authz[0].value == SERVER_NAME
    assert authz[0].status == AcmeAuthorization.STATUS_PENDING
    assert authz[0].wildcard is False


@pytest.mark.usefixtures("account")
def test_no_identifiers(client: Client, url: str, root: CertificateAuthority, kid: str) -> None:
    """Test sending no identifiers."""
    resp = acme_request(client, url, root, acme.messages.NewOrder(), kid=kid)
    assert_malformed(resp, root, "The following fields are required: identifiers")

    # try empty tuple too
    resp = acme_request(
        client,
        url,
        root,
        acme.messages.NewOrder(identifiers=tuple()),
        kid=kid,
        payload_cb=lambda d: dict(d, identifiers=()),
    )
    assert_malformed(resp, root, "The following fields are required: identifiers")

    assert AcmeOrder.objects.all().count() == 0


@pytest.mark.usefixtures("account")
@pytest.mark.parametrize(
    ("values", "expected"),
    (
        ({"not_before": now - timedelta(days=1)}, "Certificate cannot be valid before now."),
        ({"not_after": now + timedelta(days=3650)}, "Certificate cannot be valid that long."),
        (
            {"not_before": now + timedelta(days=10), "not_after": now + timedelta(days=1)},
            "notBefore must be before notAfter.",
        ),
    ),
)
def test_invalid_not_before_after(
    client: Client, url: str, root: CertificateAuthority, kid: str, values: dict[str, Any], expected: str
) -> None:
    """Test invalid not_before/not_after dates."""
    message = NewOrder(identifiers=[{"type": "dns", "value": SERVER_NAME}], **values)
    resp = acme_request(client, url, root, message, kid=kid)
    assert_malformed(resp, root, expected)


class TestAcmeNewOrderView(AcmeWithAccountViewTestCaseMixin[NewOrder]):
    """Test creating a new order."""

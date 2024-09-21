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

"""Test viewing an order."""

# pylint: disable=redefined-outer-name  # because of fixtures

from collections.abc import Iterator
from http import HTTPStatus
from typing import Optional
from unittest import mock

import josepy as jose
import pyrfc3339

from django.test import Client
from django.utils import timezone

import pytest
from pytest_django.fixtures import SettingsWrapper

from django_ca.acme.errors import AcmeUnauthorized
from django_ca.conf import model_settings
from django_ca.models import (
    AcmeAccount,
    AcmeAuthorization,
    AcmeCertificate,
    AcmeOrder,
    Certificate,
    CertificateAuthority,
)
from django_ca.tests.acme.views.assertions import assert_acme_response, assert_unauthorized
from django_ca.tests.acme.views.base import AcmeWithAccountViewTestCaseMixin
from django_ca.tests.acme.views.constants import HOST_NAME, SERVER_NAME
from django_ca.tests.acme.views.utils import acme_request
from django_ca.tests.base.constants import TIMESTAMPS
from django_ca.tests.base.utils import root_reverse

# ACME views require a currently valid certificate authority
pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])]


@pytest.fixture()
def url(order: AcmeOrder) -> Iterator[str]:
    """URL under test."""
    yield root_reverse("acme-order", slug=order.slug)


@pytest.fixture()
def message() -> Iterator[bytes]:
    """Yield an empty bytestring, since this is a POST-AS-GET request."""
    yield b""


@pytest.mark.parametrize("use_tz", (True, False))
def test_basic(
    settings: SettingsWrapper,
    client: Client,
    url: str,
    root: CertificateAuthority,
    authz: AcmeAuthorization,
    kid: Optional[str],
    use_tz: bool,
) -> None:
    """Basic test for creating an account via ACME."""
    settings.USE_TZ = use_tz
    resp = acme_request(client, url, root, b"", kid=kid)
    assert resp.status_code == HTTPStatus.OK, resp.content
    assert_acme_response(resp, root)
    expires = timezone.now() + model_settings.CA_ACME_ORDER_VALIDITY
    assert resp.json() == {
        "authorizations": [f"http://{SERVER_NAME}{authz.acme_url}"],
        "expires": pyrfc3339.generate(expires, accept_naive=not use_tz),
        "identifiers": [{"type": "dns", "value": HOST_NAME}],
        "status": "pending",
    }


def test_valid_cert(
    client: Client,
    url: str,
    root: CertificateAuthority,
    root_cert: Certificate,
    order: AcmeOrder,
    authz: AcmeAuthorization,
    kid: Optional[str],
) -> None:
    """Test viewing an order with a valid certificate."""
    order.status = AcmeOrder.STATUS_VALID
    order.save()
    authz.status = AcmeAuthorization.STATUS_VALID
    authz.save()
    acme_cert = AcmeCertificate.objects.create(order=order, cert=root_cert)

    resp = acme_request(client, url, root, b"", kid=kid)
    assert resp.status_code == HTTPStatus.OK, resp.content
    assert_acme_response(resp, root)
    expires = timezone.now() + model_settings.CA_ACME_ORDER_VALIDITY
    assert resp.json() == {
        "authorizations": [f"http://{SERVER_NAME}{authz.acme_url}"],
        "certificate": f"http://{SERVER_NAME}{acme_cert.acme_url}",
        "expires": pyrfc3339.generate(expires),
        "identifiers": [{"type": "dns", "value": HOST_NAME}],
        "status": "valid",
    }


def test_cert_not_yet_issued(
    client: Client,
    url: str,
    root: CertificateAuthority,
    order: AcmeOrder,
    authz: AcmeAuthorization,
    kid: Optional[str],
) -> None:
    """Test viewing an order where the certificate has not yet been issued.

    NOTE: test_cert_not_yet_issued and test_cert_not_yet_valid test two different conditions that
    *should* always be true at the same time.
    """
    order.status = AcmeOrder.STATUS_VALID
    order.save()
    authz.status = AcmeAuthorization.STATUS_VALID
    authz.save()
    AcmeCertificate.objects.create(order=order)

    resp = acme_request(client, url, root, b"", kid=kid)
    assert resp.status_code == HTTPStatus.OK, resp.content
    assert_acme_response(resp, root)
    expires = timezone.now() + model_settings.CA_ACME_ORDER_VALIDITY
    assert resp.json() == {
        "authorizations": [f"http://{SERVER_NAME}{authz.acme_url}"],
        "expires": pyrfc3339.generate(expires),
        "identifiers": [{"type": "dns", "value": HOST_NAME}],
        "status": "valid",
    }


def test_cert_not_yet_valid(
    client: Client,
    url: str,
    root: CertificateAuthority,
    root_cert: Certificate,
    order: AcmeOrder,
    authz: AcmeAuthorization,
    kid: Optional[str],
) -> None:
    """Test viewing an order where the certificate has not yet valid.

    NOTE: test_cert_not_yet_issued and test_cert_not_yet_valid test two different conditions that
    *should* always be true at the same time.
    """
    order.status = AcmeOrder.STATUS_PROCESSING
    order.save()
    authz.status = AcmeAuthorization.STATUS_VALID
    authz.save()
    AcmeCertificate.objects.create(order=order, cert=root_cert)

    resp = acme_request(client, url, root, b"", kid=kid)
    assert resp.status_code == HTTPStatus.OK, resp.content
    assert_acme_response(resp, root)
    expires = timezone.now() + model_settings.CA_ACME_ORDER_VALIDITY
    assert resp.json() == {
        "authorizations": [f"http://{SERVER_NAME}{authz.acme_url}"],
        "expires": pyrfc3339.generate(expires),
        "identifiers": [{"type": "dns", "value": HOST_NAME}],
        "status": "processing",
    }


def test_wrong_account(
    client: Client, url: str, root: CertificateAuthority, order: AcmeOrder, kid: Optional[str]
) -> None:
    """Test viewing for the wrong account."""
    account = AcmeAccount.objects.create(
        ca=root, terms_of_service_agreed=True, slug="def", kid="kid", pem="bar", thumbprint="foo"
    )
    order.account = account
    order.save()

    resp = acme_request(client, url, root, b"", kid=kid)
    assert_unauthorized(resp, root)


def test_not_found(client: Client, root: CertificateAuthority, order: AcmeOrder, kid: Optional[str]) -> None:
    """Test viewing an order that simply does not exist."""
    account = AcmeAccount.objects.create(
        ca=root, terms_of_service_agreed=True, slug="def", kid="kid", pem="bar", thumbprint="foo"
    )
    order.account = account
    order.save()

    url = root_reverse("acme-order", slug=order.slug)
    resp = acme_request(client, url, root, b"", kid=kid)
    assert_unauthorized(resp, root)


def test_basic_exception(client: Client, url: str, root: CertificateAuthority, kid: Optional[str]) -> None:
    """Test throwing an AcmeException in acme_request().

    We have to mock this, as at present this is not usually done.
    """
    with mock.patch(
        "django_ca.acme.views.AcmeOrderView.acme_request", side_effect=AcmeUnauthorized(message="foo")
    ):
        resp = acme_request(client, url, root, b"", kid=kid)
    assert_unauthorized(resp, root, "foo")


class TestAcmeOrderView(AcmeWithAccountViewTestCaseMixin[jose.json_util.JSONObjectWithFields]):
    """Test retrieving an order."""

    # NOTE: type parameter not required post-as-get requests

    post_as_get = True

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

# pylint: disable=redefined-outer-name  # requested pytest fixtures show up this way.

"""Test the revoking certificates via the API."""
from http import HTTPStatus
from typing import Any, Dict, Tuple, Type

from django.db.models import Model
from django.test.client import Client
from django.urls import reverse_lazy
from django.utils import timezone

import pytest
from freezegun import freeze_time

from django_ca.models import Certificate
from django_ca.tests.api.conftest import DetailResponse
from django_ca.tests.api.mixins import APIPermissionTestBase
from django_ca.tests.base import timestamps
from django_ca.tests.base.conftest_helpers import certs
from django_ca.tests.base.typehints import HttpResponse
from django_ca.tests.base.utils import iso_format

path = reverse_lazy(
    "django_ca:api:revoke_certificate",
    kwargs={"serial": certs["root"]["serial"], "certificate_serial": certs["root-cert"]["serial"]},
)


@pytest.fixture(scope="module")
def api_permission() -> Tuple[Type[Model], str]:
    """Fixture for the permission required by this view."""
    return Certificate, "revoke_certificate"


@pytest.fixture()
def expected_response(root_cert_response: Dict[str, Any]) -> DetailResponse:
    """Fixture for the regular response expected from this API view."""
    root_cert_response["revoked"] = True
    return root_cert_response


@freeze_time(timestamps["everything_valid"])
def test_revoke_view(root_cert: Certificate, api_client: Client, expected_response: DetailResponse) -> None:
    """Test an ordinary certificate revocation."""
    response = api_client.post(path, {}, content_type="application/json")
    assert response.status_code == HTTPStatus.OK, response.content
    assert response.json() == expected_response, response.json()

    root_cert.refresh_from_db()
    assert root_cert.revoked is True
    assert root_cert.revoked_reason == "unspecified"
    assert root_cert.compromised is None


@freeze_time(timestamps["everything_valid"])
def test_revoke_with_parameters(
    root_cert: Certificate, api_client: Client, expected_response: DetailResponse
) -> None:
    """Test an ordinary certificate revocation."""
    now = timezone.now()
    expected_response["updated"] = iso_format(now)

    response = api_client.post(
        path,
        {"reason": "affiliationChanged", "compromised": iso_format(now)},
        content_type="application/json",
    )

    assert response.status_code == HTTPStatus.OK, response.content
    assert response.json() == expected_response, response.json()

    root_cert.refresh_from_db()
    assert root_cert.revoked is True
    assert root_cert.revoked_reason == "affiliation_changed"
    assert root_cert.compromised == now


@freeze_time(timestamps["everything_valid"])
def test_revoked_certificate_fails(root_cert: Certificate, api_client: Client) -> None:
    """Test that revoking a revoked certificate fails."""
    root_cert.revoke()

    response = api_client.post(path, {}, content_type="application/json")
    assert response.status_code == HTTPStatus.BAD_REQUEST, response.content
    assert response.json() == {"detail": "The certificate is already revoked."}, response.json()


@freeze_time(timestamps["everything_expired"])
def test_cannot_revoke_expired_certificate(root_cert: Certificate, api_client: Client) -> None:
    """Test that we cannot revoke a certificate if it is expired."""
    response = api_client.post(path, {}, content_type="application/json")
    assert response.status_code == HTTPStatus.NOT_FOUND, response.content
    assert response.json() == {"detail": "Not Found"}, response.json()

    root_cert.refresh_from_db()
    assert root_cert.revoked is False  # cert is still not revoked (just expired)


@freeze_time(timestamps["everything_valid"])
@pytest.mark.usefixtures("root")  # CA should exist, but certificate does not
def test_certificate_not_found(api_client: Client) -> None:
    """Test response when a certificate was not found."""
    response = api_client.post(path, {}, content_type="application/json")
    assert response.status_code == HTTPStatus.NOT_FOUND, response.content
    assert response.json() == {"detail": "Not Found"}, response.json()


@freeze_time(timestamps["everything_valid"])
def test_disabled_ca(root_cert: Certificate, api_client: Client) -> None:
    """Test that certificates for a disabled can *not* be viewed."""
    root_cert.ca.enabled = False
    root_cert.ca.save()

    response = api_client.post(path, {}, content_type="application/json")
    assert response.status_code == HTTPStatus.NOT_FOUND, response.content
    assert response.json() == {"detail": "Not Found"}, response.json()


class TestPermissions(APIPermissionTestBase):
    """Test permissions for this view."""

    path = path

    def request(self, client: Client) -> HttpResponse:
        return client.post(path, {}, content_type="application/json")

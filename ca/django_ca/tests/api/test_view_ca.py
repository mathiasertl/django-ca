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

"""Test the detail-view for a CA."""

from http import HTTPStatus
from typing import Any

from django.db.models import Model
from django.test import Client
from django.urls import reverse_lazy

import pytest

from django_ca.models import CertificateAuthority
from django_ca.tests.api.conftest import APIPermissionTestBase
from django_ca.tests.base.constants import CERT_DATA, TIMESTAMPS

path = reverse_lazy(
    "django_ca:api:view_certificate_authority", kwargs={"serial": CERT_DATA["root"]["serial"]}
)


@pytest.fixture(scope="module")
def api_permission() -> tuple[type[Model], str]:
    """Fixture for the permission required by this view."""
    return CertificateAuthority, "view_certificateauthority"


@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])
def test_view(api_client: Client, root_response: dict[str, Any]) -> None:
    """Test an ordinary view."""
    response = api_client.get(path)
    assert response.status_code == HTTPStatus.OK, response.content
    assert response.json() == root_response, response.json()


@pytest.mark.freeze_time(TIMESTAMPS["everything_expired"])
def test_view_expired_ca(api_client: Client, root_response: dict[str, Any]) -> None:
    """Test that we can view an expired CA."""
    response = api_client.get(path)
    assert response.status_code == HTTPStatus.OK, response.content
    assert response.json() == root_response, response.json()


@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])
def test_with_leading_zeroes(api_client: Client, root_response: dict[str, Any]) -> None:
    """Test that leading zeros in serials are trimmed."""
    serial = f"000{CERT_DATA['root']['serial']}"
    zero_path = reverse_lazy("django_ca:api:view_certificate_authority", kwargs={"serial": serial})
    response = api_client.get(zero_path)
    assert response.status_code == HTTPStatus.OK, response.content
    assert response.json() == root_response, response.json()


class TestPermissions(APIPermissionTestBase):
    """Test permissions for this view."""

    path = path

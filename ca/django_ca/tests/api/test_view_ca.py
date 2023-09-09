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
from typing import Any, Dict, Tuple, Type

from django.db.models import Model
from django.test import Client
from django.urls import reverse_lazy

import pytest
from freezegun import freeze_time

from django_ca.models import CertificateAuthority
from django_ca.tests.api.mixins import APIPermissionTestBase
from django_ca.tests.base import timestamps
from django_ca.tests.base.conftest_helpers import certs

path = reverse_lazy("django_ca:api:view_certificate_authority", kwargs={"serial": certs["root"]["serial"]})


@pytest.fixture(scope="module")
def api_permission() -> Tuple[Type[Model], str]:
    """Fixture for the permission required by this view."""
    return CertificateAuthority, "view_certificateauthority"


@freeze_time(timestamps["everything_valid"])
def test_view(api_client: Client, root_response: Dict[str, Any]) -> None:
    """Test an ordinary view."""
    response = api_client.get(path)
    assert response.status_code == HTTPStatus.OK, response.content
    assert response.json() == root_response, response.json()


@freeze_time(timestamps["everything_expired"])
def test_view_expired_ca(api_client: Client, root_response: Dict[str, Any]) -> None:
    """Test that we can view an expired CA."""
    response = api_client.get(path)
    assert response.status_code == HTTPStatus.OK, response.content
    assert response.json() == root_response, response.json()


@freeze_time(timestamps["everything_valid"])
def test_disabled_ca(root: CertificateAuthority, api_client: Client) -> None:
    """Test that a disabled CA is *not* viewable."""
    root.enabled = False
    root.save()

    response = api_client.get(path)
    assert response.status_code == HTTPStatus.NOT_FOUND, response.content
    assert response.json() == {"detail": "Not Found"}, response.json()


class TestPermissions(APIPermissionTestBase):
    """Test permissions for this view."""

    path = path

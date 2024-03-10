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

"""Test the detail-view for a certificate."""

from http import HTTPStatus
from typing import Any, Dict, Tuple, Type

from django.db.models import Model
from django.test import Client
from django.urls import reverse_lazy

import pytest
from freezegun import freeze_time

from django_ca.models import Certificate
from django_ca.tests.api.conftest import APIPermissionTestBase
from django_ca.tests.base.constants import CERT_DATA, TIMESTAMPS

path = reverse_lazy(
    "django_ca:api:view_certificate",
    kwargs={"serial": CERT_DATA["root"]["serial"], "certificate_serial": CERT_DATA["root-cert"]["serial"]},
)


@pytest.fixture(scope="module")
def api_permission() -> Tuple[Type[Model], str]:
    """Fixture for the permission required by this view."""
    return Certificate, "view_certificate"


@freeze_time(TIMESTAMPS["everything_valid"])
def test_detail_view(api_client: Client, root_cert_response: Dict[str, Any]) -> None:
    """Test an ordinary detail view."""
    response = api_client.get(path)
    assert response.status_code == HTTPStatus.OK, response.content
    assert response.json() == root_cert_response, response.json()


@freeze_time(TIMESTAMPS["everything_expired"])
def test_expired_certificate(api_client: Client, root_cert_response: Dict[str, Any]) -> None:
    """Test that we can view the certificate even if it is expired."""
    response = api_client.get(path)
    assert response.status_code == HTTPStatus.OK, response.content
    assert response.json() == root_cert_response, response.json()


class TestPermissions(APIPermissionTestBase):
    """Test permissions for this view."""

    path = path

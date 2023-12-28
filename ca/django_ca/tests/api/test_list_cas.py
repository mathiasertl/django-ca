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

"""Test the view to list certificate authorities."""
import typing
from http import HTTPStatus
from typing import Any, Dict, List, Optional, Tuple, Type

from django.db.models import Model
from django.test.client import Client
from django.urls import reverse_lazy

import pytest
from freezegun import freeze_time

from django_ca.models import CertificateAuthority
from django_ca.tests.api.conftest import APIPermissionTestBase, ListResponse
from django_ca.tests.base.constants import TIMESTAMPS
from django_ca.tests.base.typehints import HttpResponse

path = reverse_lazy("django_ca:api:list_certificate_authorities")


@pytest.fixture(scope="module")
def api_permission() -> Tuple[Type[Model], str]:
    """Fixture for the permission required by this view."""
    return CertificateAuthority, "view_certificateauthority"


@pytest.fixture()
def expected_response(root_response: Dict[str, Any]) -> ListResponse:
    """Fixture for the regular response expected from this API view."""
    return [root_response]


def request(client: Client, data: Optional[Dict[str, str]] = None) -> HttpResponse:
    """Make a default request to the view under test."""
    return client.get(path, data=data)


def test_empty_list_view(api_client: Client) -> None:
    """Test the request with no certificate authorities (empty list view)."""
    CertificateAuthority.objects.all().delete()
    response = request(api_client)
    assert response.status_code == HTTPStatus.OK, response.content
    assert response.json() == []


@freeze_time(TIMESTAMPS["everything_valid"])
def test_list_view(api_client: Client, expected_response: ListResponse) -> None:
    """Test an ordinary list view."""
    response = request(api_client)
    assert response.status_code == HTTPStatus.OK, response.content
    assert response.json() == expected_response, response.json()


@pytest.mark.usefixtures("root")
@freeze_time(TIMESTAMPS["everything_expired"])
def test_expired_certificate_authorities_are_excluded(api_client: Client) -> None:
    """Test that expired CAs are excluded by default."""
    response = request(api_client)
    assert CertificateAuthority.objects.count() > 0  # just to be sure that there would be some
    assert response.status_code == HTTPStatus.OK, response.content
    assert response.json() == [], response.json()


@freeze_time(TIMESTAMPS["everything_expired"])
def test_expired_filter(api_client: Client, expected_response: ListResponse) -> None:
    """Test that expired CAs are excluded by default."""
    response = request(api_client, {"expired": "1"})
    assert response.status_code == HTTPStatus.OK, response.content
    assert response.json() == expected_response, response.json()


class TestPermissions(APIPermissionTestBase):
    """Test permissions for this view."""

    path = path

    expected_disabled_status_code = HTTPStatus.OK
    expected_disabled_response: typing.ClassVar[List[Any]] = []

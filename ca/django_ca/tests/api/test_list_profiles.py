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

"""Test the view to list certificate authorities."""

from http import HTTPStatus
from typing import Any, ClassVar

from django.db.models import Model
from django.test.client import Client
from django.urls import reverse_lazy

import pytest

from django_ca.models import Certificate
from django_ca.profiles import profiles
from django_ca.tests.api.conftest import APIPermissionTestBase

path = reverse_lazy("django_ca:api:list_profiles")


@pytest.fixture(scope="module")
def api_permission() -> tuple[type[Model], str]:
    """Fixture for the permission required by this view."""
    return Certificate, "sign_certificate"


def test_get(api_client: Client) -> None:
    """Test a simple get request."""
    response = api_client.get(path)
    assert response.status_code == HTTPStatus.OK, response.content
    assert len(response.json()) == len(list(profiles))


class TestPermissions(APIPermissionTestBase):
    """Test permissions for this view."""

    path = path

    expected_disabled_status_code = HTTPStatus.OK
    expected_disabled_response: ClassVar[list[Any]] = []

    # These two tests make no sense in this context:
    def test_disabled_ca(self) -> None:  # type: ignore[override]
        pass

    def test_disabled_api_access(self) -> None:  # type: ignore[override]
        pass

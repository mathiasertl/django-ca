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

"""Extra fixtures for tests for the admin interface."""

from django.test import Client
from django.urls import reverse

import pytest
from _pytest.fixtures import SubRequest

from django_ca.tests.base.typehints import User


@pytest.fixture(params=["name_to_rfc4514"])
def extra_view_url(request: "SubRequest") -> str:
    """Parametrized fixture providing reversed extra view URLs."""
    return reverse(f"admin:django_ca_certificate_{request.param}")


@pytest.fixture
def staff_client(user: "User", user_client: Client) -> Client:
    """Client with a staff user with no extra permissions."""
    user.is_staff = True
    user.save()
    return user_client

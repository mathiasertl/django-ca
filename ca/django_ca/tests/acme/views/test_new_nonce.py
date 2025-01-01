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

"""Test ACME view to retrieve a new nonce."""

from http import HTTPStatus

from django.test import Client
from django.urls import reverse

import pytest
from pytest_django import DjangoAssertNumQueries
from pytest_django.fixtures import SettingsWrapper

from django_ca.tests.base.constants import CERT_DATA

URL = reverse("django_ca:acme-new-nonce", kwargs={"serial": CERT_DATA["root"]["serial"]})


@pytest.mark.django_db
def test_get_nonce(django_assert_num_queries: DjangoAssertNumQueries, client: Client) -> None:
    """Test that getting multiple nonces returns unique nonces."""
    nonces = []
    for _i in range(1, 5):
        with django_assert_num_queries(0):
            response = client.head(URL)
        assert response.status_code == HTTPStatus.OK
        assert len(response["replay-nonce"]) == 43
        assert response["cache-control"] == "no-store"
        nonces.append(response["replay-nonce"])

    assert len(nonces) == len(set(nonces))


@pytest.mark.django_db
def test_get_request(django_assert_num_queries: DjangoAssertNumQueries, client: Client) -> None:
    """RFC 8555, section 7.2 also specifies a GET request."""
    with django_assert_num_queries(0):
        response = client.get(URL)
    assert response.status_code == HTTPStatus.NO_CONTENT
    assert len(response["replay-nonce"]) == 43
    assert response["cache-control"] == "no-store"


def test_disabled(settings: SettingsWrapper, client: Client) -> None:
    """Test that CA_ENABLE_ACME=False means HTTP 404."""
    settings.CA_ENABLE_ACME = False
    response = client.head(URL)
    assert response.status_code == HTTPStatus.NOT_FOUND
    assert response["Content-Type"].startswith("text/html")  # --> coming from Django

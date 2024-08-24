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

"""Test basic ACMEv2 directory view."""

from http import HTTPStatus
from unittest import mock

from django.test.client import Client
from django.urls import reverse

import pytest
from freezegun import freeze_time
from pytest_django.fixtures import SettingsWrapper

from django_ca.models import CertificateAuthority
from django_ca.tests.base.constants import TIMESTAMPS

# ACME views require a currently valid certificate authority
pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])]

RANDOM_URL = "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417"
URL = reverse("django_ca:acme-directory")


def test_default(client: Client, root: CertificateAuthority) -> None:
    """Test the default directory view."""
    """Test the default directory view."""
    with mock.patch("secrets.token_bytes", return_value=b"foobar"):
        response = client.get(URL)
    assert response.status_code == HTTPStatus.OK
    req = response.wsgi_request
    assert response.json() == {
        "Zm9vYmFy": RANDOM_URL,
        "keyChange": "http://localhost:8000/django_ca/acme/todo/key-change",
        "revokeCert": req.build_absolute_uri(f"/django_ca/acme/{root.serial}/revoke/"),
        "newAccount": req.build_absolute_uri(f"/django_ca/acme/{root.serial}/new-account/"),
        "newNonce": req.build_absolute_uri(f"/django_ca/acme/{root.serial}/new-nonce/"),
        "newOrder": req.build_absolute_uri(f"/django_ca/acme/{root.serial}/new-order/"),
    }


def test_named_ca(client: Client, root: CertificateAuthority) -> None:
    """Test getting directory for named CA."""
    url = reverse("django_ca:acme-directory", kwargs={"serial": root.serial})
    with mock.patch("secrets.token_bytes", return_value=b"foobar"):
        response = client.get(url)
    assert response.status_code == HTTPStatus.OK
    assert response["Content-Type"] == "application/json"
    req = response.wsgi_request
    assert response.json() == {
        "Zm9vYmFy": RANDOM_URL,
        "keyChange": "http://localhost:8000/django_ca/acme/todo/key-change",
        "revokeCert": req.build_absolute_uri(f"/django_ca/acme/{root.serial}/revoke/"),
        "newAccount": req.build_absolute_uri(f"/django_ca/acme/{root.serial}/new-account/"),
        "newNonce": req.build_absolute_uri(f"/django_ca/acme/{root.serial}/new-nonce/"),
        "newOrder": req.build_absolute_uri(f"/django_ca/acme/{root.serial}/new-order/"),
    }


def test_meta(client: Client, root: CertificateAuthority) -> None:
    """Test the meta property."""
    root.website = "http://ca.example.com"
    root.terms_of_service = "http://ca.example.com/acme/tos"
    root.caa_identity = "ca.example.com"
    root.save()

    url = reverse("django_ca:acme-directory", kwargs={"serial": root.serial})
    with mock.patch("secrets.token_bytes", return_value=b"foobar"):
        response = client.get(url)
    assert response.status_code == HTTPStatus.OK
    assert response["Content-Type"] == "application/json"
    req = response.wsgi_request
    assert response.json() == {
        "Zm9vYmFy": RANDOM_URL,
        "keyChange": "http://localhost:8000/django_ca/acme/todo/key-change",
        "revokeCert": req.build_absolute_uri(f"/django_ca/acme/{root.serial}/revoke/"),
        "newAccount": req.build_absolute_uri(f"/django_ca/acme/{root.serial}/new-account/"),
        "newNonce": req.build_absolute_uri(f"/django_ca/acme/{root.serial}/new-nonce/"),
        "newOrder": req.build_absolute_uri(f"/django_ca/acme/{root.serial}/new-order/"),
        "meta": {
            "termsOfService": root.terms_of_service,
            "caaIdentities": [root.caa_identity],
            "website": root.website,
        },
    }


def test_acme_default_disabled(client: Client, root: CertificateAuthority) -> None:
    """Test that fetching the default CA with ACME disabled doesn't work."""
    root.acme_enabled = False
    root.save()

    response = client.get(URL)
    assert response.status_code == HTTPStatus.NOT_FOUND
    assert response["Content-Type"] == "application/problem+json"
    assert response.json() == {
        "detail": "No (usable) default CA configured.",
        "status": 404,
        "type": "urn:ietf:params:acme:error:not-found",
    }


def test_acme_disabled(client: Client, root: CertificateAuthority) -> None:
    """Test that fetching a named CA with ACME disabled doesn't work."""
    root.acme_enabled = False
    root.save()

    url = reverse("django_ca:acme-directory", kwargs={"serial": root.serial})
    response = client.get(url)
    assert response.status_code == HTTPStatus.NOT_FOUND
    assert response["Content-Type"] == "application/problem+json"
    assert response.json() == {
        "detail": f"{root.serial}: CA not found.",
        "status": 404,
        "type": "urn:ietf:params:acme:error:not-found",
    }


@pytest.mark.django_db  # to query for CAs
def test_no_ca(client: Client) -> None:
    """Test using default CA when **no** CA exists."""
    response = client.get(URL)
    assert response.status_code == HTTPStatus.NOT_FOUND
    assert response["Content-Type"] == "application/problem+json"
    assert response.json() == {
        "detail": "No (usable) default CA configured.",
        "status": 404,
        "type": "urn:ietf:params:acme:error:not-found",
    }


@freeze_time(TIMESTAMPS["everything_expired"])
def test_expired_ca(client: Client, root: CertificateAuthority) -> None:
    """Test using default CA when all CAs are expired."""
    response = client.get(URL)
    assert response.status_code == HTTPStatus.NOT_FOUND
    assert response["Content-Type"] == "application/problem+json"
    assert response.json() == {
        "detail": "No (usable) default CA configured.",
        "status": 404,
        "type": "urn:ietf:params:acme:error:not-found",
    }


@pytest.mark.usefixtures("root")  # otherwise we wouldn't find anything ever anyway
def test_disabled(client: Client, settings: SettingsWrapper) -> None:
    """Test that CA_ENABLE_ACME=False means HTTP 404."""
    settings.CA_ENABLE_ACME = False
    response = client.get(URL)
    assert response.status_code == HTTPStatus.NOT_FOUND
    assert response["Content-Type"].startswith("text/html")  # --> coming from Django


@pytest.mark.usefixtures("root")  # otherwise we wouldn't find anything ever anyway
def test_unknown_serial(client: Client) -> None:
    """Test explicitly naming an unknown serial."""
    serial = "ABCDEF"
    url = reverse("django_ca:acme-directory", kwargs={"serial": serial})
    response = client.get(url)

    assert response["Content-Type"] == "application/problem+json"
    assert response.json() == {
        "detail": "ABCDEF: CA not found.",
        "status": 404,
        "type": "urn:ietf:params:acme:error:not-found",
    }

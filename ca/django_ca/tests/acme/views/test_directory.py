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

from django.test import TestCase
from django.test.utils import override_settings
from django.urls import reverse, reverse_lazy

from freezegun import freeze_time

from django_ca.models import CertificateAuthority
from django_ca.tests.base.constants import TIMESTAMPS
from django_ca.tests.base.mixins import TestCaseMixin


class DirectoryTestCase(TestCaseMixin, TestCase):
    """Test basic ACMEv2 directory view."""

    load_cas = ("root",)
    url = reverse_lazy("django_ca:acme-directory")
    random_url = "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417"

    def setUp(self) -> None:
        super().setUp()
        self.ca.acme_enabled = True
        self.ca.save()

    @freeze_time(TIMESTAMPS["everything_valid"])
    def test_default(self) -> None:
        """Test the default directory view."""
        with mock.patch("secrets.token_bytes", return_value=b"foobar"):
            response = self.client.get(self.url)
        self.assertEqual(response.status_code, HTTPStatus.OK)
        req = response.wsgi_request
        self.assertEqual(
            response.json(),
            {
                "Zm9vYmFy": self.random_url,
                "keyChange": "http://localhost:8000/django_ca/acme/todo/key-change",
                "revokeCert": req.build_absolute_uri(f"/django_ca/acme/{self.ca.serial}/revoke/"),
                "newAccount": req.build_absolute_uri(f"/django_ca/acme/{self.ca.serial}/new-account/"),
                "newNonce": req.build_absolute_uri(f"/django_ca/acme/{self.ca.serial}/new-nonce/"),
                "newOrder": req.build_absolute_uri(f"/django_ca/acme/{self.ca.serial}/new-order/"),
            },
        )

    @freeze_time(TIMESTAMPS["everything_valid"])
    def test_named_ca(self) -> None:
        """Test getting directory for named CA."""
        url = reverse("django_ca:acme-directory", kwargs={"serial": self.ca.serial})
        with mock.patch("secrets.token_bytes", return_value=b"foobar"):
            response = self.client.get(url)
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(response["Content-Type"], "application/json")
        req = response.wsgi_request
        self.assertEqual(
            response.json(),
            {
                "Zm9vYmFy": self.random_url,
                "keyChange": "http://localhost:8000/django_ca/acme/todo/key-change",
                "revokeCert": req.build_absolute_uri(f"/django_ca/acme/{self.ca.serial}/revoke/"),
                "newAccount": req.build_absolute_uri(f"/django_ca/acme/{self.ca.serial}/new-account/"),
                "newNonce": req.build_absolute_uri(f"/django_ca/acme/{self.ca.serial}/new-nonce/"),
                "newOrder": req.build_absolute_uri(f"/django_ca/acme/{self.ca.serial}/new-order/"),
            },
        )

    @freeze_time(TIMESTAMPS["everything_valid"])
    def test_meta(self) -> None:
        """Test the meta property."""
        self.ca.website = "http://ca.example.com"
        self.ca.terms_of_service = "http://ca.example.com/acme/tos"
        self.ca.caa_identity = "ca.example.com"
        self.ca.save()

        url = reverse("django_ca:acme-directory", kwargs={"serial": self.ca.serial})
        with mock.patch("secrets.token_bytes", return_value=b"foobar"):
            response = self.client.get(url)
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(response["Content-Type"], "application/json")
        req = response.wsgi_request
        self.assertEqual(
            response.json(),
            {
                "Zm9vYmFy": self.random_url,
                "keyChange": "http://localhost:8000/django_ca/acme/todo/key-change",
                "revokeCert": req.build_absolute_uri(f"/django_ca/acme/{self.ca.serial}/revoke/"),
                "newAccount": req.build_absolute_uri(f"/django_ca/acme/{self.ca.serial}/new-account/"),
                "newNonce": req.build_absolute_uri(f"/django_ca/acme/{self.ca.serial}/new-nonce/"),
                "newOrder": req.build_absolute_uri(f"/django_ca/acme/{self.ca.serial}/new-order/"),
                "meta": {
                    "termsOfService": self.ca.terms_of_service,
                    "caaIdentities": [
                        self.ca.caa_identity,
                    ],
                    "website": self.ca.website,
                },
            },
        )

    @freeze_time(TIMESTAMPS["everything_valid"])
    def test_acme_default_disabled(self) -> None:
        """Test that fetching the default CA with ACME disabled doesn't work."""
        self.ca.acme_enabled = False
        self.ca.save()

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, HTTPStatus.NOT_FOUND)
        self.assertEqual(response["Content-Type"], "application/problem+json")
        self.assertEqual(
            response.json(),
            {
                "detail": "No (usable) default CA configured.",
                "status": 404,
                "type": "urn:ietf:params:acme:error:not-found",
            },
        )

    @freeze_time(TIMESTAMPS["everything_valid"])
    def test_acme_disabled(self) -> None:
        """Test that fetching the default CA with ACME disabled doesn't work."""
        self.ca.acme_enabled = False
        self.ca.save()

        url = reverse("django_ca:acme-directory", kwargs={"serial": self.ca.serial})
        response = self.client.get(url)
        self.assertEqual(response.status_code, HTTPStatus.NOT_FOUND)
        self.assertEqual(response["Content-Type"], "application/problem+json")
        self.assertEqual(
            response.json(),
            {
                "detail": f"{self.ca.serial}: CA not found.",
                "status": 404,
                "type": "urn:ietf:params:acme:error:not-found",
            },
        )

    def test_no_ca(self) -> None:
        """Test using default CA when **no** CA exists."""
        CertificateAuthority.objects.all().delete()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, HTTPStatus.NOT_FOUND)
        self.assertEqual(response["Content-Type"], "application/problem+json")
        self.assertEqual(
            response.json(),
            {
                "detail": "No (usable) default CA configured.",
                "status": 404,
                "type": "urn:ietf:params:acme:error:not-found",
            },
        )

    @freeze_time(TIMESTAMPS["everything_expired"])
    def test_expired_ca(self) -> None:
        """Test using default CA when all CAs are expired."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, HTTPStatus.NOT_FOUND)
        self.assertEqual(response["Content-Type"], "application/problem+json")
        self.assertEqual(
            response.json(),
            {
                "detail": "No (usable) default CA configured.",
                "status": 404,
                "type": "urn:ietf:params:acme:error:not-found",
            },
        )

    @override_settings(CA_ENABLE_ACME=False)
    def test_disabled(self) -> None:
        """Test that CA_ENABLE_ACME=False means HTTP 404."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, HTTPStatus.NOT_FOUND)
        self.assertTrue(response["Content-Type"].startswith("text/html"))  # --> coming from Django

    def test_unknown_serial(self) -> None:
        """Test explicitly naming an unknown serial."""
        serial = "ABCDEF"
        url = reverse("django_ca:acme-directory", kwargs={"serial": serial})
        response = self.client.get(url)

        self.assertEqual(response["Content-Type"], "application/problem+json")
        self.assertEqual(
            response.json(),
            {
                "detail": "ABCDEF: CA not found.",
                "status": 404,
                "type": "urn:ietf:params:acme:error:not-found",
            },
        )

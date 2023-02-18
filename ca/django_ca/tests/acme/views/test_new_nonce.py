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

"""Test ACME related views."""

from http import HTTPStatus

from django.test import TestCase
from django.test.utils import override_settings
from django.urls import reverse

from django_ca.tests.base.mixins import TestCaseMixin


class AcmeNewNonceViewTestCase(TestCaseMixin, TestCase):
    """Test getting a new ACME nonce."""

    load_cas = ("root",)

    def setUp(self) -> None:
        super().setUp()
        self.ca.acme_enabled = True
        self.ca.save()
        self.url = reverse("django_ca:acme-new-nonce", kwargs={"serial": self.ca.serial})

    @override_settings(CA_ENABLE_ACME=False)
    def test_disabled(self) -> None:
        """Test that CA_ENABLE_ACME=False means HTTP 404."""
        response = self.client.head(self.url)
        self.assertEqual(response.status_code, HTTPStatus.NOT_FOUND)
        self.assertTrue(response["Content-Type"].startswith("text/html"))  # --> coming from Django

    def test_get_nonce(self) -> None:
        """Test that getting multiple nonces returns unique nonces."""

        nonces = []
        for _i in range(1, 5):
            response = self.client.head(self.url)
            self.assertEqual(response.status_code, HTTPStatus.OK)
            self.assertEqual(len(response["replay-nonce"]), 43)
            self.assertEqual(response["cache-control"], "no-store")
            nonces.append(response["replay-nonce"])

        self.assertEqual(len(nonces), len(set(nonces)))

    def test_get_request(self) -> None:
        """RFC 8555, section 7.2 also specifies a GET request."""

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)
        self.assertEqual(len(response["replay-nonce"]), 43)
        self.assertEqual(response["cache-control"], "no-store")

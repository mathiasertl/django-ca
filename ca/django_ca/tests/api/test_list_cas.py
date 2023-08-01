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

from django.test import TestCase
from django.urls import reverse_lazy

from freezegun import freeze_time

from django_ca.models import CertificateAuthority
from django_ca.tests.api.mixins import APITestCaseMixin
from django_ca.tests.base import certs, timestamps
from django_ca.utils import x509_name


class ListCertificateAuthorityTestCase(APITestCaseMixin, TestCase):
    """Test the view to list certificate authorities."""

    path = reverse_lazy("django_ca:api:list_certificate_authorities")
    required_permission = (CertificateAuthority, "view_certificateauthority")

    def setUp(self) -> None:
        super().setUp()
        cert = certs["root"]
        self.expected_response = [
            {
                "can_sign_certificates": False,
                "created": self.iso_format(self.ca.created),
                "not_after": self.iso_format(self.ca.expires),
                "not_before": self.iso_format(self.ca.valid_from),
                "name": "root",
                "pem": cert["pub"]["pem"],
                "revoked": False,
                "serial": cert["serial"],
                "subject": x509_name(cert["subject"]).rfc4514_string(),
                "updated": self.iso_format(self.ca.updated),
            }
        ]

    def test_empty_list_view(self) -> None:
        """Test the request with no certificate authorities (empty list view)."""
        CertificateAuthority.objects.all().delete()
        response = self.default_request()
        self.assertEqual(response.status_code, HTTPStatus.OK, response.json())
        self.assertEqual(response.json(), [])

    @freeze_time(timestamps["everything_valid"])
    def test_list_view(self) -> None:
        """Test an ordinary list view."""
        response = self.default_request()
        self.assertEqual(response.status_code, HTTPStatus.OK, response.json())
        self.assertEqual(response.json(), self.expected_response, response.json())

    @freeze_time(timestamps["everything_expired"])
    def test_expired_certificate_authorities_are_excluded(self) -> None:
        """Test that expired CAs are excluded by default."""
        response = self.default_request()
        self.assertEqual(response.status_code, HTTPStatus.OK, response.json())
        self.assertEqual(response.json(), [])

    @freeze_time(timestamps["everything_expired"])
    def test_expired_filter(self) -> None:
        """Test that expired CAs are excluded by default."""
        response = self.default_request({"expired": "1"})
        self.assertEqual(response.status_code, HTTPStatus.OK, response.json())
        self.assertEqual(response.json(), self.expected_response, response.json())

    @freeze_time(timestamps["everything_valid"])
    def test_disabled_ca(self) -> None:
        """Test that a disabled CA is *not* included."""
        self.ca.enabled = False
        self.ca.save()

        response = self.default_request()
        self.assertEqual(response.status_code, HTTPStatus.OK, response.json())
        self.assertEqual(response.json(), [], response.json())

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

from django.test import TestCase
from django.urls import reverse_lazy

from freezegun import freeze_time

from django_ca.models import CertificateAuthority
from django_ca.tests.api.mixins import APITestCaseMixin
from django_ca.tests.base import certs, timestamps
from django_ca.utils import x509_name


class CertificateAuthorityDetailTestCase(APITestCaseMixin, TestCase):
    """Test the view to list certificate authorities."""

    path = reverse_lazy(
        "django_ca:api:view_certificate_authority", kwargs={"serial": certs["root"]["serial"]}
    )
    required_permission = (CertificateAuthority, "view_certificateauthority")

    def setUp(self) -> None:
        super().setUp()
        cert = certs["root"]
        self.expected_response = {
            "acme_enabled": False,
            "acme_profile": "webserver",
            "acme_registration": True,
            "acme_requires_contact": True,
            "caa_identity": "",
            "can_sign_certificates": False,
            "created": self.iso_format(self.ca.created),
            "crl_url": self.ca.crl_url,
            "issuer_alt_name": "",
            "issuer_url": self.ca.issuer_url,
            "name": "root",
            "not_after": self.iso_format(self.ca.expires),
            "not_before": self.iso_format(self.ca.valid_from),
            "ocsp_responder_key_validity": 3,
            "ocsp_response_validity": 86400,
            "ocsp_url": self.ca.ocsp_url,
            "pem": cert["pub"]["pem"],
            "revoked": False,
            "serial": cert["serial"],
            "subject": x509_name(cert["subject"]).rfc4514_string(),
            "sign_certificate_policies": None,
            "terms_of_service": "",
            "updated": self.iso_format(self.ca.updated),
            "website": "",
        }

    @freeze_time(timestamps["everything_valid"])
    def test_view(self) -> None:
        """Test an ordinary view."""
        response = self.default_request()
        self.assertEqual(response.status_code, HTTPStatus.OK, response.json())
        self.assertEqual(response.json(), self.expected_response, response.json())

    @freeze_time(timestamps["everything_expired"])
    def test_view_expired_ca(self) -> None:
        """Test that we can view an expired CA."""
        response = self.default_request({"expired": "1"})
        self.assertEqual(response.status_code, HTTPStatus.OK, response.json())
        self.assertEqual(response.json(), self.expected_response, response.json())

    @freeze_time(timestamps["everything_valid"])
    def test_disabled_ca(self) -> None:
        """Test that a disabled CA is *not* viewable."""
        self.ca.enabled = False
        self.ca.save()

        response = self.default_request()
        self.assertEqual(response.status_code, HTTPStatus.NOT_FOUND, response.json())
        self.assertEqual(response.json(), {"detail": "Not Found"}, response.json())

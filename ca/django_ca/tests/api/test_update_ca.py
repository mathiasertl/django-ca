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
import typing
from http import HTTPStatus
from typing import Any, Dict, Optional

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from django.test import TestCase
from django.urls import reverse_lazy

from freezegun import freeze_time

from django_ca import constants
from django_ca.models import CertificateAuthority
from django_ca.tests.api.mixins import APITestCaseMixin
from django_ca.tests.base import certs, timestamps
from django_ca.typehints import JSON
from django_ca.utils import x509_name

if typing.TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse as HttpResponse


class CertificateAuthorityDetailTestCase(APITestCaseMixin, TestCase):
    """Test the view to list certificate authorities."""

    path = reverse_lazy(
        "django_ca:api:update_certificate_authority", kwargs={"serial": certs["root"]["serial"]}
    )
    required_permission = (CertificateAuthority, "change_certificateauthority")

    def setUp(self) -> None:
        super().setUp()
        cert = certs["root"]
        self.default_payload: Dict[str, JSON] = {
            "acme_enabled": True,
            "acme_profile": "server",
            "acme_registration": False,
            "acme_requires_contact": False,
            "caa_identity": "caa-id",
            "crl_url": "http://update.crl.example.com",
            "issuer_alt_name": "http://update.ian.example.com",
            "issuer_url": "http://update.issuer.example.com",
            "name": "root-update",
            "ocsp_responder_key_validity": 10,
            "ocsp_response_validity": 60000,
            "ocsp_url": "http://update.ocsp.example.com",
            "sign_certificate_policies": {"value": [{"policy_identifier": "1.1.1"}]},
            "terms_of_service": "http://tos.example.com",
            "website": "http://website.example.com",
        }
        self.expected_response = dict(
            self.default_payload,
            **{
                "can_sign_certificates": False,
                "created": self.iso_format(self.ca.created),
                "not_after": self.iso_format(self.ca.expires),
                "not_before": self.iso_format(self.ca.valid_from),
                "pem": cert["pub"]["pem"],
                "revoked": False,
                "serial": cert["serial"],
                "sign_certificate_policies": {
                    "critical": constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.CERTIFICATE_POLICIES],
                    "value": [{"policy_identifier": "1.1.1", "policy_qualifiers": None}],
                },
                "subject": x509_name(cert["subject"]).rfc4514_string(),
                "updated": self.iso_format(timestamps["everything_valid"]),
            },
        )

    def default_request(self, payload: Optional[Dict[str, JSON]] = None, **kwargs: Any) -> "HttpResponse":
        if payload is None:
            payload = self.default_payload
        kwargs["content_type"] = "application/json"
        return self.client.put(self.path, payload, **kwargs)

    @freeze_time(timestamps["everything_valid"])
    def test_update(self) -> None:
        """Test an ordinary view."""
        response = self.default_request()
        self.assertEqual(response.status_code, HTTPStatus.OK, response.json())
        self.assertEqual(response.json(), self.expected_response, response.json())

        self.ca.refresh_from_db()
        for field, expected in self.default_payload.items():
            actual = getattr(self.ca, field)
            if field == "sign_certificate_policies":
                self.assertEqual(
                    actual,
                    self.certificate_policies(
                        x509.PolicyInformation(
                            policy_identifier=x509.ObjectIdentifier("1.1.1"), policy_qualifiers=None
                        )
                    ),
                )
            elif expected is True:
                self.assertIs(expected, True)
            elif expected is False:
                self.assertIs(expected, False)
            else:
                self.assertEqual(expected, actual)

    @freeze_time(timestamps["everything_valid"])
    def test_minimal_update(self) -> None:
        """Test updating only one field."""

        # update expected response to what is currently in the DB, except what we actually change
        for field in self.default_payload:
            if field == "ocsp_responder_key_validity":
                self.expected_response[field] = 10
            else:
                self.expected_response[field] = getattr(self.ca, field)

        response = self.default_request({"ocsp_responder_key_validity": 10})
        self.ca.refresh_from_db()
        self.assertEqual(response.status_code, HTTPStatus.OK, response.json())
        self.assertEqual(response.json(), self.expected_response, response.json())
        self.assertEqual(self.ca.name, "root")
        self.assertEqual(self.ca.ocsp_responder_key_validity, 10)

    @freeze_time(timestamps["everything_valid"])
    def test_validation(self) -> None:
        """Test updating only one field."""

        for field in self.default_payload:
            if field == "ocsp_responder_key_validity":
                self.expected_response[field] = 10
            else:
                self.expected_response[field] = getattr(self.ca, field)

        response = self.default_request({"ocsp_url": "NOT AN URL"})
        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST, response.json())
        self.assertEqual(response.json(), {"detail": "{'ocsp_url': ['Enter a valid URL.']}"})

    @freeze_time(timestamps["everything_expired"])
    def test_update_expired_ca(self) -> None:
        """Test that we can update an expired CA."""
        self.expected_response["updated"] = self.iso_format(timestamps["everything_expired"])
        response = self.default_request()
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

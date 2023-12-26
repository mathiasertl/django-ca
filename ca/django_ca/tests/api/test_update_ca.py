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

"""Test the detail-view for a CA."""
from http import HTTPStatus
from typing import Any, Dict, Optional, Tuple, Type

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from django.db.models import Model
from django.test import Client
from django.urls import reverse_lazy

import pytest
from freezegun import freeze_time

from django_ca import constants
from django_ca.models import CertificateAuthority
from django_ca.tests.api.conftest import APIPermissionTestBase
from django_ca.tests.base.constants import CERT_DATA, TIMESTAMPS
from django_ca.tests.base.typehints import HttpResponse
from django_ca.tests.base.utils import certificate_policies, iso_format
from django_ca.typehints import JSON

path = reverse_lazy(
    "django_ca:api:update_certificate_authority", kwargs={"serial": CERT_DATA["root"]["serial"]}
)


def request(client: Client, payload: Optional[Dict[str, JSON]]) -> "HttpResponse":
    """Shortcut to run a request."""
    return client.put(path, payload, content_type="application/json")


@pytest.fixture(scope="module")
def api_permission() -> Tuple[Type[Model], str]:
    """Fixture for the permission required by this view."""
    return CertificateAuthority, "change_certificateauthority"


@pytest.fixture()
def payload() -> Dict[str, Any]:
    """Fixture for a standard request payload."""
    return {
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


@pytest.fixture()
def expected_response(root: CertificateAuthority, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Fixture for the expected response schema for the root CA."""
    return dict(
        payload,
        **{
            "can_sign_certificates": False,
            "created": iso_format(root.created),
            "issuer": [{"oid": attr.oid.dotted_string, "value": attr.value} for attr in root.issuer],
            "not_after": iso_format(root.expires),
            "not_before": iso_format(root.valid_from),
            "pem": CERT_DATA["root"]["pub"]["pem"],
            "revoked": False,
            "serial": CERT_DATA["root"]["serial"],
            "sign_certificate_policies": {
                "critical": constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.CERTIFICATE_POLICIES],
                "type": "certificate_policies",
                "value": [{"policy_identifier": "1.1.1", "policy_qualifiers": None}],
            },
            "subject": [{"oid": attr.oid.dotted_string, "value": attr.value} for attr in root.subject],
            "updated": iso_format(TIMESTAMPS["everything_valid"]),
        },
    )


@freeze_time(TIMESTAMPS["everything_valid"])
def test_update(
    root: CertificateAuthority, api_client: Client, payload: Dict[str, Any], expected_response: Dict[str, Any]
) -> None:
    """Test an ordinary view."""
    # Make sure that we actually also intend to change things
    assert root.terms_of_service != payload["terms_of_service"]
    assert root.website != payload["website"]
    assert root.sign_certificate_policies is None

    response = request(api_client, payload)
    assert response.status_code == HTTPStatus.OK, response.content
    assert response.json() == expected_response

    root.refresh_from_db()
    for field, expected in payload.items():
        actual = getattr(root, field)
        if field == "sign_certificate_policies":
            assert actual, certificate_policies(
                x509.PolicyInformation(
                    policy_identifier=x509.ObjectIdentifier("1.1.1"), policy_qualifiers=None
                )
            )
        elif expected is True:
            assert actual is True
        elif expected is False:
            assert actual is False
        else:
            assert expected == actual


@freeze_time(TIMESTAMPS["everything_valid"])
def test_minimal_update(
    root: CertificateAuthority, api_client: Client, payload: Dict[str, Any], expected_response: Dict[str, Any]
) -> None:
    """Test updating only one field."""
    # update expected response to what is currently in the DB, except what we actually change
    for field in payload:
        if field == "ocsp_responder_key_validity":
            expected_response[field] = 10
        else:
            expected_response[field] = getattr(root, field)

    response = request(api_client, {"ocsp_responder_key_validity": 10})
    root.refresh_from_db()
    assert response.status_code == HTTPStatus.OK, response.content
    assert response.json() == expected_response, response.json()
    assert root.name == "root"
    assert root.ocsp_responder_key_validity == 10


@freeze_time(TIMESTAMPS["everything_valid"])
def test_clear_sign_certificate_policies(
    root: CertificateAuthority, api_client: Client, payload: Dict[str, Any], expected_response: Dict[str, Any]
) -> None:
    """Test clearing the ``sign_certificate_policies`` flag."""
    assert root.sign_certificate_policies is None
    root.sign_certificate_policies = certificate_policies(
        x509.PolicyInformation(policy_identifier=x509.ObjectIdentifier("1.1.1"), policy_qualifiers=None)
    )
    root.save()

    for field in payload:
        if field == "sign_certificate_policies":
            expected_response[field] = None
        else:
            expected_response[field] = getattr(root, field)

    response = request(api_client, {"sign_certificate_policies": None})
    assert response.status_code == HTTPStatus.OK, response.content
    assert response.json() == expected_response, response.json()

    root.refresh_from_db()
    assert root.name == "root"
    assert root.sign_certificate_policies is None


@freeze_time(TIMESTAMPS["everything_valid"])
def test_validation(
    root: CertificateAuthority, api_client: Client, payload: Dict[str, Any], expected_response: Dict[str, Any]
) -> None:
    """Test updating only one field."""
    for field in payload:
        if field == "ocsp_responder_key_validity":
            expected_response[field] = 10
        else:
            expected_response[field] = getattr(root, field)

    response = request(api_client, {"ocsp_url": "NOT AN URL", "ocsp_responder_key_validity": 10})
    assert response.status_code == HTTPStatus.BAD_REQUEST, response.content
    assert response.json() == {"detail": "{'ocsp_url': ['Enter a valid URL.']}"}

    refetched_root: CertificateAuthority = CertificateAuthority.objects.get(pk=root.pk)
    assert root.ocsp_url == refetched_root.ocsp_url
    assert root.ocsp_responder_key_validity == refetched_root.ocsp_responder_key_validity


@freeze_time(TIMESTAMPS["everything_expired"])
def test_update_expired_ca(
    api_client: Client, payload: Dict[str, Any], expected_response: Dict[str, Any]
) -> None:
    """Test that we can update an expired CA."""
    expected_response["updated"] = iso_format(TIMESTAMPS["everything_expired"])
    response = request(api_client, payload)
    assert response.status_code == HTTPStatus.OK, response.content
    assert response.json() == expected_response, response.json()


class TestPermissions(APIPermissionTestBase):
    """Test permissions for this view."""

    path = path

    def request(self, client: Client) -> HttpResponse:
        """Make a standard request."""
        return request(client, {"ocsp_responder_key_validity": 10})

    def test_disabled_ca(self, api_client: Client, root: CertificateAuthority) -> None:
        """Test that this request works for disabled CAs."""
        super().test_disabled_ca(api_client, root)

        # Make sure that fields where not updated in the database
        root.refresh_from_db()
        assert root.ocsp_responder_key_validity == 3

    def test_disabled_api_access(self, api_client: Client, root: CertificateAuthority) -> None:
        """Test that disabling the API access for the CA really disables it."""
        super().test_disabled_api_access(api_client, root)

        # Make sure that fields where not updated in the database
        root.refresh_from_db()
        assert root.ocsp_responder_key_validity == 3

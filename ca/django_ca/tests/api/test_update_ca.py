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
from typing import Any

from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

from django.db.models import Model
from django.test import Client
from django.urls import reverse_lazy

import pytest

from django_ca import constants
from django_ca.constants import CONFIGURABLE_EXTENSION_KEYS, EXTENSION_DEFAULT_CRITICAL
from django_ca.models import CertificateAuthority
from django_ca.pydantic.extensions import EXTENSION_MODELS
from django_ca.tests.api.conftest import APIPermissionTestBase
from django_ca.tests.base.constants import CERT_DATA, TIMESTAMPS
from django_ca.tests.base.typehints import HttpResponse
from django_ca.tests.base.utils import (
    certificate_policies,
    crl_distribution_points,
    distribution_point,
    dns,
    iso_format,
    issuer_alternative_name,
    uri,
)
from django_ca.typehints import JSON

path = reverse_lazy(
    "django_ca:api:update_certificate_authority", kwargs={"serial": CERT_DATA["root"]["serial"]}
)


def request(client: Client, payload: dict[str, JSON] | None) -> "HttpResponse":
    """Shortcut to run a request."""
    return client.put(path, payload, content_type="application/json")


@pytest.fixture(scope="module")
def api_permission() -> tuple[type[Model], str]:
    """Fixture for the permission required by this view."""
    return CertificateAuthority, "change_certificateauthority"


@pytest.fixture
def payload() -> dict[str, Any]:
    """Fixture for a standard request payload."""
    return {
        "acme_enabled": True,
        "acme_profile": "server",
        "acme_registration": False,
        "acme_requires_contact": False,
        "caa_identity": "caa-id",
        "name": "root-update",
        "ocsp_responder_key_validity": 10,
        "ocsp_response_validity": 60000,
        "sign_authority_information_access": {
            "value": [
                {
                    "access_method": "ocsp",
                    "access_location": {"type": "URI", "value": "http://ocsp.example.com"},
                },
                {
                    "access_method": "ca_issuers",
                    "access_location": {"type": "URI", "value": "http://ca-issuers.example.com"},
                },
            ]
        },
        "sign_certificate_policies": {"value": [{"policy_identifier": "1.1.1"}]},
        "sign_crl_distribution_points": {
            "value": [{"full_name": [{"type": "URI", "value": "http://crl.example.com"}]}]
        },
        "sign_issuer_alternative_name": {"value": [{"type": "DNS", "value": "example.com"}]},
        "terms_of_service": "http://tos.example.com",
        "website": "http://website.example.com",
    }


@pytest.fixture
def expected_response(payload: dict[str, Any], root_response: dict[str, Any]) -> dict[str, Any]:
    """Fixture for the expected response schema for the root CA."""
    response = {**root_response, **payload}

    # Update response with non-default values
    response["sign_authority_information_access"]["critical"] = EXTENSION_DEFAULT_CRITICAL[
        ExtensionOID.AUTHORITY_INFORMATION_ACCESS
    ]
    response["sign_authority_information_access"]["type"] = CONFIGURABLE_EXTENSION_KEYS[
        ExtensionOID.AUTHORITY_INFORMATION_ACCESS
    ]
    response["sign_authority_information_access"]["value"][0]["access_method"] = (
        AuthorityInformationAccessOID.OCSP.dotted_string
    )
    response["sign_authority_information_access"]["value"][1]["access_method"] = (
        AuthorityInformationAccessOID.CA_ISSUERS.dotted_string
    )
    response["sign_certificate_policies"]["critical"] = EXTENSION_DEFAULT_CRITICAL[
        ExtensionOID.CERTIFICATE_POLICIES
    ]
    response["sign_certificate_policies"]["type"] = CONFIGURABLE_EXTENSION_KEYS[
        ExtensionOID.CERTIFICATE_POLICIES
    ]
    response["sign_certificate_policies"]["value"][0]["policy_qualifiers"] = None
    response["sign_crl_distribution_points"]["critical"] = EXTENSION_DEFAULT_CRITICAL[
        ExtensionOID.CRL_DISTRIBUTION_POINTS
    ]
    response["sign_crl_distribution_points"]["type"] = CONFIGURABLE_EXTENSION_KEYS[
        ExtensionOID.CRL_DISTRIBUTION_POINTS
    ]
    response["sign_crl_distribution_points"]["value"][0].update(
        {"crl_issuer": None, "reasons": None, "relative_name": None}
    )
    response["sign_issuer_alternative_name"]["critical"] = EXTENSION_DEFAULT_CRITICAL[
        ExtensionOID.ISSUER_ALTERNATIVE_NAME
    ]
    response["sign_issuer_alternative_name"]["type"] = CONFIGURABLE_EXTENSION_KEYS[
        ExtensionOID.ISSUER_ALTERNATIVE_NAME
    ]

    return response


@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])
def test_update(
    root: CertificateAuthority, api_client: Client, payload: dict[str, Any], expected_response: dict[str, Any]
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
        if field == "sign_authority_information_access":
            assert actual == x509.Extension(
                oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
                critical=constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.AUTHORITY_INFORMATION_ACCESS],
                value=x509.AuthorityInformationAccess(
                    [
                        x509.AccessDescription(
                            access_method=AuthorityInformationAccessOID.OCSP,
                            access_location=uri("http://ocsp.example.com"),
                        ),
                        x509.AccessDescription(
                            access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                            access_location=uri("http://ca-issuers.example.com"),
                        ),
                    ]
                ),
            )
        elif field == "sign_certificate_policies":
            assert actual == certificate_policies(
                x509.PolicyInformation(
                    policy_identifier=x509.ObjectIdentifier("1.1.1"), policy_qualifiers=None
                )
            )
        elif field == "sign_crl_distribution_points":
            assert actual == crl_distribution_points(distribution_point([uri("http://crl.example.com")]))
        elif field == "sign_issuer_alternative_name":
            assert actual == issuer_alternative_name(dns("example.com"))
        elif expected is True:
            assert actual is True
        elif expected is False:
            assert actual is False
        else:
            assert expected == actual


@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])
def test_minimal_update(
    root: CertificateAuthority, api_client: Client, payload: dict[str, Any], expected_response: dict[str, Any]
) -> None:
    """Test updating only one field."""
    # update expected response to what is currently in the DB, except what we actually change
    for field in payload:
        if field == "ocsp_responder_key_validity":
            expected_response[field] = 10
        else:
            value = getattr(root, field)
            if isinstance(value, x509.Extension):
                model_class = EXTENSION_MODELS[value.oid]
                model = model_class.model_validate(value)
                expected_response[field] = model.model_dump(mode="json")
            else:
                expected_response[field] = value

    response = request(api_client, {"ocsp_responder_key_validity": 10})
    root.refresh_from_db()
    assert response.status_code == HTTPStatus.OK, response.content
    assert response.json() == expected_response, response.json()
    assert root.name == "root"
    assert root.ocsp_responder_key_validity == 10


@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])
def test_clear_sign_certificate_policies(
    root: CertificateAuthority, api_client: Client, payload: dict[str, Any], expected_response: dict[str, Any]
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
            value = getattr(root, field)
            if isinstance(value, x509.Extension):
                model_class = EXTENSION_MODELS[value.oid]
                model = model_class.model_validate(value)
                expected_response[field] = model.model_dump(mode="json")
            else:
                expected_response[field] = value

    response = request(api_client, {"sign_certificate_policies": None})
    assert response.status_code == HTTPStatus.OK, response.content
    assert response.json() == expected_response, response.json()

    root.refresh_from_db()
    assert root.name == "root"
    assert root.sign_certificate_policies is None


@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])
def test_validation(
    root: CertificateAuthority, api_client: Client, payload: dict[str, Any], expected_response: dict[str, Any]
) -> None:
    """Test updating only one field."""
    for field in payload:
        if field == "ocsp_responder_key_validity":
            expected_response[field] = 10
        else:
            expected_response[field] = getattr(root, field)

    response = request(api_client, {"website": "NOT AN URL", "ocsp_responder_key_validity": 10})
    assert response.status_code == HTTPStatus.BAD_REQUEST, response.content
    assert response.json() == {"detail": "{'website': ['Enter a valid URL.']}"}

    refetched_root: CertificateAuthority = CertificateAuthority.objects.get(pk=root.pk)
    assert root.ocsp_responder_key_validity == refetched_root.ocsp_responder_key_validity


@pytest.mark.freeze_time(TIMESTAMPS["everything_expired"])
def test_update_expired_ca(
    api_client: Client, payload: dict[str, Any], expected_response: dict[str, Any]
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

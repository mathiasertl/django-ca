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
#
# pylint: disable=redefined-outer-name  # requested pytest fixtures show up this way.

"""pytest configuration for API tests."""

import base64
import json
import typing
from http import HTTPStatus
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives import hashes

from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db.models import Model
from django.test.client import Client

import pytest

from django_ca.models import Certificate, CertificateAuthority, X509CertMixin
from django_ca.pydantic.extensions import (
    AuthorityInformationAccessModel,
    CertificateExtensionModelList,
    CRLDistributionPointsModel,
)
from django_ca.tests.base.typehints import HttpResponse, User
from django_ca.tests.base.utils import iso_format

DetailResponse = dict[str, Any]
ListResponse = list[DetailResponse]

if TYPE_CHECKING:
    from django_stubs_ext import StrOrPromise


@pytest.fixture
def api_user(user: User, api_permission: tuple[type[Model], str]) -> User:
    """Extend user fixture to add required permission."""
    content_type = ContentType.objects.get_for_model(api_permission[0])
    permission = Permission.objects.get(codename=api_permission[1], content_type=content_type)
    user.user_permissions.add(permission)
    return user


@pytest.fixture
def api_client(client: Client, api_user: User) -> Client:
    """HTTP client with HTTP basic authentication for the user."""
    credentials = base64.b64encode(api_user.username.encode("utf-8") + b":password").decode()
    client.defaults["HTTP_AUTHORIZATION"] = "Basic " + credentials
    return client


@pytest.fixture
def root(root: CertificateAuthority) -> CertificateAuthority:
    """Extend root fixture to enable API access."""
    root.api_enabled = True
    root.save()
    return root


def _shared_response(obj: X509CertMixin) -> dict[str, Any]:
    extensions = [
        json.loads(ext.model_dump_json())
        for ext in CertificateExtensionModelList.validate_python(obj.pub.loaded.extensions)
    ]
    return {
        "certificate": {
            "extensions": extensions,
            "issuer": [{"oid": attr.oid.dotted_string, "value": attr.value} for attr in obj.issuer],
            "not_valid_after": iso_format(obj.not_after),
            "not_valid_before": iso_format(obj.not_before),
            "pem": obj.pub.pem,
            "public_key_algorithm_oid": obj.pub.loaded.public_key_algorithm_oid.dotted_string,
            "serial": obj.serial,
            "signature_algorithm_oid": obj.pub.loaded.signature_algorithm_oid.dotted_string,
            "signature_algorithm_parameters": {
                "name": "EMSA-PKCS1-v1_5",
            },
            "signature_hash_algorithm": "SHA-256",
            "subject": [{"oid": attr.oid.dotted_string, "value": attr.value} for attr in obj.subject],
            "version": 2,
        },
        "created": iso_format(obj.created),
        "compromised": obj.compromised,
        "fingerprints": {
            "SHA-224": obj.get_fingerprint(hashes.SHA224()),
            "SHA-256": obj.get_fingerprint(hashes.SHA256()),
            "SHA-384": obj.get_fingerprint(hashes.SHA384()),
            "SHA-512": obj.get_fingerprint(hashes.SHA512()),
            "SHA3/224": obj.get_fingerprint(hashes.SHA3_224()),
            "SHA3/256": obj.get_fingerprint(hashes.SHA3_256()),
            "SHA3/384": obj.get_fingerprint(hashes.SHA3_384()),
            "SHA3/512": obj.get_fingerprint(hashes.SHA3_512()),
        },
        "id": obj.pk,
        "revoked_date": None,
        "revoked_reason": "",
        "updated": iso_format(obj.updated),
    }


@pytest.fixture
def root_response(root: CertificateAuthority) -> DetailResponse:
    """Fixture for the expected response schema for the root CA."""
    sign_authority_information_access = AuthorityInformationAccessModel.model_validate(
        root.sign_authority_information_access
    ).model_dump(mode="json")
    sign_crl_distribution_points = CRLDistributionPointsModel.model_validate(
        root.sign_crl_distribution_points
    ).model_dump(mode="json")

    return {
        **_shared_response(root),
        "acme_enabled": True,
        "acme_profile": "webserver",
        "acme_registration": True,
        "acme_requires_contact": True,
        "api_enabled": root.api_enabled,
        "caa_identity": "",
        "enabled": root.enabled,
        "key_backend_alias": "default",
        "name": "root",
        "ocsp_responder_key_validity": 3,
        "ocsp_response_validity": 86400,
        "ocsp_key_backend_alias": "default",
        "parent": None,
        "revoked": False,
        "sign_authority_information_access": sign_authority_information_access,
        "sign_certificate_policies": None,
        "sign_crl_distribution_points": sign_crl_distribution_points,
        "sign_issuer_alternative_name": None,
        "terms_of_service": "",
        "website": "",
    }


@pytest.fixture
def root_cert_response(root_cert: Certificate) -> DetailResponse:
    """Fixture for the expected response schema for the certificate signed by the root CA."""
    root_cert.refresh_from_db()  # make sure we have field values and not raw values
    return {
        **_shared_response(root_cert),
        "autogenerated": False,
        "ca": root_cert.ca.pk,
        "csr": root_cert.csr.pem,
        "profile": root_cert.profile,
        "revoked": False,
        "watchers": [],
    }


class APIPermissionTestBase:
    """Base class for testing permission handling in API views."""

    path: "StrOrPromise"
    expected_disabled_status_code = HTTPStatus.NOT_FOUND
    expected_disabled_response: typing.ClassVar[Any] = {"detail": "Not Found"}

    def request(self, client: Client) -> HttpResponse:
        """Make a default request to the view under test (non-GET requests must override this)."""
        return client.get(self.path)

    def test_request_with_no_authentication(self, client: Client) -> None:
        """Test that a request with no authorization returns an HTTP 403 Unauthorized response."""
        response = self.request(client)
        assert response.status_code == HTTPStatus.UNAUTHORIZED, response.content
        assert response.json() == {"detail": "Unauthorized"}, response.json()

    @pytest.mark.django_db
    def test_user_with_wrong_username(self, user: User, client: Client) -> None:
        """Test that a user with the wrong user gets an HTTP 403 Unauthorized response."""
        credentials = base64.b64encode(user.username.encode() + b"-wrong:password").decode()
        client.defaults["HTTP_AUTHORIZATION"] = "Basic " + credentials

        response = self.request(client)
        assert response.status_code == HTTPStatus.UNAUTHORIZED, response.content
        assert response.json() == {"detail": "Unauthorized"}, response.json()

    @pytest.mark.django_db
    def test_user_with_wrong_password(self, user: User, client: Client) -> None:
        """Test that a user with the wrong password gets an HTTP 403 Unauthorized response."""
        credentials = base64.b64encode(user.username.encode() + b":wrong-password").decode()
        client.defaults["HTTP_AUTHORIZATION"] = "Basic " + credentials

        response = self.request(client)
        assert response.status_code == HTTPStatus.UNAUTHORIZED, response.content
        assert response.json() == {"detail": "Unauthorized"}, response.json()

    def test_user_with_no_permissions(self, user: User, api_client: Client) -> None:
        """Test that a user without the required permissions gets an HTTP 401 Forbidden response."""
        user.user_permissions.clear()
        response = self.request(api_client)
        assert response.status_code == HTTPStatus.FORBIDDEN, response.content
        assert response.json() == {"detail": "Forbidden"}, response.json()

    def test_disabled_ca(self, api_client: Client, root: CertificateAuthority) -> None:
        """Test that disabling the API access for the CA really disables it."""
        root.enabled = False
        root.save()

        response = self.request(api_client)
        assert response.status_code == self.expected_disabled_status_code, response.content
        assert response.json() == self.expected_disabled_response

    def test_disabled_api_access(self, api_client: Client, root: CertificateAuthority) -> None:
        """Test that disabling the API access for the CA really disables it."""
        root.api_enabled = False
        root.save()

        response = self.request(api_client)
        assert response.status_code == self.expected_disabled_status_code, response.content
        assert response.json() == self.expected_disabled_response

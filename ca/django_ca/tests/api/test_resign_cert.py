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

# pylint: disable=redefined-outer-name

"""Test the revoking certificates via the API."""

import base64
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from typing import Any

from cryptography import x509

from django.contrib.auth.models import AbstractUser
from django.db.models import Model
from django.test.client import Client
from django.urls import reverse, reverse_lazy

import pytest

from django_ca.constants import ExtensionOID
from django_ca.models import Certificate, CertificateAuthority, CertificateOrder
from django_ca.tests.api.conftest import APIPermissionTestBase
from django_ca.tests.base.constants import CERT_DATA, TIMESTAMPS
from django_ca.tests.base.typehints import CaptureOnCommitCallbacks, HttpResponse
from django_ca.tests.base.utils import (
    authority_information_access,
    certificate_policies,
    crl_distribution_points,
    distribution_point,
    dns,
    iso_format,
)

pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])]


@pytest.fixture(scope="module")
def api_permission() -> tuple[type[Model], str]:
    """Fixture for the permission required by this view."""
    return Certificate, "sign_certificate"


@pytest.fixture
def expected_response() -> dict[str, Any]:
    """Fixture for the non-dynamic parts of the expected response."""
    return {
        "created": iso_format(TIMESTAMPS["everything_valid"]),
        "updated": iso_format(TIMESTAMPS["everything_valid"]),
        "status": "pending",
        "user": "user",
        "serial": None,
    }


def resign(
    api_client: Client,
    api_user: AbstractUser,
    django_capture_on_commit_callbacks: CaptureOnCommitCallbacks,
    ca: CertificateAuthority,
    cert: Certificate,
    expected_response: dict[str, Any],
    data: dict[str, Any] | None = None,
) -> Certificate:
    """Function to resign the certificate and assert some basic assumptions."""
    path = reverse(
        "django_ca:api:resign_certificate",
        kwargs={"serial": ca.serial, "certificate_serial": cert.serial},
    )
    if data is None:
        data = {}

    with django_capture_on_commit_callbacks(execute=True) as callbacks:
        response = api_client.post(path, data, content_type="application/json")
        assert response.status_code == HTTPStatus.OK, response.json()

        actual_response = response.json()
        actual_response.pop("slug")
        assert actual_response == expected_response

        # Get order before on_commit callbacks are called to test pending state
        order: CertificateOrder = CertificateOrder.objects.get(certificate_authority=ca)
        assert order.status == CertificateOrder.STATUS_PENDING
        assert order.certificate is None
        assert order.user == api_user

    # Make sure that there was a callback
    assert len(callbacks) == 1

    # Test the order
    order.refresh_from_db()
    assert order.status == CertificateOrder.STATUS_ISSUED
    resigned_cert: Certificate | None = order.certificate
    assert resigned_cert is not None

    assert resigned_cert.ca == cert.ca
    assert resigned_cert.subject == cert.subject
    assert resigned_cert.algorithm == cert.algorithm

    # Just make sure that extensions are set despite the original certificate not having them
    assert ExtensionOID.BASIC_CONSTRAINTS in resigned_cert.extensions
    assert ExtensionOID.SUBJECT_KEY_IDENTIFIER in resigned_cert.extensions

    assert ExtensionOID.AUTHORITY_KEY_IDENTIFIER in resigned_cert.extensions

    return resigned_cert


def test_no_extensions(
    api_client: Client,
    api_user: AbstractUser,
    django_capture_on_commit_callbacks: CaptureOnCommitCallbacks,
    usable_child: CertificateAuthority,
    no_extensions: Certificate,
    expected_response: dict[str, Any],
) -> None:
    """Test resigning a certificate with no extensions."""
    assert usable_child == no_extensions.ca
    usable_child.api_enabled = True
    usable_child.save()
    resigned_cert = resign(
        api_client,
        api_user,
        django_capture_on_commit_callbacks,
        usable_child,
        no_extensions,
        expected_response,
    )
    assert ExtensionOID.AUTHORITY_INFORMATION_ACCESS in resigned_cert.extensions
    assert ExtensionOID.CRL_DISTRIBUTION_POINTS in resigned_cert.extensions


def test_with_key_backend_options(
    api_client: Client,
    api_user: AbstractUser,
    django_capture_on_commit_callbacks: CaptureOnCommitCallbacks,
    usable_pwd: CertificateAuthority,
    pwd_cert: Certificate,
    expected_response: dict[str, Any],
) -> None:
    """Test resigning a certificate with key backend options."""
    usable_pwd.api_enabled = True
    usable_pwd.save()

    encoded_password = base64.b64encode(CERT_DATA["pwd"]["password"])  # pwd needs to be base64 encoded
    data = {"key_backend_options": {"password": encoded_password.decode("utf-8")}}

    resigned_cert = resign(
        api_client,
        api_user,
        django_capture_on_commit_callbacks,
        usable_pwd,
        pwd_cert,
        expected_response,
        data=data,
    )
    assert ExtensionOID.AUTHORITY_INFORMATION_ACCESS in resigned_cert.extensions
    assert ExtensionOID.CRL_DISTRIBUTION_POINTS in resigned_cert.extensions


def test_with_invalid_key_backend_options(
    api_client: Client,
    api_user: AbstractUser,
    django_capture_on_commit_callbacks: CaptureOnCommitCallbacks,
    usable_pwd: CertificateAuthority,
    pwd_cert: Certificate,
) -> None:
    """Test resigning a certificate with invalid key backend options."""
    usable_pwd.api_enabled = True
    usable_pwd.save()

    encoded_password = base64.b64encode(b"wrong_password")  # pwd needs to be base64 encoded
    data = {"key_backend_options": {"password": encoded_password.decode("utf-8")}}

    path = reverse(
        "django_ca:api:resign_certificate",
        kwargs={"serial": usable_pwd.serial, "certificate_serial": pwd_cert.serial},
    )

    with django_capture_on_commit_callbacks(execute=True) as callbacks:
        response = api_client.post(path, data, content_type="application/json")

        order: CertificateOrder = CertificateOrder.objects.get(certificate_authority=usable_pwd)
        assert order.status == CertificateOrder.STATUS_PENDING
        assert order.certificate is None
        assert order.user == api_user

    # Response is OK, because it is sent before signing is actually done (it just informs you that the
    # operation is pending).
    assert response.status_code == HTTPStatus.OK, response.json()

    # Make sure that there was a callback
    assert len(callbacks) == 1

    # Test the order
    order.refresh_from_db()
    assert order.status == CertificateOrder.STATUS_FAILED
    assert order.error_code == 1
    assert order.error == "Could not sign certificate."
    assert order.certificate is None


def test_with_not_after(
    api_client: Client,
    api_user: AbstractUser,
    django_capture_on_commit_callbacks: CaptureOnCommitCallbacks,
    usable_root: CertificateAuthority,
    root_cert: Certificate,
    expected_response: dict[str, Any],
) -> None:
    """Test resigning a certificate while setting `not_after`."""
    usable_root.api_enabled = True
    usable_root.save()

    now = datetime.now(tz=timezone.utc)
    not_after = now + timedelta(days=12)
    data = {"not_after": not_after.isoformat()}

    resigned_cert = resign(
        api_client,
        api_user,
        django_capture_on_commit_callbacks,
        usable_root,
        root_cert,
        expected_response,
        data=data,
    )
    assert ExtensionOID.AUTHORITY_INFORMATION_ACCESS in resigned_cert.extensions
    assert ExtensionOID.CRL_DISTRIBUTION_POINTS in resigned_cert.extensions
    assert resigned_cert.not_after == not_after


def test_all_extensions_with_override_extensions(
    api_user: AbstractUser,
    api_client: Client,
    django_capture_on_commit_callbacks: CaptureOnCommitCallbacks,
    hostname: str,
    usable_child: CertificateAuthority,
    all_extensions: Certificate,
    expected_response: dict[str, Any],
) -> None:
    """Test resigning a certificate with all extensions, with the CA overriding signing extensions."""
    assert usable_child == all_extensions.ca
    usable_child.api_enabled = True

    # Change signing extensions (to make sure that the override has a different value then the cert).
    usable_child.sign_issuer_alternative_name = x509.Extension(
        oid=ExtensionOID.ISSUER_ALTERNATIVE_NAME,
        critical=False,
        value=x509.IssuerAlternativeName([dns(f"ian.{hostname}")]),
    )
    usable_child.sign_crl_distribution_points = crl_distribution_points(
        distribution_point([dns(f"override.{hostname}")])
    )
    usable_child.sign_certificate_policies = certificate_policies(
        x509.PolicyInformation(x509.ObjectIdentifier("1.2.3"), policy_qualifiers=None)
    )
    usable_child.sign_authority_information_access = authority_information_access(
        [dns(f"issuers.{hostname}")], [dns(f"ocsp.{hostname}")]
    )

    # Finally save CA
    usable_child.save()

    # Resign cert
    resigned_cert = resign(
        api_client,
        api_user,
        django_capture_on_commit_callbacks,
        usable_child,
        all_extensions,
        expected_response,
    )

    # Make sure that we have the same set of extensions at least
    # all-extensions does not have certificate policies yet, so we add it.
    assert ExtensionOID.CERTIFICATE_POLICIES not in all_extensions.extensions
    expected_extensions = {
        ExtensionOID.CERTIFICATE_POLICIES: usable_child.sign_certificate_policies,
        **all_extensions.extensions,
    }
    assert sorted(resigned_cert.extensions, key=lambda oid: oid.dotted_string) == sorted(
        expected_extensions, key=lambda oid: oid.dotted_string
    )

    for key, ext in resigned_cert.extensions.items():
        if key == ExtensionOID.ISSUER_ALTERNATIVE_NAME:
            assert ext == usable_child.sign_issuer_alternative_name
        elif key == ExtensionOID.CRL_DISTRIBUTION_POINTS:
            assert ext == usable_child.sign_crl_distribution_points
        elif key == ExtensionOID.CERTIFICATE_POLICIES:
            assert ext == usable_child.sign_certificate_policies
        elif key == ExtensionOID.AUTHORITY_INFORMATION_ACCESS:
            assert ext == usable_child.sign_authority_information_access
        else:
            assert ext == all_extensions.extensions[key]


def test_all_extensions_with_no_sign_extensions(
    api_user: AbstractUser,
    api_client: Client,
    django_capture_on_commit_callbacks: CaptureOnCommitCallbacks,
    usable_child: CertificateAuthority,
    all_extensions: Certificate,
    expected_response: dict[str, Any],
) -> None:
    """Test resigning a certificate with all extensions, with the CA overriding NO signing extensions."""
    assert usable_child == all_extensions.ca
    usable_child.api_enabled = True

    # Change signing extensions (to make sure that the override has a different value then the cert).
    usable_child.sign_issuer_alternative_name = None
    usable_child.sign_crl_distribution_points = None
    usable_child.sign_certificate_policies = None
    usable_child.sign_authority_information_access = None
    usable_child.save()

    # Resign cert
    resigned_cert = resign(
        api_client,
        api_user,
        django_capture_on_commit_callbacks,
        usable_child,
        all_extensions,
        expected_response,
    )
    assert ExtensionOID.AUTHORITY_INFORMATION_ACCESS not in resigned_cert.extensions
    assert ExtensionOID.CRL_DISTRIBUTION_POINTS not in resigned_cert.extensions
    assert ExtensionOID.CERTIFICATE_POLICIES not in resigned_cert.extensions
    assert ExtensionOID.ISSUER_ALTERNATIVE_NAME not in resigned_cert.extensions

    for key, ext in resigned_cert.extensions.items():
        assert ext == all_extensions.extensions[key]


def test_ed_cert(
    api_user: AbstractUser,
    api_client: Client,
    django_capture_on_commit_callbacks: CaptureOnCommitCallbacks,
    usable_ed25519: CertificateAuthority,
    ed25519_cert: Certificate,
    expected_response: dict[str, Any],
) -> None:
    """Test resigning an ed25519-based certificate."""
    assert usable_ed25519 == ed25519_cert.ca
    usable_ed25519.api_enabled = True

    # Change signing extensions (to make sure that the override has a different value then the cert).
    usable_ed25519.sign_issuer_alternative_name = None
    usable_ed25519.sign_crl_distribution_points = None
    usable_ed25519.sign_certificate_policies = None
    usable_ed25519.sign_authority_information_access = None
    usable_ed25519.save()

    # Resign cert
    resigned_cert = resign(
        api_client,
        api_user,
        django_capture_on_commit_callbacks,
        usable_ed25519,
        ed25519_cert,
        expected_response,
    )
    assert ExtensionOID.AUTHORITY_INFORMATION_ACCESS not in resigned_cert.extensions
    assert ExtensionOID.CRL_DISTRIBUTION_POINTS not in resigned_cert.extensions
    assert ExtensionOID.CERTIFICATE_POLICIES not in resigned_cert.extensions
    assert ExtensionOID.ISSUER_ALTERNATIVE_NAME not in resigned_cert.extensions

    for key, ext in resigned_cert.extensions.items():
        assert ext == ed25519_cert.extensions[key]


def test_with_no_csr(api_client: Client, root: CertificateAuthority, root_cert: Certificate) -> None:
    """Test resigning a certificate that does not have a CSR."""
    root.api_enabled = True
    root.save()

    root_cert.csr = None  # type: ignore[assignment]
    root_cert.save()

    path = reverse(
        "django_ca:api:resign_certificate",
        kwargs={"serial": root.serial, "certificate_serial": root_cert.serial},
    )

    response = api_client.post(path, {}, content_type="application/json")
    assert response.status_code == HTTPStatus.BAD_REQUEST, response.content.decode()
    assert response.json() == {"detail": "Cannot resign certificate without a CSR."}


def test_with_unknown_cert(api_client: Client, root: CertificateAuthority, root_cert: Certificate) -> None:
    """Test resigning an unknown certificate."""
    root.api_enabled = True
    root.save()

    root_cert.csr = None  # type: ignore[assignment]
    root_cert.save()

    path = reverse(
        "django_ca:api:resign_certificate", kwargs={"serial": root.serial, "certificate_serial": "ABC"}
    )

    response = api_client.post(path, {}, content_type="application/json")
    assert response.status_code == HTTPStatus.NOT_FOUND, response.content.decode()
    assert response.json() == {"detail": "Not Found"}


class TestPermissions(APIPermissionTestBase):
    """Test permissions for this view."""

    path = reverse_lazy(
        "django_ca:api:resign_certificate",
        kwargs={
            "serial": CERT_DATA["root"]["serial"],
            "certificate_serial": CERT_DATA["root-cert"]["serial"],
        },
    )

    def request(self, client: Client) -> HttpResponse:
        """Standard request for testing permissions."""
        return client.post(self.path, {}, content_type="application/json")

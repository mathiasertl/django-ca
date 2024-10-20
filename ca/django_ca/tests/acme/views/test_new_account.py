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

# pylint: disable=redefined-outer-name  # because of fixtures

from collections.abc import Iterator
from http import HTTPStatus
from unittest import mock

from acme.messages import Registration

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from django.test import Client

import pytest

from django_ca.models import AcmeAccount, CertificateAuthority
from django_ca.tests.acme.views.assertions import (
    assert_acme_problem,
    assert_acme_response,
    assert_malformed,
    assert_unauthorized,
)
from django_ca.tests.acme.views.base import AcmeBaseViewTestCaseMixin
from django_ca.tests.acme.views.utils import absolute_acme_uri, acme_request
from django_ca.tests.base.constants import CERT_DATA, TIMESTAMPS
from django_ca.tests.base.utils import mock_slug, root_reverse, root_uri

# ACME views require a currently valid certificate authority
pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])]
CONTACT = "mailto:user@example.com"

PEM = (
    CERT_DATA["root-cert"]["key"]["parsed"]
    .public_key()
    .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    .decode("utf-8")
    .strip()
)


@pytest.fixture
def url() -> Iterator[str]:
    """URL under test."""
    return root_reverse("acme-new-account")


@pytest.fixture
def message() -> Iterator[Registration]:
    """Default message sent to the server."""
    return Registration(contact=(CONTACT,), terms_of_service_agreed=True)


@pytest.fixture
def kid() -> Iterator[None]:
    """Request requires no kid, yield None."""
    return


def test_basic(client: Client, url: str, message: Registration, root: CertificateAuthority) -> None:
    """Basic test for creating an account via ACME."""
    with mock_slug() as slug:
        resp = acme_request(client, url, root, message)
    assert resp.status_code == HTTPStatus.CREATED, resp.content
    assert_acme_response(resp, root)

    # Get first AcmeAccount - which must be the one we just created
    acc = AcmeAccount.objects.get(slug=slug)
    assert acc.status == AcmeAccount.STATUS_VALID
    assert acc.ca == root
    assert acc.contact == CONTACT
    assert acc.terms_of_service_agreed is True
    assert acc.pem == PEM

    # Test the response body
    assert resp["location"] == absolute_acme_uri(":acme-account", serial=root.serial, slug=acc.slug)
    assert resp.json() == {
        "contact": [CONTACT],
        "orders": absolute_acme_uri(":acme-account-orders", serial=root.serial, slug=acc.slug),
        "status": "valid",
    }

    # Test making a request where we already have a key
    message = Registration(
        contact=("mailto:other@example.net",),  # make sure that we do not update the user
        terms_of_service_agreed=True,
    )
    resp = acme_request(client, url, root, message)
    assert resp.status_code == HTTPStatus.OK
    assert_acme_response(resp, root)
    assert resp["location"] == absolute_acme_uri(":acme-account", serial=root.serial, slug=acc.slug)
    assert resp.json() == {
        "contact": [CONTACT],
        "orders": absolute_acme_uri(":acme-account-orders", serial=root.serial, slug=acc.slug),
        "status": "valid",
    }

    assert AcmeAccount.objects.count() == 1

    # test only_return existing:
    message = Registration(
        contact=("mailto:other@example.net",),  # make sure that we do not update the user
        only_return_existing=True,
    )
    resp = acme_request(client, url, root, message)
    assert resp.status_code == HTTPStatus.OK
    assert_acme_response(resp, root)
    assert resp["location"] == absolute_acme_uri(":acme-account", serial=root.serial, slug=acc.slug)
    assert resp.json() == {
        "contact": [CONTACT],
        "orders": absolute_acme_uri(":acme-account-orders", serial=root.serial, slug=acc.slug),
        "status": "valid",
    }
    assert AcmeAccount.objects.count() == 1

    # Test object properties one last time
    acc = AcmeAccount.objects.get(slug=slug)
    assert acc.status == AcmeAccount.STATUS_VALID
    assert acc.ca == root
    assert acc.contact == CONTACT
    assert acc.terms_of_service_agreed is True


def test_no_contact(client: Client, url: str, message: Registration, root: CertificateAuthority) -> None:
    """Basic test for creating an account via ACME."""
    root.acme_requires_contact = False
    root.save()

    message = Registration(terms_of_service_agreed=True)
    with mock_slug() as slug:
        resp = acme_request(client, url, root, message)
    assert resp.status_code == HTTPStatus.CREATED, resp.content
    assert_acme_response(resp, root)

    # Get first AcmeAccount - which must be the one we just created
    acc = AcmeAccount.objects.get(slug=slug)
    assert acc.status == AcmeAccount.STATUS_VALID
    assert acc.ca == root
    assert acc.contact == ""
    assert acc.terms_of_service_agreed is True

    # Test the response body
    assert resp["location"] == absolute_acme_uri(":acme-account", serial=root.serial, slug=acc.slug)
    assert resp.json() == {
        "contact": [],
        "orders": absolute_acme_uri(":acme-account-orders", serial=root.serial, slug=acc.slug),
        "status": "valid",
    }


def test_multiple_contacts(
    client: Client, url: str, message: Registration, root: CertificateAuthority
) -> None:
    """Test for creating an account with multiple email addresses."""
    contact_2 = "mailto:user@example.net"
    message = Registration(contact=(CONTACT, contact_2), terms_of_service_agreed=True)
    with mock_slug() as slug:
        resp = acme_request(client, url, root, message)
    assert resp.status_code == HTTPStatus.CREATED, resp.content
    assert_acme_response(resp, root)

    # Get first AcmeAccount - which must be the one we just created
    acc = AcmeAccount.objects.get(slug=slug)
    assert acc.status == AcmeAccount.STATUS_VALID
    assert acc.ca == root
    assert acc.contact.split("\n") == [CONTACT, contact_2]
    assert acc.terms_of_service_agreed is True

    # Test the response body
    assert resp["location"] == root_uri("acme-account", slug=acc.slug)
    assert resp.json() == {
        "contact": [CONTACT, contact_2],
        "orders": root_uri("acme-account-orders", slug=acc.slug),
        "status": "valid",
    }


def test_account_registration_disabled(
    client: Client, url: str, message: Registration, root: CertificateAuthority
) -> None:
    """Test that you cannot create a new account if registration is disabled."""
    root.acme_registration = False
    root.save()

    resp = acme_request(client, url, root, message)
    assert resp.status_code == HTTPStatus.UNAUTHORIZED, resp.content
    assert_unauthorized(resp, root, "Account registration is disabled.")
    assert AcmeAccount.objects.count() == 0


def test_contacts_required(client: Client, url: str, root: CertificateAuthority) -> None:
    """Test failing to create an account if contact is required."""
    root.acme_requires_contact = True
    root.save()

    resp = acme_request(client, url, root, Registration(terms_of_service_agreed=True))
    assert resp.status_code == HTTPStatus.UNAUTHORIZED, resp.content
    assert_unauthorized(resp, root, "Must provide at least one contact address.")
    assert AcmeAccount.objects.count() == 0


def test_unsupported_contact(client: Client, url: str, root: CertificateAuthority) -> None:
    """Test that creating an account with a phone number fails."""
    message = Registration(contact=("tel:1234567", CONTACT), terms_of_service_agreed=True)
    resp = acme_request(client, url, root, message)
    assert resp.status_code == HTTPStatus.BAD_REQUEST, resp.content
    assert_acme_problem(
        resp,
        "unsupportedContact",
        status=HTTPStatus.BAD_REQUEST,
        message="tel:1234567: Unsupported address scheme.",
        ca=root,
    )
    assert AcmeAccount.objects.count() == 0


@pytest.mark.parametrize(
    "value,expected",
    (
        ('mailto:"with spaces"@example.com', "Quoted local part in email is not allowed."),
        ("mailto:user@example.com,user@example.net", "More than one addr-spec is not allowed."),
        ("mailto:user@example.com?who-uses=this", "example.com?who-uses=this: hfields are not allowed."),
        ("mailto:user@example..com", "example..com: Not a valid email address."),
    ),
)
def test_invalid_email(
    client: Client, url: str, root: CertificateAuthority, value: str, expected: str
) -> None:
    """Test that creating an account with a phone number fails."""
    message = Registration(contact=(value,), terms_of_service_agreed=True)
    resp = acme_request(client, url, root, message)
    assert resp.status_code == HTTPStatus.BAD_REQUEST, resp.content
    assert_acme_problem(resp, "invalidContact", status=HTTPStatus.BAD_REQUEST, message=expected, ca=root)
    assert AcmeAccount.objects.count() == 0


def test_no_tos_agreed_flag(client: Client, url: str, root: CertificateAuthority) -> None:
    """Test not sending the terms_of_service_agreed flag."""
    message = Registration(contact=(CONTACT,))
    assert message.terms_of_service_agreed is None
    with mock_slug() as slug:
        resp = acme_request(client, url, root, message)
    assert resp.status_code == HTTPStatus.CREATED, resp.content
    assert_acme_response(resp, root)

    # Get first AcmeAccount - which must be the one we just created
    acc = AcmeAccount.objects.get(slug=slug)
    assert acc.status == AcmeAccount.STATUS_VALID
    assert acc.ca == root
    assert acc.contact == CONTACT
    assert acc.terms_of_service_agreed is False
    assert acc.pem == PEM

    # Test the response
    assert resp["location"] == root_uri("acme-account", slug=acc.slug)
    assert resp.json() == {
        "contact": [CONTACT],
        "orders": root_uri("acme-account-orders", slug=acc.slug),
        "status": "valid",
    }


def test_only_existing_does_not_exist(client: Client, url: str, root: CertificateAuthority) -> None:
    """Test making an only_existing request for an account that does not exist."""
    # test only_return existing:
    message = Registration(only_return_existing=True)
    resp = acme_request(client, url, root, message)
    assert_acme_problem(
        resp,
        "accountDoesNotExist",
        status=HTTPStatus.BAD_REQUEST,
        message="Account does not exist.",
        ca=root,
    )
    assert AcmeAccount.objects.count() == 0


def test_validation_error(client: Client, url: str, root: CertificateAuthority) -> None:
    """Test triggering a model validation error.

    Note that at present it's probably impossible to have such an error in real life as no fields have any
    validation of user-generated input that would not be captured before model validation.
    """
    msg = "Invalid account: thumbprint: Ensure this value has at most 64 characters (it has 256)."
    message = Registration(contact=(CONTACT,), terms_of_service_agreed=True)
    with mock.patch("josepy.jwk.JWKRSA.thumbprint", return_value=b"abc" * 64):
        resp = acme_request(client, url, root, message)
        assert_malformed(resp, root, msg)


class TestAcmeNewAccountView(AcmeBaseViewTestCaseMixin[Registration]):
    """Test creating a new account."""

    requires_kid = False

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

"""Test updating and ACME account."""

# pylint: disable=redefined-outer-name  # because of fixtures

import unittest
from collections.abc import Iterator
from http import HTTPStatus

from acme.messages import IDENTIFIER_FQDN, Identifier, Registration

from django.test import Client

import pytest

from django_ca.models import AcmeAccount, AcmeAuthorization, AcmeOrder, CertificateAuthority
from django_ca.tests.acme.views.assertions import assert_malformed
from django_ca.tests.acme.views.base import AcmeWithAccountViewTestCaseMixin
from django_ca.tests.acme.views.utils import acme_request
from django_ca.tests.base.constants import TIMESTAMPS
from django_ca.tests.base.utils import root_reverse, root_uri

# ACME views require a currently valid certificate authority
pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])]

ACCOUNT_ONE_CONTACT = "mailto:one@example.com"


@pytest.fixture()
def url(account_slug: str) -> Iterator[str]:
    """URL under test."""
    yield root_reverse("acme-account", slug=account_slug)


@pytest.fixture()
def message() -> Iterator[Registration]:
    """Default message sent to the server."""
    yield Registration()


def test_deactivation(
    client: Client, url: str, root: CertificateAuthority, account: AcmeAccount, kid: str
) -> None:
    """Test basic account deactivation."""
    order = AcmeOrder.objects.create(account=account)
    order.add_authorizations([Identifier(typ=IDENTIFIER_FQDN, value="example.com")])
    authorizations = order.authorizations.all()

    # send actual message
    message = Registration(status="deactivated")
    resp = acme_request(client, url, root, message, kid=kid)
    assert resp.status_code == HTTPStatus.OK, resp.content
    assert resp.json() == {
        "contact": [ACCOUNT_ONE_CONTACT],
        "orders": root_uri("acme-account-orders", slug=account.slug),
        "status": AcmeAccount.STATUS_DEACTIVATED,
    }
    account.refresh_from_db()
    order.refresh_from_db()

    assert account.usable is False
    assert account.status == AcmeAccount.STATUS_DEACTIVATED
    assert order.status == AcmeOrder.STATUS_INVALID

    for authz in authorizations:
        authz.refresh_from_db()
        assert authz.status == AcmeAuthorization.STATUS_DEACTIVATED


def test_email(client: Client, url: str, root: CertificateAuthority, account: AcmeAccount, kid: str) -> None:
    """Test setting an email address."""
    email = "mailto:user.updated@example.com"
    message = Registration(contact=(email,))
    resp = acme_request(client, url, root, message, kid=kid)
    assert resp.status_code == HTTPStatus.OK, resp.content
    assert resp.json() == {
        "contact": [email],
        "orders": root_uri("acme-account-orders", slug=account.slug),
        "status": AcmeAccount.STATUS_VALID,
    }

    account.refresh_from_db()
    assert account.contact == email
    assert account.usable is True


def test_multiple_emails(
    client: Client, url: str, root: CertificateAuthority, account: AcmeAccount, kid: str
) -> None:
    """Test setting multiple emails."""
    email1 = "mailto:user.updated.1@example.com"
    email2 = "mailto:user.updated.2@example.com"
    message = Registration(contact=(email1, email2))
    resp = acme_request(client, url, root, message, kid=kid)
    assert resp.status_code == HTTPStatus.OK, resp.content
    assert resp.json() == {
        "contact": [email1, email2],
        "orders": root_uri("acme-account-orders", slug=account.slug),
        "status": AcmeAccount.STATUS_VALID,
    }

    account.refresh_from_db()
    assert account.contact.split() == [email1, email2]
    assert account.usable is True


def test_deactivate_with_email(
    client: Client, url: str, root: CertificateAuthority, account: AcmeAccount, kid: str
) -> None:
    """Test that a deactivation message does not allow you to configure emails too."""
    email = "mailto:user.updated@example.com"
    message = Registration(status="deactivated", contact=(email,))
    resp = acme_request(client, url, root, message, kid=kid)
    assert resp.status_code == HTTPStatus.OK, resp.content
    assert resp.json() == {
        "contact": [ACCOUNT_ONE_CONTACT],
        "orders": root_uri("acme-account-orders", slug=account.slug),
        "status": AcmeAccount.STATUS_DEACTIVATED,
    }

    account.refresh_from_db()
    assert account.usable is False
    assert account.contact == ACCOUNT_ONE_CONTACT
    assert account.status == AcmeAccount.STATUS_DEACTIVATED


def test_agree_tos(
    client: Client, url: str, root: CertificateAuthority, account: AcmeAccount, kid: str
) -> None:
    """Test updating the agreement to the terms of service."""
    account.terms_of_service_agreed = False
    account.save()

    message = Registration(terms_of_service_agreed=True)
    resp = acme_request(client, url, root, message, kid=kid)
    assert resp.json() == {
        "contact": [ACCOUNT_ONE_CONTACT],
        "orders": root_uri("acme-account-orders", slug=account.slug),
        "status": AcmeAccount.STATUS_VALID,
    }

    account.refresh_from_db()

    assert account.terms_of_service_agreed is True
    assert account.usable is True
    assert account.contact == ACCOUNT_ONE_CONTACT
    assert account.status == AcmeAccount.STATUS_VALID


def test_malformed(
    client: Client, url: str, root: CertificateAuthority, account: AcmeAccount, kid: str
) -> None:
    """Test updating something we cannot update."""
    message = Registration()
    resp = acme_request(client, url, root, message, kid=kid)
    assert_malformed(resp, root, "Only contact information can be updated.")

    account.refresh_from_db()
    assert account.usable is True
    assert account.contact == ACCOUNT_ONE_CONTACT
    assert account.status == AcmeAccount.STATUS_VALID


class TestAcmeUpdateAccountView(AcmeWithAccountViewTestCaseMixin[Registration]):
    """Test updating and ACME account."""

    @unittest.skip("Not applicable.")
    def test_tos_not_agreed_account(self) -> None:  # type: ignore[override]
        """Skipped here because clients can agree to the TOS in an update, so not having agreed is okay."""

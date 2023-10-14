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

import unittest
from http import HTTPStatus

import acme
import acme.jws

from django.test import TestCase

from freezegun import freeze_time

from django_ca.models import AcmeAccount, AcmeAuthorization, AcmeOrder
from django_ca.tests.acme.views.base import AcmeWithAccountViewTestCaseMixin
from django_ca.tests.base.constants import TIMESTAMPS


@freeze_time(TIMESTAMPS["everything_valid"])
class AcmeUpdateAccountViewTestCase(AcmeWithAccountViewTestCaseMixin[acme.messages.Registration], TestCase):
    """Test updating and ACME account."""

    message_cls = acme.messages.Registration
    view_name = "acme-account"

    @property
    def url(self) -> str:
        """Get URL for the standard auth object."""
        return self.get_url(serial=self.ca.serial, slug=self.account_slug)

    @unittest.skip("Not applicable.")
    def test_tos_not_agreed_account(self) -> None:
        """Skipped here because clients can agree to the TOS in an update, so not having agreed is okay."""

    def test_deactivation(self) -> None:
        """Test basic account deactivation."""
        order = AcmeOrder.objects.create(account=self.account)
        order.add_authorizations(
            [acme.messages.Identifier(typ=acme.messages.IDENTIFIER_FQDN, value="example.com")]
        )
        authorizations = order.authorizations.all()

        # send actual message
        message = self.get_message(status="deactivated")
        resp = self.acme(self.url, message, kid=self.kid)
        self.assertEqual(resp.status_code, HTTPStatus.OK, resp.content)
        self.assertEqual(
            resp.json(),
            {
                "contact": [self.ACCOUNT_ONE_CONTACT],
                "orders": self.absolute_uri(
                    ":acme-account-orders", serial=self.ca.serial, slug=self.account_slug
                ),
                "status": AcmeAccount.STATUS_DEACTIVATED,
            },
        )
        self.account.refresh_from_db()
        order.refresh_from_db()

        self.assertFalse(self.account.usable)
        self.assertEqual(self.account.status, AcmeAccount.STATUS_DEACTIVATED)
        self.assertEqual(order.status, AcmeOrder.STATUS_INVALID)

        for authz in authorizations:
            authz.refresh_from_db()
            self.assertEqual(authz.status, AcmeAuthorization.STATUS_DEACTIVATED)

    def test_email(self) -> None:
        """Test setting an email address."""
        email = "mailto:user.updated@example.com"
        message = self.get_message(contact=(email,))
        resp = self.acme(self.url, message, kid=self.kid)
        self.assertEqual(resp.status_code, HTTPStatus.OK, resp.content)
        self.assertEqual(
            resp.json(),
            {
                "contact": [email],
                "orders": self.absolute_uri(
                    ":acme-account-orders", serial=self.ca.serial, slug=self.account_slug
                ),
                "status": AcmeAccount.STATUS_VALID,
            },
        )

        self.account.refresh_from_db()

        self.assertEqual(self.account.contact, email)
        self.assertTrue(self.account.usable)

    def test_multiple_emails(self) -> None:
        """Test setting multiple emails."""
        email1 = "mailto:user.updated.1@example.com"
        email2 = "mailto:user.updated.2@example.com"
        message = self.get_message(contact=(email1, email2))
        resp = self.acme(self.url, message, kid=self.kid)
        self.assertEqual(resp.status_code, HTTPStatus.OK, resp.content)
        self.assertEqual(
            resp.json(),
            {
                "contact": [email1, email2],
                "orders": self.absolute_uri(
                    ":acme-account-orders", serial=self.ca.serial, slug=self.account_slug
                ),
                "status": AcmeAccount.STATUS_VALID,
            },
        )

        self.account.refresh_from_db()

        self.assertEqual(self.account.contact.split(), [email1, email2])
        self.assertTrue(self.account.usable)

    def test_deactivate_with_email(self) -> None:
        """Test that a deactivation message does not allow you to configure emails too."""
        email = "mailto:user.updated@example.com"
        message = self.get_message(status="deactivated", contact=(email,))
        resp = self.acme(self.url, message, kid=self.kid)
        self.assertEqual(resp.status_code, HTTPStatus.OK, resp.content)
        self.assertEqual(
            resp.json(),
            {
                "contact": [self.ACCOUNT_ONE_CONTACT],
                "orders": self.absolute_uri(
                    ":acme-account-orders", serial=self.ca.serial, slug=self.account_slug
                ),
                "status": AcmeAccount.STATUS_DEACTIVATED,
            },
        )
        self.account.refresh_from_db()

        self.assertFalse(self.account.usable)
        self.assertEqual(self.account.contact, self.ACCOUNT_ONE_CONTACT)
        self.assertEqual(self.account.status, AcmeAccount.STATUS_DEACTIVATED)

    def test_agree_tos(self) -> None:
        """Test updating the agreement to the terms of service."""
        self.account.terms_of_service_agreed = False
        self.account.save()

        message = self.get_message(terms_of_service_agreed=True)
        resp = self.acme(self.url, message, kid=self.kid)
        self.assertEqual(
            resp.json(),
            {
                "contact": [self.ACCOUNT_ONE_CONTACT],
                "orders": self.absolute_uri(
                    ":acme-account-orders", serial=self.ca.serial, slug=self.account_slug
                ),
                "status": AcmeAccount.STATUS_VALID,
            },
        )

        self.account.refresh_from_db()

        self.assertTrue(self.account.terms_of_service_agreed)
        self.assertTrue(self.account.usable)
        self.assertEqual(self.account.contact, self.ACCOUNT_ONE_CONTACT)
        self.assertEqual(self.account.status, AcmeAccount.STATUS_VALID)

    def test_malformed(self) -> None:
        """Test updating something we cannot update."""
        message = self.get_message()
        resp = self.acme(self.url, message, kid=self.kid)
        self.assertMalformed(resp, "Only contact information can be updated.")
        self.account.refresh_from_db()

        self.assertTrue(self.account.usable)
        self.assertEqual(self.account.contact, self.ACCOUNT_ONE_CONTACT)
        self.assertEqual(self.account.status, AcmeAccount.STATUS_VALID)

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

from http import HTTPStatus
from unittest import mock

import acme
import acme.jws

from django.test import TestCase
from django.urls import reverse_lazy

from freezegun import freeze_time

from django_ca.models import AcmeAccount
from django_ca.tests.acme.views.base import AcmeBaseViewTestCaseMixin
from django_ca.tests.base import certs, override_tmpcadir, timestamps


@freeze_time(timestamps["everything_valid"])
class AcmeNewAccountViewTestCase(AcmeBaseViewTestCaseMixin[acme.messages.Registration], TestCase):
    """Test creating a new account."""

    contact = "mailto:user@example.com"
    url = reverse_lazy("django_ca:acme-new-account", kwargs={"serial": certs["root"]["serial"]})
    message = acme.messages.Registration(contact=(contact,), terms_of_service_agreed=True)
    message_cls = acme.messages.Registration
    requires_kid = False
    view_name = "acme-new-account"

    @override_tmpcadir()
    def test_basic(self) -> None:
        """Basic test for creating an account via ACME."""

        self.assertEqual(AcmeAccount.objects.count(), 0)
        with self.mock_slug() as slug:
            resp = self.acme(self.url, self.message)
        self.assertEqual(resp.status_code, HTTPStatus.CREATED, resp.content)
        self.assertAcmeResponse(resp)

        # Get first AcmeAccount - which must be the one we just created
        acc = AcmeAccount.objects.get(slug=slug)
        self.assertEqual(acc.status, AcmeAccount.STATUS_VALID)
        self.assertEqual(acc.ca, self.ca)
        self.assertEqual(acc.contact, self.contact)
        self.assertTrue(acc.terms_of_service_agreed)
        self.assertEqual(acc.pem, self.PEM)

        # Test the response body
        self.assertEqual(
            resp["location"], self.absolute_uri(":acme-account", serial=self.ca.serial, slug=acc.slug)
        )
        self.assertEqual(
            resp.json(),
            {
                "contact": [self.contact],
                "orders": self.absolute_uri(":acme-account-orders", serial=self.ca.serial, slug=acc.slug),
                "status": "valid",
            },
        )

        # Test making a request where we already have a key
        resp = self.acme(
            self.url,
            self.get_message(
                contact=("mailto:other@example.net",),  # make sure that we do not update the user
                terms_of_service_agreed=True,
            ),
        )
        self.assertEqual(resp.status_code, HTTPStatus.OK)
        self.assertAcmeResponse(resp)
        self.assertEqual(
            resp["location"], self.absolute_uri(":acme-account", serial=self.ca.serial, slug=acc.slug)
        )
        self.assertEqual(
            resp.json(),
            {
                "contact": [self.contact],
                "orders": self.absolute_uri(":acme-account-orders", serial=self.ca.serial, slug=acc.slug),
                "status": "valid",
            },
        )
        self.assertEqual(AcmeAccount.objects.count(), 1)

        # test only_return existing:
        resp = self.acme(
            self.url,
            self.get_message(
                contact=("mailto:other@example.net",),  # make sure that we do not update the user
                only_return_existing=True,
            ),
        )
        self.assertEqual(resp.status_code, HTTPStatus.OK)
        self.assertAcmeResponse(resp)
        self.assertEqual(
            resp["location"], self.absolute_uri(":acme-account", serial=self.ca.serial, slug=acc.slug)
        )
        self.assertEqual(
            resp.json(),
            {
                "contact": [self.contact],
                "orders": self.absolute_uri(":acme-account-orders", serial=self.ca.serial, slug=acc.slug),
                "status": "valid",
            },
        )
        self.assertEqual(AcmeAccount.objects.count(), 1)

        # Test object properties one last time
        acc = AcmeAccount.objects.get(slug=slug)
        self.assertEqual(acc.status, AcmeAccount.STATUS_VALID)
        self.assertEqual(acc.ca, self.ca)
        self.assertEqual(acc.contact, self.contact)
        self.assertTrue(acc.terms_of_service_agreed)

    @override_tmpcadir()
    def test_no_contact(self) -> None:
        """Basic test for creating an account via ACME."""

        self.ca.acme_requires_contact = False
        self.ca.save()

        self.assertEqual(AcmeAccount.objects.count(), 0)
        with self.mock_slug() as slug:
            resp = self.acme(self.url, self.get_message(terms_of_service_agreed=True))
        self.assertEqual(resp.status_code, HTTPStatus.CREATED)
        self.assertAcmeResponse(resp)

        # Get first AcmeAccount - which must be the one we just created
        acc = AcmeAccount.objects.get(slug=slug)
        self.assertEqual(acc.status, AcmeAccount.STATUS_VALID)
        self.assertEqual(acc.ca, self.ca)
        self.assertEqual(acc.contact, "")
        self.assertTrue(acc.terms_of_service_agreed)

        # Test the response body
        self.assertEqual(
            resp["location"], self.absolute_uri(":acme-account", serial=self.ca.serial, slug=acc.slug)
        )
        self.assertEqual(
            resp.json(),
            {
                "contact": [],
                "orders": self.absolute_uri(":acme-account-orders", serial=self.ca.serial, slug=acc.slug),
                "status": "valid",
            },
        )

    @override_tmpcadir()
    def test_multiple_contacts(self) -> None:
        """Test for creating an account with multiple email addresses."""

        contact_2 = "mailto:user@example.net"
        with self.mock_slug() as slug:
            resp = self.acme(
                self.url, self.get_message(contact=(self.contact, contact_2), terms_of_service_agreed=True)
            )
        self.assertEqual(resp.status_code, HTTPStatus.CREATED)
        self.assertAcmeResponse(resp)

        # Get first AcmeAccount - which must be the one we just created
        acc = AcmeAccount.objects.get(slug=slug)
        self.assertEqual(acc.status, AcmeAccount.STATUS_VALID)
        self.assertEqual(acc.ca, self.ca)
        self.assertCountEqual(acc.contact.split("\n"), [self.contact, contact_2])
        self.assertTrue(acc.terms_of_service_agreed)

        # Test the response body
        self.assertEqual(
            resp["location"], self.absolute_uri(":acme-account", serial=self.ca.serial, slug=acc.slug)
        )
        self.assertEqual(
            resp.json(),
            {
                "contact": [self.contact, contact_2],
                "orders": self.absolute_uri(":acme-account-orders", serial=self.ca.serial, slug=acc.slug),
                "status": "valid",
            },
        )

    @override_tmpcadir()
    def test_account_registration_disabled(self) -> None:
        """Test that you cannot create a new account if registration is disabled."""
        self.ca.acme_registration = False
        self.ca.save()

        resp = self.acme(self.url, self.message)
        self.assertEqual(resp.status_code, HTTPStatus.UNAUTHORIZED)
        self.assertUnauthorized(resp, "Account registration is disabled.")
        self.assertEqual(AcmeAccount.objects.count(), 0)

    @override_tmpcadir()
    def test_contacts_required(self) -> None:
        """Test failing to create an account if contact is required."""
        self.ca.acme_requires_contact = True
        self.ca.save()

        resp = self.acme(self.url, acme.messages.Registration(terms_of_service_agreed=True))
        self.assertEqual(resp.status_code, HTTPStatus.UNAUTHORIZED)
        self.assertUnauthorized(resp, "Must provide at least one contact address.")
        self.assertEqual(AcmeAccount.objects.count(), 0)

    @override_tmpcadir()
    def test_unsupported_contact(self) -> None:
        """Test that creating an account with a phone number fails."""

        message = acme.messages.Registration(
            contact=("tel:1234567", self.contact), terms_of_service_agreed=True
        )
        resp = self.acme(self.url, message)
        self.assertEqual(resp.status_code, HTTPStatus.BAD_REQUEST)
        self.assertAcmeProblem(
            resp,
            "unsupportedContact",
            status=HTTPStatus.BAD_REQUEST,
            message="tel:1234567: Unsupported address scheme.",
        )
        self.assertEqual(AcmeAccount.objects.count(), 0)

    @override_tmpcadir()
    def test_invalid_email(self) -> None:
        """Test that creating an account with a phone number fails."""

        resp = self.acme(
            self.url,
            acme.messages.Registration(
                contact=('mailto:"with spaces"@example.com',),
                terms_of_service_agreed=True,
            ),
        )
        self.assertEqual(resp.status_code, HTTPStatus.BAD_REQUEST)
        self.assertAcmeProblem(
            resp,
            "invalidContact",
            status=HTTPStatus.BAD_REQUEST,
            message="Quoted local part in email is not allowed.",
        )
        self.assertEqual(AcmeAccount.objects.count(), 0)

        resp = self.acme(
            self.url,
            acme.messages.Registration(
                contact=("mailto:user@example.com,user@example.net",),
                terms_of_service_agreed=True,
            ),
        )
        self.assertEqual(resp.status_code, HTTPStatus.BAD_REQUEST)
        self.assertAcmeProblem(
            resp,
            "invalidContact",
            status=HTTPStatus.BAD_REQUEST,
            message="More than one addr-spec is not allowed.",
        )
        self.assertEqual(AcmeAccount.objects.count(), 0)

        resp = self.acme(
            self.url,
            acme.messages.Registration(
                contact=("mailto:user@example.com?who-uses=this",),
                terms_of_service_agreed=True,
            ),
        )
        self.assertEqual(resp.status_code, HTTPStatus.BAD_REQUEST)
        self.assertAcmeProblem(
            resp,
            "invalidContact",
            status=HTTPStatus.BAD_REQUEST,
            message="example.com?who-uses=this: hfields are not allowed.",
        )
        self.assertEqual(AcmeAccount.objects.count(), 0)

        resp = self.acme(
            self.url,
            acme.messages.Registration(
                contact=("mailto:user@example..com",),
                terms_of_service_agreed=True,
            ),
        )
        self.assertEqual(resp.status_code, HTTPStatus.BAD_REQUEST)
        self.assertAcmeProblem(
            resp,
            "invalidContact",
            status=HTTPStatus.BAD_REQUEST,
            message="example..com: Not a valid email address.",
        )
        self.assertEqual(AcmeAccount.objects.count(), 0)

    @override_tmpcadir()
    def test_no_tos_agreed_flag(self) -> None:
        """Test not sending the terms_of_service_agreed flag."""

        self.assertEqual(AcmeAccount.objects.count(), 0)
        message = self.get_message(contact=(self.contact,))
        self.assertIsNone(message.terms_of_service_agreed)  # type: ignore[union-attr]
        with self.mock_slug() as slug:
            resp = self.acme(self.url, message)
        self.assertEqual(resp.status_code, HTTPStatus.CREATED, resp.content)
        self.assertAcmeResponse(resp)

        # Get first AcmeAccount - which must be the one we just created
        acc = AcmeAccount.objects.get(slug=slug)
        self.assertEqual(acc.status, AcmeAccount.STATUS_VALID)
        self.assertEqual(acc.ca, self.ca)
        self.assertEqual(acc.contact, self.contact)
        self.assertFalse(acc.terms_of_service_agreed)
        self.assertEqual(acc.pem, self.PEM)

        # Test the response body
        self.assertEqual(
            resp["location"], self.absolute_uri(":acme-account", serial=self.ca.serial, slug=acc.slug)
        )
        self.assertEqual(
            resp.json(),
            {
                "contact": [self.contact],
                "orders": self.absolute_uri(":acme-account-orders", serial=self.ca.serial, slug=acc.slug),
                "status": "valid",
            },
        )

    @override_tmpcadir()
    def test_only_existing_does_not_exist(self) -> None:
        """Test making an only_existing request for an account that does not exist."""

        # test only_return existing:
        resp = self.acme(
            self.url,
            acme.messages.Registration(
                only_return_existing=True,
            ),
        )
        self.assertAcmeProblem(
            resp, "accountDoesNotExist", status=HTTPStatus.BAD_REQUEST, message="Account does not exist."
        )
        self.assertEqual(AcmeAccount.objects.count(), 0)

    @override_tmpcadir()
    def test_validation_error(self) -> None:
        """Test triggering a model validation error.

        Note that at present it's probably impossible to have such an error in real life as no fields have any
        validation of user-generated input that would not be captured before model validation.
        """
        msg = "Invalid account: thumbprint: Ensure this value has at most 64 characters (it has 256)."
        with mock.patch("josepy.jwk.JWKRSA.thumbprint", return_value=b"abc" * 64):
            resp = self.acme(
                self.url,
                acme.messages.Registration(
                    contact=(self.contact,),
                    terms_of_service_agreed=True,
                ),
            )
            self.assertMalformed(resp, msg)

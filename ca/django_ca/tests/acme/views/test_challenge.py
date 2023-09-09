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

"""Test retrieving a challenge."""

from http import HTTPStatus
from unittest import mock

import acme
import acme.jws
import josepy as jose

from django.test import TransactionTestCase

from freezegun import freeze_time

from django_ca.models import AcmeAuthorization, AcmeChallenge, AcmeOrder
from django_ca.tasks import acme_validate_challenge
from django_ca.tests.acme.views.base import AcmeWithAccountViewTestCaseMixin
from django_ca.tests.base import override_tmpcadir, timestamps


@freeze_time(timestamps["everything_valid"])
class AcmeChallengeViewTestCase(
    AcmeWithAccountViewTestCaseMixin[jose.json_util.JSONObjectWithFields], TransactionTestCase
):
    """Test retrieving a challenge."""

    # NOTE: type parameter not required post-as-get requests

    post_as_get = True
    view_name = "acme-challenge"

    def setUp(self) -> None:
        super().setUp()
        self.order = AcmeOrder.objects.create(account=self.account)
        self.order.add_authorizations(
            [acme.messages.Identifier(typ=acme.messages.IDENTIFIER_FQDN, value="example.com")]
        )
        self.authz = AcmeAuthorization.objects.get(order=self.order, value="example.com")
        self.challenge = self.authz.get_challenges()[0]
        self.challenge.token = "foobar"
        self.challenge.save()

    @property
    def url(self) -> str:
        """Get default generic url."""
        return self.get_url(serial=self.challenge.serial, slug=self.challenge.slug)

    @override_tmpcadir()
    def test_basic(self) -> None:
        """Basic test for creating an account via ACME."""
        with self.patch("django_ca.acme.views.run_task") as mockcm:
            resp = self.acme(self.url, self.message, kid=self.kid)

        self.assertEqual(mockcm.call_args_list, [mock.call(acme_validate_challenge, self.challenge.pk)])

        self.assertEqual(resp.status_code, HTTPStatus.OK, resp.content)
        self.assertAcmeResponse(
            resp, link_relations={"up": f"http://{self.SERVER_NAME}{self.authz.acme_url}"}
        )

        self.assertEqual(
            resp.json(),
            {
                "status": "processing",
                "type": self.challenge.type,
                "token": jose.json_util.encode_b64jose(self.challenge.token.encode()),
                "url": f"http://{self.SERVER_NAME}{self.challenge.acme_url}",
            },
        )

    def test_duplicate_nonce(self) -> None:
        # wrapped so that the triggered task is not run, which would do an HTTP request
        with self.patch("django_ca.acme.views.run_task"):
            super().test_duplicate_nonce()

    @override_tmpcadir()
    def test_no_state_change(self) -> None:
        """Test challenge endpoint when no state change is triggered (e.g. already valid)."""
        self.challenge.status = AcmeChallenge.STATUS_VALID
        self.challenge.save()
        self.authz.status = AcmeAuthorization.STATUS_VALID
        self.authz.save()
        self.order.status = AcmeOrder.STATUS_VALID
        self.order.save()

        with self.patch("django_ca.acme.views.run_task") as mockcm:
            resp = self.acme(self.url, self.message, kid=self.kid)

        mockcm.assert_not_called()  # no validation task was triggerd

        # ... but response is still ok
        self.assertEqual(resp.status_code, HTTPStatus.OK, resp.content)
        self.assertAcmeResponse(
            resp, link_relations={"up": f"http://{self.SERVER_NAME}{self.authz.acme_url}"}
        )

        self.assertEqual(
            resp.json(),
            {
                "status": "valid",
                "type": self.challenge.type,
                "token": jose.json_util.encode_b64jose(self.challenge.token.encode()),
                "url": f"http://{self.SERVER_NAME}{self.challenge.acme_url}",
            },
        )

    @override_tmpcadir()
    def test_not_found(self) -> None:
        """Basic test for creating an account via ACME."""
        url = self.get_url(serial=self.challenge.serial, slug="abc")
        with self.patch("django_ca.acme.views.run_task") as mockcm:
            resp = self.acme(url, self.message, kid=self.kid)
        mockcm.assert_not_called()
        self.assertUnauthorized(resp, "You are not authorized to perform this request.")

    def test_payload_in_post_as_get(self) -> None:
        """Do nothing, since we ignore the body."""
        return

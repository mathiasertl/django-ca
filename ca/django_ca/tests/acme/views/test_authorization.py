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

"""Test requesting a new authorization."""

from http import HTTPStatus

import acme
import acme.jws
import josepy as jose
import pyrfc3339

from django.test import TestCase
from django.test.utils import override_settings
from django.utils import timezone

from freezegun import freeze_time

from django_ca import ca_settings
from django_ca.models import AcmeAuthorization, AcmeChallenge, AcmeOrder
from django_ca.tests.acme.views.base import AcmeWithAccountViewTestCaseMixin
from django_ca.tests.base import override_tmpcadir, timestamps


@freeze_time(timestamps["everything_valid"])
class AcmeAuthorizationViewTestCase(
    AcmeWithAccountViewTestCaseMixin[jose.json_util.JSONObjectWithFields], TestCase
):
    """Test requesting a new auhtorization."""

    # NOTE: type parameter not required post-as-get requests

    post_as_get = True
    view_name = "acme-authz"

    def setUp(self) -> None:
        super().setUp()
        self.order = AcmeOrder.objects.create(account=self.account)
        self.order.add_authorizations(
            [acme.messages.Identifier(typ=acme.messages.IDENTIFIER_FQDN, value="example.com")]
        )
        self.authz = AcmeAuthorization.objects.get(order=self.order, value="example.com")

    @property
    def url(self) -> str:
        """Get URL for the standard auth object."""
        return self.get_url(serial=self.ca.serial, slug=self.authz.slug)

    @override_tmpcadir()
    def test_basic(self, accept_naive: bool = False) -> None:
        """Basic test for creating an account via ACME."""

        resp = self.acme(self.url, self.message, kid=self.kid)
        self.assertEqual(resp.status_code, HTTPStatus.OK, resp.content)
        self.assertAcmeResponse(resp)

        challenges = self.authz.challenges.all()
        self.assertEqual(len(challenges), 2)

        resp_data = resp.json()
        resp_challenges = resp_data.pop("challenges")
        slug0 = challenges[0].slug
        slug1 = challenges[1].slug
        self.assertCountEqual(
            resp_challenges,
            [
                {
                    "type": challenges[0].type,
                    "status": "pending",
                    "token": jose.json_util.encode_b64jose(challenges[0].token.encode("utf-8")),
                    "url": f"http://{self.SERVER_NAME}/django_ca/acme/{self.ca.serial}/chall/{slug0}/",
                },
                {
                    "type": challenges[1].type,
                    "status": "pending",
                    "token": jose.json_util.encode_b64jose(challenges[1].token.encode("utf-8")),
                    "url": f"http://{self.SERVER_NAME}/django_ca/acme/{self.ca.serial}/chall/{slug1}/",
                },
            ],
        )

        expires = timezone.now() + ca_settings.ACME_ORDER_VALIDITY
        self.assertEqual(
            resp_data,
            {
                "expires": pyrfc3339.generate(expires, accept_naive=accept_naive),
                "identifier": {
                    "type": "dns",
                    "value": "example.com",
                },
                "status": "pending",
            },
        )

    @override_settings(USE_TZ=False)
    def test_basic_without_tz(self) -> None:
        """Basic test but with timezone support."""
        self.test_basic(accept_naive=True)

    @override_tmpcadir()
    def test_valid_auth(self) -> None:
        """Test fetching a valid auth object."""

        self.authz.get_challenges()  # creates challenges in the first place
        self.authz.status = AcmeAuthorization.STATUS_VALID
        self.authz.save()
        self.authz.challenges.filter(type=AcmeChallenge.TYPE_HTTP_01).update(
            status=AcmeChallenge.STATUS_VALID, validated=timezone.now()
        )

        resp = self.acme(self.url, self.message, kid=self.kid)
        self.assertEqual(resp.status_code, HTTPStatus.OK, resp.content)
        self.assertAcmeResponse(resp)

        challenges = self.authz.challenges.filter(status=AcmeChallenge.STATUS_VALID)
        self.assertEqual(len(challenges), 1)

        resp_data = resp.json()
        resp_challenges = resp_data.pop("challenges")
        slug = challenges[0].slug
        self.assertCountEqual(
            resp_challenges,
            [
                {
                    "type": challenges[0].type,
                    "status": "valid",
                    "validated": pyrfc3339.generate(timezone.now()),  # time is frozen anyway
                    "token": jose.json_util.encode_b64jose(challenges[0].token.encode("utf-8")),
                    "url": f"http://{self.SERVER_NAME}/django_ca/acme/{self.ca.serial}/chall/{slug}/",
                },
            ],
        )

        expires = timezone.now() + ca_settings.ACME_ORDER_VALIDITY
        self.assertEqual(
            resp_data,
            {
                "expires": pyrfc3339.generate(expires),
                "identifier": {
                    "type": "dns",
                    "value": "example.com",
                },
                "status": "valid",
            },
        )

    @override_tmpcadir()
    def test_no_challenges(self) -> None:
        """Test viewing Auth with **no* challenges.

        This test case is useful because the ACME message class does not tolerate empty lists.
        """

        self.authz.get_challenges()  # creates challenges in the first place
        self.authz.status = AcmeAuthorization.STATUS_VALID
        self.authz.save()

        resp = self.acme(self.url, self.message, kid=self.kid)
        self.assertEqual(resp.status_code, HTTPStatus.OK, resp.content)
        self.assertAcmeResponse(resp)

        challenges = self.authz.challenges.filter(status=AcmeChallenge.STATUS_VALID)
        self.assertEqual(len(challenges), 0)

        expires = timezone.now() + ca_settings.ACME_ORDER_VALIDITY
        self.assertEqual(
            resp.json(),
            {
                "expires": pyrfc3339.generate(expires),
                "identifier": {
                    "type": "dns",
                    "value": "example.com",
                },
                "status": "valid",
            },
        )

    @override_tmpcadir()
    def test_unknown_auth(self) -> None:
        """Test fetching unknown auth object."""
        resp = self.acme(self.get_url(serial=self.ca.serial, slug="abc"), self.message, kid=self.kid)
        self.assertUnauthorized(resp, "You are not authorized to perform this request.")

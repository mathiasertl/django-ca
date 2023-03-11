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

"""Test viewing an order."""

from http import HTTPStatus

import josepy as jose
import pyrfc3339

from django.test import TestCase, override_settings
from django.utils import timezone

from freezegun import freeze_time

from django_ca import ca_settings
from django_ca.acme.errors import AcmeUnauthorized
from django_ca.models import AcmeAccount, AcmeAuthorization, AcmeCertificate, AcmeOrder
from django_ca.tests.acme.views.base import AcmeWithAccountViewTestCaseMixin
from django_ca.tests.base import override_tmpcadir, timestamps


@freeze_time(timestamps["everything_valid"])
class AcmeOrderViewTestCase(AcmeWithAccountViewTestCaseMixin[jose.json_util.JSONObjectWithFields], TestCase):
    """Test retrieving an order."""

    # NOTE: type parameter not required post-as-get requests

    post_as_get = True
    view_name = "acme-order"

    def setUp(self) -> None:
        super().setUp()
        self.order = AcmeOrder.objects.create(account=self.account)
        self.authz = AcmeAuthorization.objects.create(order=self.order, value=self.hostname)

    @property
    def url(self) -> str:
        """Get URL for the standard auth object."""
        return self.get_url(serial=self.ca.serial, slug=self.order.slug)

    @override_tmpcadir()
    def test_basic(self, accept_naive: bool = False) -> None:
        """Basic test for creating an account via ACME."""

        resp = self.acme(self.url, self.message, kid=self.kid)
        self.assertEqual(resp.status_code, HTTPStatus.OK, resp.content)
        self.assertAcmeResponse(resp)
        expires = timezone.now() + ca_settings.ACME_ORDER_VALIDITY
        self.assertEqual(
            resp.json(),
            {
                "authorizations": [f"http://{self.SERVER_NAME}{self.authz.acme_url}"],
                "expires": pyrfc3339.generate(expires, accept_naive=accept_naive),
                "identifiers": [{"type": "dns", "value": self.hostname}],
                "status": "pending",
            },
        )

    @override_settings(USE_TZ=False)
    def test_basic_with_tz(self) -> None:
        """Basic test without timezone support."""
        self.test_basic(True)

    @override_tmpcadir()
    def test_valid_cert(self) -> None:
        """Test viewing an order with a valid certificate"""

        self.order.status = AcmeOrder.STATUS_VALID
        self.order.save()
        self.authz.status = AcmeAuthorization.STATUS_VALID
        self.authz.save()
        acmecert = AcmeCertificate.objects.create(order=self.order, cert=self.cert)

        resp = self.acme(self.url, self.message, kid=self.kid)
        self.assertEqual(resp.status_code, HTTPStatus.OK, resp.content)
        self.assertAcmeResponse(resp)
        expires = timezone.now() + ca_settings.ACME_ORDER_VALIDITY
        self.assertEqual(
            resp.json(),
            {
                "authorizations": [f"http://{self.SERVER_NAME}{self.authz.acme_url}"],
                "certificate": f"http://{self.SERVER_NAME}{acmecert.acme_url}",
                "expires": pyrfc3339.generate(expires, accept_naive=True),
                "identifiers": [{"type": "dns", "value": self.hostname}],
                "status": "valid",
            },
        )

    @override_tmpcadir()
    def test_cert_not_yet_issued(self) -> None:
        """Test viewing an order where the certificate has not yet been issued.

        NOTE: test_cert_not_yet_issued and test_cert_not_yet_valid test two different conditionas that
        *should* always be true at the same time.
        """

        self.order.status = AcmeOrder.STATUS_VALID
        self.order.save()
        self.authz.status = AcmeAuthorization.STATUS_VALID
        self.authz.save()
        AcmeCertificate.objects.create(order=self.order)

        resp = self.acme(self.url, self.message, kid=self.kid)
        self.assertEqual(resp.status_code, HTTPStatus.OK, resp.content)
        self.assertAcmeResponse(resp)
        expires = timezone.now() + ca_settings.ACME_ORDER_VALIDITY
        self.assertEqual(
            resp.json(),
            {
                "authorizations": [f"http://{self.SERVER_NAME}{self.authz.acme_url}"],
                "expires": pyrfc3339.generate(expires, accept_naive=True),
                "identifiers": [{"type": "dns", "value": self.hostname}],
                "status": "valid",
            },
        )

    @override_tmpcadir()
    def test_cert_not_yet_valid(self) -> None:
        """Test viewing an order where the certificate has not yet valid.

        NOTE: test_cert_not_yet_issued and test_cert_not_yet_valid test two different conditionas that
        *should* always be true at the same time.
        """

        self.order.status = AcmeOrder.STATUS_PROCESSING
        self.order.save()
        self.authz.status = AcmeAuthorization.STATUS_VALID
        self.authz.save()
        AcmeCertificate.objects.create(order=self.order, cert=self.cert)

        resp = self.acme(self.url, self.message, kid=self.kid)
        self.assertEqual(resp.status_code, HTTPStatus.OK, resp.content)
        self.assertAcmeResponse(resp)
        expires = timezone.now() + ca_settings.ACME_ORDER_VALIDITY
        self.assertEqual(
            resp.json(),
            {
                "authorizations": [f"http://{self.SERVER_NAME}{self.authz.acme_url}"],
                "expires": pyrfc3339.generate(expires, accept_naive=True),
                "identifiers": [{"type": "dns", "value": self.hostname}],
                "status": "processing",
            },
        )

    @override_tmpcadir()
    def test_wrong_account(self) -> None:
        """Test viewing for the wrong account"""

        account = AcmeAccount.objects.create(
            ca=self.ca, terms_of_service_agreed=True, slug="def", kid="kid", pem="bar", thumbprint="foo"
        )
        self.order.account = account
        self.order.save()

        resp = self.acme(self.url, self.message, kid=self.kid)
        self.assertUnauthorized(resp)

    @override_tmpcadir()
    def test_not_found(self) -> None:
        """Test viewing an order that simply does not exist."""

        account = AcmeAccount.objects.create(
            ca=self.ca, terms_of_service_agreed=True, slug="def", kid="kid", pem="bar", thumbprint="foo"
        )
        self.order.account = account
        self.order.save()

        url = self.get_url(serial=self.ca.serial, slug=self.order.slug)
        resp = self.acme(url, self.message, kid=self.kid)
        self.assertUnauthorized(resp)

    @override_tmpcadir()
    def test_basic_exception(self) -> None:
        """Test throwing an AcmeException in acme_request().

        We have to mock this, as at present this is not usually done.
        """

        with self.patch(
            "django_ca.acme.views.AcmeOrderView.acme_request", side_effect=AcmeUnauthorized(message="foo")
        ):
            resp = self.acme(self.url, self.message, kid=self.kid)
        self.assertUnauthorized(resp, "foo")

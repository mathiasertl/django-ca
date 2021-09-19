# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca.  If not,
# see <http://www.gnu.org/licenses/>.

"""Test ACME related views."""

import json
import os
import typing
from datetime import datetime
from http import HTTPStatus
from unittest import mock

from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponse
from django.test import TestCase
from django.test.utils import override_settings
from django.urls import reverse
from django.utils import timezone

from freezegun import freeze_time

from .. import ca_settings
from ..models import AcmeAccount
from ..models import AcmeAuthorization
from ..models import AcmeCertificate
from ..models import AcmeChallenge
from ..models import AcmeOrder
from ..models import CertificateAuthority
from .tests_views_acme import AcmeTestCaseMixin

ACCOUNT_SLUG = "DzW4PQ6L76PE"

with open(os.path.join(settings.FIXTURES_DIR, "prepared-acme-requests.json")) as stream:
    prepared_requests: typing.Dict[str, typing.List[typing.Dict[str, typing.Any]]] = json.load(stream)


class AcmePreparedRequestsTestCaseMixin(AcmeTestCaseMixin):
    """Mixin for testing requests recorded from actual certbot sessions."""

    # The serial of the CA that was used when recording requests
    ca_serial = "3F1E6E9B3996B26B8072E4DD2597E8B40F3FBC7E"
    expected_status_code = HTTPStatus.OK
    view_name: str
    url: str

    def setUp(self) -> None:  # pylint: disable=invalid-name, missing-function-docstring; unittest standard
        super().setUp()
        self.ca.serial = self.ca_serial
        self.ca.save()

    def add_account(self, data: typing.Dict[str, str]) -> AcmeAccount:
        """Add an account with the given test data."""
        return AcmeAccount.objects.get_or_create(  # type: ignore[no-any-return]
            thumbprint=data["thumbprint"],
            defaults={
                "pk": data["account_pk"],
                "contact": "user@localhost",
                "ca": self.ca,
                "kid": data["kid"],
                "terms_of_service_agreed": True,
                "pem": data["pem"],
                "slug": data["account_pk"],
            },
        )[0]

    def before_prepared_request(self, data: typing.Dict[str, str]) -> None:
        """Any action to take **before** sending a prepared request."""

    def assertFailedPreparedResponse(  # pylint: disable=invalid-name
        self, data: typing.Dict[str, str], response: HttpResponse
    ) -> None:
        """Any assertions after doing a prepared request while ACME is disabled."""

    def assertPreparedResponse(  # pylint: disable=invalid-name
        self, data: typing.Dict[str, str], response: HttpResponse, celery_mock: mock.MagicMock
    ) -> None:
        """Any assertions on the response of a prepared request."""

    def get_url(self, data: typing.Dict[str, str]) -> str:  # pylint: disable=unused-argument
        """Get URL based on given request data."""
        return self.url

    def post(self, url: str, data: typing.Any, **kwargs: str) -> HttpResponse:
        kwargs.setdefault("SERVER_NAME", "localhost:8000")
        return super().post(url, data, **kwargs)

    @property
    def requests(self) -> typing.List[typing.Dict[str, typing.Any]]:
        """Get prepared requests for `self.view_name`."""
        return prepared_requests[self.view_name]

    def test_requests(self) -> None:
        """Test requests collected from certbot."""

        for data in self.requests:
            cache.set("acme-nonce-%s-%s" % (self.ca.serial, data["nonce"]), 0)
            self.before_prepared_request(data)
            with self.mute_celery() as celery_mock:
                response = self.post(self.get_url(data), data["body"])
            self.assertEqual(response.status_code, self.expected_status_code, response.content)
            self.assertAcmeResponse(response)
            self.assertPreparedResponse(data, response, celery_mock)

    @override_settings(USE_TZ=True)
    def test_requests_no_tz(self) -> None:
        """Test requests but with timezone support enabled."""
        self.test_requests()

    @override_settings(CA_ENABLE_ACME=False)
    def test_disabled(self) -> None:
        """Test that CA_ENABLE_ACME=False means HTTP 404."""
        for data in self.requests:
            cache.set("acme-nonce-%s-%s" % (self.ca.serial, data["nonce"]), 0)
            self.before_prepared_request(data)
            response = self.post(self.get_url(data), data["body"])
            self.assertEqual(response.status_code, HTTPStatus.NOT_FOUND)
            self.assertEqual(response["Content-Type"], "text/html")  # --> coming from Django
            self.assertFailedPreparedResponse(data, response)

    def test_invalid_content_type(self) -> None:
        """Test sending an invalid content type."""
        for data in self.requests:
            cache.set("acme-nonce-%s-%s" % (self.ca.serial, data["nonce"]), 0)
            self.before_prepared_request(data)
            response = self.post(self.get_url(data), data["body"], content_type="application/json")
            self.assertAcmeProblem(
                response,
                typ="malformed",
                status=415,
                message="Requests must use the application/jose+json content type.",
            )
            self.assertFailedPreparedResponse(data, response)

    def test_generic_exception(self) -> None:
        """Test the dispatch function raising a generic exception."""

        for data in self.requests:
            cache.set("acme-nonce-%s-%s" % (self.ca.serial, data["nonce"]), 0)
            self.before_prepared_request(data)

            url = self.get_url(data)
            view = "django.views.generic.base.View.dispatch"
            msg = f"{url} mock-exception"

            with mock.patch(view, side_effect=Exception(msg)), self.assertLogs() as logcm:
                response = self.post(url, data["body"], content_type="application/json")
            self.assertEqual(response.status_code, HTTPStatus.INTERNAL_SERVER_ERROR)
            self.assertEqual(
                response.json(),
                {
                    "detail": "Internal server error",
                    "status": HTTPStatus.INTERNAL_SERVER_ERROR,
                    "type": "urn:ietf:params:acme:error:serverInternal",
                },
            )
            self.assertEqual(len(logcm.output), 1)
            self.assertIn(msg, logcm.output[0])

    def test_duplicate_nonce_use(self) -> None:
        """Test that a Nonce can really only be used once."""
        for data in self.requests:
            cache.set("acme-nonce-%s-%s" % (self.ca.serial, data["nonce"]), 0)
            self.before_prepared_request(data)
            with self.mute_celery() as celery_mock:
                response = self.post(self.get_url(data), data["body"])
            self.assertEqual(response.status_code, self.expected_status_code)
            self.assertAcmeResponse(response)
            self.assertPreparedResponse(data, response, celery_mock)

            # Do the request again to validate that the nonce is now invalid
            response = self.post(self.get_url(data), data["body"])
            self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
            self.assertAcmeProblem(response, typ="badNonce", status=400, message="Bad or invalid nonce.")

    def test_unknown_nonce_use(self) -> None:
        """Test that an unknown nonce does not work."""
        for data in self.requests:
            self.before_prepared_request(data)
            response = self.post(self.get_url(data), data["body"])
            self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
            self.assertAcmeProblem(response, typ="badNonce", status=400, message="Bad or invalid nonce.")
            self.assertFailedPreparedResponse(data, response)


@override_settings(ALLOWED_HOSTS=["localhost"])
@freeze_time(datetime(2020, 10, 29, 20, 15, 35))  # when we recorded these requests
class PreparedAcmeNewAccountViewTestCase(AcmePreparedRequestsTestCaseMixin, TestCase):
    """Test creating a new account."""

    expected_status_code = HTTPStatus.CREATED
    view_name = "AcmeNewAccountView"

    def setUp(self) -> None:
        super().setUp()
        self.url = reverse("django_ca:acme-new-account", kwargs={"serial": self.ca_serial})

    def assertFailedPreparedResponse(self, data: typing.Dict[str, str], response: HttpResponse) -> None:
        # Test that *no* account was created
        self.assertEqual(AcmeAccount.objects.all().count(), 0)

    def assertPreparedResponse(
        self, data: typing.Dict[str, str], response: HttpResponse, celery_mock: mock.MagicMock
    ) -> None:
        account = AcmeAccount.objects.get(thumbprint=data["thumbprint"])
        uri = response.wsgi_request.build_absolute_uri
        kwargs = {"serial": self.ca.serial, "slug": account.slug}
        self.assertEqual(response["Location"], uri(reverse("django_ca:acme-account", kwargs=kwargs)))
        # An example response can be found in RFC 8555, section 7.3
        # https://tools.ietf.org/html/rfc8555#section-7.3
        self.assertEqual(
            response.json(),
            {
                "status": "valid",
                "contact": ["mailto:user@localhost"],
                "orders": uri(reverse("django_ca:acme-account-orders", kwargs=kwargs)),
            },
        )


@override_settings(ALLOWED_HOSTS=["localhost"])
@freeze_time(datetime(2020, 10, 29, 20, 15, 35))  # when we recorded these requests
class PreparedAcmeNewOrderViewTestCase(AcmePreparedRequestsTestCaseMixin, TestCase):
    """Test creating a new order."""

    expected_status_code = HTTPStatus.CREATED
    view_name = "AcmeNewOrderView"

    def setUp(self) -> None:
        super().setUp()
        self.url = reverse("django_ca:acme-new-order", kwargs={"serial": self.ca_serial})
        self.done: typing.Dict[str, AcmeOrder] = {}

    def before_prepared_request(self, data: typing.Dict[str, str]) -> None:
        # pylint: disable=attribute-defined-outside-init
        self.account = self.add_account(data)

    def assertPreparedResponse(
        self, data: typing.Dict[str, str], response: HttpResponse, celery_mock: mock.MagicMock
    ) -> None:
        self.assertEqual(list(AcmeAccount.objects.all()), [self.account])

        order = AcmeOrder.objects.exclude(pk__in=[o.pk for o in self.done.values()]).get(account=self.account)
        self.done[data["nonce"]] = order

        self.assertEqual(order.account, self.account)
        self.assertEqual(order.status, "pending")
        self.assertEqual(order.expires, timezone.now() + ca_settings.ACME_ORDER_VALIDITY)
        self.assertIsNone(order.not_before)
        self.assertIsNone(order.not_after)
        self.assertEqual(
            order.acme_finalize_url, f"/django_ca/acme/{self.ca_serial}/order/{order.slug}/finalize/"
        )
        # pylint: disable=no-member
        with self.assertRaises(
            AcmeOrder.acmecertificate.RelatedObjectDoesNotExist  # type: ignore[attr-defined]
        ):
            self.assertIsNone(order.acmecertificate)
        # pylint: enable=no-member

        auths = order.authorizations.all()
        self.assertEqual(len(auths), 1)
        auth = auths[0]
        self.assertEqual(auth.status, "pending")
        self.assertEqual(auth.type, "dns")
        self.assertEqual(auth.value, "localhost")
        self.assertEqual(auth.expires, order.expires)
        self.assertFalse(auth.wildcard)

        # Challenges are only created once the selected authorization is retrieved, not when order is created
        self.assertFalse(auth.challenges.exists())


@override_settings(ALLOWED_HOSTS=["localhost"])
@freeze_time(datetime(2020, 10, 29, 20, 15, 35))  # when we recorded these requests
class PreparedAcmeAuthorizationViewTestCase(AcmePreparedRequestsTestCaseMixin, TestCase):
    """Test creating a new order."""

    view_name = "AcmeAuthorizationView"

    def before_prepared_request(self, data: typing.Dict[str, str]) -> None:
        acc = self.add_account(data)
        order = AcmeOrder.objects.get_or_create(account=acc, slug=data["order"])[0]
        AcmeAuthorization.objects.get_or_create(
            order=order, slug=data["auth"], defaults={"value": "localhost"}
        )

    def get_url(self, data: typing.Dict[str, str]) -> str:
        return reverse("django_ca:acme-authz", kwargs={"serial": self.ca_serial, "slug": data["auth"]})


@override_settings(ALLOWED_HOSTS=["localhost"])
@freeze_time(datetime(2020, 10, 29, 20, 15, 35))  # when we recorded these requests
class PreparedAcmeChallengeViewTestCase(AcmePreparedRequestsTestCaseMixin, TestCase):
    """Test retrieving a challenge."""

    view_name = "AcmeChallengeView"

    def assertLinkRelations(  # pylint: disable=invalid-name
        self, response: HttpResponse, ca: typing.Optional[CertificateAuthority] = None, **kwargs: typing.Any
    ) -> None:
        if response.status_code < HTTPStatus.BAD_REQUEST:
            kwargs.setdefault("up", response.wsgi_request.build_absolute_uri(self.challenge.auth.acme_url))
        super().assertLinkRelations(response=response, ca=ca, **kwargs)

    def before_prepared_request(self, data: typing.Dict[str, str]) -> None:
        acc = self.add_account(data)
        order = AcmeOrder.objects.create(account=acc, slug=data["order"])
        auth = AcmeAuthorization.objects.create(order=order, slug=data["auth"], value="localhost")

        self.challenge = AcmeChallenge.objects.create(  # pylint: disable=attribute-defined-outside-init
            slug=data["challenge"], auth=auth, type=AcmeChallenge.TYPE_HTTP_01
        )

    def get_url(self, data: typing.Dict[str, str]) -> str:
        return reverse(
            "django_ca:acme-challenge",
            kwargs={
                "serial": self.ca_serial,
                "slug": data["challenge"],
            },
        )


@override_settings(ALLOWED_HOSTS=["localhost"])
@freeze_time(datetime(2020, 10, 29, 20, 15, 35))  # when we recorded these requests
class PreparedAcmeOrderFinalizeViewTestCase(AcmePreparedRequestsTestCaseMixin, TestCase):
    """Test retrieving a challenge."""

    view_name = "AcmeOrderFinalizeView"

    def before_prepared_request(self, data: typing.Dict[str, str]) -> None:
        acc = self.add_account(data)
        order = AcmeOrder.objects.create(account=acc, slug=data["order"], status=AcmeOrder.STATUS_READY)
        AcmeAuthorization.objects.create(
            order=order, value="localhost", status=AcmeAuthorization.STATUS_VALID
        )

    def get_url(self, data: typing.Dict[str, str]) -> str:
        return reverse(
            "django_ca:acme-order-finalize",
            kwargs={
                "serial": self.ca_serial,
                "slug": data["order"],
            },
        )


@override_settings(ALLOWED_HOSTS=["localhost"])
@freeze_time(datetime(2020, 10, 29, 20, 15, 35))  # when we recorded these requests
class PreparedAcmeOrderViewTestCase(AcmePreparedRequestsTestCaseMixin, TestCase):
    """Test retrieving a challenge."""

    view_name = "AcmeOrderView"

    def before_prepared_request(self, data: typing.Dict[str, str]) -> None:
        acc = self.add_account(data)
        AcmeOrder.objects.create(account=acc, slug=data["order"], status=AcmeOrder.STATUS_READY)

    def get_url(self, data: typing.Dict[str, str]) -> str:
        return reverse(
            "django_ca:acme-order",
            kwargs={
                "serial": self.ca_serial,
                "slug": data["order"],
            },
        )


@override_settings(ALLOWED_HOSTS=["localhost"])
@freeze_time(datetime(2020, 10, 29, 20, 15, 35))  # when we recorded these requests
class PreparedAcmeCertificateViewTestCase(AcmePreparedRequestsTestCaseMixin, TestCase):
    """Test retrieving a challenge."""

    view_name = "AcmeCertificateView"

    def assertAcmeResponse(
        self,
        response: HttpResponse,
        ca: typing.Optional[CertificateAuthority] = None,
        link_relations: typing.Optional[typing.Dict[str, str]] = None,
    ) -> None:
        """This view does not return normal ACME responses but a certificate bundle."""
        link_relations = link_relations or {}
        self.assertLinkRelations(response, ca=ca, **link_relations)
        self.assertEqual(response["Content-Type"], "application/pem-certificate-chain")

    def before_prepared_request(self, data: typing.Dict[str, str]) -> None:
        acc = self.add_account(data)
        order = AcmeOrder.objects.create(account=acc, slug=data["order"], status=AcmeOrder.STATUS_VALID)
        AcmeCertificate.objects.create(slug=data["cert"], order=order, cert=self.cert, csr=data["csr"])

    def get_url(self, data: typing.Dict[str, str]) -> str:
        return reverse(
            "django_ca:acme-cert",
            kwargs={
                "serial": self.ca_serial,
                "slug": data["cert"],
            },
        )

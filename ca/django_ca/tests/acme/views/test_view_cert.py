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

"""Test downloading the certificiate."""

from http import HTTPStatus

import josepy as jose

from django.test import TestCase

from freezegun import freeze_time

from django_ca.models import AcmeAccount, AcmeCertificate, AcmeOrder
from django_ca.tests.acme.views.base import AcmeWithAccountViewTestCaseMixin
from django_ca.tests.base import CERT_PEM_REGEX, override_tmpcadir, timestamps


@freeze_time(timestamps["everything_valid"])
class AcmeCertificateViewTestCase(
    AcmeWithAccountViewTestCaseMixin[jose.json_util.JSONObjectWithFields], TestCase
):
    """Test retrieving a certificate."""

    # NOTE: This is the request that does *not* return a JSON object (but the full cert), so the generic
    #       type for AcmeWithAccountViewTestCaseMixin really is just a dummy.

    post_as_get = True
    view_name = "acme-cert"

    def setUp(self) -> None:
        super().setUp()
        self.order = AcmeOrder.objects.create(account=self.account, status=AcmeOrder.STATUS_VALID)
        self.acmecert = AcmeCertificate.objects.create(order=self.order, cert=self.cert)

    @property
    def url(self) -> str:
        """Get URL for the standard cert object."""
        return self.get_url(serial=self.ca.serial, slug=self.acmecert.slug)

    @override_tmpcadir()
    def test_basic(self) -> None:
        """Basic test case."""
        resp = self.acme(self.url, self.message, kid=self.kid)
        self.assertEqual(resp.status_code, HTTPStatus.OK, resp.content)

        # Make sure that certbot parses the expected list of PEMs
        certbot_split = CERT_PEM_REGEX.findall(resp.content)
        self.assertEqual([c.pub.pem.encode() for c in self.cert.bundle], certbot_split)

    @override_tmpcadir()
    def test_not_found(self) -> None:
        """Test fetching a cert that simply does not exist."""
        resp = self.acme(self.get_url(serial=self.ca.serial, slug="abc"), self.message, kid=self.kid)
        self.assertUnauthorized(resp)

    @override_tmpcadir()
    def test_wrong_account(self) -> None:
        """Test fetching a certificate for a different account."""
        account = AcmeAccount.objects.create(
            ca=self.ca, terms_of_service_agreed=True, slug="def", kid="kid", pem="bar", thumbprint="foo"
        )
        self.order.account = account
        self.order.save()

        resp = self.acme(self.url, self.message, kid=self.kid)
        self.assertUnauthorized(resp)

    @override_tmpcadir()
    def test_no_cert_issued(self) -> None:
        """Test when no cert is issued.

        NOTE: should not really happen, as the order is marked as valid, the certificate is also set in one
        transaction.
        """

        self.acmecert.cert = None
        self.acmecert.save()
        resp = self.acme(self.url, self.message, kid=self.kid)
        self.assertUnauthorized(resp)

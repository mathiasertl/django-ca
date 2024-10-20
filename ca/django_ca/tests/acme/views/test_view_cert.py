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

"""Test downloading the certificate."""

# pylint: disable=redefined-outer-name  # for to fixtures

from collections.abc import Iterator
from http import HTTPStatus
from typing import Optional

import josepy as jose

from django.test import Client

import pytest

from django_ca.models import AcmeAccount, AcmeCertificate, AcmeOrder, CertificateAuthority
from django_ca.tests.acme.views.assertions import assert_unauthorized
from django_ca.tests.acme.views.base import AcmeWithAccountViewTestCaseMixin
from django_ca.tests.acme.views.utils import acme_request
from django_ca.tests.base.constants import CERT_PEM_REGEX, TIMESTAMPS
from django_ca.tests.base.utils import root_reverse

# ACME views require a currently valid certificate authority
pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])]


@pytest.fixture
def order(order: AcmeOrder) -> Iterator[AcmeOrder]:
    """Override to set status to valid."""
    order.status = AcmeOrder.STATUS_VALID
    order.save()
    return order


@pytest.fixture
def url(acme_cert_slug: str) -> Iterator[str]:
    """URL under test."""
    return root_reverse("acme-cert", slug=acme_cert_slug)


@pytest.fixture
def message() -> Iterator[bytes]:
    """Yield an empty bytestring, since this is a POST-AS-GET request."""
    return b""


def test_basic(
    client: Client,
    url: str,
    root: CertificateAuthority,
    kid: Optional[str],
    acme_cert: AcmeCertificate,
) -> None:
    """Basic test case."""
    # acme_cert.order.status = AcmeOrder.STATUS_VALID
    # acme_cert.order.save()
    resp = acme_request(client, url, root, b"", kid=kid)
    assert resp.status_code == HTTPStatus.OK, resp.content

    # Make sure that certbot parses the expected list of PEMs
    certbot_split = CERT_PEM_REGEX.findall(resp.content)
    assert len(certbot_split) == 2  # make sure that we get cert and root ca
    assert [c.pub.pem.encode() for c in acme_cert.cert.bundle] == certbot_split  # type: ignore[union-attr]


@pytest.mark.usefixtures("account")
def test_not_found(client: Client, root: CertificateAuthority, kid: Optional[str]) -> None:
    """Test fetching a cert that simply does not exist."""
    url = root_reverse("acme-cert", slug="abc")
    resp = acme_request(client, url, root, b"", kid=kid)
    assert_unauthorized(resp, root)


def test_wrong_account(
    client: Client, url: str, root: CertificateAuthority, order: AcmeOrder, kid: Optional[str]
) -> None:
    """Test fetching a certificate for a different account."""
    account = AcmeAccount.objects.create(
        ca=root, terms_of_service_agreed=True, slug="def", kid="kid", pem="bar", thumbprint="foo"
    )
    order.account = account
    order.save()

    resp = acme_request(client, url, root, b"", kid=kid)
    assert_unauthorized(resp, root)


def test_no_cert_issued(
    client: Client, url: str, root: CertificateAuthority, acme_cert: AcmeCertificate, kid: Optional[str]
) -> None:
    """Test when no cert is issued.

    NOTE: should not really happen, as the order is marked as valid, the certificate is also set in one
    transaction.
    """
    acme_cert.cert = None
    acme_cert.save()
    resp = acme_request(client, url, root, b"", kid=kid)
    assert_unauthorized(resp, root)


class TestAcmeCertificateView(AcmeWithAccountViewTestCaseMixin[jose.json_util.JSONObjectWithFields]):
    """Test retrieving a certificate."""

    # NOTE: This is the request that does *not* return a JSON object (but the full cert), so the generic
    #       type for AcmeWithAccountViewTestCaseMixin really is just a dummy.

    post_as_get = True

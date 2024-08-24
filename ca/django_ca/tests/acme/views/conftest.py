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

"""Fixtures for pytest tests."""

# pylint: disable=redefined-outer-name

from collections.abc import Iterator

from django.test import Client

import pytest

from django_ca.models import (
    AcmeAccount,
    AcmeAuthorization,
    AcmeCertificate,
    AcmeChallenge,
    AcmeOrder,
    Certificate,
    CertificateAuthority,
    acme_slug,
)
from django_ca.tests.acme.views.constants import HOST_NAME, PEM, SERVER_NAME, THUMBPRINT
from django_ca.tests.acme.views.utils import absolute_acme_uri


@pytest.fixture()
def account_slug() -> Iterator[str]:
    """Fixture for an account slug."""
    yield acme_slug()


@pytest.fixture()
def order_slug() -> Iterator[str]:
    """Fixture for an order slug."""
    yield acme_slug()


@pytest.fixture()
def acme_cert_slug() -> Iterator[str]:
    """Fixture for an ACME certificate slug."""
    yield acme_slug()


@pytest.fixture()
def client(client: Client) -> Iterator[Client]:
    """Override client fixture to set the default server name."""
    client.defaults["SERVER_NAME"] = SERVER_NAME
    yield client


@pytest.fixture()
def account(root: CertificateAuthority, account_slug: str, kid: str) -> Iterator[AcmeAccount]:
    """Fixture for an account."""
    yield AcmeAccount.objects.create(
        ca=root,
        contact="mailto:one@example.com",
        terms_of_service_agreed=True,
        slug=account_slug,
        kid=kid,
        pem=PEM,
        thumbprint=THUMBPRINT,
    )


@pytest.fixture()
def kid(root: CertificateAuthority, account_slug: str) -> Iterator[str]:
    """Fixture for a full KID."""
    yield absolute_acme_uri(":acme-account", serial=root.serial, slug=account_slug)


@pytest.fixture()
def order(account: AcmeAccount, order_slug: str) -> Iterator[AcmeOrder]:
    """Fixture for an order."""
    yield AcmeOrder.objects.create(account=account, slug=order_slug)


@pytest.fixture()
def authz(order: AcmeOrder) -> Iterator[AcmeAuthorization]:
    """Fixture for an authorization."""
    yield AcmeAuthorization.objects.create(order=order, value=HOST_NAME)


@pytest.fixture()
def challenge(authz: AcmeAuthorization) -> Iterator[AcmeChallenge]:
    """Fixture for a challenge."""
    challenge = authz.get_challenges()[0]
    challenge.token = "foobar"
    challenge.save()
    yield challenge


@pytest.fixture()
def acme_cert(root_cert: Certificate, order: AcmeOrder, acme_cert_slug: str) -> Iterator[AcmeCertificate]:
    """Fixture for an ACME certificate."""
    yield AcmeCertificate.objects.create(order=order, cert=root_cert, slug=acme_cert_slug)

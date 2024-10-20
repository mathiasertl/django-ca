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

# pylint: disable=redefined-outer-name  # because of fixtures

from collections.abc import Iterator
from http import HTTPStatus

import josepy as jose
import pyrfc3339

from django.test import Client
from django.utils import timezone

import pytest
from pytest_django.fixtures import SettingsWrapper

from django_ca.conf import model_settings
from django_ca.models import AcmeAuthorization, AcmeChallenge, CertificateAuthority
from django_ca.tests.acme.views.assertions import assert_acme_response, assert_unauthorized
from django_ca.tests.acme.views.base import AcmeWithAccountViewTestCaseMixin
from django_ca.tests.acme.views.constants import HOST_NAME, SERVER_NAME
from django_ca.tests.acme.views.utils import acme_request
from django_ca.tests.base.constants import TIMESTAMPS
from django_ca.tests.base.utils import root_reverse

# ACME views require a currently valid certificate authority
pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])]


@pytest.fixture
def url(authz: AcmeAuthorization) -> Iterator[str]:
    """URL under test."""
    return root_reverse("acme-authz", slug=authz.slug)


@pytest.fixture
def message() -> Iterator[bytes]:
    """Yield an empty bytestring, since this is a POST-AS-GET request."""
    return b""


@pytest.mark.parametrize("use_tz", (True, False))
def test_basic(
    settings: SettingsWrapper,
    client: Client,
    url: str,
    root: CertificateAuthority,
    authz: AcmeAuthorization,
    kid: str,
    use_tz: bool,
) -> None:
    """Basic test for creating an account via ACME."""
    settings.USE_TZ = use_tz
    resp = acme_request(client, url, root, b"", kid=kid)
    assert resp.status_code == HTTPStatus.OK, resp.content
    assert_acme_response(resp, root)

    challenges = authz.challenges.all()
    assert len(challenges) == 2

    resp_data = resp.json()
    resp_challenges = resp_data.pop("challenges")
    slug0 = challenges[0].slug
    slug1 = challenges[1].slug
    assert resp_challenges == [
        {
            "type": challenges[0].type,
            "status": "pending",
            "token": jose.json_util.encode_b64jose(challenges[0].token.encode("utf-8")),
            "url": f"http://{SERVER_NAME}/django_ca/acme/{root.serial}/chall/{slug0}/",
        },
        {
            "type": challenges[1].type,
            "status": "pending",
            "token": jose.json_util.encode_b64jose(challenges[1].token.encode("utf-8")),
            "url": f"http://{SERVER_NAME}/django_ca/acme/{root.serial}/chall/{slug1}/",
        },
    ]

    expires = timezone.now() + model_settings.CA_ACME_ORDER_VALIDITY
    assert resp_data == {
        "expires": pyrfc3339.generate(expires, accept_naive=not use_tz),
        "identifier": {
            "type": "dns",
            "value": "example.com",
        },
        "status": "pending",
    }


def test_valid_auth(
    client: Client, url: str, root: CertificateAuthority, authz: AcmeAuthorization, kid: str
) -> None:
    """Test fetching a valid auth object."""
    authz.get_challenges()  # creates challenges in the first place
    authz.status = AcmeAuthorization.STATUS_VALID
    authz.save()
    authz.challenges.filter(type=AcmeChallenge.TYPE_HTTP_01).update(
        status=AcmeChallenge.STATUS_VALID, validated=timezone.now()
    )

    resp = acme_request(client, url, root, b"", kid=kid)
    assert resp.status_code == HTTPStatus.OK, resp.content
    assert_acme_response(resp, root)

    challenges = authz.challenges.filter(status=AcmeChallenge.STATUS_VALID)
    assert len(challenges) == 1

    resp_data = resp.json()
    resp_challenges = resp_data.pop("challenges")
    slug = challenges[0].slug
    assert resp_challenges == [
        {
            "type": challenges[0].type,
            "status": "valid",
            "validated": pyrfc3339.generate(timezone.now()),  # time is frozen anyway
            "token": jose.json_util.encode_b64jose(challenges[0].token.encode("utf-8")),
            "url": f"http://{SERVER_NAME}/django_ca/acme/{root.serial}/chall/{slug}/",
        },
    ]

    expires = timezone.now() + model_settings.CA_ACME_ORDER_VALIDITY
    assert resp_data == {
        "expires": pyrfc3339.generate(expires),
        "identifier": {"type": "dns", "value": "example.com"},
        "status": "valid",
    }


def test_no_challenges(
    client: Client, url: str, root: CertificateAuthority, authz: AcmeAuthorization, kid: str
) -> None:
    """Test viewing Auth with **no* challenges.

    This test case is useful because the ACME message class does not tolerate empty lists.
    """
    authz.get_challenges()  # creates challenges in the first place
    authz.status = AcmeAuthorization.STATUS_VALID
    authz.save()

    resp = acme_request(client, url, root, b"", kid=kid)
    assert resp.status_code == HTTPStatus.OK, resp.content
    assert_acme_response(resp, root)

    challenges = authz.challenges.filter(status=AcmeChallenge.STATUS_VALID)
    assert len(challenges) == 0

    expires = timezone.now() + model_settings.CA_ACME_ORDER_VALIDITY
    assert resp.json() == {
        "expires": pyrfc3339.generate(expires),
        "identifier": {"type": "dns", "value": HOST_NAME},
        "status": "valid",
    }


@pytest.mark.usefixtures("account")
def test_unknown_auth(client: Client, root: CertificateAuthority, kid: str) -> None:
    """Test fetching unknown auth object."""
    url = root_reverse("acme-authz", slug="abc")
    resp = acme_request(client, url, root, b"", kid=kid)
    assert_unauthorized(resp, root, "You are not authorized to perform this request.")


class TestAcmeAuthorizationView(AcmeWithAccountViewTestCaseMixin[jose.json_util.JSONObjectWithFields]):
    """Test requesting a new authorization."""

    # NOTE: type parameter not required post-as-get requests

    post_as_get = True

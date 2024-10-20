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

# pylint: disable=redefined-outer-name  # because of fixtures

import unittest
from collections.abc import Iterator
from http import HTTPStatus
from typing import Optional
from unittest import mock

import josepy as jose

from django.test import Client

import pytest

from django_ca.models import AcmeAuthorization, AcmeChallenge, AcmeOrder, CertificateAuthority
from django_ca.tasks import acme_validate_challenge
from django_ca.tests.acme.views.assertions import assert_acme_response, assert_unauthorized
from django_ca.tests.acme.views.base import AcmeWithAccountViewTestCaseMixin
from django_ca.tests.acme.views.constants import SERVER_NAME
from django_ca.tests.acme.views.utils import acme_request
from django_ca.tests.base.constants import TIMESTAMPS
from django_ca.tests.base.typehints import CaptureOnCommitCallbacks
from django_ca.tests.base.utils import root_reverse

# ACME views require a currently valid certificate authority
pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])]


@pytest.fixture
def url(challenge: AcmeChallenge) -> Iterator[str]:
    """URL under test."""
    return root_reverse("acme-challenge", slug=challenge.slug)


@pytest.fixture
def message() -> Iterator[bytes]:
    """Yield an empty bytestring, since this is a POST-AS-GET request."""
    return b""


def test_basic(
    client: Client,
    url: str,
    django_capture_on_commit_callbacks: CaptureOnCommitCallbacks,
    root: CertificateAuthority,
    authz: AcmeAuthorization,
    challenge: AcmeChallenge,
    kid: str,
) -> None:
    """Basic test for creating an account via ACME."""
    with (
        mock.patch("django_ca.acme.views.run_task") as mockcm,
        django_capture_on_commit_callbacks(execute=True),
    ):
        resp = acme_request(client, url, root, b"", kid=kid)
    assert resp.status_code == HTTPStatus.OK, resp.content
    assert mockcm.call_args_list == [mock.call(acme_validate_challenge, challenge.pk)]

    assert_acme_response(resp, root, link_relations={"up": f"http://{SERVER_NAME}{authz.acme_url}"})

    assert resp.json() == {
        "status": "processing",
        "type": challenge.type,
        "token": jose.json_util.encode_b64jose(challenge.token.encode()),
        "url": f"http://{SERVER_NAME}{challenge.acme_url}",
    }


def test_no_state_change(
    client: Client,
    url: str,
    django_capture_on_commit_callbacks: CaptureOnCommitCallbacks,
    root: CertificateAuthority,
    authz: AcmeAuthorization,
    challenge: AcmeChallenge,
    kid: str,
) -> None:
    """Test challenge endpoint when no state change is triggered (e.g. already valid)."""
    challenge.status = AcmeChallenge.STATUS_VALID
    challenge.save()
    authz.status = AcmeAuthorization.STATUS_VALID
    authz.save()
    authz.order.status = AcmeOrder.STATUS_VALID
    authz.order.save()

    with django_capture_on_commit_callbacks() as callbacks:
        resp = acme_request(client, url, root, b"", kid=kid)
    assert callbacks == []  # no validation task was triggerd

    # ... but response is still ok
    assert resp.status_code == HTTPStatus.OK, resp.content
    assert_acme_response(resp, root, link_relations={"up": f"http://{SERVER_NAME}{authz.acme_url}"})

    assert resp.json() == {
        "status": "valid",
        "type": challenge.type,
        "token": jose.json_util.encode_b64jose(challenge.token.encode()),
        "url": f"http://{SERVER_NAME}{challenge.acme_url}",
    }


@pytest.mark.usefixtures("challenge")
def test_not_found(
    client: Client,
    django_capture_on_commit_callbacks: CaptureOnCommitCallbacks,
    root: CertificateAuthority,
    kid: str,
) -> None:
    """Basic test for creating an account via ACME."""
    url = root_reverse("acme-challenge", slug="abc")
    with django_capture_on_commit_callbacks() as callbacks:
        resp = acme_request(client, url, root, b"", kid=kid)
    assert callbacks == []  # no validation task was triggerd
    assert_unauthorized(resp, root, "You are not authorized to perform this request.")


class TestAcmeChallengeView(AcmeWithAccountViewTestCaseMixin[jose.json_util.JSONObjectWithFields]):
    """Test retrieving a challenge."""

    # NOTE: type parameter not required post-as-get requests
    post_as_get = True

    def test_duplicate_nonce(
        self,
        client: Client,
        url: str,
        message: bytes,  # type: ignore[override]
        root: CertificateAuthority,
        kid: Optional[str],
    ) -> None:
        # wrapped so that the triggered task is not run, which would do an HTTP request
        with mock.patch("django_ca.acme.views.run_task"):
            super().test_duplicate_nonce(client, url, message, root, kid)

    @unittest.skip("Do nothing, since we ignore the body")
    def test_payload_in_post_as_get(self) -> None:  # type: ignore[override]
        """Do nothing, since we ignore the body."""

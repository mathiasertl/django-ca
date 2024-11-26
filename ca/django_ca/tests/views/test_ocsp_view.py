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

"""Test OCSPView."""

# pylint: disable=redefined-outer-name

import base64
import logging
import shutil
from http import HTTPStatus
from pathlib import Path
from unittest import mock
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.x509 import ocsp

from django.test import Client
from django.urls import include, path, re_path, reverse

import pytest
from _pytest.logging import LogCaptureFixture

from django_ca.constants import ReasonFlags
from django_ca.modelfields import LazyCertificate
from django_ca.models import Certificate, CertificateAuthority
from django_ca.tests.base.constants import CERT_DATA, FIXTURES_DATA, FIXTURES_DIR, TIMESTAMPS
from django_ca.tests.views.assertions import assert_ocsp_response
from django_ca.utils import hex_to_bytes
from django_ca.views import OCSPView

pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["everything_valid"]), pytest.mark.urls(__name__)]


# openssl ocsp -issuer django_ca/tests/fixtures/root.pem -serial <serial> \
#         -reqout django_ca/tests/fixtures/ocsp/unknown-serial -resp_text
#
# WHERE serial is an int: (int('0x<hex>'.replace(':', '').lower(), 0)
def _load_req(req: str) -> bytes:
    with open(FIXTURES_DIR / "ocsp" / req, "rb") as stream:
        return stream.read()


ocsp_profile = CERT_DATA["profile-ocsp"]
ocsp_pem = ocsp_profile["pub"]["pem"]
req1 = _load_req(FIXTURES_DATA["ocsp"]["nonce"]["filename"])
req1_nonce = hex_to_bytes(FIXTURES_DATA["ocsp"]["nonce"]["nonce"])
unknown_req = _load_req("unknown-serial")
multiple_req = _load_req("multiple-serial")

app_name = "django_ca"
urlpatterns = [
    path("django_ca/", include("django_ca.urls")),  # needed for fixtures
    path(
        "ocsp/",
        OCSPView.as_view(
            ca=CERT_DATA["child"]["serial"],
            responder_key=ocsp_profile["key_filename"],
            responder_cert=ocsp_profile["pub_filename"],
            expires=1200,
        ),
        name="post",
    ),
    path(
        "ocsp/serial/",
        OCSPView.as_view(
            ca=CERT_DATA["child"]["serial"],
            responder_key=ocsp_profile["key_filename"],
            responder_cert=CERT_DATA["profile-ocsp"]["serial"],
            expires=1300,
        ),
        name="post-serial",
    ),
    path(
        "ocsp/full-pem/",
        OCSPView.as_view(
            ca=CERT_DATA["child"]["serial"],
            responder_key=ocsp_profile["key_filename"],
            responder_cert=ocsp_pem,
            expires=1400,
        ),
        name="post-full-pem",
    ),
    path(
        "ocsp/loaded-cryptography/",
        OCSPView.as_view(
            ca=CERT_DATA["child"]["serial"],
            responder_key=ocsp_profile["key_filename"],
            responder_cert=CERT_DATA["profile-ocsp"]["pub"]["parsed"],
            expires=1500,
        ),
        name="post-loaded-cryptography",
    ),
    re_path(
        r"^ocsp/cert/(?P<data>[a-zA-Z0-9=+/]+)$",
        OCSPView.as_view(
            ca=CERT_DATA["child"]["serial"],
            responder_key=ocsp_profile["key_filename"],
            responder_cert=ocsp_profile["pub_filename"],
        ),
        name="get",
    ),
    re_path(
        r"^ocsp/ca/(?P<data>[a-zA-Z0-9=+/]+)$",
        OCSPView.as_view(
            ca=CERT_DATA["root"]["serial"],
            responder_key=ocsp_profile["key_filename"],
            responder_cert=ocsp_profile["pub_filename"],
            ca_ocsp=True,
        ),
        name="get-ca",
    ),
    re_path(
        r"^ocsp-unknown/(?P<data>[a-zA-Z0-9=+/]+)$",
        OCSPView.as_view(
            ca="unknown",
            responder_key=ocsp_profile["key_filename"],
            responder_cert=ocsp_profile["pub_filename"],
        ),
        name="unknown",
    ),
    re_path(
        r"^ocsp/false-key/(?P<data>[a-zA-Z0-9=+/]+)$",
        OCSPView.as_view(
            ca=CERT_DATA["child"]["serial"],
            responder_key="foobar",
            responder_cert=ocsp_profile["pub_filename"],
            expires=1200,
        ),
        name="false-key",
    ),
    # set invalid responder_certs
    re_path(
        r"^ocsp/false-pem-serial/(?P<data>[a-zA-Z0-9=+/]+)$",
        OCSPView.as_view(
            ca=CERT_DATA["child"]["serial"],
            responder_key=ocsp_profile["key_filename"],
            responder_cert="AA:BB:CC",
        ),
        name="false-pem-serial",
    ),
    re_path(
        r"^ocsp/false-pem-full/(?P<data>[a-zA-Z0-9=+/]+)$",
        OCSPView.as_view(
            ca=CERT_DATA["child"]["serial"],
            responder_key=ocsp_profile["key_filename"],
            responder_cert="-----BEGIN CERTIFICATE-----\nvery-mean!",
        ),
        name="false-pem-full",
    ),
]


@pytest.fixture
def profile_ocsp(tmpcadir: Path, profile_ocsp: Certificate) -> Certificate:
    """Augmented fixture to copy the certificates into the tmpcadir."""
    shutil.copy(FIXTURES_DIR / "profile-ocsp.key", tmpcadir)
    shutil.copy(FIXTURES_DIR / "profile-ocsp.pub", tmpcadir)
    return profile_ocsp


def test_get(client: Client, child_cert: Certificate, profile_ocsp: Certificate) -> None:
    """Basic GET test."""
    data = base64.b64encode(req1).decode("utf-8")
    response = client.get(reverse("get", kwargs={"data": data}))
    assert response.status_code == HTTPStatus.OK
    assert_ocsp_response(
        response,
        child_cert,
        nonce=req1_nonce,
        expires=600,
        single_response_hash_algorithm=hashes.SHA1,
        responder_certificate=profile_ocsp,
    )


def test_bad_query(client: Client) -> None:
    """Test sending a bad query."""
    response = client.get(reverse("get", kwargs={"data": "XXX"}))
    assert response.status_code == HTTPStatus.OK
    ocsp_response = ocsp.load_der_ocsp_response(response.content)
    assert ocsp_response.response_status == ocsp.OCSPResponseStatus.MALFORMED_REQUEST


def test_raises_exception(caplog: LogCaptureFixture, client: Client) -> None:
    """Generic test if the handling function throws any uncaught exception."""
    exception_str = f"{__name__}.test_raises_exception"
    ex = Exception(exception_str)

    data = base64.b64encode(req1).decode("utf-8")
    view_path = "django_ca.views.OCSPView.process_ocsp_request"
    with mock.patch(view_path, side_effect=ex):
        response = client.get(reverse("get", kwargs={"data": data}))
    assert response.status_code == HTTPStatus.OK
    ocsp_response = ocsp.load_der_ocsp_response(response.content)
    assert ocsp_response.response_status == ocsp.OCSPResponseStatus.INTERNAL_ERROR
    assert caplog.record_tuples == [
        ("django_ca.views", logging.ERROR, "django_ca.tests.views.test_ocsp_view.test_raises_exception")
    ]
    caplog.clear()

    # also do a post request
    with mock.patch(view_path, side_effect=ex):
        response = client.post(reverse("post"), req1, content_type="application/ocsp-request")
    assert response.status_code == HTTPStatus.OK
    ocsp_response = ocsp.load_der_ocsp_response(response.content)
    assert ocsp_response.response_status == ocsp.OCSPResponseStatus.INTERNAL_ERROR
    assert caplog.record_tuples == [
        ("django_ca.views", logging.ERROR, "django_ca.tests.views.test_ocsp_view.test_raises_exception")
    ]


def test_post(client: Client, child_cert: Certificate, profile_ocsp: Certificate) -> None:
    """Test the post request."""
    response = client.post(reverse("post"), req1, content_type="application/ocsp-request")
    assert response.status_code == HTTPStatus.OK
    assert_ocsp_response(
        response,
        child_cert,
        nonce=req1_nonce,
        expires=1200,
        single_response_hash_algorithm=hashes.SHA1,
        responder_certificate=profile_ocsp,
    )

    response = client.post(
        reverse("post-serial"),
        req1,
        content_type="application/ocsp-request",
        single_response_hash_algorithm=hashes.SHA1,
    )
    assert response.status_code == HTTPStatus.OK
    assert_ocsp_response(
        response,
        child_cert,
        nonce=req1_nonce,
        expires=1300,
        single_response_hash_algorithm=hashes.SHA1,
        responder_certificate=profile_ocsp,
    )

    response = client.post(reverse("post-full-pem"), req1, content_type="application/ocsp-request")
    assert response.status_code == HTTPStatus.OK
    assert_ocsp_response(
        response,
        child_cert,
        nonce=req1_nonce,
        expires=1400,
        single_response_hash_algorithm=hashes.SHA1,
        responder_certificate=profile_ocsp,
    )


def test_loaded_cryptography_cert(client: Client, child_cert: Certificate, profile_ocsp: Certificate) -> None:
    """Test view with loaded cryptography cert."""
    response = client.post(reverse("post-loaded-cryptography"), req1, content_type="application/ocsp-request")
    assert response.status_code == HTTPStatus.OK
    assert_ocsp_response(
        response,
        child_cert,
        nonce=req1_nonce,
        expires=1500,
        single_response_hash_algorithm=hashes.SHA1,
        responder_certificate=profile_ocsp,
    )


def test_revoked(client: Client, child_cert: Certificate, profile_ocsp: Certificate) -> None:
    """Test fetching for revoked certificate."""
    child_cert.revoke()

    response = client.post(reverse("post"), req1, content_type="application/ocsp-request")
    assert response.status_code == HTTPStatus.OK
    assert_ocsp_response(
        response,
        child_cert,
        nonce=req1_nonce,
        expires=1200,
        single_response_hash_algorithm=hashes.SHA1,
        responder_certificate=profile_ocsp,
    )

    child_cert.revoke(ReasonFlags.affiliation_changed)
    response = client.post(reverse("post"), req1, content_type="application/ocsp-request")
    assert response.status_code == HTTPStatus.OK
    assert_ocsp_response(
        response,
        requested_certificate=child_cert,
        nonce=req1_nonce,
        expires=1200,
        single_response_hash_algorithm=hashes.SHA1,
        responder_certificate=profile_ocsp,
    )


def test_ca_ocsp(
    client: Client, child: CertificateAuthority, child_cert: Certificate, profile_ocsp: Certificate
) -> None:
    """Make a CA OCSP request."""
    # req1 has serial for self.cert hard-coded, so we update the child CA to contain data for self.cert
    child.serial = child_cert.serial
    child.pub = child_cert.pub
    child.save()

    data = base64.b64encode(req1).decode("utf-8")
    response = client.get(reverse("get-ca", kwargs={"data": data}))
    assert response.status_code == HTTPStatus.OK
    assert_ocsp_response(
        response,
        requested_certificate=child,
        nonce=req1_nonce,
        expires=600,
        single_response_hash_algorithm=hashes.SHA1,
        responder_certificate=profile_ocsp,
    )


@pytest.mark.django_db
def test_bad_ca(caplog: LogCaptureFixture, client: Client) -> None:
    """Fetch data for a CA that does not exist."""
    data = base64.b64encode(req1).decode("utf-8")
    response = client.get(reverse("unknown", kwargs={"data": data}))
    assert caplog.record_tuples == [
        ("django_ca.views", logging.ERROR, "unknown: Certificate Authority could not be found.")
    ]

    assert response.status_code == HTTPStatus.OK
    ocsp_response = ocsp.load_der_ocsp_response(response.content)
    assert ocsp_response.response_status == ocsp.OCSPResponseStatus.INTERNAL_ERROR


@pytest.mark.usefixtures("profile_ocsp")
def test_unknown_certificate(caplog: LogCaptureFixture, client: Client) -> None:
    """Test fetching data for an unknown certificate."""
    data = base64.b64encode(unknown_req).decode("utf-8")
    response = client.get(reverse("get", kwargs={"data": data}))
    assert caplog.record_tuples == [
        ("django_ca.views", logging.WARNING, "7B: OCSP request for unknown cert received.")
    ]

    assert response.status_code == HTTPStatus.OK
    ocsp_response = ocsp.load_der_ocsp_response(response.content)
    assert ocsp_response.response_status == ocsp.OCSPResponseStatus.INTERNAL_ERROR


@pytest.mark.usefixtures("profile_ocsp")
def test_unknown_ca(caplog: LogCaptureFixture, client: Client) -> None:
    """Try requesting an unknown CA in a CA OCSP view."""
    data = base64.b64encode(req1).decode("utf-8")
    response = client.get(reverse("get-ca", kwargs={"data": data}))
    serial = CERT_DATA["child-cert"]["serial"]
    assert caplog.record_tuples == [
        (
            "django_ca.views",
            logging.WARNING,
            f"{serial}: OCSP request for unknown CA received.",
        )
    ]

    assert response.status_code == HTTPStatus.OK
    ocsp_response = ocsp.load_der_ocsp_response(response.content)
    assert ocsp_response.response_status == ocsp.OCSPResponseStatus.INTERNAL_ERROR


@pytest.mark.usefixtures("child_cert")
@pytest.mark.usefixtures("profile_ocsp")
def test_private_key_with_error(caplog: LogCaptureFixture, client: Client) -> None:
    """Test unreadable OCSP private key."""
    data = base64.b64encode(req1).decode("utf-8")

    with patch(
        "cryptography.hazmat.primitives.serialization.load_der_private_key",
        spec_set=True,
        side_effect=ValueError("wrong"),  # usually would be an unsupported key type
    ):
        response = client.get(reverse("get", kwargs={"data": data}))
    ocsp_response = ocsp.load_der_ocsp_response(response.content)
    assert ocsp_response.response_status == ocsp.OCSPResponseStatus.INTERNAL_ERROR
    assert caplog.record_tuples == [
        (
            "django_ca.views",
            logging.ERROR,
            "Could not read responder key/cert: Could not decrypt private key.",
        )
    ]


@pytest.mark.usefixtures("child_cert")
@pytest.mark.usefixtures("profile_ocsp")
def test_unsupported_private_key_type(caplog: LogCaptureFixture, client: Client) -> None:
    """Test that we log an error when the private key is of an unsupported type."""
    data = base64.b64encode(req1).decode("utf-8")

    with patch(
        "cryptography.hazmat.primitives.serialization.load_der_private_key",
        spec_set=True,
        return_value="wrong",  # usually would be an unsupported key type
    ):
        response = client.get(reverse("get", kwargs={"data": data}))
    ocsp_response = ocsp.load_der_ocsp_response(response.content)
    assert ocsp_response.response_status == ocsp.OCSPResponseStatus.INTERNAL_ERROR
    assert caplog.record_tuples == [
        ("django_ca.views", logging.ERROR, "<class 'str'>: Unsupported private key type."),
        (
            "django_ca.views",
            logging.ERROR,
            "Could not read responder key/cert: <class 'str'>: Unsupported private key type.",
        ),
    ]


@pytest.mark.usefixtures("child_cert")
def test_responder_cert_not_found(caplog: LogCaptureFixture, client: Client) -> None:
    """Test the error when the private key cannot be read.

    NOTE: since we don't use ``override_tmpcadir()`` here, the path to the key simply doesn't exist.
    """
    data = base64.b64encode(req1).decode("utf-8")

    response = client.get(reverse("get", kwargs={"data": data}))
    assert response.status_code == HTTPStatus.OK
    ocsp_response = ocsp.load_der_ocsp_response(response.content)
    assert ocsp_response.response_status == ocsp.OCSPResponseStatus.INTERNAL_ERROR
    assert "No such file or directory:" in caplog.text


def test_bad_request(caplog: LogCaptureFixture, client: Client) -> None:
    """Try making a bad request."""
    data = base64.b64encode(b"foobar").decode("utf-8")
    response = client.get(reverse("get", kwargs={"data": data}))
    assert response.status_code == HTTPStatus.OK
    ocsp_response = ocsp.load_der_ocsp_response(response.content)
    assert ocsp_response.response_status == ocsp.OCSPResponseStatus.MALFORMED_REQUEST
    assert "ValueError: error parsing asn1 value" in caplog.text


def test_multiple(caplog: LogCaptureFixture, client: Client) -> None:
    """Try making multiple OCSP requests (not currently supported)."""
    data = base64.b64encode(multiple_req).decode("utf-8")
    response = client.get(reverse("get", kwargs={"data": data}))
    assert response.status_code == HTTPStatus.OK
    ocsp_response = ocsp.load_der_ocsp_response(response.content)
    assert ocsp_response.response_status == ocsp.OCSPResponseStatus.MALFORMED_REQUEST
    assert "OCSP request contains more than one request" in caplog.text


def test_bad_ca_cert(caplog: LogCaptureFixture, client: Client, child_cert: Certificate) -> None:
    """Try naming an invalid CA."""
    # NOTE: set LazyCertificate because this way we can avoid all value checking while saving.
    child_cert.ca.pub = LazyCertificate(b"foobar")
    child_cert.ca.save()

    data = base64.b64encode(req1).decode("utf-8")
    response = client.get(reverse("get", kwargs={"data": data}))
    assert response.status_code == HTTPStatus.OK
    ocsp_response = ocsp.load_der_ocsp_response(response.content)
    assert ocsp_response.response_status == ocsp.OCSPResponseStatus.INTERNAL_ERROR
    assert caplog.record_tuples


@pytest.mark.usefixtures("child_cert")
def test_bad_responder_cert(caplog: LogCaptureFixture, client: Client) -> None:
    """Try configuring a bad responder cert."""
    data = base64.b64encode(req1).decode("utf-8")

    response = client.get(reverse("false-pem-serial", kwargs={"data": data}))
    assert response.status_code == HTTPStatus.OK
    ocsp_response = ocsp.load_der_ocsp_response(response.content)
    assert ocsp_response.response_status == ocsp.OCSPResponseStatus.INTERNAL_ERROR
    assert "Could not read responder key/cert:" in caplog.text
    caplog.clear()

    response = client.get(reverse("false-pem-full", kwargs={"data": data}))
    assert response.status_code == HTTPStatus.OK
    ocsp_response = ocsp.load_der_ocsp_response(response.content)
    assert ocsp_response.response_status == ocsp.OCSPResponseStatus.INTERNAL_ERROR
    assert "Could not read responder key/cert:" in caplog.text

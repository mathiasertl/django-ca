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

"""Test GenericOCSPView."""

# pylint: disable=redefined-outer-name

import base64
import logging
import shutil
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat
from cryptography.x509 import ocsp

from django.core.cache import cache
from django.core.files.storage import storages
from django.test import Client
from django.urls import reverse

import pytest
from _pytest.logging import LogCaptureFixture
from pytest_django import DjangoAssertNumQueries
from pytest_django.fixtures import SettingsWrapper

from django_ca.celery.messages import CacheOCSPResponseTaskArgs
from django_ca.conf import model_settings
from django_ca.key_backends.hsm.models import HSMUsePrivateKeyOptions
from django_ca.key_backends.storages.models import StoragesUsePrivateKeyOptions
from django_ca.models import Certificate, CertificateAuthority
from django_ca.tasks import cache_ocsp_response
from django_ca.tests.base.constants import CA_OCSP_RESPONSE_CACHE_EXPIRES, CERT_DATA, FIXTURES_DIR, TIMESTAMPS
from django_ca.tests.views.assertions import assert_ocsp_response_via_http
from django_ca.tests.views.conftest import ocsp_get

pytestmark = [pytest.mark.usefixtures("clear_cache"), pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])]


@pytest.fixture
def child(tmpcadir: Path, child: CertificateAuthority, profile_ocsp: Certificate) -> CertificateAuthority:
    """Augment the child fixture to add a usable OCSP certificate."""
    ocsp_dir = tmpcadir / "ocsp"
    ocsp_dir.mkdir(exist_ok=True, parents=True)
    dest = ocsp_dir / "child-ocsp.key"
    shutil.copy(FIXTURES_DIR / "profile-ocsp.key", dest)

    child.ocsp_key_backend_options = {
        "private_key": {"path": str(dest)},
        "certificate": {"pem": profile_ocsp.pub.pem},
    }
    child.save()

    return child


@pytest.mark.usefixtures("child_with_ocsp_responder_certificate")
def test_get(
    django_assert_num_queries: DjangoAssertNumQueries, client: Client, child_cert: Certificate
) -> None:
    """Test getting OCSP responses."""
    with django_assert_num_queries(1):
        response = ocsp_get(client, child_cert)
    assert_ocsp_response_via_http(response, child_cert)


@pytest.mark.usefixtures("child_with_ocsp_responder_certificate")
def test_get_with_nonce(client: Client, child_cert: Certificate) -> None:
    """Test OCSP responder via GET request while passing a nonce."""
    response = ocsp_get(client, child_cert, nonce=b"foo")
    assert_ocsp_response_via_http(response, child_cert, nonce=b"foo")


@pytest.mark.usefixtures("root_with_ocsp_responder_certificate")
def test_get_with_ca(
    django_assert_num_queries: DjangoAssertNumQueries, client: Client, child: CertificateAuthority
) -> None:
    """Test getting OCSP responses for CA OCSP URLs."""
    # Copy OCSP key config from child to root. This cert is issued by the child, but this is not tested
    # anyway.
    assert child.parent is not None  # To make mypy happy
    child.parent.ocsp_key_backend_options = child.ocsp_key_backend_options
    child.parent.save()

    with django_assert_num_queries(1):
        response = ocsp_get(client, child)
    assert_ocsp_response_via_http(response, child)


@pytest.mark.usefixtures("hsm_ocsp_backend")
@pytest.mark.hsm
def test_hsm_ocsp_key(client: Client, child_cert: Certificate, usable_hsm_ca: CertificateAuthority) -> None:
    """Test fetching an OCSP response when using the HSM OCSP key backend."""
    usable_hsm_ca.ocsp_key_backend_alias = "hsm"
    usable_hsm_ca.save()

    child_cert.ca = usable_hsm_ca
    child_cert.save()

    key_backend_options = HSMUsePrivateKeyOptions.model_validate(
        {}, context={"backend": usable_hsm_ca.key_backend}
    )
    cert = usable_hsm_ca.generate_ocsp_key(key_backend_options)
    assert isinstance(cert, Certificate)
    assert usable_hsm_ca.ocsp_key_backend_options["certificate"] == {"pem": cert.pub.pem, "pk": cert.pk}

    algorithm = None
    if cert.algorithm is not None:
        algorithm = type(cert.algorithm)

    response = ocsp_get(client, child_cert)
    assert_ocsp_response_via_http(response, child_cert, signature_hash_algorithm=algorithm)


def test_db_ocsp_key(client: Client, root_cert: Certificate, usable_root: CertificateAuthority) -> None:
    """Test fetching an OCSP response when using the database OCSP key backend."""
    usable_root.ocsp_key_backend_alias = "db"
    usable_root.save()

    key_backend_options = StoragesUsePrivateKeyOptions.model_validate(
        {}, context={"backend": usable_root.key_backend, "ca": usable_root}
    )
    usable_root.generate_ocsp_key(key_backend_options)

    response = ocsp_get(client, root_cert)
    assert_ocsp_response_via_http(response, root_cert, signature_hash_algorithm=hashes.SHA256)


def test_response_validity(client: Client, child_cert: Certificate) -> None:
    """Test a custom OCSP response validity."""
    # Reduce OCSP response validity before making request
    child_cert.ca.ocsp_response_validity = 3600
    child_cert.ca.save()

    response = ocsp_get(client, child_cert)

    # URL config sets expires to 3600
    assert_ocsp_response_via_http(response, child_cert, expires=timedelta(seconds=3600))


def test_sha512_hash_algorithm(client: Client, child_cert: Certificate) -> None:
    """Test the OCSP responder with an EC-based certificate authority."""
    response = ocsp_get(client, child_cert, hash_algorithm=hashes.SHA512)

    assert_ocsp_response_via_http(response, child_cert, single_response_hash_algorithm=hashes.SHA512)


def test_pem_responder_key(client: Client, child_cert: Certificate) -> None:
    """Test the OCSP responder with PEM-encoded private key."""
    # Overwrite key with PEM format
    storage = storages[model_settings.CA_DEFAULT_STORAGE_ALIAS]
    private_path = storage.generate_filename(f"{child_cert.ca.serial}.key")
    pem_private_key = CERT_DATA["profile-ocsp"]["key"]["parsed"].private_bytes(
        Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with storage.open(private_path, "wb") as stream:
        stream.write(pem_private_key)

    child_cert.ca.ocsp_key_backend_options["private_key"]["path"] = private_path
    child_cert.ca.ocsp_key_backend_options["private_key"]["password"] = None
    child_cert.ca.save()

    response = ocsp_get(client, child_cert)
    assert_ocsp_response_via_http(response, child_cert)


@pytest.mark.usefixtures("dsa_with_ocsp_responder_certificate")
def test_dsa_certificate_authority(client: Client, dsa_cert: Certificate) -> None:
    """Test the OCSP responder with an DSA-based certificate authority."""
    response = ocsp_get(client, dsa_cert)
    assert_ocsp_response_via_http(response, dsa_cert)


@pytest.mark.usefixtures("ec_with_ocsp_responder_certificate")
def test_ec_certificate_authority(client: Client, ec_cert: Certificate) -> None:
    """Test the OCSP responder with an EC-based certificate authority."""
    response = ocsp_get(client, ec_cert)
    assert_ocsp_response_via_http(response, ec_cert)


@pytest.mark.usefixtures("ed25519_with_ocsp_responder_certificate")
def test_ed25519_certificate_authority(client: Client, ed25519_cert: Certificate) -> None:
    """Test the OCSP responder with an Ed25519-based certificate authority."""
    response = ocsp_get(client, ed25519_cert)
    assert_ocsp_response_via_http(response, ed25519_cert, signature_hash_algorithm=None)


@pytest.mark.usefixtures("ed448_with_ocsp_responder_certificate")
def test_ed448_certificate_authority(client: Client, ed448_cert: Certificate) -> None:
    """Test the OCSP responder with an Ed448-based certificate authority."""
    response = ocsp_get(client, ed448_cert)
    assert_ocsp_response_via_http(response, ed448_cert, signature_hash_algorithm=None)


def test_ca_request_with_root_ca(client: Client, root: CertificateAuthority) -> None:
    """Test fetching a CA OCSP response for a root CA."""
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(root.pub.loaded, root.pub.loaded, hashes.SHA512())
    ocsp_request = builder.build()
    encoded_ocsp_request = base64.b64encode(ocsp_request.public_bytes(Encoding.DER)).decode("utf-8")

    url = reverse("django_ca:ocsp-ca-get", kwargs={"serial": root.serial, "data": encoded_ocsp_request})
    response = client.get(url)

    ocsp_response = ocsp.load_der_ocsp_response(response.content)
    assert ocsp_response.response_status == ocsp.OCSPResponseStatus.INTERNAL_ERROR


def test_invalid_responder_key(caplog: LogCaptureFixture, client: Client, child_cert: Certificate) -> None:
    """Test the OCSP responder error when there is an invalid responder."""
    # Overwrite key with PEM format
    storage = storages[model_settings.CA_DEFAULT_STORAGE_ALIAS]
    with storage.open(child_cert.ca.ocsp_key_backend_options["private_key"]["path"], "wb") as stream:
        stream.write(b"bogus")

    response = ocsp_get(client, child_cert, hash_algorithm=hashes.SHA512)
    assert caplog.record_tuples == [("django_ca.views", logging.ERROR, "Could not decrypt private key.")]
    assert response.status_code == HTTPStatus.OK
    ocsp_response = ocsp.load_der_ocsp_response(response.content)
    assert ocsp_response.response_status == ocsp.OCSPResponseStatus.INTERNAL_ERROR


def test_certificate_never_generated(
    caplog: LogCaptureFixture, client: Client, root_cert: Certificate
) -> None:
    """Test error log when the key was never generated."""
    assert "pem" not in root_cert.ca.ocsp_key_backend_options["certificate"]  # assert initial state

    response = ocsp_get(client, root_cert, hash_algorithm=hashes.SHA512)
    assert caplog.record_tuples == [
        ("django_ca.views", logging.ERROR, "OCSP responder certificate not found, please regenerate it.")
    ]
    assert response.status_code == HTTPStatus.OK
    ocsp_response = ocsp.load_der_ocsp_response(response.content)
    assert ocsp_response.response_status == ocsp.OCSPResponseStatus.INTERNAL_ERROR


@pytest.mark.freeze_time(TIMESTAMPS["profile_certs_expired"])
def test_certificate_expired(caplog: LogCaptureFixture, client: Client, child_cert: Certificate) -> None:
    """Test error log when the key has expired."""
    response = ocsp_get(client, child_cert, hash_algorithm=hashes.SHA512)
    assert caplog.record_tuples == [
        (
            "django_ca.views",
            logging.ERROR,
            "OCSP responder certificate is not currently valid. Please regenerate it.",
        )
    ]
    assert response.status_code == HTTPStatus.OK
    ocsp_response = ocsp.load_der_ocsp_response(response.content)
    assert ocsp_response.response_status == ocsp.OCSPResponseStatus.INTERNAL_ERROR


def test_method_not_allowed(client: Client) -> None:
    """Try HTTP methods that are not allowed."""
    url = reverse("django_ca:ocsp-cert-post", kwargs={"serial": "00AA"})
    response = client.get(url)
    assert response.status_code == HTTPStatus.METHOD_NOT_ALLOWED  # 405

    url = reverse("django_ca:ocsp-cert-get", kwargs={"serial": "00AA", "data": "irrelevant"})
    response = client.post(url, b"dont-care", content_type="application/ocsp-request")
    assert response.status_code == HTTPStatus.METHOD_NOT_ALLOWED  # 405


# ---------------------------------------------------------------------------
# OCSP response caching tests
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("ocsp_response_caching")
def test_cached_response_served_from_django_cache(
    settings: SettingsWrapper,
    django_assert_num_queries: DjangoAssertNumQueries,
    client: Client,
    child_cert: Certificate,
) -> None:
    """When a cached response exists in Django cache, it is returned directly."""
    cache_ocsp_response(CacheOCSPResponseTaskArgs(serial=child_cert.serial, ca=False))

    with django_assert_num_queries(0):
        response = ocsp_get(client, child_cert)

    assert response.status_code == HTTPStatus.OK
    assert_ocsp_response_via_http(response, child_cert, nonce=None, expires=CA_OCSP_RESPONSE_CACHE_EXPIRES)


@pytest.mark.usefixtures("ocsp_response_caching")
def test_cached_response_with_non_critical_nonce(
    settings: SettingsWrapper,
    django_assert_num_queries: DjangoAssertNumQueries,
    client: Client,
    child_cert: Certificate,
) -> None:
    """Test that non-critical extensions are ignored."""
    cache_ocsp_response(CacheOCSPResponseTaskArgs(serial=child_cert.serial, ca=False))

    with django_assert_num_queries(0):
        response = ocsp_get(client, child_cert, nonce=b"nonce", nonce_critical=False)

    assert response.status_code == HTTPStatus.OK
    assert_ocsp_response_via_http(response, child_cert, nonce=None, expires=CA_OCSP_RESPONSE_CACHE_EXPIRES)


@pytest.mark.usefixtures("ocsp_response_caching")
def test_cached_response_served_from_db(
    django_assert_num_queries: DjangoAssertNumQueries, client: Client, child_cert: Certificate
) -> None:
    """When no Django-cache entry exists, a valid DB-stored response is used."""
    # Obtain a real OCSP response without caching.
    cache_ocsp_response(CacheOCSPResponseTaskArgs(serial=child_cert.serial, ca=False))
    cache.clear()  # clear cache again

    with django_assert_num_queries(1):
        response = ocsp_get(client, child_cert)

    assert response.status_code == HTTPStatus.OK
    assert_ocsp_response_via_http(response, child_cert, nonce=None, expires=CA_OCSP_RESPONSE_CACHE_EXPIRES)


@pytest.mark.usefixtures("usable_root", "ocsp_response_caching")
def test_cached_response_served_from_db_with_certificate_authority(
    django_assert_num_queries: DjangoAssertNumQueries, client: Client, child: CertificateAuthority
) -> None:
    """When no Django-cache entry exists, a valid DB-stored response is used."""
    # Obtain a real OCSP response without caching.
    child.parent.generate_ocsp_key(StoragesUsePrivateKeyOptions(password=None))
    cache_ocsp_response(CacheOCSPResponseTaskArgs(serial=child.serial, ca=True))
    cache.clear()  # clear cache again

    with django_assert_num_queries(1):
        response = ocsp_get(client, child)

    assert response.status_code == HTTPStatus.OK
    assert_ocsp_response_via_http(response, child, nonce=None, expires=CA_OCSP_RESPONSE_CACHE_EXPIRES)


@pytest.mark.usefixtures("ocsp_response_caching")
def test_no_cached_response_returns_error(
    caplog: LogCaptureFixture, client: Client, child_cert: Certificate
) -> None:
    """When caching is enabled but no response is available, INTERNAL_ERROR is returned."""
    # Build a request manually so we can inspect the raw HTTP response (ocsp_get asserts HTTP 200).
    with caplog.at_level(logging.WARNING, logger="django_ca.views"):
        response = ocsp_get(client, child_cert)

    assert response.status_code == HTTPStatus.OK
    ocsp_response = ocsp.load_der_ocsp_response(response.content)
    assert ocsp_response.response_status == ocsp.OCSPResponseStatus.INTERNAL_ERROR
    assert "No cached OCSP response available" in caplog.text


@pytest.mark.usefixtures("ocsp_response_caching")
def test_expired_db_response_returns_error(client: Client, child_cert: Certificate) -> None:
    """An expired DB-stored response is not served; INTERNAL_ERROR is returned instead."""
    now = datetime.now(tz=UTC)
    child_cert.ocsp_response = b"stale-data"
    child_cert.ocsp_response_expires = now - timedelta(seconds=1)  # already expired
    child_cert.save()

    response = ocsp_get(client, child_cert)

    ocsp_response = ocsp.load_der_ocsp_response(response.content)
    assert ocsp_response.response_status == ocsp.OCSPResponseStatus.INTERNAL_ERROR


@pytest.mark.usefixtures("ocsp_response_caching")
def test_cache_requests_with_invalid_request(
    caplog: LogCaptureFixture, client: Client, child: CertificateAuthority
) -> None:
    """Test fetching a cached response for a request that cannot be parsed."""
    url = reverse("django_ca:ocsp-ca-get", kwargs={"serial": child.serial, "data": "deadbeef"})

    with caplog.at_level(logging.DEBUG, logger="django_ca.views"):
        response = client.get(url)

    ocsp_response = ocsp.load_der_ocsp_response(response.content)
    assert ocsp_response.response_status == ocsp.OCSPResponseStatus.MALFORMED_REQUEST
    assert "Cannot parse OCSP request:" in caplog.text


@pytest.mark.usefixtures("ocsp_response_caching")
def test_cache_requests_with_critical_extensions(
    caplog: LogCaptureFixture, client: Client, child_cert: Certificate
) -> None:
    """Test fetching a cached response for a request with a critical extension."""
    with caplog.at_level(logging.DEBUG, logger="django_ca.views"):
        response = ocsp_get(client, child_cert, nonce=b"nonce", nonce_critical=True)

    ocsp_response = ocsp.load_der_ocsp_response(response.content)
    assert ocsp_response.response_status == ocsp.OCSPResponseStatus.MALFORMED_REQUEST
    assert "Critical extension received" in caplog.text


@pytest.mark.usefixtures("ocsp_response_caching")
def test_cache_requests_with_unknown_ca(
    caplog: LogCaptureFixture, client: Client, child_cert: Certificate
) -> None:
    """Test fetching a cached response for a request with a critical extension."""
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(child_cert.pub.loaded, child_cert.ca.pub.loaded, hashes.SHA512())
    ocsp_request = builder.build()
    encoded_ocsp_request = base64.b64encode(ocsp_request.public_bytes(Encoding.DER)).decode("utf-8")

    url = reverse("django_ca:ocsp-ca-get", kwargs={"serial": "0", "data": encoded_ocsp_request})

    with caplog.at_level(logging.INFO, logger="django_ca.views"):
        response = client.get(url)

    ocsp_response = ocsp.load_der_ocsp_response(response.content)
    assert ocsp_response.response_status == ocsp.OCSPResponseStatus.MALFORMED_REQUEST
    assert "OCSP request for unknown CA received" in caplog.text


@pytest.mark.usefixtures("ocsp_response_caching")
def test_cache_requests_with_unknown_cert(
    caplog: LogCaptureFixture, client: Client, child_cert: Certificate
) -> None:
    """Test fetching a cached response for a request with a critical extension."""
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(child_cert.pub.loaded, child_cert.ca.pub.loaded, hashes.SHA512())
    ocsp_request = builder.build()
    encoded_ocsp_request = base64.b64encode(ocsp_request.public_bytes(Encoding.DER)).decode("utf-8")

    url = reverse("django_ca:ocsp-cert-get", kwargs={"serial": "0", "data": encoded_ocsp_request})

    with caplog.at_level(logging.INFO, logger="django_ca.views"):
        response = client.get(url)

    ocsp_response = ocsp.load_der_ocsp_response(response.content)
    assert ocsp_response.response_status == ocsp.OCSPResponseStatus.MALFORMED_REQUEST
    assert "OCSP request for unknown certificate received" in caplog.text

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

"""Tests for the ``cache_ocsp_response`` Celery task."""

import logging

import pytest
from _pytest.logging import LogCaptureFixture

from django_ca.celery.messages import CacheOCSPResponseTaskArgs
from django_ca.constants import ReasonFlags
from django_ca.models import Certificate, CertificateAuthority
from django_ca.tasks import cache_ocsp_response
from django_ca.tests.base.assertions import assert_ocsp_response_for_model
from django_ca.tests.base.constants import CA_OCSP_RESPONSE_CACHE_EXPIRES, TIMESTAMPS

pytestmark = [
    pytest.mark.django_db,
    pytest.mark.usefixtures("clear_cache"),
    pytest.mark.freeze_time(TIMESTAMPS["everything_valid"]),
]


def test_caching_disabled(child_cert: Certificate) -> None:
    """Task is a no-op when CA_OCSP_RESPONSE_CACHE_EXPIRES is None (the default)."""
    cache_ocsp_response(CacheOCSPResponseTaskArgs(serial=child_cert.serial, ca=False))

    child_cert.refresh_from_db()
    assert child_cert.ocsp_response is None
    assert child_cert.ocsp_response_expires is None


@pytest.mark.usefixtures("ocsp_response_caching", "child_with_ocsp_responder_certificate")
def test_cache_good_cert(child_cert: Certificate) -> None:
    """Task caches a GOOD response for a valid, non-revoked certificate."""
    cache_ocsp_response(CacheOCSPResponseTaskArgs(serial=child_cert.serial, ca=False))
    child_cert.refresh_from_db()
    assert_ocsp_response_for_model(child_cert, expires=CA_OCSP_RESPONSE_CACHE_EXPIRES)


@pytest.mark.usefixtures("ocsp_response_caching", "child_with_ocsp_responder_certificate")
def test_cache_revoked_cert(child_cert: Certificate) -> None:
    """Task caches a REVOKED response for a revoked certificate."""
    child_cert.revoke(reason=ReasonFlags.key_compromise)
    cache_ocsp_response(CacheOCSPResponseTaskArgs(serial=child_cert.serial, ca=False))

    child_cert.refresh_from_db()
    assert_ocsp_response_for_model(child_cert, expires=CA_OCSP_RESPONSE_CACHE_EXPIRES)


@pytest.mark.usefixtures("ocsp_response_caching")
def test_unknown_certificate(caplog: LogCaptureFixture) -> None:
    """Task logs an error and returns if the certificate serial is not found."""
    with caplog.at_level(logging.ERROR, logger="django_ca.tasks"):
        cache_ocsp_response(CacheOCSPResponseTaskArgs(serial="DEADBEEF", ca=False))

    assert "DEADBEEF: Certificate not found." in caplog.text


@pytest.mark.usefixtures("ocsp_response_caching")
def test_missing_responder_cert(root_cert: Certificate, usable_root: CertificateAuthority) -> None:
    """Task logs an error when the CA has no OCSP responder certificate configured."""
    # root's CA has no OCSP key configured by default.
    root_cert.ca.refresh_from_db()
    assert "pem" not in root_cert.ca.ocsp_key_backend_options["certificate"]

    message = rf"^{root_cert.ca.name}: {root_cert.ca.serial}: OCSP responder certificate not found\.$"
    with pytest.raises(ValueError, match=message):
        cache_ocsp_response(CacheOCSPResponseTaskArgs(serial=root_cert.serial, ca=False))

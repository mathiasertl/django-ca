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

"""Tests for the ``generate_ocsp_responses`` Celery task."""

import logging
from datetime import UTC, datetime, timedelta
from unittest import mock

import pytest
from _pytest.logging import LogCaptureFixture

from django_ca.models import Certificate, CertificateAuthority
from django_ca.tasks import generate_ocsp_responses
from django_ca.tests.base.assertions import assert_ocsp_response_for_model
from django_ca.tests.base.constants import CA_OCSP_RESPONSE_CACHE_EXPIRES, TIMESTAMPS

pytestmark = [
    pytest.mark.usefixtures("clear_cache"),
    pytest.mark.django_db,
    pytest.mark.freeze_time(TIMESTAMPS["everything_valid"]),
]


def test_caching_disabled() -> None:
    """Task is a no-op when CA_OCSP_RESPONSE_CACHE_EXPIRES is None (the default)."""
    with mock.patch("django_ca.tasks.run_task") as mock_run:
        generate_ocsp_responses()
    mock_run.assert_not_called()


@pytest.mark.usefixtures("ocsp_response_caching")
def test_caches_uncached_certs(
    root_with_ocsp_responder_certificate: CertificateAuthority,
    child_with_ocsp_responder_certificate: CertificateAuthority,
    root_cert: Certificate,
    child_cert: Certificate,
) -> None:
    """Task schedules caching for certificates with no cached response yet."""
    assert child_cert.ocsp_response is None
    generate_ocsp_responses()

    # The root CA does not get an OCSP response as it would have to be signed by the CA itself.
    root_with_ocsp_responder_certificate.refresh_from_db()
    assert root_with_ocsp_responder_certificate.ocsp_response is None

    for cert in child_with_ocsp_responder_certificate, root_cert, child_cert:
        cert.refresh_from_db()
        assert_ocsp_response_for_model(cert, expires=CA_OCSP_RESPONSE_CACHE_EXPIRES)


@pytest.mark.usefixtures("ocsp_response_caching")
def test_skips_fresh_certs(
    child_with_ocsp_responder_certificate: CertificateAuthority,
    root_cert: Certificate,
    child_cert: Certificate,
) -> None:
    """Certificates whose cached response is still far from expiry are not renewed."""
    now = datetime.now(tz=UTC)
    for cert in child_with_ocsp_responder_certificate, root_cert, child_cert:
        cert.ocsp_response = b"dummy"
        cert.ocsp_response_expires = now + CA_OCSP_RESPONSE_CACHE_EXPIRES * 2
        cert.save()

    with mock.patch("django_ca.tasks.run_task") as mock_run:
        generate_ocsp_responses()
    mock_run.assert_not_called()

    for cert in child_with_ocsp_responder_certificate, root_cert, child_cert:
        cert.refresh_from_db()
        assert cert.ocsp_response == b"dummy"
        assert cert.ocsp_response_expires == now + CA_OCSP_RESPONSE_CACHE_EXPIRES * 2


@pytest.mark.usefixtures("ocsp_response_caching")
def test_renews_expiring_certs(child_cert: Certificate) -> None:
    """Certificates whose cached response is within the renewal window are renewed."""
    now = datetime.now(tz=UTC)
    child_cert.ocsp_response = b"dummy"
    child_cert.ocsp_response_expires = now + timedelta(minutes=10)  # within renewal threshold
    child_cert.save()

    with mock.patch("django_ca.tasks.run_task") as mock_run:
        generate_ocsp_responses()

    scheduled_serials = [call.args[1].serial for call in mock_run.call_args_list]
    assert child_cert.serial in scheduled_serials


@pytest.mark.usefixtures("ocsp_response_caching", "child_cert")
def test_error_handling(caplog: LogCaptureFixture) -> None:
    """Exceptions when scheduling per-cert tasks are caught and logged."""
    with (
        mock.patch("django_ca.tasks.run_task", side_effect=Exception("boom")),
        caplog.at_level(logging.ERROR, logger="django_ca.tasks"),
    ):
        generate_ocsp_responses()

    assert "Error scheduling OCSP response caching for" in caplog.text

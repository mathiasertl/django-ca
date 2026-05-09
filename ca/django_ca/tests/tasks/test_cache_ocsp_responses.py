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

"""Tests for the ``cache_ocsp_responses`` Celery task."""

import logging
from datetime import UTC, datetime, timedelta
from unittest import mock

from django.core.cache import cache
from django.test import override_settings

import pytest
from _pytest.logging import LogCaptureFixture

from django_ca.models import Certificate
from django_ca.tasks import cache_ocsp_responses
from django_ca.tests.base.constants import TIMESTAMPS

pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])]

_CACHE_EXPIRES = timedelta(hours=1)
_RENEWAL = timedelta(minutes=30)


@pytest.fixture(autouse=True)
def _clear_cache() -> None:
    """Clear the Django cache after every test."""
    yield  # type: ignore[misc]
    cache.clear()


def test_caching_disabled(child_cert: Certificate) -> None:
    """Task is a no-op when CA_OCSP_RESPONSE_CACHE_EXPIRES is None (the default)."""
    with mock.patch("django_ca.tasks.run_task") as mock_run:
        cache_ocsp_responses()
    mock_run.assert_not_called()


@pytest.mark.usefixtures("make_ocsp_key")
@override_settings(CA_OCSP_RESPONSE_CACHE_EXPIRES=_CACHE_EXPIRES, CA_OCSP_RESPONSE_CACHE_RENEWAL=_RENEWAL)
def test_caches_uncached_certs(child_cert: Certificate) -> None:
    """Task schedules caching for certificates with no cached response yet."""
    assert child_cert.ocsp_response is None

    with mock.patch("django_ca.tasks.run_task") as mock_run:
        cache_ocsp_responses()

    # At least child_cert should be scheduled.
    assert mock_run.called
    scheduled_serials = [call.args[1].serial for call in mock_run.call_args_list]
    assert child_cert.serial in scheduled_serials


@pytest.mark.usefixtures("make_ocsp_key")
@override_settings(CA_OCSP_RESPONSE_CACHE_EXPIRES=_CACHE_EXPIRES, CA_OCSP_RESPONSE_CACHE_RENEWAL=_RENEWAL)
def test_skips_fresh_certs(child_cert: Certificate) -> None:
    """Certificates whose cached response is still far from expiry are not renewed."""
    now = datetime.now(tz=UTC)
    child_cert.ocsp_response = b"dummy"  # type: ignore[assignment]
    child_cert.ocsp_response_expires = now + timedelta(hours=2)  # well past renewal threshold
    child_cert.save()

    with mock.patch("django_ca.tasks.run_task") as mock_run:
        cache_ocsp_responses()

    scheduled_serials = [call.args[1].serial for call in mock_run.call_args_list]
    assert child_cert.serial not in scheduled_serials


@pytest.mark.usefixtures("make_ocsp_key")
@override_settings(CA_OCSP_RESPONSE_CACHE_EXPIRES=_CACHE_EXPIRES, CA_OCSP_RESPONSE_CACHE_RENEWAL=_RENEWAL)
def test_renews_expiring_certs(child_cert: Certificate) -> None:
    """Certificates whose cached response is within the renewal window are renewed."""
    now = datetime.now(tz=UTC)
    child_cert.ocsp_response = b"dummy"  # type: ignore[assignment]
    child_cert.ocsp_response_expires = now + timedelta(minutes=10)  # within renewal threshold
    child_cert.save()

    with mock.patch("django_ca.tasks.run_task") as mock_run:
        cache_ocsp_responses()

    scheduled_serials = [call.args[1].serial for call in mock_run.call_args_list]
    assert child_cert.serial in scheduled_serials


@pytest.mark.usefixtures("make_ocsp_key")
@override_settings(CA_OCSP_RESPONSE_CACHE_EXPIRES=_CACHE_EXPIRES, CA_OCSP_RESPONSE_CACHE_RENEWAL=_RENEWAL)
def test_error_handling(caplog: LogCaptureFixture, child_cert: Certificate) -> None:
    """Exceptions when scheduling per-cert tasks are caught and logged."""
    with (
        mock.patch("django_ca.tasks.run_task", side_effect=Exception("boom")),
        caplog.at_level(logging.ERROR, logger="django_ca.tasks"),
    ):
        cache_ocsp_responses()

    assert "Error scheduling OCSP response caching for" in caplog.text

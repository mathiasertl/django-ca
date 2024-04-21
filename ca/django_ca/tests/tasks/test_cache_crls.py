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

"""Test the cache_crls task."""

import base64
import logging
from unittest import mock

from cryptography.hazmat.primitives.serialization import Encoding

from django.core.cache import cache

import pytest
from _pytest.logging import LogCaptureFixture

from django_ca.models import CertificateAuthority
from django_ca.tasks import cache_crls
from django_ca.tests.base.constants import CERT_DATA, TIMESTAMPS
from django_ca.tests.tasks.conftest import assert_crls
from django_ca.utils import get_crl_cache_key

pytestmark = [pytest.mark.usefixtures("clear_cache"), pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])]


def test_all_crls(usable_cas: list[CertificateAuthority]) -> None:
    """Test caching when all CAs are valid."""
    cache_crls()

    for ca in usable_cas:
        assert_crls(ca)


@pytest.mark.freeze_time(TIMESTAMPS["everything_expired"])
def test_with_expired_certificate_authorities(usable_cas: list[CertificateAuthority]) -> None:
    """Test that nothing is cashed if all CAs are expired."""
    cache_crls()

    for ca in usable_cas:
        key = get_crl_cache_key(ca.serial, Encoding.DER, "ca")
        assert cache.get(key) is None


def test_with_key_options(usable_pwd: CertificateAuthority) -> None:
    """Test passing the password explicitly."""
    cache_crls([usable_pwd.serial], {usable_pwd.serial: {"password": CERT_DATA["pwd"]["password"]}})
    assert_crls(usable_pwd)


def test_with_invalid_password(usable_pwd: CertificateAuthority) -> None:
    """Test passing an invalid password."""
    password = base64.b64encode(b"wrong").decode()
    cache_crls([usable_pwd.serial], {usable_pwd.serial: {"password": password}})
    key = get_crl_cache_key(usable_pwd.serial, Encoding.DER, "ca")
    assert cache.get(key) is None


@pytest.mark.usefixtures("root")
def test_with_exception_child_task(caplog: LogCaptureFixture) -> None:
    """Test exceptions for the task are logged."""
    with (
        mock.patch("django_ca.tasks.run_task", side_effect=Exception("error")),
        caplog.at_level(logging.INFO),
    ):
        cache_crls()
    assert "Error caching CRL" in caplog.text

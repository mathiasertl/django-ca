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

# pylint: disable=redefined-outer-name  # because of fixtures
# pylint: disable=invalid-name  # for model loading

"""Test 0048 database migration."""

import json
from typing import Callable, Optional
from unittest import mock

from django_test_migrations.migrator import Migrator

from cryptography import x509

from django.core.cache import cache
from django.db.migrations.state import ProjectState
from django.utils import timezone
from django.utils.timezone import make_naive

import pytest
from pytest_django.fixtures import SettingsWrapper

from django_ca.tests.base import constants
from django_ca.tests.base.constants import CERT_DATA

# Fixture tries to query the cache, so always clear the cache
pytestmark = [pytest.mark.usefixtures("clear_cache")]


def setup(
    migrator: Migrator, scope: str, setup: Optional[Callable[[ProjectState], None]] = None
) -> ProjectState:
    """Set up a CA with a CRL Number for the given scope."""
    old_state = migrator.apply_initial_migration(("django_ca", "0047_certificaterevocationlist"))
    now = timezone.now()

    cert: x509.Certificate = CERT_DATA["root"]["pub"]["parsed"]
    CertificateAuthority = old_state.apps.get_model("django_ca", "CertificateAuthority")
    CertificateAuthority.objects.create(
        pub=cert,
        cn="",
        serial="123",
        not_before=now,  # doesn't matter here, just need something with right tz.
        not_after=now,  # doesn't matter here, just need something with right tz.
        crl_number=json.dumps({"scope": {scope: 3}}),
    )

    if setup is not None:
        setup(old_state)

    return migrator.apply_tested_migration(("django_ca", "0048_auto_20241017_2104"))


@pytest.mark.parametrize(
    "scope,ca,user,attribute",
    (
        ("all", False, False, False),
        ("ca", True, False, False),
        ("user", False, True, False),
        ("attribute", False, False, True),
    ),
)
def test_with_empty_cache(migrator: Migrator, scope: str, ca: bool, user: bool, attribute: bool) -> None:
    """Test running the migration with an empty cache."""
    state = setup(migrator, scope)
    CertificateRevocationList = state.apps.get_model("django_ca", "CertificateRevocationList")
    crl = CertificateRevocationList.objects.get(ca__serial="123")
    assert crl.data is None
    assert crl.number == 3
    assert crl.only_contains_ca_certs == ca
    assert crl.only_contains_user_certs == user
    assert crl.only_contains_attribute_certs == attribute
    assert crl.only_some_reasons is None


def test_with_cache(migrator: Migrator) -> None:
    """Test running fixture with a populated cache."""
    with open(constants.FIXTURES_DIR / "root.ca.crl", "rb") as stream:
        crl_data = stream.read()
    x509_crl = x509.load_der_x509_crl(crl_data)

    # Use cache key as it was used before 2.1.0
    state = setup(migrator, "ca", lambda apps: cache.set("crl_123_DER_ca", crl_data))

    CertificateRevocationList = state.apps.get_model("django_ca", "CertificateRevocationList")
    crl = CertificateRevocationList.objects.get(ca__serial="123")
    assert crl.data == crl_data  # data was retrieved from the cache
    assert crl.number == 3
    assert crl.only_contains_ca_certs is True
    assert crl.only_contains_user_certs is False
    assert crl.only_contains_attribute_certs is False
    assert crl.only_some_reasons is None
    assert crl.last_update == x509_crl.last_update_utc
    assert crl.next_update == x509_crl.next_update_utc


def test_with_cache_with_use_tz_is_false(migrator: Migrator, settings: SettingsWrapper) -> None:
    """Test running fixture with a populated cache, with USE_TZ=False."""
    settings.USE_TZ = False
    with open(constants.FIXTURES_DIR / "root.ca.crl", "rb") as stream:
        crl_data = stream.read()
    x509_crl = x509.load_der_x509_crl(crl_data)

    # Use cache key as it was used before 2.1.0
    state = setup(migrator, "ca", lambda apps: cache.set("crl_123_DER_ca", crl_data))

    CertificateRevocationList = state.apps.get_model("django_ca", "CertificateRevocationList")
    crl = CertificateRevocationList.objects.get(ca__serial="123")
    assert crl.data == crl_data  # data was retrieved from the cache
    assert crl.number == 3
    assert crl.only_contains_ca_certs is True
    assert crl.only_contains_user_certs is False
    assert crl.only_contains_attribute_certs is False
    assert crl.only_some_reasons is None
    assert crl.last_update == make_naive(x509_crl.last_update_utc)
    assert crl.next_update == make_naive(x509_crl.next_update_utc)


def test_with_cache_with_exception(migrator: Migrator) -> None:
    """Test migration when fetching from the cache throws an exception."""
    with mock.patch.object(cache, "get", autospec=True, side_effect=Exception()):
        state = setup(migrator, "ca")
    CertificateRevocationList = state.apps.get_model("django_ca", "CertificateRevocationList")
    crl = CertificateRevocationList.objects.get(ca__serial="123")
    assert crl.data is None
    assert crl.number == 3
    assert crl.only_contains_ca_certs is True
    assert crl.only_contains_user_certs is False
    assert crl.only_contains_attribute_certs is False
    assert crl.only_some_reasons is None


def test_with_cache_with_corrupted_data(migrator: Migrator) -> None:
    """Test migration when fetching from the cache returns corrupted data."""
    with mock.patch.object(cache, "get", autospec=True, return_value=b"123"):
        state = setup(migrator, "ca")
    CertificateRevocationList = state.apps.get_model("django_ca", "CertificateRevocationList")
    crl = CertificateRevocationList.objects.get(ca__serial="123")
    assert crl.data is None
    assert crl.number == 3
    assert crl.only_contains_ca_certs is True
    assert crl.only_contains_user_certs is False
    assert crl.only_contains_attribute_certs is False
    assert crl.only_some_reasons is None

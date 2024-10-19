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
#
# pylint: disable=redefined-outer-name  # because of fixtures
# pylint: disable=invalid-name  # for model loading

"""Test 0043 database migration."""

from typing import Callable, Optional

from django_test_migrations.migrator import Migrator

from cryptography import x509

from django.db.migrations.state import ProjectState
from django.utils import timezone

import pytest

from django_ca.tests.base.constants import CERT_DATA


def setup(migrator: Migrator, setup: Optional[Callable[[ProjectState], None]] = None) -> ProjectState:
    """Set up a CA with a CRL Number for the given scope."""
    old_state = migrator.apply_initial_migration(
        ("django_ca", "0042_certificateauthority_key_backend_options_and_more")
    )
    now = timezone.now()

    cert: x509.Certificate = CERT_DATA["root"]["pub"]["parsed"]
    CertificateAuthority = old_state.apps.get_model("django_ca", "CertificateAuthority")
    CertificateAuthority.objects.create(
        name="foo",
        pub=cert,
        cn="",
        serial="123",
        valid_from=now,  # doesn't matter here, just need something with right tz.
        expires=now,  # doesn't matter here, just need something with right tz.
        private_key_path="/foo/bar/ca.key",
    )

    if setup is not None:
        setup(old_state)

    return migrator.apply_tested_migration(("django_ca", "0043_auto_20240221_2153"))


def test_forward(migrator: Migrator) -> None:
    """Test standard migration and backwards migration."""
    state = setup(migrator)
    CertificateAuthority = state.apps.get_model("django_ca", "CertificateAuthority")
    ca = CertificateAuthority.objects.get(serial="123")
    assert ca.key_backend_alias == "default"
    assert ca.key_backend_options == {"path": "/foo/bar/ca.key"}


def test_backward(migrator: Migrator) -> None:
    """Apply migration backwards."""
    old_state = migrator.apply_initial_migration(("django_ca", "0043_auto_20240221_2153"))

    now = timezone.now()
    cert: x509.Certificate = CERT_DATA["root"]["pub"]["parsed"]
    CertificateAuthority = old_state.apps.get_model("django_ca", "CertificateAuthority")
    CertificateAuthority.objects.create(
        name="foo",
        pub=cert,
        cn="",
        serial="123",
        valid_from=now,  # doesn't matter here, just need something with right tz.
        expires=now,  # doesn't matter here, just need something with right tz.
        key_backend_alias="default",
        key_backend_options={"path": "/foo/bar/ca.key"},
    )

    state = migrator.apply_tested_migration(
        ("django_ca", "0042_certificateauthority_key_backend_options_and_more")
    )

    CertificateAuthority = state.apps.get_model("django_ca", "CertificateAuthority")
    ca = CertificateAuthority.objects.get(serial="123")
    assert ca.private_key_path == "/foo/bar/ca.key"

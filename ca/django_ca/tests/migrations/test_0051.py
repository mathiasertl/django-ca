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

"""Test 0051 database migration."""

import logging
import shutil
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable, Optional

from django_test_migrations.migrator import Migrator

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from django.db.migrations.state import ProjectState
from django.utils import timezone

import pytest
from _pytest.logging import LogCaptureFixture
from pytest_django.fixtures import SettingsWrapper

from django_ca.tests.base.constants import CERT_DATA, FIXTURES_DIR


@pytest.fixture(scope="session")
def ocsp_pem() -> str:
    """Fixture for a PEM certificate."""
    with open(FIXTURES_DIR / "profile-ocsp.pub", "rb") as stream:
        public_key_data = stream.read()
    public_key = x509.load_der_x509_certificate(public_key_data)
    public_key_data = public_key.public_bytes(Encoding.PEM)
    return public_key_data.decode()


def setup(migrator: Migrator, setup: Optional[Callable[[ProjectState], None]] = None) -> ProjectState:
    """Set up a CA with a CRL Number for the given scope."""
    old_state = migrator.apply_initial_migration(("django_ca", "0049_remove_certificateauthority_crl_number"))
    now = timezone.now()

    cert: x509.Certificate = CERT_DATA["root"]["pub"]["parsed"]
    CertificateAuthority = old_state.apps.get_model("django_ca", "CertificateAuthority")
    ca = CertificateAuthority.objects.create(
        pub=cert,
        cn="",
        serial="123",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=1),
    )

    if setup is not None:
        setup(ca)

    return migrator.apply_tested_migration(("django_ca", "0051_auto_20241201_2038"))


@pytest.mark.usefixtures("tmpcadir")
def test_normal_migration(
    caplog: LogCaptureFixture, migrator: Migrator, tmpcadir: Path, ocsp_pem: str
) -> None:
    """Test running the migration with an empty cache."""
    ocsp_dest = tmpcadir / "ocsp"
    ocsp_dest.mkdir(exist_ok=True, parents=True)

    def setup_ocsp_keys(ca: Any) -> None:
        shutil.copy(FIXTURES_DIR / "profile-ocsp.key", ocsp_dest / f"{ca.serial}.key")
        shutil.copy(FIXTURES_DIR / "profile-ocsp.pub", ocsp_dest / f"{ca.serial}.pem")

    state = setup(migrator, setup=setup_ocsp_keys)

    CertificateAuthority = state.apps.get_model("django_ca", "CertificateAuthority")
    ca = CertificateAuthority.objects.get(serial="123")

    assert ca.ocsp_key_backend_options == {
        "certificate": {"pem": ocsp_pem},
        "private_key": {"path": "ocsp/123.key"},
    }
    assert caplog.record_tuples == []


@pytest.mark.usefixtures("tmpcadir")
def test_with_pem_public_key(
    caplog: LogCaptureFixture, migrator: Migrator, tmpcadir: Path, ocsp_pem: str
) -> None:
    """Test running the migration with a PEM public key."""
    ocsp_dest = tmpcadir / "ocsp"
    ocsp_dest.mkdir(exist_ok=True, parents=True)

    def setup_ocsp_keys(ca: Any) -> None:
        shutil.copy(FIXTURES_DIR / "profile-ocsp.key", ocsp_dest / f"{ca.serial}.key")
        with open(ocsp_dest / f"{ca.serial}.pem", "w", encoding="ascii") as stream:
            stream.write(ocsp_pem)

    state = setup(migrator, setup=setup_ocsp_keys)

    CertificateAuthority = state.apps.get_model("django_ca", "CertificateAuthority")
    ca = CertificateAuthority.objects.get(serial="123")
    assert caplog.record_tuples == []
    assert ca.ocsp_key_backend_options == {
        "certificate": {"pem": ocsp_pem},
        "private_key": {"path": "ocsp/123.key"},
    }


@pytest.mark.usefixtures("tmpcadir")
def test_ocsp_keys_dont_exist(caplog: LogCaptureFixture, migrator: Migrator) -> None:
    """Test running the migration where no OCSP key was generated."""
    state = setup(migrator)
    CertificateAuthority = state.apps.get_model("django_ca", "CertificateAuthority")
    ca = CertificateAuthority.objects.get(serial="123")
    assert ca.ocsp_key_backend_options == {"certificate": {}, "private_key": {}}
    assert caplog.record_tuples == [
        (
            "django_ca.migrations.0051_auto_20241201_2038",
            logging.WARNING,
            "Private or public key not found. Regenerate OCSP keys manually.",
        )
    ]


@pytest.mark.usefixtures("tmpcadir")
def test_with_bogus_public_key(caplog: LogCaptureFixture, migrator: Migrator, tmpcadir: Path) -> None:
    """Test running the migration with a bogus public key."""
    ocsp_dest = tmpcadir / "ocsp"
    ocsp_dest.mkdir(exist_ok=True, parents=True)

    def setup_ocsp_keys(ca: Any) -> None:
        shutil.copy(FIXTURES_DIR / "profile-ocsp.key", ocsp_dest / f"{ca.serial}.key")
        with open(ocsp_dest / f"{ca.serial}.pem", "w", encoding="ascii") as stream:
            stream.write("foobar")

    state = setup(migrator, setup=setup_ocsp_keys)

    CertificateAuthority = state.apps.get_model("django_ca", "CertificateAuthority")
    ca = CertificateAuthority.objects.get(serial="123")
    assert caplog.record_tuples == [
        (
            "django_ca.migrations.0051_auto_20241201_2038",
            logging.WARNING,
            "ocsp/123.pem: Cannot encode certificate. Regenerate OCSP keys manually.",
        )
    ]
    assert ca.ocsp_key_backend_options == {"certificate": {}, "private_key": {}}

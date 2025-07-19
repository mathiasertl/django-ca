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

"""Test the regenerate_ocsp_keys management command."""

import typing
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from typing import Any, cast

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPublicKeyTypes
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

from django.core.files.storage import storages

import pytest
from pytest_django.fixtures import SettingsWrapper

from django_ca.conf import model_settings
from django_ca.key_backends.storages import StoragesOCSPBackend
from django_ca.models import Certificate, CertificateAuthority
from django_ca.tests.base.assertions import assert_command_error
from django_ca.tests.base.constants import TIMESTAMPS
from django_ca.tests.base.mocks import mock_celery_task
from django_ca.tests.base.utils import cmd

pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])]


def regenerate_ocsp_keys(*serials: str, stdout: str = "", stderr: str = "", **kwargs: Any) -> tuple[str, str]:
    """Execute the regenerate_ocsp_keys command."""
    actual_stdout, actual_stderr = cmd("regenerate_ocsp_keys", *serials, **kwargs)
    assert actual_stdout == stdout
    assert actual_stderr == stderr
    return actual_stdout, actual_stderr


def assert_key(
    ca: CertificateAuthority,
    key_type: type[CertificateIssuerPublicKeyTypes] | None = None,
    excludes: Iterable[int] | None = None,
    profile: str = "ocsp",
) -> x509.Certificate:
    """Assert that they key is present and can be read."""
    ca.refresh_from_db()  # need to reload data to be able to see new OCSP key data

    if key_type is None:
        key_type = type(cast(CertificateIssuerPublicKeyTypes, ca.pub.loaded.public_key()))

    ocsp_key_backend = ca.ocsp_key_backend
    assert isinstance(ocsp_key_backend, StoragesOCSPBackend)

    cert = x509.load_pem_x509_certificate(ca.ocsp_key_backend_options["certificate"]["pem"].encode())
    assert isinstance(cert, x509.Certificate)
    assert isinstance(cert.public_key(), key_type)

    cert_qs = Certificate.objects.filter(ca=ca, profile=profile)

    if excludes:
        cert_qs = cert_qs.exclude(pk__in=excludes)

    db_cert = cert_qs.get()

    aia = typing.cast(
        x509.Extension[x509.AuthorityInformationAccess],
        db_cert.extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS],
    )

    expected_aia = x509.Extension(
        oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
        critical=ca.sign_authority_information_access.critical,  # type: ignore[union-attr]
        value=x509.AuthorityInformationAccess(
            ad
            for ad in ca.sign_authority_information_access.value  # type: ignore[union-attr]
            if ad.access_method == AuthorityInformationAccessOID.CA_ISSUERS
        ),
    )
    assert aia == expected_aia

    return cert


def assert_no_key(serial: str) -> None:
    """Assert that the OCSP key is **not** present."""
    priv_path = f"ocsp/{serial}.key"
    cert_path = f"ocsp/{serial}.pem"
    storage = storages[model_settings.CA_DEFAULT_STORAGE_ALIAS]
    assert storage.exists(priv_path) is False
    assert storage.exists(cert_path) is False


def test_with_serial(usable_root: CertificateAuthority) -> None:
    """Basic test."""
    regenerate_ocsp_keys(usable_root.serial)
    certificate = assert_key(usable_root)

    # test expiry of the certificate
    now = datetime.now(tz=timezone.utc).replace(microsecond=0, second=0)
    expected_expires = now + timedelta(days=usable_root.ocsp_responder_key_validity)
    assert certificate.not_valid_after_utc == expected_expires

    # get list of existing certificates
    excludes = list(Certificate.objects.all().values_list("pk", flat=True))

    # Try regenerating certificate
    regenerate_ocsp_keys(usable_root.serial, force=True)
    new_cert = assert_key(usable_root, excludes=excludes)

    # Cert should now be different
    assert certificate != new_cert


def test_with_celery(settings: SettingsWrapper, usable_root: CertificateAuthority) -> None:
    """Basic test."""
    settings.CA_USE_CELERY = True
    with mock_celery_task(
        "django_ca.tasks.generate_ocsp_key",
        (
            (
                tuple(),
                {
                    "serial": usable_root.serial,
                    "key_backend_options": {"password": None},
                    "force": False,
                },
            ),
            {},
        ),
    ):
        regenerate_ocsp_keys(usable_root.serial)
    assert_no_key(usable_root.serial)


def test_without_serial(
    settings: SettingsWrapper, root: CertificateAuthority, ec: CertificateAuthority
) -> None:
    """Test for all CAs."""
    settings.CA_USE_CELERY = True
    kwargs = {"key_backend_options": {"password": None}, "force": False}
    with mock_celery_task(
        "django_ca.tasks.generate_ocsp_key",
        ((tuple(), {"serial": root.serial, **kwargs}), {}),
        ((tuple(), {"serial": ec.serial, **kwargs}), {}),
    ):
        cmd("regenerate_ocsp_keys")


@pytest.mark.django_db
def test_wrong_serial() -> None:
    """Try passing an unknown CA."""
    regenerate_ocsp_keys("ZZZZZ", stderr="0Z:ZZ:ZZ: Unknown CA.\n", no_color=True)


def test_no_ocsp_profile(settings: SettingsWrapper, root: CertificateAuthority) -> None:
    """Try when there is no OCSP profile."""
    settings.CA_PROFILES = {"ocsp": None}
    with assert_command_error(r"^ocsp: Undefined profile\.$"):
        regenerate_ocsp_keys(root.serial)
    assert_no_key(root.serial)


@pytest.mark.usefixtures("tmpcadir")
def test_without_private_key(root: CertificateAuthority) -> None:
    """Try regenerating the OCSP key when no CA private key is available."""
    with assert_command_error(r"No such file or directory"):
        regenerate_ocsp_keys(root.serial)


def test_model_validation_error(root: CertificateAuthority) -> None:
    """Test model validation is tested properly.

    NOTE: This example is contrived for the default backend, as the type of the password would already be
    checked by argparse. Other backends however might have other validation mechanisms.
    """
    with assert_command_error(r"^password: Input should be a valid bytes$"):
        regenerate_ocsp_keys(root.serial, password=123)

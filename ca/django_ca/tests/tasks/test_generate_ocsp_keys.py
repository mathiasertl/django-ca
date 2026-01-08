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

"""Test the generate_ocsp_keys task."""

import base64
import logging
from unittest import mock

from django.core.files.storage import storages

import pytest
from _pytest.logging import LogCaptureFixture

from django_ca.celery.messages import UseCertificateAuthoritiesTaskArgs
from django_ca.conf import model_settings
from django_ca.models import CertificateAuthority
from django_ca.tasks import generate_ocsp_keys
from django_ca.tests.base.constants import TIMESTAMPS

pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])]


def test_generate_ocsp_keys(usable_cas: list[CertificateAuthority]) -> None:
    """Test creating all keys at once."""
    generate_ocsp_keys()
    storage = storages[model_settings.CA_DEFAULT_STORAGE_ALIAS]

    for ca in usable_cas:
        ca.refresh_from_db()  # models from fixture have old data
        assert ca.ocsp_key_backend_options["private_key"]["path"] == f"ocsp/{ca.serial}.key"
        assert "password" in ca.ocsp_key_backend_options["private_key"]
        assert ca.ocsp_key_backend_options["certificate"]["pem"].startswith("-----BEGIN CERTIFICATE-----\n")
        assert storage.exists(ca.ocsp_key_backend_options["private_key"]["path"]) is True


@pytest.mark.usefixtures("root")
def test_generate_ocsp_keys_with_error(caplog: LogCaptureFixture) -> None:
    """Test case where child-task throws an error."""
    with (
        mock.patch("django_ca.tasks.run_task", side_effect=Exception("error")),
        caplog.at_level(logging.INFO),
    ):
        generate_ocsp_keys()
    assert "Error creating OCSP responder key for" in caplog.text


def test_with_invalid_password(usable_pwd: CertificateAuthority) -> None:
    """Test passing an invalid password."""
    password = base64.b64encode(b"wrong").decode()
    storage = storages[model_settings.CA_DEFAULT_STORAGE_ALIAS]
    message = UseCertificateAuthoritiesTaskArgs(
        serials=[usable_pwd.serial], key_backend_options={usable_pwd.serial: {"password": password}}
    )
    generate_ocsp_keys(message)
    usable_pwd.refresh_from_db()  # models from fixture have old data
    assert usable_pwd.ocsp_key_backend_options == {"private_key": {}, "certificate": {}}
    assert storage.exists(f"ocsp/{usable_pwd.serial}.pem") is False

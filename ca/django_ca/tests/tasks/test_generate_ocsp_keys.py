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

from django_ca.conf import model_settings
from django_ca.models import CertificateAuthority
from django_ca.tasks import generate_ocsp_keys
from django_ca.tests.base.constants import TIMESTAMPS

pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])]


def test_generate_ocsp_keys_all(usable_cas: list[CertificateAuthority]) -> None:
    """Test creating all keys at once."""
    generate_ocsp_keys()
    storage = storages[model_settings.CA_DEFAULT_STORAGE_ALIAS]

    for ca in usable_cas:
        assert storage.exists(f"ocsp/{ca.serial}.key") is True
        assert storage.exists(f"ocsp/{ca.serial}.pem") is True


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
    generate_ocsp_keys([usable_pwd.serial], {usable_pwd.serial: {"password": password}})
    assert storage.exists(f"ocsp/{usable_pwd.serial}.key") is False
    assert storage.exists(f"ocsp/{usable_pwd.serial}.pem") is False

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

"""Test the generate_ocsp_key task."""

import base64
from datetime import timedelta

from django.core.files.storage import storages

import pytest

from django_ca.celery.messages import GenerateOCSPKeyCeleryMessage
from django_ca.conf import model_settings
from django_ca.models import Certificate, CertificateAuthority
from django_ca.tasks import generate_ocsp_key
from django_ca.tests.base.constants import CERT_DATA, TIMESTAMPS

pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])]


def test_with_no_parameters(usable_root: CertificateAuthority) -> None:
    """Test creating a single key."""
    storage = storages[model_settings.CA_DEFAULT_STORAGE_ALIAS]
    generate_ocsp_key(GenerateOCSPKeyCeleryMessage(serial=usable_root.serial))
    assert storage.exists(f"ocsp/{usable_root.serial}.key") is True


def test_responder_key_validity(usable_root: CertificateAuthority) -> None:
    """Test that the ocsp_responder_key_validity field works."""
    qs = Certificate.objects.filter(profile="ocsp", ca=usable_root)
    usable_root.ocsp_responder_key_validity = 10
    usable_root.save()
    assert qs.exists() is False

    generate_ocsp_key(GenerateOCSPKeyCeleryMessage(serial=usable_root.serial))
    cert = qs.get()
    assert cert.not_after == TIMESTAMPS["everything_valid"] + timedelta(days=10)


def test_with_explicit_password(usable_pwd: CertificateAuthority) -> None:
    """Test explicitly passing a password."""
    storage = storages[model_settings.CA_DEFAULT_STORAGE_ALIAS]
    message = GenerateOCSPKeyCeleryMessage(
        serial=usable_pwd.serial,
        key_backend_options={usable_pwd.serial: {"password": CERT_DATA["pwd"]["password"]}},
    )
    generate_ocsp_key(message)
    assert storage.exists(f"ocsp/{usable_pwd.serial}.key") is True


def test_no_renewal_required(usable_root: CertificateAuthority) -> None:
    """Test that keys are not renewed and None is returned in this case."""
    assert generate_ocsp_key(GenerateOCSPKeyCeleryMessage(serial=usable_root.serial)) is not None
    assert generate_ocsp_key(GenerateOCSPKeyCeleryMessage(serial=usable_root.serial)) is None


def test_with_wrong_password(usable_pwd: CertificateAuthority) -> None:
    """Test passing the wrong password."""
    password = base64.b64encode(b"wrong").decode()
    message = GenerateOCSPKeyCeleryMessage(
        serial=usable_pwd.serial, key_backend_options={"password": password}
    )
    with pytest.raises(ValueError, match=r"^Could not decrypt private key - bad password\?$"):
        generate_ocsp_key(message)
    assert Certificate.objects.filter(profile="ocsp", ca=usable_pwd).exists() is False

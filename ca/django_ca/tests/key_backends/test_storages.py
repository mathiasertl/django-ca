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

"""Test the StoragesBackend backend."""

from pathlib import Path

import pytest
from pytest_django.fixtures import SettingsWrapper

from django_ca.conf import model_settings
from django_ca.key_backends import key_backends
from django_ca.key_backends.storages import (
    StoragesBackend,
    StoragesUsePrivateKeyOptions,
    StoragesCreatePrivateKeyOptions,
)
from django_ca.models import CertificateAuthority


@pytest.mark.parametrize("key_size", (2048, 4096, 8192))
def test_private_key_options_key_size(key_size: int) -> None:
    """Test valid key sizes for private key options."""
    model = StoragesCreatePrivateKeyOptions(
        key_type="RSA", password=None, path=Path("/does/not/exist"), key_size=key_size
    )
    assert model.key_size == key_size


@pytest.mark.parametrize("key_size", (-2048, -1, 0, 1, 1023, 1025, 2047, 2049, 8191, 8193, 1000, 2000, 3000))
def test_private_key_options_with_invalid_key_size(key_size: int) -> None:
    """Test invalid key sizes for private key options."""
    with pytest.raises(ValueError):
        StoragesCreatePrivateKeyOptions(
            key_type="RSA", password=None, path=Path("/does/not/exist"), key_size=key_size
        )


@pytest.mark.usefixtures("clean_key_backends")
def test_invalid_storages_alias(settings: SettingsWrapper) -> None:
    """Test configuring an invalid storage alias."""
    settings.CA_KEY_BACKENDS = {
        model_settings.CA_DEFAULT_KEY_BACKEND: {
            "BACKEND": "django_ca.key_backends.storages.StoragesBackend",
            "OPTIONS": {"storage_alias": "invalid"},
        },
    }
    with pytest.raises(
        ValueError,
        match=rf"^{model_settings.CA_DEFAULT_KEY_BACKEND}: invalid: Storage alias is not configured\.$",
    ):
        key_backends[model_settings.CA_DEFAULT_KEY_BACKEND]


def test_eq(settings: SettingsWrapper) -> None:
    """Test equality."""
    settings.STORAGES = {
        "foo-alias": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
        "bar-alias": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    }

    assert StoragesBackend("foo", "foo-alias") == StoragesBackend("foo", "foo-alias")

    # Different key backend alias but same configuration --> still equal
    assert StoragesBackend("foo", "foo-alias") == StoragesBackend("bar", "foo-alias")

    # same key backend alias but different storage alias --> not identical
    assert StoragesBackend("foo", "foo-alias") != StoragesBackend("foo", "bar-alias")


def test_check_usable_no_path_configured(root: CertificateAuthority) -> None:
    """Test check_usable() when no path is configured."""
    root.key_backend_options = {}
    root.save()
    with pytest.raises(ValueError, match=r"^{}: Path not configured in database\.$"):
        root.check_usable(StoragesUsePrivateKeyOptions(password=None))


def test_is_usable_no_path_configured(root: CertificateAuthority) -> None:
    """Test is_usable() when no path is configured."""
    root.key_backend_options = {}
    root.save()
    assert root.is_usable(StoragesUsePrivateKeyOptions(password=None)) is False


def test_get_ocsp_key_size_with_invalid_key_type(usable_ec: CertificateAuthority) -> None:
    """Test getting key size for a non-RSA/DSA CA."""
    with pytest.raises(ValueError, match=r"^This function should only be called with RSA/DSA CAs\.$"):
        key_backends[model_settings.CA_DEFAULT_KEY_BACKEND].get_ocsp_key_size(
            usable_ec, StoragesUsePrivateKeyOptions(password=None)
        )


def test_get_ocsp_key_elliptic_curve_invalid_key_type(usable_root: CertificateAuthority) -> None:
    """Test getting elliptic key curve for a non-EC CA."""
    with pytest.raises(
        ValueError, match=r"^This function should only be called with EllipticCurve-based CAs\.$"
    ):
        key_backends[model_settings.CA_DEFAULT_KEY_BACKEND].get_ocsp_key_elliptic_curve(
            usable_root, StoragesUsePrivateKeyOptions(password=None)
        )

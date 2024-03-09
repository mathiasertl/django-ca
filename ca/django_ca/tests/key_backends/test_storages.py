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

import pytest
from pytest_django.fixtures import SettingsWrapper

from django_ca import ca_settings
from django_ca.backends import key_backends
from django_ca.backends.storages import StoragesBackend, UsePrivateKeyOptions
from django_ca.models import CertificateAuthority


@pytest.mark.usefixtures("clean_key_backends")
def test_invalid_storages_alias(settings: SettingsWrapper) -> None:
    """Test configuring an invalid storage alias."""
    settings.CA_KEY_BACKENDS = {
        ca_settings.CA_DEFAULT_KEY_BACKEND: {
            "BACKEND": "django_ca.backends.storages.StoragesBackend",
            "OPTIONS": {"storage_alias": "invalid"},
        },
    }
    with pytest.raises(
        ValueError,
        match=rf"^{ca_settings.CA_DEFAULT_KEY_BACKEND}: invalid: Storage alias is not configured\.$",
    ):
        key_backends[ca_settings.CA_DEFAULT_KEY_BACKEND]


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


def test_get_ocsp_key_size_with_invalid_key_type(usable_ec: CertificateAuthority) -> None:
    """Test getting key size for a non-RSA/DSA CA."""
    with pytest.raises(ValueError, match=r"^This function should only be called with RSA/DSA CAs\.$"):
        key_backends[ca_settings.CA_DEFAULT_KEY_BACKEND].get_ocsp_key_size(
            usable_ec, UsePrivateKeyOptions(password=None)
        )


def test_get_ocsp_key_elliptic_curve_invalid_key_type(usable_root: CertificateAuthority) -> None:
    """Test getting elliptic key curve for a non-EC CA."""
    with pytest.raises(
        ValueError, match=r"^This function should only be called with EllipticCurve-based CAs\.$"
    ):
        key_backends[ca_settings.CA_DEFAULT_KEY_BACKEND].get_ocsp_key_elliptic_curve(
            usable_root, UsePrivateKeyOptions(password=None)
        )

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

"""Test key backend base class."""

from unittest.mock import patch

import pytest
from pytest_django.fixtures import SettingsWrapper

from django_ca.conf import model_settings
from django_ca.key_backends import KeyBackend, key_backends
from django_ca.tests.base.assertions import assert_improperly_configured
from django_ca.tests.base.utils import DummyBackend, DummyModel

pytestmark = pytest.mark.usefixtures("clean_key_backends")  # every test gets clean key backends


def test_key_backends_getitem_with_default() -> None:
    """Test dict-style lookup ."""
    assert isinstance(key_backends[model_settings.CA_DEFAULT_KEY_BACKEND], KeyBackend)


def test_key_backends_getitem_caching() -> None:
    """Test that lookups are cached properly."""
    patch_target = "django_ca.key_backends.key_backends._get_key_backend"
    value = "xxx"
    with patch(patch_target, autospec=True, return_value=value) as load_mock:
        assert key_backends[model_settings.CA_DEFAULT_KEY_BACKEND] == value  # type: ignore[comparison-overlap]
    load_mock.assert_called_once_with(model_settings.CA_DEFAULT_KEY_BACKEND)

    with patch(patch_target, autospec=True, return_value=value) as load_mock:
        assert key_backends[model_settings.CA_DEFAULT_KEY_BACKEND] == value  # type: ignore[comparison-overlap]
    load_mock.assert_not_called()


def test_key_backends_getitem_with_invalid_backend() -> None:
    """Test looking up the wrong backend."""
    with pytest.raises(ValueError, match=r"^wrong-backend: key backend is not configured\.$"):
        key_backends["wrong-backend"]


def test_key_backends_iter(settings: SettingsWrapper) -> None:
    """Test dict-style lookup ."""
    assert list(key_backends) == [
        key_backends[model_settings.CA_DEFAULT_KEY_BACKEND],
        key_backends["secondary"],
        key_backends["hsm"],
    ]

    settings.CA_KEY_BACKENDS = {
        model_settings.CA_DEFAULT_KEY_BACKEND: {
            "BACKEND": "django_ca.key_backends.storages.StoragesBackend",
            "OPTIONS": {"storage_alias": "django-ca"},
        },
        "test": {
            "BACKEND": f"{__name__}.DummyBackend",
            "OPTIONS": {},
        },
    }

    assert list(key_backends) == [
        key_backends[model_settings.CA_DEFAULT_KEY_BACKEND],
        DummyBackend(alias="test"),
    ]


def test_key_backends_class_not_found(settings: SettingsWrapper) -> None:
    """Test configuring a class that cannot be found."""
    settings.CA_KEY_BACKENDS = {
        model_settings.CA_DEFAULT_KEY_BACKEND: {
            "BACKEND": "not_found.NotFoundBackend",
            "OPTIONS": {},
        },
    }

    with assert_improperly_configured(
        r"^Could not find backend 'not_found.NotFoundBackend': No module named 'not_found'$"
    ):
        key_backends[model_settings.CA_DEFAULT_KEY_BACKEND]


def test_key_backends_class_is_not_key_backend(settings: SettingsWrapper) -> None:
    """Test configuring a class that is not a KeyBackend subclass."""
    backend_path = f"{DummyModel.__module__}.DummyModel"
    settings.CA_KEY_BACKENDS = {
        model_settings.CA_DEFAULT_KEY_BACKEND: {
            "BACKEND": backend_path,
            "OPTIONS": {},
        },
    }

    with assert_improperly_configured(rf"^{backend_path}: Class does not refer to a key backend\.$"):
        key_backends[model_settings.CA_DEFAULT_KEY_BACKEND]


def test_key_backend_overwritten_methods(settings: SettingsWrapper) -> None:
    """Test methods usually overwritten by StoragesBackend."""
    settings.CA_KEY_BACKENDS = {
        model_settings.CA_DEFAULT_KEY_BACKEND: {
            "BACKEND": f"{DummyModel.__module__}.DummyBackend",
            "OPTIONS": {},
        },
    }

    backend = key_backends[model_settings.CA_DEFAULT_KEY_BACKEND]
    assert backend.add_use_private_key_arguments(None) is None  # type: ignore[func-returns-value,arg-type]

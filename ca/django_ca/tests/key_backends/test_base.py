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

from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import patch

from pydantic import BaseModel

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    CertificateIssuerPublicKeyTypes,
)

import pytest
from pytest_django.fixtures import SettingsWrapper

from django_ca import ca_settings
from django_ca.key_backends import KeyBackend, key_backends
from django_ca.models import CertificateAuthority
from django_ca.tests.base.assertions import assert_improperly_configured
from django_ca.typehints import AllowedHashTypes, ArgumentGroup, ParsableKeyType

pytestmark = pytest.mark.usefixtures("clean_key_backends")  # every test gets clean key backends


class DummyModel(BaseModel):
    """Dummy model for the dummy backend."""


class DummyBackend(KeyBackend[DummyModel, DummyModel, DummyModel]):
    """Backend with no actions whatsoever."""

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, DummyBackend)

    def add_create_private_key_arguments(self, group: ArgumentGroup) -> None:
        return None

    def add_store_private_key_arguments(self, group: ArgumentGroup) -> None:
        return None

    def get_create_private_key_options(
        self, key_type: ParsableKeyType, options: Dict[str, Any]
    ) -> DummyModel:
        return DummyModel()

    def add_use_parent_private_key_arguments(self, group: ArgumentGroup) -> None:
        return None

    def get_use_parent_private_key_options(self, options: Dict[str, Any]) -> DummyModel:
        return DummyModel()

    def get_store_private_key_options(self, options: Dict[str, Any]) -> DummyModel:
        return DummyModel()

    def create_private_key(
        self, ca: CertificateAuthority, key_type: ParsableKeyType, options: DummyModel
    ) -> Tuple[CertificateIssuerPublicKeyTypes, DummyModel]:
        return None, DummyModel()  # type: ignore[return-value]

    def get_use_private_key_options(self, options: Dict[str, Any]) -> DummyModel:
        return DummyModel()

    def is_usable(
        self, ca: "CertificateAuthority", use_private_key_options: Optional[DummyModel] = None
    ) -> bool:
        return True

    def sign_certificate_revocation_list(
        self,
        ca: "CertificateAuthority",
        use_private_key_options: DummyModel,
        builder: x509.CertificateRevocationListBuilder,
        algorithm: Optional[AllowedHashTypes],
    ) -> x509.CertificateRevocationList:
        return None  # type: ignore[return-value]

    def sign_certificate(
        self,
        ca: "CertificateAuthority",
        use_private_key_options: DummyModel,
        public_key: CertificateIssuerPublicKeyTypes,
        serial: int,
        algorithm: Optional[AllowedHashTypes],
        issuer: x509.Name,
        subject: x509.Name,
        expires: datetime,
        extensions: List[x509.Extension[x509.ExtensionType]],
    ) -> x509.Certificate:
        return None  # type: ignore[return-value]

    def store_private_key(
        self, ca: "CertificateAuthority", key: CertificateIssuerPrivateKeyTypes, options: DummyModel
    ) -> None:
        return None


def test_key_backends_getitem_with_default() -> None:
    """Test dict-style lookup ."""
    assert isinstance(key_backends[ca_settings.CA_DEFAULT_KEY_BACKEND], KeyBackend)


def test_key_backends_getitem_caching() -> None:
    """Test that lookups are cached properly."""
    patch_target = "django_ca.key_backends.key_backends._get_key_backend"
    value = "xxx"
    with patch(patch_target, autospec=True, return_value=value) as load_mock:
        assert key_backends[ca_settings.CA_DEFAULT_KEY_BACKEND] == value  # type: ignore[comparison-overlap]
    load_mock.assert_called_once_with(ca_settings.CA_DEFAULT_KEY_BACKEND)

    with patch(patch_target, autospec=True, return_value=value) as load_mock:
        assert key_backends[ca_settings.CA_DEFAULT_KEY_BACKEND] == value  # type: ignore[comparison-overlap]
    load_mock.assert_not_called()


def test_key_backends_getitem_with_invalid_backend() -> None:
    """Test looking up the wrong backend."""
    with pytest.raises(ValueError, match=r"^wrong-backend: key backend is not configured\.$"):
        key_backends["wrong-backend"]


def test_key_backends_iter(settings: SettingsWrapper) -> None:
    """Test dict-style lookup ."""
    assert list(key_backends) == [key_backends[ca_settings.CA_DEFAULT_KEY_BACKEND]]

    settings.CA_KEY_BACKENDS = {
        ca_settings.CA_DEFAULT_KEY_BACKEND: {
            "BACKEND": "django_ca.key_backends.storages.StoragesBackend",
            "OPTIONS": {"storage_alias": "django-ca"},
        },
        "test": {
            "BACKEND": f"{__name__}.DummyBackend",
            "OPTIONS": {},
        },
    }

    assert list(key_backends) == [
        key_backends[ca_settings.CA_DEFAULT_KEY_BACKEND],
        DummyBackend(alias="test"),
    ]


def test_key_backends_class_not_found(settings: SettingsWrapper) -> None:
    """Test configuring a class that cannot be found."""
    settings.CA_KEY_BACKENDS = {
        ca_settings.CA_DEFAULT_KEY_BACKEND: {
            "BACKEND": "not_found.NotFoundBackend",
            "OPTIONS": {},
        },
    }

    with assert_improperly_configured(
        r"^Could not find backend 'not_found.NotFoundBackend': No module named 'not_found'$"
    ):
        key_backends[ca_settings.CA_DEFAULT_KEY_BACKEND]


def test_key_backends_class_is_not_key_backend(settings: SettingsWrapper) -> None:
    """Test configuring a class that is not a KeyBackend subclass."""
    settings.CA_KEY_BACKENDS = {
        ca_settings.CA_DEFAULT_KEY_BACKEND: {
            "BACKEND": f"{__name__}.DummyModel",
            "OPTIONS": {},
        },
    }

    with assert_improperly_configured(rf"^{__name__}.DummyModel: Class does not refer to a key backend\.$"):
        key_backends[ca_settings.CA_DEFAULT_KEY_BACKEND]


def test_key_backend_overwritten_methods(settings: SettingsWrapper, root: CertificateAuthority) -> None:
    """Test methods usually overwritten by StoragesBackend."""
    settings.CA_KEY_BACKENDS = {
        ca_settings.CA_DEFAULT_KEY_BACKEND: {
            "BACKEND": f"{__name__}.DummyBackend",
            "OPTIONS": {},
        },
    }

    backend = key_backends[ca_settings.CA_DEFAULT_KEY_BACKEND]
    assert backend.add_use_private_key_arguments(None) is None  # type: ignore[func-returns-value,arg-type]
    assert backend.get_ocsp_key_size(root, DummyModel()) == ca_settings.CA_DEFAULT_KEY_SIZE
    assert isinstance(
        backend.get_ocsp_key_elliptic_curve(root, DummyModel()), ca_settings.CA_DEFAULT_ELLIPTIC_CURVE
    )

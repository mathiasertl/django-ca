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

"""Tests for the database key backend."""

import pytest

from django_ca.key_backends.db import DBBackend
from django_ca.key_backends.db.models import DBStorePrivateKeyOptions, DBUsePrivateKeyOptions
from django_ca.key_backends.storages.models import StoragesUsePrivateKeyOptions
from django_ca.models import CertificateAuthority
from django_ca.tests.key_backends.conftest import KeyBackendTestBase


def test_eq(db_backend: DBBackend) -> None:
    """Teest equality of database backends."""
    assert db_backend == DBBackend(alias="other")


def test_get_use_parent_private_key_options(db_backend: DBBackend, root: CertificateAuthority) -> None:
    """Test getting parent private key options."""
    assert db_backend.get_use_parent_private_key_options(root, {}) == DBUsePrivateKeyOptions()


def test_is_not_usable_with_no_key_backend_options(db_backend: DBBackend, root: CertificateAuthority) -> None:
    """Test key backend knows CA is not usable with no key backend options."""
    root.key_backend_options = {}
    root.key_backend_alias = db_backend.alias
    root.save()

    assert db_backend.is_usable(root) is False
    match = rf"^{root.key_backend_options}: Private key not stored in database\.$"
    with pytest.raises(ValueError, match=match):
        db_backend.check_usable(root, DBUsePrivateKeyOptions())


def test_is_not_usable_with_no_private_key(db_backend: DBBackend, root: CertificateAuthority) -> None:
    """Test key backend knows CA is not usable with no key backend options."""
    root.key_backend_options = {"private_key": None}
    root.key_backend_alias = db_backend.alias
    root.save()

    assert db_backend.is_usable(root) is False

    match = rf"^{root.key_backend_options}: Private key not stored in database\.$"
    with pytest.raises(ValueError, match=match):
        db_backend.check_usable(root, DBUsePrivateKeyOptions())


class TestKeyBackend(KeyBackendTestBase):
    """Generic tests for the Storages backend."""

    def _convert_ca(self, ca: CertificateAuthority, backend: DBBackend) -> CertificateAuthority:
        private_key = ca.key_backend.get_key(ca, StoragesUsePrivateKeyOptions())  # type: ignore[attr-defined]
        ca._key_backend = None  # pylint: disable=protected-access  # clear cache
        ca.key_backend_alias = "db"
        backend.store_private_key(ca, private_key, ca.pub.loaded, DBStorePrivateKeyOptions())
        ca.save()
        return ca

    @pytest.fixture
    def use_key_backend_options(self) -> DBUsePrivateKeyOptions:
        """Fixture to retrieve key backend options."""
        return DBUsePrivateKeyOptions()

    @pytest.fixture
    def usable_dsa(self, usable_dsa: CertificateAuthority, db_backend: DBBackend) -> CertificateAuthority:
        """Override fixture to convert to this backend."""
        return self._convert_ca(usable_dsa, db_backend)

    @pytest.fixture
    def usable_root(self, usable_root: CertificateAuthority, db_backend: DBBackend) -> CertificateAuthority:
        """Override fixture to convert to this backend."""
        return self._convert_ca(usable_root, db_backend)

    @pytest.fixture
    def usable_ec(self, usable_ec: CertificateAuthority, db_backend: DBBackend) -> CertificateAuthority:
        """Override fixture to convert to this backend."""
        return self._convert_ca(usable_ec, db_backend)

    @pytest.fixture
    def usable_ed25519(
        self, usable_ed25519: CertificateAuthority, db_backend: DBBackend
    ) -> CertificateAuthority:
        """Override fixture to convert to this backend."""
        return self._convert_ca(usable_ed25519, db_backend)

    @pytest.fixture
    def usable_ed448(self, usable_ed448: CertificateAuthority, db_backend: DBBackend) -> CertificateAuthority:
        """Override fixture to convert to this backend."""
        return self._convert_ca(usable_ed448, db_backend)

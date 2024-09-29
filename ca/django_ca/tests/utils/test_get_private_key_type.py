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

"""Test get_private_key_type function."""

import pytest

from django_ca.key_backends.storages import StoragesBackend, StoragesUsePrivateKeyOptions
from django_ca.models import CertificateAuthority
from django_ca.utils import get_private_key_type


def test_get_private_key_type(key_backend: StoragesBackend, usable_cas: list[CertificateAuthority]) -> None:
    """Test the normal operation of this function."""
    cas = {ca.name: ca for ca in usable_cas}

    assert get_private_key_type(key_backend.get_key(cas["root"], StoragesUsePrivateKeyOptions())) == "RSA"
    assert get_private_key_type(key_backend.get_key(cas["dsa"], StoragesUsePrivateKeyOptions())) == "DSA"
    assert get_private_key_type(key_backend.get_key(cas["ec"], StoragesUsePrivateKeyOptions())) == "EC"
    assert (
        get_private_key_type(key_backend.get_key(cas["ed25519"], StoragesUsePrivateKeyOptions())) == "Ed25519"
    )
    assert get_private_key_type(key_backend.get_key(cas["ed448"], StoragesUsePrivateKeyOptions())) == "Ed448"


def test_get_private_key_type_with_invalid_type() -> None:
    """Test passing an invalid type."""
    with pytest.raises(ValueError, match="^True: Unknown private key type.$"):
        get_private_key_type(True)  # type: ignore[arg-type]  # what we test

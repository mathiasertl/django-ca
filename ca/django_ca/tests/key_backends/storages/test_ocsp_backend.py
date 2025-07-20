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

"""Test the StoragesOCSPBackend backend."""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from django.core.files.base import ContentFile
from django.core.files.storage import storages

import pytest

from django_ca.conf import model_settings
from django_ca.key_backends.storages import StoragesOCSPBackend
from django_ca.models import CertificateAuthority


def test_storage_alias_not_configured() -> None:
    """Test error thrown when storage alias does not exist."""
    with pytest.raises(ValueError, match=r"^alias: does-not-exist: Storage alias is not configured\.$"):
        StoragesOCSPBackend(alias="alias", storage_alias="does-not-exist")


def test_path_ends_with_slash() -> None:
    """Test that path option automatically has a slash appended."""
    backend = StoragesOCSPBackend(alias="alias", storage_alias="django-ca", path="ocsp")
    assert backend.path == "ocsp/"


@pytest.mark.usefixtures("tmpcadir")
def test_no_encryption(root: CertificateAuthority) -> None:
    """Test creating a key with no encryption."""
    root.ocsp_key_backend_options.setdefault("private_key", {})
    root.ocsp_key_backend_options.setdefault("certificate", {})
    backend = StoragesOCSPBackend(alias="alias", storage_alias="django-ca", encrypt_private_key=False)
    backend.create_private_key(root, "RSA", model_settings.CA_MIN_KEY_SIZE, None)
    root.save()

    root.refresh_from_db()
    assert "password" not in root.ocsp_key_backend_options["private_key"]
    assert isinstance(backend.load_private_key(root), rsa.RSAPrivateKey)


@pytest.mark.usefixtures("tmpcadir")
def test_unsupported_private_key(x448_private_key: X448PrivateKey, root: CertificateAuthority) -> None:
    """Test loading a private key that is not supported."""
    private_key_der = x448_private_key.private_bytes(
        Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()
    )
    storage = storages[model_settings.CA_DEFAULT_STORAGE_ALIAS]
    private_key_path = storage.save(f"ocsp/{root.serial}.key", ContentFile(private_key_der))

    root.ocsp_key_backend_options = {"private_key": {"path": private_key_path}}
    root.save()

    with pytest.raises(ValueError, match=r"Unsupported private key type\.$"):
        root.ocsp_key_backend.load_private_key(root)  # type: ignore[attr-defined]


def test_get_default_key_size(ec: CertificateAuthority) -> None:
    """Test getting the default key-size for non-RSA keys."""
    backend = StoragesOCSPBackend(alias="alias", storage_alias="django-ca", path="ocsp")
    assert backend.get_default_key_size(ec) == model_settings.CA_DEFAULT_KEY_SIZE


def test_get_default_ec_curve(root: CertificateAuthority) -> None:
    """Test getting the default elliptic curve for non-EC keys."""
    backend = StoragesOCSPBackend(alias="alias", storage_alias="django-ca", path="ocsp")
    assert isinstance(
        backend.get_default_elliptic_curve(root), type(model_settings.get_default_elliptic_curve())
    )

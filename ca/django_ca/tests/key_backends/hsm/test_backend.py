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

"""Main tests for the HSM backend."""

from unittest.mock import patch

import pkcs11

from cryptography import x509

from django.conf import settings

import pytest

from django_ca.key_backends import key_backends
from django_ca.key_backends.hsm import HSMBackend
from django_ca.key_backends.hsm.models import (
    HSMCreatePrivateKeyOptions,
    HSMStorePrivateKeyOptions,
    HSMUsePrivateKeyOptions,
)
from django_ca.models import CertificateAuthority


def test_session_with_session_read_only_exception(hsm_backend: HSMBackend) -> None:
    """Test exception message when SessionReadOnly() is raised."""
    with pytest.raises(pkcs11.PKCS11Error, match=r"^Attempting to write to a read-only session\.$"):
        with hsm_backend.session(so_pin=None, user_pin=settings.PKCS11_USER_PIN) as session:
            with patch.object(session, "get_key", side_effect=pkcs11.SessionReadOnly()):
                session.get_key()


def test_session_with_unknown_pkcs11_exception(hsm_backend: HSMBackend) -> None:
    """Test exception message when a generic PKCS11 error is raised."""
    with pytest.raises(pkcs11.PKCS11Error, match=r"^Unknown pkcs11 error \(SessionCount\)\.$"):
        with hsm_backend.session(so_pin=None, user_pin=settings.PKCS11_USER_PIN) as session:
            with patch.object(session, "get_key", side_effect=pkcs11.SessionCount()):
                session.get_key()


@pytest.mark.usefixtures("softhsm_token")
def test_invalid_token_configuration() -> None:
    """Test validation of so_pin/user_pin."""
    backend = HSMBackend("test", settings.PKCS11_PATH, "my-token", user_pin=settings.PKCS11_USER_PIN)
    with pytest.raises(pkcs11.NoSuchToken, match=r"^my-token: Token not found\.$"):
        with backend.session(so_pin=None, user_pin=settings.PKCS11_USER_PIN):
            pass


def test_invalid_pin_configuration() -> None:
    """Test validation of so_pin/user_pin."""
    with pytest.raises(ValueError, match=r"^test: Set either so_pin or user_pin\.$"):
        HSMBackend("test", "/path", "token", so_pin="so-pin", user_pin="user-pin")


@pytest.mark.usefixtures("softhsm_token")
def test_invalid_private_key_type(root: CertificateAuthority) -> None:
    """Test an invalid private key."""
    root.key_backend_alias = "hsm"
    root.key_backend_options = {"key_id": "123", "key_label": "label", "key_type": "WRONG"}
    root.save()
    use_options = HSMUsePrivateKeyOptions(user_pin=settings.PKCS11_USER_PIN)
    with pytest.raises(ValueError, match=r"^WRONG: Unsupported key type\.$"):
        root.check_usable(use_options)


def test_is_usable_with_no_options(root: CertificateAuthority) -> None:
    """Test that is_usable() returns True if no options are passed."""
    root.key_backend_alias = "hsm"
    root.key_backend_options = {"key_id": "123", "key_label": "label", "key_type": "RSA"}
    root.save()
    assert root.is_usable() is True
    assert root.is_usable(None) is True


@pytest.mark.usefixtures("softhsm_token")
def test_is_usable_with_wrong_user_pin(root: CertificateAuthority) -> None:
    """Test that is_usable() returns False if the wrong pin is passed."""
    root.key_backend_alias = "hsm"
    root.key_backend_options = {"key_id": "123", "key_label": "label", "key_type": "RSA"}
    root.save()
    assert root.is_usable(HSMUsePrivateKeyOptions(user_pin="wrong")) is False


def test_no_private_key_options(root: CertificateAuthority) -> None:
    """Test ...usable() with empty private key options."""
    root.key_backend_alias = "hsm"
    root.key_backend_options = {}
    root.save()
    use_options = HSMUsePrivateKeyOptions(user_pin=settings.PKCS11_USER_PIN)
    assert root.is_usable(use_options) is False
    with pytest.raises(ValueError, match=r"^key backend options are not defined\.$"):
        root.check_usable(use_options)


def test_private_key_options_not_a_dict(root: CertificateAuthority) -> None:
    """Test ...usable() with private key options that are not a dict."""
    root.key_backend_alias = "hsm"
    root.key_backend_options = []
    root.save()
    use_options = HSMUsePrivateKeyOptions(user_pin=settings.PKCS11_USER_PIN)
    assert root.is_usable(use_options) is False
    with pytest.raises(ValueError, match=r"^key backend options are not defined\.$"):
        root.check_usable(use_options)


# pylint: disable-next=protected-access  # okay in test cases
@pytest.mark.parametrize("parameter", HSMBackend._required_key_backend_options)
def test_private_key_options_missing_parameter(root: CertificateAuthority, parameter: str) -> None:
    """Test ...usable() with private key options that are missing a value."""
    root.key_backend_alias = "hsm"
    root.key_backend_options = {"key_id": "123", "key_label": "label", "key_type": "RSA"}
    del root.key_backend_options[parameter]
    root.save()

    use_options = HSMUsePrivateKeyOptions(user_pin=settings.PKCS11_USER_PIN)
    assert root.is_usable(use_options) is False

    with pytest.raises(ValueError, match=rf"^{parameter}: Required key option is not defined\.$"):
        root.check_usable(use_options)


@pytest.mark.usefixtures("softhsm_token")
@pytest.mark.parametrize("key_type", HSMBackend.supported_key_types)
def test_create_private_key_with_read_only_session(
    root: CertificateAuthority, ca_name: str, key_type: str
) -> None:
    """Test creating a private key if a read-only session is already open."""
    root.key_backend_alias = "hsm"
    root.key_backend_options = {"key_id": "123", "key_label": "label", "key_type": "RSA"}
    root.save()

    options = HSMCreatePrivateKeyOptions(
        key_type=key_type, key_label=ca_name, elliptic_curve=None, user_pin=settings.PKCS11_USER_PIN
    )

    backend: HSMBackend = key_backends["hsm"]  # type: ignore[assignment]
    with pytest.raises(
        ValueError, match=r"^Requested R/W session, but R/O session is already initialized\.$"
    ):
        with backend.session(so_pin=None, user_pin=settings.PKCS11_USER_PIN):
            backend.create_private_key(root, options.key_type, options)


@pytest.mark.usefixtures("softhsm_token")
def test_create_private_key_with_unknown_key_type(root: CertificateAuthority, ca_name: str) -> None:
    """Test creating a private key if a read-only session is already open."""
    root.key_backend_alias = "hsm"
    root.key_backend_options = {"key_id": "123", "key_label": "label", "key_type": "WRONG"}
    root.save()

    options = HSMCreatePrivateKeyOptions(
        key_type="RSA", key_label=ca_name, elliptic_curve=None, user_pin=settings.PKCS11_USER_PIN
    )

    backend: HSMBackend = key_backends["hsm"]  # type: ignore[assignment]
    with pytest.raises(ValueError, match=r"^WRONG: unknown key type$"):
        backend.create_private_key(root, "WRONG", options)  # type: ignore[arg-type]  # what we test


def test_store_private_key_with_unknown_type(
    root: CertificateAuthority, root_cert_pub: x509.Certificate
) -> None:
    """Test storing a private key with an unknown type."""
    options = HSMStorePrivateKeyOptions(user_pin="abc", key_label="def")
    backend: HSMBackend = key_backends["hsm"]  # type: ignore[assignment]
    with pytest.raises(ValueError, match=r"^True: Importing a key of this type is not supported\.$"):
        backend.store_private_key(
            root,
            True,  # type: ignore[arg-type]  # what we test
            root_cert_pub,
            options,
        )

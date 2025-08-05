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

from unittest.mock import create_autospec

import pkcs11

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import MGF1, PSS, AsymmetricPadding, PKCS1v15
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from django.conf import settings

import pytest

from django_ca.key_backends import key_backends
from django_ca.key_backends.hsm import HSMBackend
from django_ca.key_backends.hsm.models import (
    HSMCreatePrivateKeyOptions,
    HSMStorePrivateKeyOptions,
    HSMUsePrivateKeyOptions,
)
from django_ca.key_backends.storages.models import StoragesUsePrivateKeyOptions
from django_ca.models import CertificateAuthority
from django_ca.tests.key_backends.conftest import KeyBackendTestBase


def test_session_with_session_read_only_exception(hsm_backend: HSMBackend) -> None:
    """Test exception message when SessionReadOnly() is raised."""
    with pytest.raises(pkcs11.PKCS11Error, match=r"^Attempting to write to a read-only session\.$"):  # noqa: PT012
        with hsm_backend.session(so_pin=None, user_pin=settings.PKCS11_USER_PIN) as session:
            session_mock = create_autospec(session, spec_set=True)
            session_mock.get_key = create_autospec(
                session.get_key, spec_set=True, side_effect=pkcs11.SessionReadOnly()
            )

            session_mock.get_key()


def test_session_with_unknown_pkcs11_exception(hsm_backend: HSMBackend) -> None:
    """Test exception message when a generic PKCS11 error is raised."""
    with pytest.raises(pkcs11.PKCS11Error, match=r"^Unknown pkcs11 error \(SessionCount\)\.$"):  # noqa: PT012
        with hsm_backend.session(so_pin=None, user_pin=settings.PKCS11_USER_PIN) as session:
            session_mock = create_autospec(session, spec_set=True)
            session_mock.get_key = create_autospec(
                session.get_key, spec_set=True, side_effect=pkcs11.SessionCount()
            )

            session_mock.get_key()


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


class TestKeyBackend(KeyBackendTestBase):
    """Generic tests for the Storages backend."""

    def _convert_ca(
        self,
        ca: CertificateAuthority,
        backend: HSMBackend,
        store_key_backend_options: HSMStorePrivateKeyOptions,
    ) -> CertificateAuthority:
        private_key = ca.key_backend.get_key(ca, StoragesUsePrivateKeyOptions())  # type: ignore[attr-defined]
        ca._key_backend = None  # pylint: disable=protected-access  # clear cache
        ca.key_backend_alias = "hsm"
        backend.store_private_key(ca, private_key, ca.pub.loaded, store_key_backend_options)
        ca.save()
        return ca

    @pytest.fixture
    def usable_root(
        self,
        usable_root: CertificateAuthority,
        hsm_backend: HSMBackend,
        store_key_backend_options: HSMStorePrivateKeyOptions,
    ) -> CertificateAuthority:
        """Override fixture to convert to this backend."""
        return self._convert_ca(usable_root, hsm_backend, store_key_backend_options)

    @pytest.fixture
    def usable_ec(
        self,
        usable_ec: CertificateAuthority,
        hsm_backend: HSMBackend,
        store_key_backend_options: HSMStorePrivateKeyOptions,
    ) -> CertificateAuthority:
        """Override fixture to convert to this backend."""
        return self._convert_ca(usable_ec, hsm_backend, store_key_backend_options)

    @pytest.fixture
    def usable_ed25519(
        self,
        usable_ed25519: CertificateAuthority,
        hsm_backend: HSMBackend,
        store_key_backend_options: HSMStorePrivateKeyOptions,
    ) -> CertificateAuthority:
        """Override fixture to convert to this backend."""
        return self._convert_ca(usable_ed25519, hsm_backend, store_key_backend_options)

    @pytest.fixture
    def usable_ed448(
        self,
        usable_ed448: CertificateAuthority,
        hsm_backend: HSMBackend,
        store_key_backend_options: HSMStorePrivateKeyOptions,
    ) -> CertificateAuthority:
        """Override fixture to convert to this backend."""
        return self._convert_ca(usable_ed448, hsm_backend, store_key_backend_options)

    @pytest.fixture
    def store_key_backend_options(self, hsm_backend: HSMBackend) -> HSMStorePrivateKeyOptions:
        """Fixture to retrieve key backend options."""
        return HSMStorePrivateKeyOptions.model_validate(
            {"key_label": "label"}, context={"backend": hsm_backend}
        )

    @pytest.fixture
    def use_key_backend_options(self, hsm_backend: HSMBackend) -> HSMUsePrivateKeyOptions:
        """Fixture to retrieve key backend options."""
        return HSMUsePrivateKeyOptions.model_validate({}, context={"backend": hsm_backend})

    def sign_data_with_rsa_xfail(self, algorithm: hashes.HashAlgorithm, padding: AsymmetricPadding) -> None:
        # pylint: disable=protected-access  # no public access available
        if isinstance(padding, PSS) and algorithm.name != padding.mgf._algorithm.name:
            pytest.xfail("Signing fails if singing algorithm and MGF1 hash algorithm don't match.")
        if isinstance(padding, PSS) and padding._salt_length == PSS.DIGEST_LENGTH:
            pytest.xfail("DIGEST_LENGTH is not supported.")

    def test_sign_data_with_dsa(self) -> None:  # type: ignore[override]
        pytest.xfail("DSA is not supported for HSMs.")

    def test_sign_data_with_dsa_without_algorithm(self) -> None:  # type: ignore[override]
        pytest.xfail("DSA is not supported for HSMs.")

    def test_sign_data_with_rsa_with_pkcs15_prehashed(self) -> None:  # type: ignore[override]
        pytest.xfail("Prehashed data with PKCS1v15 padding is not supported.")

    def test_sign_data_with_rsa_with_unsupported_algorithm(
        self, usable_root: CertificateAuthority, use_key_backend_options: HSMUsePrivateKeyOptions
    ) -> None:
        """Try signing data with an unsupported algorithm."""
        padding = PSS(mgf=MGF1(hashes.SHA256()), salt_length=PSS.MAX_LENGTH)
        with pytest.raises(ValueError, match=r"^sha3-256: Hash algorithm not supported\.$"):
            usable_root.key_backend.sign_data(
                usable_root, use_key_backend_options, b"", algorithm=hashes.SHA3_256(), padding=padding
            )

    def test_sign_data_with_rsa_with_unsupported_mgf_algorithm(
        self, usable_root: CertificateAuthority, use_key_backend_options: HSMUsePrivateKeyOptions
    ) -> None:
        """Try signing data with an unsupported algorithm in an MGF."""
        padding = PSS(mgf=MGF1(hashes.SHA3_256()), salt_length=PSS.MAX_LENGTH)
        with pytest.raises(ValueError, match=r"^sha3-256: Hash algorithm not supported\.$"):
            usable_root.key_backend.sign_data(
                usable_root, use_key_backend_options, b"", algorithm=hashes.SHA256(), padding=padding
            )

    @pytest.mark.parametrize("salt_length", ("AUTO", "DIGEST_LENGTH"))
    def test_sign_data_with_rsa_with_unsupported_digest_length(
        self,
        usable_root: CertificateAuthority,
        use_key_backend_options: HSMUsePrivateKeyOptions,
        salt_length: str,
    ) -> None:
        """Try signing data with an unsupported algorithm in an MGF."""
        padding = PSS(mgf=MGF1(hashes.SHA256()), salt_length=getattr(PSS, salt_length))
        with pytest.raises(ValueError, match=rf"^{salt_length} is not supported when signing\.$"):
            usable_root.key_backend.sign_data(
                usable_root, use_key_backend_options, b"", algorithm=hashes.SHA256(), padding=padding
            )

    def test_sign_data_with_rsa_with_prehashed_and_pkcs1v15(
        self, usable_root: CertificateAuthority, use_key_backend_options: HSMUsePrivateKeyOptions
    ) -> None:
        """Try signing pre-hashed data with PKCS1v15, which is not supported.."""
        padding = PKCS1v15()
        algo = Prehashed(hashes.SHA256())
        with pytest.raises(ValueError, match=r"^Prehashed data with PKCS1v15 is not supported\.$"):
            usable_root.key_backend.sign_data(
                usable_root, use_key_backend_options, b"", algorithm=algo, padding=padding
            )

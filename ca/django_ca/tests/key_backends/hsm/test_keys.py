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

"""Tests for models used in the HSM key backend."""

from typing import cast
from unittest.mock import patch

import pkcs11

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from django.conf import settings

import pytest

from django_ca.key_backends import key_backends
from django_ca.key_backends.hsm import HSMBackend
from django_ca.key_backends.hsm.keys import (
    PKCS11Ed448PrivateKey,
    PKCS11Ed25519PrivateKey,
    PKCS11EllipticCurvePrivateKey,
    PKCS11PrivateKeyTypes,
    PKCS11RSAPrivateKey,
)


@pytest.mark.usefixtures("softhsm_token")
def test_private_key_caching() -> None:
    """Test caching of private keys."""
    obj = object()
    key_backend = cast(HSMBackend, key_backends["hsm"])
    with key_backend.session(so_pin=None, user_pin=settings.PKCS11_USER_PIN) as session:
        cert = PKCS11RSAPrivateKey(session, "foo", "bar")
        with patch.object(session, "get_key", autospec=True, return_value=obj) as mock:
            assert cert.pkcs11_private_key is obj
            assert cert.pkcs11_private_key is obj

        # Check that the mock was called only once
        mock.assert_called_once_with(
            key_type=pkcs11.KeyType.RSA, object_class=pkcs11.ObjectClass.PRIVATE_KEY, id=b"foo", label="bar"
        )


@pytest.mark.usefixtures("softhsm_token")
def test_public_key_caching() -> None:
    """Test caching of public keys."""
    obj = object()
    key_backend = cast(HSMBackend, key_backends["hsm"])
    with key_backend.session(so_pin=None, user_pin=settings.PKCS11_USER_PIN) as session:
        cert = PKCS11RSAPrivateKey(session, "foo", "bar")
        with patch.object(session, "get_key", autospec=True, return_value=obj) as mock:
            assert cert.pkcs11_public_key is obj
            assert cert.pkcs11_public_key is obj

        # Check that the mock was called only once
        mock.assert_called_once_with(
            key_type=pkcs11.KeyType.RSA, object_class=pkcs11.ObjectClass.PUBLIC_KEY, id=b"foo", label="bar"
        )


@pytest.mark.parametrize(
    "key_class",
    (PKCS11RSAPrivateKey, PKCS11EllipticCurvePrivateKey, PKCS11Ed25519PrivateKey, PKCS11Ed448PrivateKey),
)
def test_not_implemented_error(key_class: type[PKCS11PrivateKeyTypes]) -> None:
    """Test methods that are not implemented."""
    key: PKCS11PrivateKeyTypes = key_class(None, "key_id", "key_label")

    error = r"^Private numbers cannot be retrieved for keys stored in a hardware security module \(HSM\)\.$"
    with pytest.raises(NotImplementedError, match=error):
        key.private_numbers()

    with pytest.raises(
        NotImplementedError,
        match=r"^Private bytes cannot be retrieved for keys stored in a hardware security module \(HSM\)\.$",
    ):
        key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())

    with pytest.raises(
        NotImplementedError,
        match=r"^Decryption is not implemented for keys stored in a hardware security module \(HSM\)\.$",
    ):
        key.decrypt(b"foo", PKCS1v15())


def test_rsa_with_sha3_error() -> None:
    """Test signing data with SHA3, which is unsupported (by the underlying library)."""
    key = PKCS11RSAPrivateKey(None, "key_id", "key_label")
    with pytest.raises(ValueError, match=r"^SHA3 is not support by the HSM backend\.$"):
        key.sign(b"", PKCS1v15(), hashes.SHA3_256())


def test_rsa_with_unsupported_algorithm() -> None:
    """Test signing data with an unsupported algorithms."""
    key = PKCS11RSAPrivateKey(None, "key_id", "key_label")
    with pytest.raises(
        ValueError,
        match=r"^blake2s with EMSA-PKCS1-v1_5 padding: Unknown signing algorithm and/or padding\.$",
    ):
        key.sign(b"", PKCS1v15(), hashes.BLAKE2s(32))


def test_elliptic_curve_key_not_implemented_error() -> None:
    """Test methods that are not implemented for elliptic curve keys."""
    key = PKCS11EllipticCurvePrivateKey(None, "key_id", "key_label")

    with pytest.raises(
        NotImplementedError,
        match=r"^exchange is not implemented for keys stored in a hardware security module \(HSM\)\.$",
    ):
        key.exchange(None, None)  # type: ignore[arg-type]  # don't care here


def test_elliptic_curve_with_sha3_error() -> None:
    """Test signing data with SHA3, which is unsupported (by the underlying library)."""
    key = PKCS11EllipticCurvePrivateKey(None, "key_id", "key_label")
    algo = ec.ECDSA(hashes.SHA3_256())
    with pytest.raises(ValueError, match=r"^SHA3 is not support by the HSM backend\.$"):
        key.sign(b"", algo)


def test_elliptic_curve_with_unsupported_algorithm() -> None:
    """Test signing data with an unsupported algorithm."""
    key = PKCS11EllipticCurvePrivateKey(None, "key_id", "key_label")
    algo = ec.ECDSA(hashes.BLAKE2s(32))
    with pytest.raises(ValueError, match=r"^blake2s: Signature algorithm is not supported\.$"):
        key.sign(b"", algo)


def test_elliptic_curve_with_prehashed_data() -> None:
    """Test signing data with prehashed data."""
    key = PKCS11EllipticCurvePrivateKey(None, "key_id", "key_label")
    algo = ec.ECDSA(Prehashed(hashes.BLAKE2s(32)))
    with pytest.raises(ValueError, match=r"^Signing of prehashed data is not supported\.$"):
        key.sign(b"", algo)


@pytest.mark.parametrize("key_class", (PKCS11Ed25519PrivateKey, PKCS11Ed448PrivateKey))
def test_ed_key_not_implemented_error(
    key_class: type[PKCS11Ed25519PrivateKey | PKCS11Ed448PrivateKey],
) -> None:
    """Test methods that are not implemented for Ed448/Ed25519 keys."""
    key: PKCS11Ed25519PrivateKey | PKCS11Ed448PrivateKey = key_class(None, "key_id", "key_label")

    with pytest.raises(
        NotImplementedError,
        match=r"^Private bytes cannot be retrieved for keys stored in a hardware security module \(HSM\)\.$",
    ):
        key.private_bytes_raw()

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

"""Test fixtures for testing key backends."""

from collections.abc import Iterator
from typing import Any, cast

from pydantic import BaseModel

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.padding import MGF1, PSS, AsymmetricPadding, PKCS1v15
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

import pytest

from django_ca.key_backends import key_backends
from django_ca.key_backends.base import KeyBackends
from django_ca.models import CertificateAuthority


@pytest.fixture
def clean_key_backends() -> Iterator[KeyBackends]:
    """Fixture to make sure that no key backends are loaded yet."""
    key_backends._reset()  # pylint: disable=protected-access
    yield key_backends
    key_backends._reset()  # pylint: disable=protected-access


class KeyBackendTestBase:
    """Base class containing universal tests for all backends."""

    def sign_data_with_rsa_xfail(self, algorithm: hashes.HashAlgorithm, padding: AsymmetricPadding) -> None:
        """Override to mark some tests as expected failure."""

    @pytest.mark.parametrize("data", (b"", b"abc"))
    @pytest.mark.parametrize(
        "algorithm", (hashes.SHA224(), hashes.SHA256(), hashes.SHA384(), hashes.SHA512())
    )
    def test_sign_data_with_dsa(
        self,
        usable_dsa: CertificateAuthority,
        use_key_backend_options: BaseModel,
        data: bytes,
        algorithm: hashes.HashAlgorithm,
    ) -> None:
        """Test signing data with an DSA CA."""
        signature = usable_dsa.key_backend.sign_data(
            usable_dsa, use_key_backend_options, data, algorithm=algorithm
        )
        public_key = cast(dsa.DSAPublicKey, usable_dsa.pub.loaded.public_key())
        assert isinstance(public_key, dsa.DSAPublicKey)
        assert public_key.verify(signature, data, algorithm=algorithm) is None

    @pytest.mark.parametrize("data", (b"", b"abc"))
    @pytest.mark.parametrize(
        "algorithm", (hashes.SHA224(), hashes.SHA256(), hashes.SHA384(), hashes.SHA512())
    )
    @pytest.mark.parametrize(
        "padding",
        (
            PSS(mgf=MGF1(hashes.SHA224()), salt_length=PSS.MAX_LENGTH),  # 0
            PSS(mgf=MGF1(hashes.SHA256()), salt_length=PSS.MAX_LENGTH),  # 1
            PSS(mgf=MGF1(hashes.SHA384()), salt_length=PSS.MAX_LENGTH),  # 2
            PSS(mgf=MGF1(hashes.SHA512()), salt_length=PSS.MAX_LENGTH),  # 3
            PSS(mgf=MGF1(hashes.SHA224()), salt_length=PSS.DIGEST_LENGTH),
            PSS(mgf=MGF1(hashes.SHA256()), salt_length=PSS.DIGEST_LENGTH),
            PSS(mgf=MGF1(hashes.SHA384()), salt_length=PSS.DIGEST_LENGTH),
            PSS(mgf=MGF1(hashes.SHA512()), salt_length=PSS.DIGEST_LENGTH),
            PSS(mgf=MGF1(hashes.SHA512()), salt_length=20),
            PKCS1v15(),
        ),
    )
    def test_sign_data_with_rsa(
        self,
        usable_root: CertificateAuthority,
        use_key_backend_options: BaseModel,
        data: bytes,
        algorithm: hashes.HashAlgorithm,
        padding: AsymmetricPadding,
    ) -> None:
        """Test signing data with an RSA CA."""
        self.sign_data_with_rsa_xfail(algorithm, padding)
        signature = usable_root.key_backend.sign_data(
            usable_root, use_key_backend_options, data, algorithm=algorithm, padding=padding
        )
        public_key = cast(rsa.RSAPublicKey, usable_root.pub.loaded.public_key())
        assert isinstance(public_key, rsa.RSAPublicKey)
        assert public_key.verify(signature, data, algorithm=algorithm, padding=padding) is None

    @pytest.mark.parametrize("data", (b"", b"abc"))
    @pytest.mark.parametrize(
        "algorithm", (hashes.SHA224(), hashes.SHA256(), hashes.SHA384(), hashes.SHA512())
    )
    def test_sign_data_with_rsa_with_pss_prehashed(
        self,
        usable_root: CertificateAuthority,
        use_key_backend_options: BaseModel,
        data: bytes,
        algorithm: hashes.HashAlgorithm,
    ) -> None:
        """Test signing pre-hashed data with PSS padding."""
        h = hashes.Hash(algorithm)
        h.update(data)
        digest = h.finalize()
        prehashed_alg = Prehashed(algorithm)
        pss = PSS(mgf=MGF1(algorithm), salt_length=0)
        signature = usable_root.key_backend.sign_data(
            usable_root, use_key_backend_options, digest, algorithm=prehashed_alg, padding=pss
        )
        public_key = cast(rsa.RSAPublicKey, usable_root.pub.loaded.public_key())
        assert isinstance(public_key, rsa.RSAPublicKey)
        public_key.verify(signature, data, pss, algorithm)

    @pytest.mark.parametrize("data", (b"", b"abc"))
    @pytest.mark.parametrize(
        "algorithm", (hashes.SHA224(), hashes.SHA256(), hashes.SHA384(), hashes.SHA512())
    )
    def test_sign_data_with_rsa_with_pkcs15_prehashed(
        self,
        usable_root: CertificateAuthority,
        use_key_backend_options: BaseModel,
        data: bytes,
        algorithm: hashes.HashAlgorithm,
    ) -> None:
        """Test signing pre-hashed data with PKCS1v15 padding."""
        h = hashes.Hash(algorithm)
        h.update(data)
        digest = h.finalize()
        prehashed_alg = Prehashed(algorithm)
        signature = usable_root.key_backend.sign_data(
            usable_root, use_key_backend_options, digest, algorithm=prehashed_alg, padding=PKCS1v15()
        )
        public_key = cast(rsa.RSAPublicKey, usable_root.pub.loaded.public_key())
        assert isinstance(public_key, rsa.RSAPublicKey)
        public_key.verify(signature, data, PKCS1v15(), algorithm)

    @pytest.mark.parametrize("data", (b"", b"abc"))
    @pytest.mark.parametrize(
        "algorithm", (hashes.SHA224(), hashes.SHA256(), hashes.SHA384(), hashes.SHA512())
    )
    def test_sign_data_with_ec(
        self,
        usable_ec: CertificateAuthority,
        use_key_backend_options: BaseModel,
        data: bytes,
        algorithm: hashes.HashAlgorithm,
    ) -> None:
        """Test signing data with an EC CA."""
        signature = usable_ec.key_backend.sign_data(
            usable_ec, use_key_backend_options, data, signature_algorithm=ec.ECDSA(algorithm)
        )
        public_key = cast(ec.EllipticCurvePublicKey, usable_ec.pub.loaded.public_key())
        assert isinstance(public_key, ec.EllipticCurvePublicKey)
        assert public_key.verify(signature, data, signature_algorithm=ec.ECDSA(algorithm)) is None

    @pytest.mark.parametrize("data", (b"", b"abc"))
    def test_sign_data_with_ed25519(
        self, usable_ed25519: CertificateAuthority, use_key_backend_options: BaseModel, data: bytes
    ) -> None:
        """Test signing data with an Ed25519 CA."""
        signature = usable_ed25519.key_backend.sign_data(usable_ed25519, use_key_backend_options, data)
        public_key = cast(ed25519.Ed25519PublicKey, usable_ed25519.pub.loaded.public_key())
        assert isinstance(public_key, ed25519.Ed25519PublicKey)
        assert public_key.verify(signature, data) is None

    @pytest.mark.parametrize("data", (b"", b"abc"))
    def test_sign_data_with_ed448(
        self, usable_ed448: CertificateAuthority, use_key_backend_options: BaseModel, data: bytes
    ) -> None:
        """Test signing data with an Ed448 CA."""
        signature = usable_ed448.key_backend.sign_data(usable_ed448, use_key_backend_options, data)
        public_key = cast(ed448.Ed448PublicKey, usable_ed448.pub.loaded.public_key())
        assert isinstance(public_key, ed448.Ed448PublicKey)
        assert public_key.verify(signature, data) is None

    def test_sign_data_with_dsa_without_algorithm(
        self, usable_dsa: CertificateAuthority, use_key_backend_options: BaseModel
    ) -> None:
        """Test that an algorithm is required when using DSA keys."""
        with pytest.raises(ValueError, match=r"^algorithm is required for DSA keys\.$"):
            usable_dsa.key_backend.sign_data(usable_dsa, use_key_backend_options, b"")

    def test_sign_data_with_rsa_without_algorithm(
        self, usable_root: CertificateAuthority, use_key_backend_options: BaseModel
    ) -> None:
        """Test that an algorithm is required when using RSA keys."""
        with pytest.raises(ValueError, match=r"^algorithm is required for RSA keys\.$"):
            usable_root.key_backend.sign_data(usable_root, use_key_backend_options, b"", padding=PKCS1v15())

    def test_sign_data_with_rsa_without_padding(
        self, usable_root: CertificateAuthority, use_key_backend_options: BaseModel
    ) -> None:
        """Test that an padding is required when using RSA keys."""
        with pytest.raises(ValueError, match=r"^padding is required for RSA keys\.$"):
            usable_root.key_backend.sign_data(
                usable_root, use_key_backend_options, b"", algorithm=hashes.SHA256()
            )

    def test_sign_data_with_ec_without_algorithm(
        self, usable_ec: CertificateAuthority, use_key_backend_options: BaseModel
    ) -> None:
        """Test that an algorithm is required when using EC keys."""
        with pytest.raises(ValueError, match=r"^signature_algorithm is required for elliptic curve keys\.$"):
            usable_ec.key_backend.sign_data(usable_ec, use_key_backend_options, b"")

    @pytest.mark.parametrize(
        "kwargs",
        (
            {"algorithm": hashes.SHA256()},
            {"padding": PKCS1v15()},
            {"signature_algorithm": ec.ECDSA(hashes.SHA256())},
        ),
    )
    def test_sign_data_with_ed25519_with_parameters(
        self, usable_ed25519: CertificateAuthority, use_key_backend_options: BaseModel, kwargs: dict[str, Any]
    ) -> None:
        """Test that parameters must not be set for Ed25519 keys."""
        with pytest.raises(
            ValueError,
            match=r"^algorithm, padding and signature_algorithm are not allowed for this key type\.$",
        ):
            usable_ed25519.key_backend.sign_data(usable_ed25519, use_key_backend_options, b"", **kwargs)

    @pytest.mark.parametrize(
        "kwargs",
        (
            {"algorithm": hashes.SHA256()},
            {"padding": PKCS1v15()},
            {"signature_algorithm": ec.ECDSA(hashes.SHA256())},
        ),
    )
    def test_sign_data_with_ed448_with_parameters(
        self, usable_ed448: CertificateAuthority, use_key_backend_options: BaseModel, kwargs: dict[str, Any]
    ) -> None:
        """Test that parameters must not be set for Ed448 keys."""
        with pytest.raises(
            ValueError,
            match=r"^algorithm, padding and signature_algorithm are not allowed for this key type\.$",
        ):
            usable_ed448.key_backend.sign_data(usable_ed448, use_key_backend_options, b"", **kwargs)

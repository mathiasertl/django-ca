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

"""Tests for padding models."""

from typing import Any

from pydantic import BaseModel

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hashes import HashAlgorithm

import pytest

from django_ca.pydantic.padding import AsymmetricPaddingTypes, MGF1Model, PKCS1v15Model, PSSModel
from django_ca.tests.pydantic.base import assert_cryptography_model


class AsymmetricPaddingTypesModel(BaseModel):
    """Test model class"."""

    value: AsymmetricPaddingTypes


def test_pkcs1v15_model() -> None:
    """Test PKCS1v15Model."""
    model = assert_cryptography_model(PKCS1v15Model, {}, padding.PKCS1v15(), has_equality=False)
    assert isinstance(model.cryptography, padding.PKCS1v15)


@pytest.mark.parametrize(
    ("parameter", "hash_algorithm"),
    (
        ("SHA-256", hashes.SHA256()),
        ("SHA3/512", hashes.SHA3_512()),
        (hashes.SHA256(), hashes.SHA256()),
    ),
)
def test_mgf1model(parameter: Any, hash_algorithm: HashAlgorithm) -> None:
    """Test MGF1Model."""
    model = assert_cryptography_model(
        MGF1Model, {"algorithm": parameter}, padding.MGF1(hash_algorithm), has_equality=False
    )
    assert isinstance(model.cryptography, padding.MGF1)
    # pylint: disable-next=protected-access  # no public accessors available
    assert isinstance(model.cryptography._algorithm, type(hash_algorithm))


@pytest.mark.parametrize(
    ("parameters", "expected"),
    (
        (
            {"salt_length": 16, "mgf": MGF1Model(algorithm="SHA-256")},
            padding.PSS(salt_length=16, mgf=padding.MGF1(algorithm=hashes.SHA256())),
        ),
        # Try a different salt length:
        (
            {"salt_length": 32, "mgf": MGF1Model(algorithm="SHA-256")},
            padding.PSS(salt_length=32, mgf=padding.MGF1(algorithm=hashes.SHA256())),
        ),
        # try different algorithm
        (
            {"salt_length": 32, "mgf": MGF1Model(algorithm="SHA-512")},
            padding.PSS(salt_length=32, mgf=padding.MGF1(algorithm=hashes.SHA512())),
        ),
        # Try salt lengths derived from constants
        (
            {"salt_length": "AUTO", "mgf": MGF1Model(algorithm="SHA-256")},
            padding.PSS(salt_length=padding.PSS.AUTO, mgf=padding.MGF1(algorithm=hashes.SHA256())),
        ),
        (
            {"salt_length": "DIGEST_LENGTH", "mgf": MGF1Model(algorithm="SHA-256")},
            padding.PSS(salt_length=padding.PSS.DIGEST_LENGTH, mgf=padding.MGF1(algorithm=hashes.SHA256())),
        ),
        (
            {"salt_length": "MAX_LENGTH", "mgf": MGF1Model(algorithm="SHA-256")},
            padding.PSS(salt_length=padding.PSS.MAX_LENGTH, mgf=padding.MGF1(algorithm=hashes.SHA256())),
        ),
    ),
)
def test_pssmodel(parameters: dict[str, Any], expected: padding.PSS) -> None:
    """Test PSSModel."""
    model = assert_cryptography_model(PSSModel, parameters, expected, has_equality=False)
    converted = model.cryptography
    assert isinstance(converted, padding.PSS)
    assert isinstance(converted.mgf, padding.MGF1)
    assert isinstance(expected.mgf, padding.MGF1)  # just for type hinting
    # pylint: disable-next=protected-access  # no public accessors available
    assert isinstance(converted.mgf._algorithm, type(expected.mgf._algorithm))
    # pylint: disable-next=protected-access  # no public accessors available
    assert converted._salt_length == expected._salt_length


def test_asymmetric_padding_types_with_pkcs1v15() -> None:
    """Test type alias."""
    model = AsymmetricPaddingTypesModel(value=padding.PKCS1v15())
    assert isinstance(model.value, PKCS1v15Model)
    assert isinstance(model.value.cryptography, padding.PKCS1v15)


@pytest.mark.parametrize(
    "value",
    (
        padding.PSS(salt_length=1, mgf=padding.MGF1(hashes.SHA256())),
        {"name": "EMSA-PSS", "salt_length": padding.PSS.AUTO, "mgf": {"algorithm": "SHA-256"}},
    ),
)
def test_asymmetric_padding_types_with_pss(value: Any) -> None:
    """Test type alias."""
    model = AsymmetricPaddingTypesModel(value=value)
    assert isinstance(model.value, PSSModel)
    assert isinstance(model.value.cryptography, padding.PSS)

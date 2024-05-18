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

"""Test type aliases for Pydantic from django_ca.pydantic.type_aliases."""

from datetime import timedelta
from typing import Any

from pydantic import BaseModel

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding

import pytest

from django_ca import constants
from django_ca.pydantic.type_aliases import (
    Base64EncodedBytes,
    CertificateRevocationListEncodingTypeAlias,
    EllipticCurveTypeAlias,
    HashAlgorithmTypeAlias,
    Serial,
    TimedeltaInSeconds,
)


class EllipticCurveTypeAliasModel(BaseModel):
    """Test EllipticCurveTypeAlias."""

    value: EllipticCurveTypeAlias


class HashAlgorithmTypeAliasModel(BaseModel):
    """Test HashAlgorithmTypeAlias."""

    value: HashAlgorithmTypeAlias


class CertificateRevocationListEncodingTypeAliasModel(BaseModel):
    """Test CertificateRevocationListEncodingTypeAlias."""

    value: CertificateRevocationListEncodingTypeAlias


class JSONSerializableBytesModel(BaseModel):
    """Test class to test the Base64EncodedBytes type aliases."""

    value: Base64EncodedBytes


class SerialModel(BaseModel):
    """Test class to test the Serial type alias."""

    value: Serial


class TimedeltaInSecondsModel(BaseModel):
    """Test class to test the TimedeltaInSeconds type alias."""

    value: TimedeltaInSeconds


@pytest.mark.parametrize("name,curve_cls", constants.ELLIPTIC_CURVE_TYPES.items())
def test_elliptic_curve(name: str, curve_cls: type[ec.EllipticCurve]) -> None:
    """Test EllipticCurveTypeAliasModel."""
    model = EllipticCurveTypeAliasModel(value=name)
    assert isinstance(model.value, curve_cls)

    model = EllipticCurveTypeAliasModel(value=curve_cls())
    assert isinstance(model.value, curve_cls)

    model = EllipticCurveTypeAliasModel.model_validate({"value": name})
    assert isinstance(model.value, curve_cls)

    model = EllipticCurveTypeAliasModel.model_validate({"value": name}, strict=True)
    assert isinstance(model.value, curve_cls)

    assert isinstance(model.model_dump()["value"], curve_cls)
    assert model.model_dump(mode="json") == {"value": name}

    assert isinstance(
        EllipticCurveTypeAliasModel.model_validate_json(model.model_dump_json()).value, curve_cls
    )


@pytest.mark.parametrize("value", ("", "wrong", True, 42, ec.SECP224R1))
def test_elliptic_curve_errors(value: str) -> None:
    """Test invalid values for EllipticCurveTypeAliasModel."""
    with pytest.raises(ValueError):
        EllipticCurveTypeAliasModel(value=value)


@pytest.mark.parametrize("name,hash_cls", constants.HASH_ALGORITHM_TYPES.items())
def test_hash_algorithm(name: str, hash_cls: type[hashes.HashAlgorithm]) -> None:
    """Test EllipticCurveTypeAliasModel."""
    model = HashAlgorithmTypeAliasModel(value=name)
    assert isinstance(model.value, hash_cls)

    model = HashAlgorithmTypeAliasModel(value=hash_cls())
    assert isinstance(model.value, hash_cls)

    model = HashAlgorithmTypeAliasModel.model_validate({"value": name})
    assert isinstance(model.value, hash_cls)

    model = HashAlgorithmTypeAliasModel.model_validate({"value": name}, strict=True)
    assert isinstance(model.value, hash_cls)

    assert isinstance(model.model_dump()["value"], hash_cls)
    assert model.model_dump(mode="json") == {"value": name}

    assert isinstance(
        HashAlgorithmTypeAliasModel.model_validate_json(model.model_dump_json()).value, hash_cls
    )


@pytest.mark.xfail  # This currently works, unfortunately.
@pytest.mark.parametrize("hash_obj", (hashes.SM3(), hashes.BLAKE2b(64), hashes.BLAKE2s(32)))
def test_hash_algorithm_unsupported_types(hash_obj: hashes.HashAlgorithm) -> None:
    """Test that unsupported hash algorithm instances throw an error."""
    with pytest.raises(ValueError):
        HashAlgorithmTypeAliasModel(value=hash_obj)


@pytest.mark.parametrize("name,encoding", constants.CERTIFICATE_REVOCATION_LIST_ENCODING_TYPES.items())
def test_crl_encoding(name: str, encoding: Encoding) -> None:
    """Test CertificateRevocationListEncoding."""
    model = CertificateRevocationListEncodingTypeAliasModel(value=name)
    assert model.value == encoding

    model = CertificateRevocationListEncodingTypeAliasModel(value=encoding)
    assert model.value == encoding

    model = CertificateRevocationListEncodingTypeAliasModel.model_validate({"value": name})
    assert model.value == encoding

    model = CertificateRevocationListEncodingTypeAliasModel.model_validate({"value": name}, strict=True)
    assert model.value == encoding

    assert model.model_dump()["value"] == encoding
    assert model.model_dump(mode="json") == {"value": name}

    assert (
        CertificateRevocationListEncodingTypeAliasModel.model_validate_json(model.model_dump_json()).value
        == encoding
    )


@pytest.mark.parametrize("value", ("", "wrong", True))
def test_crl_encoding_errors(value: str) -> None:
    """Test invalid values for CertificateRevocationListEncodingTypeAliasModel."""
    with pytest.raises(ValueError):
        CertificateRevocationListEncodingTypeAliasModel(value=value)


@pytest.mark.parametrize("value", (Encoding.OpenSSH, Encoding.Raw, Encoding.SMIME, Encoding.X962))
def test_crl_encoding_unsupported_encodings(value: Encoding) -> None:
    """Test unsupported encodings."""
    with pytest.raises(ValueError, match=r"Input should be 'PEM' or 'DER'"):
        CertificateRevocationListEncodingTypeAliasModel(value=value.name)
    with pytest.raises(ValueError, match=r"Input should be 'PEM' or 'DER'"):
        CertificateRevocationListEncodingTypeAliasModel(value=value)


@pytest.mark.parametrize(
    "value,encoded",
    (
        (b"\xb5\xee\x0e\x01\x10U", "te4OARBV"),
        (b"\xb5\xee\x0e\x01\x10U\xaa", "te4OARBVqg=="),
        # Examples from Wikipedia
        (b"light work.", "bGlnaHQgd29yay4="),
        (b"light work", "bGlnaHQgd29yaw=="),
        (b"light wor", "bGlnaHQgd29y"),
        (b"light wo", "bGlnaHQgd28="),
        (b"light w", "bGlnaHQgdw=="),
    ),
)
def test_json_serializable_bytes(value: bytes, encoded: str) -> None:
    """Test Base64EncodedBytes."""
    model = JSONSerializableBytesModel(value=value)
    assert model.value == value
    assert JSONSerializableBytesModel.model_validate({"value": value}).value == value
    assert JSONSerializableBytesModel.model_validate({"value": value}).value == value
    assert JSONSerializableBytesModel.model_validate({"value": encoded}).value == value
    assert JSONSerializableBytesModel.model_validate({"value": encoded}, strict=True).value == value
    assert model.model_dump() == {"value": value}
    assert model.model_dump(mode="json") == {"value": encoded}


@pytest.mark.parametrize(
    "value,validated",
    (
        ("a", "A"),
        ("abc", "ABC"),
        ("0", "0"),  # single zero is not stripped
        ("1234567890abcdef", "1234567890ABCDEF"),  # all characters, lowercased
        ("1234567890ABCDEF", "1234567890ABCDEF"),  # all characters
        ("0abc", "ABC"),  # leading zero is stripped
        ("a" * 40, "A" * 40),  # maximum length
        (12345678, "BC614E"),
    ),
)
def test_serial(value: str, validated: str) -> None:
    """Test the Serial type alias."""
    model = SerialModel(value=value)
    assert model.value == validated
    assert SerialModel.model_validate({"value": value}).value == validated
    assert SerialModel.model_validate({"value": value}).value == validated
    assert SerialModel.model_validate({"value": validated}).value == validated
    assert SerialModel.model_validate({"value": validated}, strict=True).value == validated
    assert model.model_dump() == {"value": validated}
    assert model.model_dump(mode="json") == {"value": validated}


@pytest.mark.parametrize(
    "value",
    (
        "",  # too short
        True,  # invalid type
        "1" * 41,  # too long
        "x",  # invalid character
        "abcxdef",  # invalid character
    ),
)
def test_serial_errors(value: str) -> None:
    """Test invalid values for the Serial type alias."""
    with pytest.raises(ValueError):
        SerialModel(value=value)


@pytest.mark.parametrize(
    "value,expected",
    (
        (0, timedelta(seconds=0)),
        (1, timedelta(seconds=1)),
        (3600, timedelta(seconds=3600)),
    ),
)
def test_timedelta_in_seconds(value: int, expected: timedelta) -> None:
    """Test the TimedeltaInSeconds type alias."""
    model = TimedeltaInSecondsModel(value=value)
    assert model.value == expected
    assert TimedeltaInSecondsModel(value=expected).value == expected

    assert model.model_dump() == {"value": expected}
    assert model.model_dump(mode="json") == {"value": value}


@pytest.mark.parametrize("value", (1.1, "false"))
def test_timedelta_in_seconds_errors(value: Any) -> None:
    """Test wrong values for the TimedeltaInSeconds type alias."""
    with pytest.raises(ValueError):
        TimedeltaInSecondsModel(value=value)

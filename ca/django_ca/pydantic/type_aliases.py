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

"""Reusable type aliases for Pydantic models."""

import base64
from collections.abc import Hashable
from typing import Annotated, Any, Callable, Optional, TypeVar, Union

from pydantic import AfterValidator, BeforeValidator, Field, GetPydanticSchema, PlainSerializer
from pydantic_core import core_schema
from pydantic_core.core_schema import IsInstanceSchema, LiteralSchema

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding

from django_ca import constants
from django_ca.pydantic.validators import (
    base64_encoded_str_validator,
    int_to_hex_parser,
    is_power_two_validator,
    non_empty_validator,
    oid_parser,
    oid_validator,
    serial_validator,
    unique_validator,
)
from django_ca.typehints import AllowedHashTypes, CertificateRevocationListEncodings

T = TypeVar("T", bound=type[Any])


def _get_cryptography_schema(
    cls: Union[type[T], list[T]],
    type_mapping: dict[str, type[T]],
    name_mapping: dict[type[T], str],
    json_serializer: Optional[Callable[[T], str]] = None,
    str_loader: Optional[Callable[[str], T]] = None,
) -> GetPydanticSchema:
    if json_serializer is None:

        def json_serializer(instance: T) -> str:
            return name_mapping[type(instance)]

    if str_loader is None:

        def str_loader(value: str) -> T:
            return type_mapping[value]()  # type: ignore[no-any-return,misc]  # false positive

    json_schema = core_schema.chain_schema(
        [
            core_schema.literal_schema(list(type_mapping)),
            core_schema.no_info_plain_validator_function(str_loader),
        ]
    )

    if isinstance(cls, list):
        python_schema: Union[LiteralSchema, IsInstanceSchema] = core_schema.literal_schema(cls)
    else:
        python_schema = core_schema.is_instance_schema(cls)

    return GetPydanticSchema(
        lambda tp, handler: core_schema.json_or_python_schema(
            json_schema=json_schema,
            python_schema=core_schema.union_schema([python_schema, json_schema]),
            serialization=core_schema.plain_serializer_function_ser_schema(json_serializer, when_used="json"),
        )
    )


#: A bytes type that validates strings as base64-encoded strings and serializes as such when using JSON.
#:
#: This type differs from ``pydantic.Base64Bytes`` in that bytes are left untouched and strings are decoded
#: `before` the inner validation logic, making this type suitable for strict type validation.
Base64EncodedBytes = Annotated[
    bytes,
    BeforeValidator(base64_encoded_str_validator),
    PlainSerializer(
        lambda value: base64.b64encode(value).decode(encoding="ascii"), return_type=str, when_used="json"
    ),
]


#: A type alias for :py:class:`~cg:cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve` instances.
#:
#: This type alias validates names from :py:attr:`~django_ca.constants.ELLIPTIC_CURVE_TYPES` and serializes
#: to the canonical name in JSON. Models using this type alias can be used with strict schema validation.
EllipticCurveTypeAlias = Annotated[
    ec.EllipticCurve,
    _get_cryptography_schema(
        ec.EllipticCurve, constants.ELLIPTIC_CURVE_TYPES, constants.ELLIPTIC_CURVE_NAMES
    ),
]

#: A type alias for :py:class:`~cg:cryptography.hazmat.primitives.hashes.HashAlgorithm` instances.
#:
#: This type alias validates names from :py:attr:`~django_ca.constants.HASH_ALGORITHM_TYPES` and serializes
#: to the canonical name in JSON. Models using this type alias can be used with strict schema validation.
HashAlgorithmTypeAlias = Annotated[
    AllowedHashTypes,
    _get_cryptography_schema(
        hashes.HashAlgorithm, constants.HASH_ALGORITHM_TYPES, constants.HASH_ALGORITHM_NAMES
    ),
]

#: A type alias for :py:class:`~cg:cryptography.hazmat.primitives.serialization.Encoding` instances.
#:
#: This type alias validates names from
#: :py:attr:`~django_ca.constants.CERTIFICATE_REVOCATION_LIST_ENCODING_TYPES` and serializes to the canonical
#: name in JSON. Models using this type alias can be used with strict schema validation.
CertificateRevocationListEncodingTypeAlias = Annotated[
    CertificateRevocationListEncodings,
    _get_cryptography_schema(
        list(constants.CERTIFICATE_REVOCATION_LIST_ENCODING_NAMES),
        constants.CERTIFICATE_REVOCATION_LIST_ENCODING_TYPES,
        constants.CERTIFICATE_REVOCATION_LIST_ENCODING_NAMES,
        json_serializer=lambda v: v.name,
        str_loader=lambda v: Encoding[v],
    ),
]

#: A type alias for an integer that is a power of two, e.g. an RSA/DSA KeySize.
#:
#: Note that this type alias does not validate :ref:`settings-ca-min-key-size`, as validators in this module
#: must not use any settings, as this would cause a circular import.
PowerOfTwoInt = Annotated[int, AfterValidator(is_power_two_validator)]

#: A certificate serial as a hex string, as they are stored in the database.
#:
#: This type will convert integers to hex, upper-case any lower-case strings and remove ':'. The minimum
#: length is 1 character, the maximum length is 40 (RFC 5280, section 4.1.2.2 specifies a maximum of 20
#: octets, which equals 40 characters in hex).
Serial = Annotated[
    str,
    BeforeValidator(int_to_hex_parser),
    AfterValidator(serial_validator),
    Field(min_length=1, max_length=40, pattern="^[A-F0-9]+$"),
]


NonEmptyOrderedSetTypeVar = TypeVar("NonEmptyOrderedSetTypeVar", bound=list[Any])

OIDType = Annotated[str, BeforeValidator(oid_parser), AfterValidator(oid_validator)]

UniqueTupleTypeVar = TypeVar("UniqueTupleTypeVar", bound=tuple[Hashable, ...])
UniqueElementsTuple = Annotated[UniqueTupleTypeVar, AfterValidator(unique_validator)]

# A list validated to be non-empty and have a unique set of elements.
NonEmptyOrderedSet = Annotated[
    NonEmptyOrderedSetTypeVar, AfterValidator(unique_validator), AfterValidator(non_empty_validator)
]

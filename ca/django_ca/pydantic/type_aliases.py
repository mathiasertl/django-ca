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
import re
from datetime import timedelta
from typing import Annotated, Any, TypeVar

from pydantic import AfterValidator, BeforeValidator, Field, GetPydanticSchema, PlainSerializer
from pydantic_core import core_schema

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from django_ca import constants
from django_ca.pydantic.validators import (
    base64_encoded_str_validator,
    int_to_hex_parser,
    is_power_two_validator,
    non_empty_validator,
    oid_parser,
    oid_validator,
    unique_str_validator,
)
from django_ca.typehints import AllowedHashTypes

T = TypeVar("T", bound=type[Any])


def _get_cryptography_schema(
    cls: type[T], type_mapping: dict[str, type[T]], name_mapping: dict[type[T], str]
) -> GetPydanticSchema:
    json_schema = core_schema.chain_schema(
        [
            core_schema.literal_schema(list(type_mapping)),
            core_schema.no_info_plain_validator_function(
                lambda value: type_mapping[value]()  # type: ignore[misc]  # False positive
            ),
        ]
    )
    return GetPydanticSchema(
        lambda tp, handler: core_schema.json_or_python_schema(
            json_schema=json_schema,
            python_schema=core_schema.union_schema([core_schema.is_instance_schema(cls), json_schema]),
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda instance: name_mapping[type(instance)], when_used="json"
            ),
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

#: A type alias for an integer that is a power of two, e.g. an RSA/DSA KeySize.
#:
#: Note that this type alias does not validate :ref:`settings-ca-min-key-size`, as validators in this module
#: must not use any settings, as this would cause a circular import.
PowerOfTwoTypeAlias = Annotated[int, AfterValidator(is_power_two_validator)]

#: A certificate serial as a hex string, as they are stored in the database.
#:
#: This type will convert integers to hex and upper-case any lower-case strings. The minimum length is 1
#: character, the maximum length is 40 (RFC 5280, section 4.1.2.2 specifies a maximum of 20 octets, which
#: equals 40 characters in hex).
Serial = Annotated[
    str,
    BeforeValidator(int_to_hex_parser),
    AfterValidator(str.upper),
    Field(min_length=1, max_length=40, pattern=re.compile("^[A-F0-9]+$")),
]

_timedelta_json_schema = core_schema.chain_schema(
    [
        core_schema.int_schema(),
        core_schema.no_info_plain_validator_function(lambda value: timedelta(seconds=value)),
    ]
)
TimedeltaInSeconds = Annotated[
    int,
    GetPydanticSchema(
        lambda tp, handler: core_schema.json_or_python_schema(
            json_schema=_timedelta_json_schema,
            python_schema=core_schema.union_schema(
                [core_schema.is_instance_schema(timedelta), _timedelta_json_schema]
            ),
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda instance: int(instance.total_seconds()), when_used="json"
            ),
        )
    ),
]

NonEmptyOrderedSetTypeVar = TypeVar("NonEmptyOrderedSetTypeVar", bound=list[Any])

OIDType = Annotated[str, BeforeValidator(oid_parser), AfterValidator(oid_validator)]

# A list validated to be non-empty and have a unique set of elements.
NonEmptyOrderedSet = Annotated[
    NonEmptyOrderedSetTypeVar, AfterValidator(unique_str_validator), AfterValidator(non_empty_validator)
]

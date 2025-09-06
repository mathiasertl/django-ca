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

from collections.abc import Hashable
from datetime import timedelta
from typing import Annotated, Any, TypeVar

from annotated_types import Ge
from pydantic import AfterValidator, BeforeValidator, Field

from cryptography import x509

from django.utils.functional import Promise

from django_ca.pydantic.schemas import get_promise_schema
from django_ca.pydantic.validators import (
    SignatureHashAlgorithmValidator,
    base64_str_validator,
    bytes_to_base64_str_validator,
    elliptic_curve_validator,
    int_to_hex_parser,
    is_power_two_validator,
    non_empty_validator,
    oid_parser,
    oid_validator,
    reason_flag_crl_scope_validator,
    reason_flag_validator,
    serial_validator,
    timedelta_as_number_parser,
    unique_validator,
)
from django_ca.typehints import (
    EllipticCurveName,
    SignatureHashAlgorithmName,
    SignatureHashAlgorithmNameWithLegacy,
)

T = TypeVar("T", bound=type[Any])


PromiseTypeAlias = Annotated[Promise, get_promise_schema(), Field(validate_default=True)]
"""Type alias for Djangos lazily translated strings.

Translated strings will be evaluated (= translated) upon JSON serialization. For JSON schemas, this type alias
identifies itself as a normal string. 
"""


Base64EncodedBytes = Annotated[
    str, BeforeValidator(bytes_to_base64_str_validator), AfterValidator(base64_str_validator)
]
"""A str type that converts bytes to base64-encoded strings.

This type differs from ``pydantic.Base64Bytes`` in that bytes will be considered as *unencoded* input and
converted to base64.
"""


#: A subset of :class:`~cg:cryptography.x509.ReasonFlags` that allows only reason codes valid in a certificate
#: revocation list (CRL).
CertificateRevocationListReasonCode = Annotated[
    x509.ReasonFlags, BeforeValidator(reason_flag_validator), AfterValidator(reason_flag_crl_scope_validator)
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

#: A string that will convert :py:class:`~cg:cryptography.x509.ObjectIdentifier` objects.
#:
#: This type alias will also validate the x509 dotted string format.
OIDType = Annotated[str, BeforeValidator(oid_parser), AfterValidator(oid_validator)]

AnnotatedEllipticCurveName = Annotated[EllipticCurveName, BeforeValidator(elliptic_curve_validator)]
"""Annotated version of :py:attr:`~django_ca.typehints.EllipticCurveName`.

This type will also accept instances of |EllipticCurve| and convert them transparently.
"""

AnnotatedSignatureHashAlgorithmName = Annotated[
    SignatureHashAlgorithmName, BeforeValidator(SignatureHashAlgorithmValidator())
]
"""Annotated version of :py:attr:`~django_ca.typehints.SignatureHashAlgorithmName`.

This type will also accept instances of |HashAlgorithm| and convert them transparently.
"""

AnnotatedSignatureHashAlgorithmNameWithLegacy = Annotated[
    SignatureHashAlgorithmNameWithLegacy, BeforeValidator(SignatureHashAlgorithmValidator(legacy=True))
]
"""Same as :attr:`~django_ca.pydantic.type_aliases.AnnotatedSignatureHashAlgorithmName`, but also accepts
legacy algorithms."""

DayValidator = BeforeValidator(timedelta_as_number_parser("days"))
PositiveTimedelta = Annotated[timedelta, Ge(timedelta(seconds=0))]

UniqueTupleTypeVar = TypeVar("UniqueTupleTypeVar", bound=tuple[Hashable, ...])
UniqueElementsTuple = Annotated[UniqueTupleTypeVar, AfterValidator(unique_validator)]

# A list validated to be non-empty and have a unique set of elements.
NonEmptyOrderedSet = Annotated[
    NonEmptyOrderedSetTypeVar, AfterValidator(unique_validator), AfterValidator(non_empty_validator)
]

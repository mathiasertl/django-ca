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

"""Various type aliases used in throughout django-ca."""

import argparse
import ipaddress
import sys
import typing
from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Any, Dict, List, Literal, Optional, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.certificate_transparency import SignedCertificateTimestamp

from django.core.management.base import CommandParser

# IMPORTANT: Do **not** import any module from django_ca at runtime here, or you risk circular imports.

# Module level imports to enable forward references. See also:
#
#   https://peps.python.org/pep-0484/#forward-references
if typing.TYPE_CHECKING:
    from django_ca import models

if sys.version_info[:2] < (3, 9):  # pragma: only py<3.9
    from typing import Annotated as Annotated  # noqa: PLC0414
else:  # pragma: only py>=3.9
    from typing import Annotated as Annotated  # noqa: PLC0414


class SupportsLessThan(typing.Protocol):
    """Protocol that specifies <, making something sortable."""

    def __lt__(self, __other: Any) -> bool:  # pragma: nocover
        ...


# pylint: disable-next=invalid-name
JSON = Union[Dict[str, "JSON"], List["JSON"], str, int, float, bool, None]

#: Hash algorithms that can be used for signing certificates.
#: NOTE: This is a duplicate of the protected ``cryptography.x509.base._AllowedHashTypes``.
AllowedHashTypes = typing.Union[
    hashes.SHA224,
    hashes.SHA256,
    hashes.SHA384,
    hashes.SHA512,
    hashes.SHA3_224,
    hashes.SHA3_256,
    hashes.SHA3_384,
    hashes.SHA3_512,
]

ExtensionDict = Dict[x509.ObjectIdentifier, x509.Extension[x509.ExtensionType]]

ParsableName = Union[str, Iterable[Tuple[str, str]]]

Expires = Optional[Union[int, datetime, timedelta]]
ParsableKeyType = typing.Literal["RSA", "DSA", "EC", "Ed25519", "Ed448"]
ParsableSubject = Union[
    str,
    # Union for keys is not supported, see: https://github.com/python/mypy/issues/6001
    typing.Mapping[x509.ObjectIdentifier, Union[str, Iterable[str]]],
    typing.Mapping[str, Union[str, Iterable[str]]],
    x509.Name,
    Iterable[Tuple[Union[x509.ObjectIdentifier, str], Union[str, Iterable[str]]]],
]

# GeneralNameList
ParsableGeneralName = Union[x509.GeneralName, str]
ParsableGeneralNameList = Iterable[ParsableGeneralName]

class SerializedExtension(typing.TypedDict):
    critical: bool
    value: Any
class SerializedObjectIdentifier(typing.TypedDict):
    oid: str
    value: str
SerializedName = List[SerializedObjectIdentifier]


# Looser variants of the above for incoming arguments
class ParsableNoticeReference(typing.TypedDict, total=False):
    organization: str
    notice_numbers: Iterable[int]
class ParsableUserNotice(typing.TypedDict, total=False):
    notice_reference: Union[x509.NoticeReference, ParsableNoticeReference]
    explicit_text: str

# Parsable arguments
class ParsableDistributionPoint(typing.TypedDict, total=False):
    full_name: Optional[ParsableGeneralNameList]
    relative_name: Union[SerializedName, x509.RelativeDistinguishedName]
    crl_issuer: ParsableGeneralNameList
    reasons: Iterable[Union[str, x509.ReasonFlags]]
ParsablePolicyQualifier = Union[str, x509.UserNotice, ParsableUserNotice]
ParsablePolicyIdentifier = Union[str, x509.ObjectIdentifier]
class ParsablePolicyInformation(typing.TypedDict, total=False):
    policy_identifier: ParsablePolicyIdentifier
    policy_qualifiers: Optional[typing.Sequence[ParsablePolicyQualifier]]

PolicyQualifier = Union[str, x509.UserNotice]

class ParsableExtension(typing.TypedDict, total=False):
    critical: bool
    value: Any


class BasicConstraintsBase(typing.TypedDict):
    ca: bool
class ParsableAuthorityKeyIdentifierDict(typing.TypedDict, total=False):
    key_identifier: Optional[bytes]
    authority_cert_issuer: Iterable[str]
    authority_cert_serial_number: Optional[int]


class SerializedNullExtension(typing.TypedDict):
    critical: bool

############
# Literals #
############

#: Valid types of general names.
GeneralNames = Literal["email", "URI", "IP", "DNS", "RID", "dirName", "otherName"]

#: Valid hash algorithm names.
#:
#: These names are used in various settings, with the ``--algorithm`` command line parameter and in the API.
HashAlgorithms = Literal[
    "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA3/224", "SHA3/256", "SHA3/384", "SHA3/512"
]

SubjectFormats = Literal["openssl", "rfc4514"]  # pragma: only django-ca<=2.2  # will be removed in 2.2

#: Serialized values of :py:class:`~cg:cryptography.x509.certificate_transparency.LogEntryType` instances.
LogEntryTypes = Literal["precertificate", "x509_certificate"]

#: Serialized access method for :py:class:`~cg:cryptography.x509.AccessDescription` instances.
AccessMethods = Literal["ocsp", "ca_issuers", "ca_repository"]

#: List of possible values for :py:class:`~cg:cryptography.x509.KeyUsage` instances.
KeyUsages = Literal[
    "crl_sign",
    "data_encipherment",
    "decipher_only",
    "digital_signature",
    "encipher_only",
    "key_agreement",
    "key_cert_sign",
    "key_encipherment",
    "content_commitment",
]

DistributionPointReasons = Literal[
    "aa_compromise",
    "affiliation_changed",
    "ca_compromise",
    "certificate_hold",
    "cessation_of_operation",
    "key_compromise",
    "privilege_withdrawn",
    "superseded",
]

#: Valid OtherName types
OtherNames = Literal[
    "UTF8String",
    "UNIVERSALSTRING",
    "IA5STRING",
    "BOOLEAN",
    "NULL",
    "UTCTIME",
    "GENERALIZEDTIME",
    "INTEGER",
    "OctetString",
]

# only py<3.8: python3.9 supports DistributionPointReasons | Literal["unspecified", "remove_from_crl"]
Reasons = Literal[
    "key_compromise",
    "ca_compromise",
    "affiliation_changed",
    "superseded",
    "cessation_of_operation",
    "certificate_hold",
    "privilege_withdrawn",
    "aa_compromise",
    "unspecified",
    "remove_from_crl",
]

EllipticCurves = Literal[
    "sect571r1",
    "sect409r1",
    "sect283r1",
    "sect233r1",
    "sect163r2",
    "sect571k1",
    "sect409k1",
    "sect283k1",
    "sect233k1",
    "sect163k1",
    "secp521r1",
    "secp384r1",
    "secp256r1",
    "secp256k1",
    "secp224r1",
    "secp192r1",
    "brainpoolP256r1",
    "brainpoolP384r1",
    "brainpoolP512r1",
]

################
# Type aliases #
################
ExtensionMapping = Dict[x509.ObjectIdentifier, x509.Extension[x509.ExtensionType]]

# Type aliases for protected subclass returned by add_argument_group().
ArgumentGroup = argparse._ArgumentGroup  # pylint: disable=protected-access

# An CommandParser (subclass of argparse.ArgumentParser) or an argument group added by add_argument_group().
ActionsContainer = Union[CommandParser, ArgumentGroup]

############
# TypeVars #
############
# pylint: disable-next=invalid-name  # Should match class, but pylint is more sensitive here
X509CertMixinTypeVar = typing.TypeVar("X509CertMixinTypeVar", bound="models.X509CertMixin")

ExtensionTypeVar = typing.TypeVar("ExtensionTypeVar", bound=x509.Extension[x509.ExtensionType])

# A TypeVar bound to :py:class:`~cg:cryptography.x509.ExtensionType`.
ExtensionTypeTypeVar = typing.TypeVar("ExtensionTypeTypeVar", bound=x509.ExtensionType)


AlternativeNameTypeVar = typing.TypeVar(
    "AlternativeNameTypeVar", x509.SubjectAlternativeName, x509.IssuerAlternativeName
)
CRLExtensionTypeTypeVar = typing.TypeVar(
    "CRLExtensionTypeTypeVar", x509.CRLDistributionPoints, x509.FreshestCRL
)
InformationAccessTypeVar = typing.TypeVar(
    "InformationAccessTypeVar", x509.AuthorityInformationAccess, x509.SubjectInformationAccess
)
NoValueExtensionTypeVar = typing.TypeVar("NoValueExtensionTypeVar", x509.OCSPNoCheck, x509.PrecertPoison)

SignedCertificateTimestampTypeVar = typing.TypeVar(
    "SignedCertificateTimestampTypeVar",
    x509.PrecertificateSignedCertificateTimestamps,
    x509.SignedCertificateTimestamps,
)

##############################
# Serialized Pydantic models #
##############################

class SerializedPydanticNameAttribute(typing.TypedDict):
    oid: str
    value: str
SerializedPydanticName = List[SerializedPydanticNameAttribute]

class SerializedPydanticExtension(typing.TypedDict):
    type: str
    critical: bool
    value: Any

class SerializedProfile(typing.TypedDict):
    name: str
    description: str
    subject: Optional[SerializedPydanticName]
    algorithm: Optional[HashAlgorithms]
    extensions: List[SerializedPydanticExtension]
    clear_extensions: List[str]


#####################
# Serialized values #
#####################
# Collect JSON-serializable versions of cryptography values. Typehints in this section start with
# "Serialized...".
class SerializedAuthorityInformationAccess(typing.TypedDict, total=False):
    issuers: List[str]
    ocsp: List[str]
class SerializedAuthorityKeyIdentifier(typing.TypedDict, total=False):
    key_identifier: str
    authority_cert_issuer: List[str]
    authority_cert_serial_number: int


class SerializedBasicConstraints(BasicConstraintsBase, total=False):
    """Serialized representation of a BasicConstraints extension.

    A value of this type is a dictionary with a ``"ca"`` key with a boolean value. If ``True``, it also
    has a ``"path_length"`` value that is either ``None`` or an int.
    """

    path_length: Optional[int]


class SerializedDistributionPoint(typing.TypedDict, total=False):
    full_name: List[str]
    relative_name: SerializedName
    crl_issuer: List[str]
    reasons: List[str]
class SerializedDistributionPoints(typing.TypedDict):
    critical: bool
    value: List[SerializedDistributionPoint]

class SerializedNameConstraints(typing.TypedDict, total=False):
    permitted: List[str]
    excluded: List[str]
class SerializedPolicyConstraints(typing.TypedDict, total=False):
    inhibit_policy_mapping: int
    require_explicit_policy: int

# PolicyInformation serialization
class SerializedNoticeReference(typing.TypedDict, total=False):
    organization: str
    notice_numbers: List[int]
class SerializedUserNotice(typing.TypedDict, total=False):
    explicit_text: str
    notice_reference: SerializedNoticeReference
SerializedPolicyQualifier = Union[str, SerializedUserNotice]
SerializedPolicyQualifiers = List[SerializedPolicyQualifier]
class SerializedPolicyInformation(typing.TypedDict):
    policy_identifier: str
    policy_qualifiers: Optional[SerializedPolicyQualifiers]

class SerializedSignedCertificateTimestamp(typing.TypedDict):
    log_id: str
    timestamp: str
    type: str
    version: str
"""A dictionary with four keys: log_id, timestamp, type, version, values are all str."""

###################
# Parsable values #
###################
# Collect typehints for values that can be parsed back into cryptography values. Typehints in this section
# start with "Parsable...".

ParsableAuthorityKeyIdentifier = Union[str, bytes, ParsableAuthorityKeyIdentifierDict]
class ParsableAuthorityInformationAccess(typing.TypedDict, total=False):
    ocsp: Optional[ParsableGeneralNameList]
    issuers: Optional[ParsableGeneralNameList]


class ParsableBasicConstraints(BasicConstraintsBase, total=False):
    """Serialized representation of a BasicConstraints extension.

    A value of this type is a dictionary with a ``"ca"`` key with a boolean value. If ``True``, it also
    has a ``"path_length"`` value that is either ``None`` or an int.
    """

    path_length: Union[int, str]


class ParsableNameConstraints(typing.TypedDict, total=False):
    permitted: ParsableGeneralNameList
    excluded: ParsableGeneralNameList

class ParsablePolicyConstraints(typing.TypedDict, total=False):
    require_explicit_policy: int
    inhibit_policy_mapping: int
ParsableSignedCertificateTimestamp = Union[SerializedSignedCertificateTimestamp, SignedCertificateTimestamp]
ParsableSubjectKeyIdentifier = Union[str, bytes, x509.SubjectKeyIdentifier]


#####################
# Type alternatives #
#####################
# Collect Union[] typehints that occur multiple times, e.g. multiple x509.ExtensionType classes that behave
# the same way. Typehints in this section are named "...Type".

AlternativeNameExtensionType = Union[x509.SubjectAlternativeName, x509.IssuerAlternativeName]
CRLExtensionType = Union[x509.FreshestCRL, x509.CRLDistributionPoints]
InformationAccessExtensionType = Union[x509.AuthorityInformationAccess, x509.SubjectInformationAccess]
SignedCertificateTimestampType = Union[
    x509.PrecertificateSignedCertificateTimestamps, x509.SignedCertificateTimestamps
]

#: Union of all IP address types
IPAddressType = Union[
    ipaddress.IPv4Address, ipaddress.IPv6Address, ipaddress.IPv4Network, ipaddress.IPv6Network
]

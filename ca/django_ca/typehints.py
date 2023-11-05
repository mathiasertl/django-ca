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
import typing
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Literal, Optional, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.certificate_transparency import SignedCertificateTimestamp

from django.core.management.base import CommandParser

# Module level imports to enable forward references. See also:
#
#   https://peps.python.org/pep-0484/#forward-references
if typing.TYPE_CHECKING:
    from django_ca import models


class SupportsLessThan(typing.Protocol):
    """Protocol that specifies <, making something sortable."""

    def __lt__(self, __other: Any) -> bool:  # pragma: nocover
        ...


# pylint: disable-next=invalid-name
JSON = Union[Dict[str, "JSON"], List["JSON"], str, int, float, bool, None]

# from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes

CRLExtensionTypeTypeVar = typing.TypeVar(
    "CRLExtensionTypeTypeVar", x509.CRLDistributionPoints, x509.FreshestCRL
)

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

KeyUsages = typing.Literal[
    "cRLSign",
    "dataEncipherment",
    "decipherOnly",
    "digitalSignature",
    "encipherOnly",
    "keyAgreement",
    "keyCertSign",
    "keyEncipherment",
    "nonRepudiation",  # http://marc.info/?t=107176106300005&r=1&w=2
]


ParsableName = Union[str, Iterable[Tuple[str, str]]]

Expires = Optional[Union[int, datetime, timedelta]]
ParsableHash = Optional[Union[str, AllowedHashTypes]]
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

SerializedExtension = typing.TypedDict(
    "SerializedExtension",
    {
        "critical": bool,
        # Value should be a generic typevar, but this is not yet supported in mypy:
        #   https://github.com/python/mypy/issues/3863
        "value": Any,
    },
)
SerializedObjectIdentifier = typing.TypedDict(
    "SerializedObjectIdentifier",
    {
        "oid": str,
        "value": str,
    },
)
SerializedName = List[SerializedObjectIdentifier]
SerializedProfile = typing.TypedDict(
    "SerializedProfile",
    {
        "cn_in_san": bool,
        "description": str,
        "subject": Optional[SerializedName],
        "extensions": Dict[str, Any],
    },
)


# Looser variants of the above for incoming arguments
ParsableNoticeReference = typing.TypedDict(
    "ParsableNoticeReference", {"organization": str, "notice_numbers": Iterable[int]}, total=False
)
ParsableUserNotice = typing.TypedDict(
    "ParsableUserNotice",
    {"notice_reference": Union[x509.NoticeReference, ParsableNoticeReference], "explicit_text": str},
    total=False,
)

# Parsable arguments
ParsableDistributionPoint = typing.TypedDict(
    "ParsableDistributionPoint",
    {
        "full_name": Optional[ParsableGeneralNameList],
        "relative_name": Union[SerializedName, x509.RelativeDistinguishedName],
        "crl_issuer": ParsableGeneralNameList,
        "reasons": Iterable[Union[str, x509.ReasonFlags]],
    },
    total=False,
)
ParsablePolicyQualifier = Union[str, x509.UserNotice, ParsableUserNotice]
ParsablePolicyIdentifier = Union[str, x509.ObjectIdentifier]
ParsablePolicyInformation = typing.TypedDict(
    "ParsablePolicyInformation",
    {
        "policy_identifier": ParsablePolicyIdentifier,
        "policy_qualifiers": Optional[typing.Sequence[ParsablePolicyQualifier]],
    },
    total=False,
)

PolicyQualifier = Union[str, x509.UserNotice]

ExtensionTypeTypeVar = typing.TypeVar("ExtensionTypeTypeVar", bound=x509.ExtensionType)
# """A type variable for a :py:class:`~cg:cryptography.x509.ExtensionType` instance."""

ParsableExtension = typing.TypedDict(
    "ParsableExtension",
    {
        "critical": bool,
        # Value should be a generic typevar, but this is not yet supported in mypy:
        #   https://github.com/python/mypy/issues/3863
        "value": Any,
    },
    total=False,
)

if typing.TYPE_CHECKING:
    ExtensionTypeVar = x509.Extension[ExtensionTypeTypeVar]
    ExtensionType = x509.Extension[x509.ExtensionType]
    SubjectKeyIdentifierType = x509.Extension[x509.SubjectKeyIdentifier]
    UnrecognizedExtensionType = x509.Extension[x509.UnrecognizedExtension]
    TLSFeatureExtensionType = x509.Extension[x509.TLSFeature]
    PrecertificateSignedCertificateTimestampsType = x509.Extension[
        x509.PrecertificateSignedCertificateTimestamps
    ]
else:
    ExtensionType = ExtensionTypeVar = x509.Extension
    SubjectKeyIdentifierType = (
        TLSFeatureExtensionType
    ) = UnrecognizedExtensionType = PrecertificateSignedCertificateTimestampsType = x509.ExtensionType


BasicConstraintsBase = typing.TypedDict("BasicConstraintsBase", {"ca": bool})
ParsableAuthorityKeyIdentifierDict = typing.TypedDict(
    "ParsableAuthorityKeyIdentifierDict",
    {
        "key_identifier": Optional[bytes],
        "authority_cert_issuer": Iterable[str],
        "authority_cert_serial_number": Optional[int],
    },
    total=False,
)


SerializedNullExtension = typing.TypedDict("SerializedNullExtension", {"critical": bool})

############
# Literals #
############
SubjectFormats = Literal["openssl", "rfc4514"]  # pragma: only django-ca<=2.2  # will be removed in 2.2

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


#####################
# Serialized values #
#####################
# Collect JSON-serializable versions of cryptography values. Typehints in this section start with
# "Serialized...".
SerializedAuthorityInformationAccess = typing.TypedDict(
    "SerializedAuthorityInformationAccess",
    {
        "issuers": List[str],
        "ocsp": List[str],
    },
    total=False,
)
SerializedAuthorityKeyIdentifier = typing.TypedDict(
    "SerializedAuthorityKeyIdentifier",
    {
        "key_identifier": str,
        "authority_cert_issuer": List[str],
        "authority_cert_serial_number": int,
    },
    total=False,
)


# pylint: disable-next=inherit-non-class; False positive
class SerializedBasicConstraints(BasicConstraintsBase, total=False):
    """Serialized representation of a BasicConstraints extension.

    A value of this type is a dictionary with a ``"ca"`` key with a boolean value. If ``True``, it also
    has a ``"path_length"`` value that is either ``None`` or an int.
    """

    path_length: Optional[int]


SerializedDistributionPoint = typing.TypedDict(
    "SerializedDistributionPoint",
    {
        "full_name": List[str],
        "relative_name": SerializedName,
        "crl_issuer": List[str],
        "reasons": List[str],
    },
    total=False,
)
SerializedDistributionPoints = typing.TypedDict(
    "SerializedDistributionPoints",
    {
        "critical": bool,
        "value": List[SerializedDistributionPoint],
    },
)

SerializedNameConstraints = typing.TypedDict(
    "SerializedNameConstraints",
    {
        "permitted": List[str],
        "excluded": List[str],
    },
    total=False,
)
SerializedPolicyConstraints = typing.TypedDict(
    "SerializedPolicyConstraints",
    {
        "inhibit_policy_mapping": int,
        "require_explicit_policy": int,
    },
    total=False,
)

# PolicyInformation serialization
SerializedNoticeReference = typing.TypedDict(
    "SerializedNoticeReference", {"organization": str, "notice_numbers": List[int]}, total=False
)
SerializedUserNotice = typing.TypedDict(
    "SerializedUserNotice", {"explicit_text": str, "notice_reference": SerializedNoticeReference}, total=False
)
SerializedPolicyQualifier = Union[str, SerializedUserNotice]
SerializedPolicyQualifiers = List[SerializedPolicyQualifier]
SerializedPolicyInformation = typing.TypedDict(
    "SerializedPolicyInformation",
    {"policy_identifier": str, "policy_qualifiers": Optional[SerializedPolicyQualifiers]},
)

SerializedSignedCertificateTimestamp = typing.TypedDict(
    "SerializedSignedCertificateTimestamp",
    {
        "log_id": str,
        "timestamp": str,
        "type": str,
        "version": str,
    },
)
"""A dictionary with four keys: log_id, timestamp, type, version, values are all str."""

###################
# Parsable values #
###################
# Collect typehints for values that can be parsed back into cryptography values. Typehints in this section
# start with "Parsable...".

ParsableAuthorityKeyIdentifier = Union[str, bytes, ParsableAuthorityKeyIdentifierDict]
ParsableAuthorityInformationAccess = typing.TypedDict(
    "ParsableAuthorityInformationAccess",
    {
        "ocsp": Optional[ParsableGeneralNameList],
        "issuers": Optional[ParsableGeneralNameList],
    },
    total=False,
)


# pylint: disable-next=inherit-non-class; False positive
class ParsableBasicConstraints(BasicConstraintsBase, total=False):
    """Serialized representation of a BasicConstraints extension.

    A value of this type is a dictionary with a ``"ca"`` key with a boolean value. If ``True``, it also
    has a ``"path_length"`` value that is either ``None`` or an int.
    """

    path_length: Union[int, str]


ParsableNameConstraints = typing.TypedDict(
    "ParsableNameConstraints",
    {
        "permitted": ParsableGeneralNameList,
        "excluded": ParsableGeneralNameList,
    },
    total=False,
)

ParsablePolicyConstraints = typing.TypedDict(
    "ParsablePolicyConstraints",
    {
        "require_explicit_policy": int,
        "inhibit_policy_mapping": int,
    },
    total=False,
)
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

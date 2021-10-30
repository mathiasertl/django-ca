# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca.  If not,
# see <http://www.gnu.org/licenses/>.

"""Various type aliases used in throughout django-ca."""

import sys
import typing
from datetime import datetime
from datetime import timedelta
from typing import TYPE_CHECKING
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Mapping
from typing import Optional
from typing import Sequence
from typing import Tuple
from typing import TypeVar
from typing import Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed448
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.certificate_transparency import SignedCertificateTimestamp

# pylint: disable=useless-import-alias; or mypy won't consider imports as "re-exported"
# NOTE: Explicit re-export (... import foo as foo) to make classes usable in other modules
if sys.version_info >= (3, 8):  # pragma: only py>=3.8
    from typing import Literal as Literal
    from typing import Protocol as Protocol
    from typing import SupportsIndex as SupportsIndex
    from typing import TypedDict as TypedDict
else:  # pragma: only py<3.8
    # pylint: disable=import-error; typing_extensions is not present in newer environments
    from typing_extensions import Literal as Literal
    from typing_extensions import Protocol as Protocol
    from typing_extensions import SupportsIndex as SupportsIndex  # NOQA: F401 # only for re-export
    from typing_extensions import TypedDict as TypedDict

    # pylint: enable=import-error
# pylint: enable=useless-import-alias


class SupportsLessThan(Protocol):
    """Protocol that specifies <, making something sortable."""

    def __lt__(self, __other: Any) -> bool:  # pragma: nocover
        ...


CRLExtensionTypeTypeVar = TypeVar("CRLExtensionTypeTypeVar", x509.CRLDistributionPoints, x509.FreshestCRL)

PrivateKeyTypes = Union[
    rsa.RSAPrivateKey,
    dsa.DSAPrivateKey,
    ec.EllipticCurvePrivateKey,
    ed25519.Ed25519PrivateKey,
]

try:
    # pylint: disable=ungrouped-imports; pylint wants us to group it with global imports
    # pylint: disable=useless-import-alias; or mypy won't consider imports as "re-exported"
    from cryptography.hazmat.primitives.asymmetric.types import PRIVATE_KEY_TYPES as PRIVATE_KEY_TYPES

    # pylint: enable=useless-import-alias,ungrouped-imports
except ImportError:  # pragma: only cryptography<35.0
    # MYPY NOTE: Cannot re-assign type alias from above. We ignore the error here as mypy requires
    #            cryptography>=35.0 anyway
    # PYLINT NOTE: Name is given by import above
    PRIVATE_KEY_TYPES = Union[  # type: ignore[misc]  # pylint: disable=invalid-name
        rsa.RSAPrivateKey,
        dsa.DSAPrivateKey,
        ec.EllipticCurvePrivateKey,
        ed25519.Ed25519PrivateKey,
        ed448.Ed448PrivateKey,
    ]

Expires = Optional[Union[int, datetime, timedelta]]
ParsableHash = Optional[Union[str, hashes.HashAlgorithm]]
ParsableKeyType = Literal["RSA", "DSA", "ECC", "EdDSA", "Ed448"]
ParsableKeyCurve = Optional[Union[ec.EllipticCurve, str]]
ParsableSubject = Union[
    str,
    # Union for keys is not supported, see: https://github.com/python/mypy/issues/6001
    Mapping[x509.ObjectIdentifier, Union[str, Iterable[str]]],
    Mapping[str, Union[str, Iterable[str]]],
    x509.Name,
    Iterable[Tuple[Union[x509.ObjectIdentifier, str], Union[str, Iterable[str]]]],
]

# GeneralNameList
ParsableGeneralName = Union[x509.GeneralName, str]
ParsableGeneralNameList = Iterable[ParsableGeneralName]

SerializedExtension = TypedDict(
    "SerializedExtension",
    {
        "critical": bool,
        # Value should be a generic typevar, but this is not yet supported in mypy:
        #   https://github.com/python/mypy/issues/3863
        "value": Any,
    },
)
SerializedDistributionPoint = TypedDict(
    "SerializedDistributionPoint",
    {
        "full_name": List[str],
        "relative_name": str,
        "crl_issuer": List[str],
        "reasons": List[str],
    },
    total=False,
)
SerializedDistributionPoints = TypedDict(
    "SerializedDistributionPoints",
    {
        "critical": bool,
        "value": List[SerializedDistributionPoint],
    },
)
SerializedProfile = TypedDict(
    "SerializedProfile",
    {
        "cn_in_san": bool,
        "description": str,
        "subject": Dict[str, Union[str, List[str]]],
        "extensions": Dict[str, Any],
    },
)

SerializedNoticeReference = TypedDict(
    "SerializedNoticeReference", {"organization": str, "notice_numbers": List[int]}, total=False
)
SerializedUserNotice = TypedDict(
    "SerializedUserNotice", {"explicit_text": str, "notice_reference": SerializedNoticeReference}, total=False
)

SerializedPolicyQualifier = Union[str, SerializedUserNotice]
SerializedPolicyQualifiers = List[SerializedPolicyQualifier]

# Looser variants of the above for incoming arguments
ParsableNoticeReference = TypedDict(
    "ParsableNoticeReference", {"organization": str, "notice_numbers": Iterable[int]}, total=False
)
ParsableUserNotice = TypedDict(
    "ParsableUserNotice",
    {"notice_reference": Union[x509.NoticeReference, ParsableNoticeReference], "explicit_text": str},
    total=False,
)

# Parsable arguments
ParsableDistributionPoint = TypedDict(
    "ParsableDistributionPoint",
    {
        "full_name": Optional[ParsableGeneralNameList],
        "relative_name": typing.Union[str, x509.RelativeDistinguishedName],
        "crl_issuer": ParsableGeneralNameList,
        "reasons": Iterable[Union[str, x509.ReasonFlags]],
    },
    total=False,
)
ParsablePolicyQualifier = Union[str, x509.UserNotice, ParsableUserNotice]
ParsablePolicyIdentifier = Union[str, x509.ObjectIdentifier]
ParsablePolicyInformation = TypedDict(
    "ParsablePolicyInformation",
    {
        "policy_identifier": Optional[ParsablePolicyIdentifier],
        "policy_qualifiers": Sequence[ParsablePolicyQualifier],
    },
    total=False,
)

PolicyQualifier = Union[str, x509.UserNotice]
SerializedPolicyInformation = TypedDict(
    "SerializedPolicyInformation",
    {"policy_identifier": str, "policy_qualifiers": Optional[SerializedPolicyQualifiers]},
)

ExtensionTypeTypeVar = TypeVar("ExtensionTypeTypeVar", bound=x509.ExtensionType)
"""A type variable for a :py:class:`~cg:cryptography.x509.ExtensionType` instance."""

AlternativeNameTypeVar = TypeVar(
    "AlternativeNameTypeVar", x509.IssuerAlternativeName, x509.SubjectAlternativeName
)
SignedCertificateTimestampsBaseTypeVar = TypeVar(
    "SignedCertificateTimestampsBaseTypeVar",
    x509.SignedCertificateTimestamps,
    x509.PrecertificateSignedCertificateTimestamps,
)

ParsableExtension = TypedDict(
    "ParsableExtension",
    {
        "critical": bool,
        # Value should be a generic typevar, but this is not yet supported in mypy:
        #   https://github.com/python/mypy/issues/3863
        "value": Any,
    },
    total=False,
)
ParsableItem = TypeVar("ParsableItem")
"""TypeVar representing a parsable list item."""

ParsableValue = TypeVar("ParsableValue")
"""A value that can be parsed to a valid extension."""

SerializedItem = TypeVar("SerializedItem")
"""TypeVar representing a serialized item for an iterable extension."""

SerializedSortableItem = TypeVar("SerializedSortableItem", bound=SupportsLessThan)
"""TypeVar representing a serialized item that can be sorted  (for OrderedSetExtension)."""

SerializedValue = TypeVar("SerializedValue")
"""TypeVar representing a serialized value for an extension."""

IterableItem = TypeVar("IterableItem")
"""TypeVar representing a value contained in an iterable extension."""

ParsableSubjectKeyIdentifier = Union[str, bytes, x509.SubjectKeyIdentifier]

if TYPE_CHECKING:
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


BasicConstraintsBase = TypedDict("BasicConstraintsBase", {"ca": bool})
ParsableAuthorityInformationAccess = TypedDict(
    "ParsableAuthorityInformationAccess",
    {
        "ocsp": Optional[ParsableGeneralNameList],
        "issuers": Optional[ParsableGeneralNameList],
    },
)
ParsableAuthorityKeyIdentifierDict = TypedDict(
    "ParsableAuthorityKeyIdentifierDict",
    {
        "key_identifier": Optional[bytes],
        "authority_cert_issuer": Iterable[str],
        "authority_cert_serial_number": Optional[int],
    },
    total=False,
)
ParsableAuthorityKeyIdentifier = Union[str, bytes, ParsableAuthorityKeyIdentifierDict]


class ParsableBasicConstraints(BasicConstraintsBase, total=False):
    """Serialized representation of a BasicConstraints extension.

    A value of this type is a dictionary with a ``"ca"`` key with a boolean value. If ``True``, it also
    has a ``"pathlen"`` value that is either ``None`` or an int.
    """

    pathlen: Union[int, str]


ParsableNameConstraints = TypedDict(
    "ParsableNameConstraints",
    {
        "permitted": ParsableGeneralNameList,
        "excluded": ParsableGeneralNameList,
    },
    total=False,
)
ParsablePolicyConstraints = TypedDict(
    "ParsablePolicyConstraints",
    {
        "require_explicit_policy": int,
        "inhibit_policy_mapping": int,
    },
    total=False,
)


class SerializedBasicConstraints(BasicConstraintsBase, total=False):
    """Serialized representation of a BasicConstraints extension.

    A value of this type is a dictionary with a ``"ca"`` key with a boolean value. If ``True``, it also
    has a ``"pathlen"`` value that is either ``None`` or an int.
    """

    pathlen: Optional[int]


SerializedNullExtension = TypedDict("SerializedNullExtension", {"critical": bool})
SerializedAuthorityInformationAccess = TypedDict(
    "SerializedAuthorityInformationAccess",
    {
        "issuers": List[str],
        "ocsp": List[str],
    },
    total=False,
)
SerializedAuthorityKeyIdentifier = TypedDict(
    "SerializedAuthorityKeyIdentifier",
    {
        "key_identifier": str,
        "authority_cert_issuer": List[str],
        "authority_cert_serial_number": int,
    },
    total=False,
)
SerializedNameConstraints = TypedDict(
    "SerializedNameConstraints",
    {
        "permitted": List[str],
        "excluded": List[str],
    },
)
SerializedPolicyConstraints = TypedDict(
    "SerializedPolicyConstraints",
    {
        "inhibit_policy_mapping": int,
        "require_explicit_policy": int,
    },
    total=False,
)
SerializedSignedCertificateTimestamp = TypedDict(
    "SerializedSignedCertificateTimestamp",
    {
        "log_id": str,
        "timestamp": str,
        "type": str,
        "version": str,
    },
)
"""A dictionary with four keys: log_id, timestamp, type, version, values are all str."""

ParsableSignedCertificateTimestamp = Union[SerializedSignedCertificateTimestamp, SignedCertificateTimestamp]

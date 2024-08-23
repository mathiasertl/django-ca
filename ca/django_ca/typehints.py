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
from collections.abc import Iterable, Mapping, Sequence
from typing import TYPE_CHECKING, Any, Literal, Optional, TypedDict, TypeVar, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

from django.core.management.base import CommandParser

# IMPORTANT: Do **not** import any module from django_ca at runtime here, or you risk circular imports.

# Module level imports to enable forward references. See also:
#
#   https://peps.python.org/pep-0484/#forward-references
if TYPE_CHECKING:
    from django_ca import models

if sys.version_info < (3, 12):  # pragma: only py<3.12
    from typing_extensions import TypeAliasType as TypeAliasType  # noqa: PLC0414
else:  # pragma: only py>=3.12
    from typing import TypeAliasType as TypeAliasType  # noqa: PLC0414

# pylint: disable-next=invalid-name
JSON = Union[dict[str, "JSON"], list["JSON"], str, int, float, bool, None]

#: Hash algorithms that can be used for signing certificates.
#: NOTE: This is a duplicate of the protected ``cryptography.x509.base._AllowedHashTypes``.
AllowedHashTypes = Union[
    hashes.SHA224,
    hashes.SHA256,
    hashes.SHA384,
    hashes.SHA512,
    hashes.SHA3_224,
    hashes.SHA3_256,
    hashes.SHA3_384,
    hashes.SHA3_512,
]

ParsableName = Union[str, Iterable[tuple[str, str]]]

ParsableKeyType = Literal["RSA", "DSA", "EC", "Ed25519", "Ed448"]
ParsableSubject = Union[
    str,
    # Union for keys is not supported, see: https://github.com/python/mypy/issues/6001
    Mapping[x509.ObjectIdentifier, Union[str, Iterable[str]]],
    Mapping[str, Union[str, Iterable[str]]],
    x509.Name,
    Iterable[tuple[Union[x509.ObjectIdentifier, str], Union[str, Iterable[str]]]],
]

# GeneralNameList
ParsableGeneralName = Union[x509.GeneralName, str]
ParsableGeneralNameList = Iterable[ParsableGeneralName]


class SerializedObjectIdentifier(TypedDict):
    """Parsable version of an object identifier."""

    oid: str
    value: str


SerializedName = list[SerializedObjectIdentifier]


# Looser variants of the above for incoming arguments
class ParsableNoticeReference(TypedDict, total=False):
    """Parsable version of a Notice Reference."""

    organization: str
    notice_numbers: Iterable[int]


class ParsableUserNotice(TypedDict, total=False):
    """Parsable version of a User Notice."""

    notice_reference: Union[x509.NoticeReference, ParsableNoticeReference]
    explicit_text: str


# Parsable arguments
class ParsableDistributionPoint(TypedDict, total=False):
    """Parsable version of a Distribution Point."""

    full_name: Optional[ParsableGeneralNameList]
    relative_name: Union[SerializedName, x509.RelativeDistinguishedName]
    crl_issuer: ParsableGeneralNameList
    reasons: Iterable[Union[str, x509.ReasonFlags]]


ParsablePolicyQualifier = Union[str, x509.UserNotice, ParsableUserNotice]
ParsablePolicyIdentifier = Union[str, x509.ObjectIdentifier]


class ParsablePolicyInformation(TypedDict, total=False):
    """Parsable version of the Policy Information extension."""

    policy_identifier: ParsablePolicyIdentifier
    policy_qualifiers: Optional[Sequence[ParsablePolicyQualifier]]


PolicyQualifier = Union[str, x509.UserNotice]


class ParsableExtension(TypedDict, total=False):
    """Base for all extensions."""

    critical: bool
    value: Any


class BasicConstraintsBase(TypedDict):
    """Base for BasicConstraints extension."""

    ca: bool


class ParsableAuthorityKeyIdentifierDict(TypedDict, total=False):
    """Parsable version of the ParsableAuthorityKeyIdentifier extension."""

    key_identifier: Optional[bytes]
    authority_cert_issuer: Iterable[str]
    authority_cert_serial_number: Optional[int]


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

#: Extension keys for extensions that may be configured by the user when issuing certificates.
ConfigurableExtensionKeys = Literal[
    "authority_information_access",
    "certificate_policies",
    "crl_distribution_points",
    "extended_key_usage",
    "freshest_crl",
    "issuer_alternative_name",
    "key_usage",
    "ms_certificate_template",
    "ocsp_no_check",
    "precert_poison",
    "subject_alternative_name",
    "tls_feature",
]

#: Extension keys for extensions that may occur in an end entity certificate.
#:
#: This literal includes keys from :py:attr:`~django_ca.typehints.ConfigurableExtensionKeys` and adds the keys
#: for extensions that are either derived from the issuer or the certificates public key or that must not
#: be configured by a user.
EndEntityCertificateExtensionKeys = Union[
    ConfigurableExtensionKeys,
    Literal[
        "authority_key_identifier",  # derived from the issuer
        "basic_constraints",  # must not be configured by a user
        "precertificate_signed_certificate_timestamps",  # added by the CA
        "signed_certificate_timestamps",  # added by the CA
        "subject_information_access",
        "subject_key_identifier",  # derived from the certificates public key
    ],
]

#: Extension keys for extensions that may occur in any certificate.
#:
#: This literal includes keys from :py:attr:`~django_ca.typehints.EndEntityCertificateExtensionKeys` and adds
#: the keys for extensions only occur in certificate authorities.
CertificateExtensionKeys = Union[
    EndEntityCertificateExtensionKeys,
    Literal[
        "inhibit_any_policy",
        "name_constraints",
        "policy_constraints",
        "unknown",
    ],
]

#: Extension keys for all known x509 Extensions.
#:
#: This literal includes keys from :py:attr:`~django_ca.typehints.ConfigurableExtensionKeys` and includes
#: extensions that may occur in certificate authorities or CRLs.
ExtensionKeys = Union[
    CertificateExtensionKeys,
    Literal[
        "crl_number",
        "delta_crl_indicator",
        "issuing_distribution_point",
        "policy_mappings",
        "subject_directory_attributes",
    ],
]

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

CertificateRevocationListScopes = Literal["ca", "user", "attribute"]
CertificateRevocationListEncodings = Literal[Encoding.PEM, Encoding.DER]
CertificateRevocationListEncodingNames = Literal["PEM", "DER"]


################
# Type aliases #
################
#: :py:class:`~cg:cryptography.x509.ExtensionType` classes that can be configured by the user.
ConfigurableExtensionType = Union[
    x509.AuthorityInformationAccess,
    x509.CertificatePolicies,
    x509.CRLDistributionPoints,
    x509.ExtendedKeyUsage,
    x509.FreshestCRL,
    x509.IssuerAlternativeName,
    x509.KeyUsage,
    x509.MSCertificateTemplate,
    x509.OCSPNoCheck,
    x509.PrecertPoison,
    x509.SubjectAlternativeName,
    x509.TLSFeature,
]
#: :py:class:`~cg:cryptography.x509.ExtensionType` classes that may appear in an end entity certificate.
#:
#: This union is based on :py:attr:`~django_ca.typehints.ConfigurableExtensionType` and adds extension types
#: that are either derived from the issuer or the certificates public key or that must not be configured by
#: the user.
EndEntityCertificateExtensionType = Union[
    ConfigurableExtensionType,
    x509.AuthorityKeyIdentifier,
    x509.BasicConstraints,
    x509.PrecertificateSignedCertificateTimestamps,
    x509.SignedCertificateTimestamps,
    x509.SubjectInformationAccess,
    x509.SubjectKeyIdentifier,
]

#: :py:class:`~cg:cryptography.x509.ExtensionType` classes that may appear in any certificate.
#:
#: This union is based on :py:attr:`~django_ca.typehints.EndEntityCertificateExtensionType` and adds extension
#: types that may appear in certificate authorities.
CertificateExtensionType = Union[
    EndEntityCertificateExtensionType,
    x509.InhibitAnyPolicy,
    x509.NameConstraints,
    x509.PolicyConstraints,
    x509.UnrecognizedExtension,
]

ConfigurableExtension = Union[
    x509.Extension[x509.AuthorityInformationAccess],
    x509.Extension[x509.CertificatePolicies],
    x509.Extension[x509.CRLDistributionPoints],
    x509.Extension[x509.ExtendedKeyUsage],
    x509.Extension[x509.FreshestCRL],
    x509.Extension[x509.IssuerAlternativeName],
    x509.Extension[x509.KeyUsage],
    x509.Extension[x509.MSCertificateTemplate],
    x509.Extension[x509.OCSPNoCheck],
    x509.Extension[x509.PrecertPoison],
    x509.Extension[x509.SubjectAlternativeName],
    x509.Extension[x509.TLSFeature],
]

EndEntityCertificateExtension = Union[
    ConfigurableExtension,
    x509.Extension[x509.AuthorityKeyIdentifier],
    x509.Extension[x509.BasicConstraints],
    x509.Extension[x509.PrecertificateSignedCertificateTimestamps],
    x509.Extension[x509.SignedCertificateTimestamps],
    x509.Extension[x509.SubjectInformationAccess],
    x509.Extension[x509.SubjectKeyIdentifier],
]
CertificateExtension = Union[
    EndEntityCertificateExtension,
    x509.Extension[x509.InhibitAnyPolicy],
    x509.Extension[x509.NameConstraints],
    x509.Extension[x509.PolicyConstraints],
    x509.Extension[x509.UnrecognizedExtension],
]

ConfigurableExtensionDict = dict[x509.ObjectIdentifier, ConfigurableExtension]
EndEntityCertificateExtensionDict = dict[x509.ObjectIdentifier, EndEntityCertificateExtension]
CertificateExtensionDict = dict[x509.ObjectIdentifier, CertificateExtension]

# Type aliases for protected subclass returned by add_argument_group().
ArgumentGroup = argparse._ArgumentGroup  # pylint: disable=protected-access

# An CommandParser (subclass of argparse.ArgumentParser) or an argument group added by add_argument_group().
ActionsContainer = Union[CommandParser, ArgumentGroup]


############
# TypeVars #
############
# pylint: disable-next=invalid-name  # Should match class, but pylint is more sensitive here
X509CertMixinTypeVar = TypeVar("X509CertMixinTypeVar", bound="models.X509CertMixin")

ExtensionTypeVar = TypeVar("ExtensionTypeVar", bound=x509.Extension[x509.ExtensionType])

# A TypeVar bound to :py:class:`~cg:cryptography.x509.ExtensionType`.
ExtensionTypeTypeVar = TypeVar("ExtensionTypeTypeVar", bound=x509.ExtensionType)


AlternativeNameTypeVar = TypeVar(
    "AlternativeNameTypeVar", x509.SubjectAlternativeName, x509.IssuerAlternativeName
)
CRLExtensionTypeTypeVar = TypeVar("CRLExtensionTypeTypeVar", x509.CRLDistributionPoints, x509.FreshestCRL)
InformationAccessTypeVar = TypeVar(
    "InformationAccessTypeVar", x509.AuthorityInformationAccess, x509.SubjectInformationAccess
)
NoValueExtensionTypeVar = TypeVar("NoValueExtensionTypeVar", x509.OCSPNoCheck, x509.PrecertPoison)

SignedCertificateTimestampTypeVar = TypeVar(
    "SignedCertificateTimestampTypeVar",
    x509.PrecertificateSignedCertificateTimestamps,
    x509.SignedCertificateTimestamps,
)

#################################
# Typehints for Pydantic models #
#################################


class ProfileExtensionValue(TypedDict, total=False):
    """Typed dict as it occurs in profiles.

    This TypedDict lacks a `type`, as the configuration uses a dictionary with the type as mapping key.

    This TypedDict is more lenient than ``SerializedPydanticExtension``, as critical often has a default,
    and `value` may not be set for extensions that don't have a value.
    """

    value: Optional[Any]
    critical: Optional[bool]


class SerializedPydanticNameAttribute(TypedDict):
    """Serialized version of a Pydantic name attribute."""

    oid: str
    value: str


SerializedPydanticName = list[SerializedPydanticNameAttribute]


class SerializedPydanticExtension(TypedDict):
    """Serialized pydantic extension."""

    type: EndEntityCertificateExtensionKeys
    critical: bool
    value: Any


class SerializedProfile(TypedDict):
    """Serialized profile."""

    name: str
    description: str
    subject: Optional[SerializedPydanticName]
    algorithm: Optional[HashAlgorithms]
    extensions: list[SerializedPydanticExtension]
    clear_extensions: list[EndEntityCertificateExtensionKeys]


#####################
# Serialized values #
#####################
# Collect JSON-serializable versions of cryptography values. Typehints in this section start with
# "Serialized...".


# PolicyInformation serialization
class SerializedNoticeReference(TypedDict, total=False):
    """Serialized variant of a Notice Reference."""

    organization: str
    notice_numbers: list[int]


class SerializedUserNotice(TypedDict, total=False):
    """Serialized variant of a User Notice."""

    explicit_text: str
    notice_reference: SerializedNoticeReference


SerializedPolicyQualifier = Union[str, SerializedUserNotice]
SerializedPolicyQualifiers = list[SerializedPolicyQualifier]


class SerializedPolicyInformation(TypedDict):
    """Serialized variant of a PolicyInformation extension."""

    policy_identifier: str
    policy_qualifiers: Optional[SerializedPolicyQualifiers]


###################
# Parsable values #
###################
# Collect typehints for values that can be parsed back into cryptography values. Typehints in this section
# start with "Parsable...".

ParsableAuthorityKeyIdentifier = Union[str, bytes, ParsableAuthorityKeyIdentifierDict]


class ParsableAuthorityInformationAccess(TypedDict, total=False):
    """Parsable Authority Information Access extension."""

    ocsp: Optional[ParsableGeneralNameList]
    issuers: Optional[ParsableGeneralNameList]


class ParsableBasicConstraints(BasicConstraintsBase, total=False):
    """Serialized representation of a BasicConstraints extension.

    A value of this type is a dictionary with a ``"ca"`` key with a boolean value. If ``True``, it also
    has a ``"path_length"`` value that is either ``None`` or an int.
    """

    path_length: Union[int, str]


class ParsableNameConstraints(TypedDict, total=False):
    """Parsable NameConstraints extension."""

    permitted: ParsableGeneralNameList
    excluded: ParsableGeneralNameList


class ParsablePolicyConstraints(TypedDict, total=False):
    """Parsable PolicyConstriants extension."""

    require_explicit_policy: int
    inhibit_policy_mapping: int


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

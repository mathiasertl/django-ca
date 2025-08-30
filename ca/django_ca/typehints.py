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
from typing import TYPE_CHECKING, Any, Literal, TypedDict, TypeVar

import packaging.version

import cryptography
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

from django.core.management.base import CommandParser

CRYPTOGRAPHY_VERSION = packaging.version.parse(cryptography.__version__).release

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

if sys.version_info < (3, 11):  # pragma: only py<3.11
    from typing_extensions import Self as Self  # noqa: PLC0414
else:  # pragma: only py>=3.11
    from typing import Self as Self  # noqa: PLC0414


#: JSON serializable data.
JSON = dict[str, "JSON"] | list["JSON"] | str | int | float | bool | None


class OCSPKeyBackendDict(TypedDict):
    """Data structure stored in the `ocsp_key_backend` field of CertificateAuthority."""

    private_key: dict[str, JSON]
    certificate: dict[str, JSON]


SignatureHashAlgorithm = (
    hashes.SHA224
    | hashes.SHA256
    | hashes.SHA384
    | hashes.SHA512
    | hashes.SHA3_224
    | hashes.SHA3_256
    | hashes.SHA3_384
    | hashes.SHA3_512
)
"""Hash algorithms that can be used for signing certificates.

NOTE: This is a duplicate of the protected ``cryptography.x509.base._AllowedHashTypes``.
"""

SignatureHashAlgorithmWithLegacy = hashes.MD5 | hashes.SHA1 | SignatureHashAlgorithm
""":attr:`~django_ca.typehints.SignatureHashAlgorithm` plus insecure legacy algorithms (MD5 and SHA1)."""


############
# Literals #
############

ParsableKeyType = Literal["RSA", "DSA", "EC", "Ed25519", "Ed448"]


GeneralName = Literal["email", "URI", "IP", "DNS", "RID", "dirName", "otherName"]
"""Valid types of general names."""

SignatureHashAlgorithmName = Literal[
    "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA3/224", "SHA3/256", "SHA3/384", "SHA3/512"
]
"""Names of hash algorithms that can be used for signing certificates.

These names are used in various settings, with the ``--algorithm`` command line parameter and in the API.
"""

SignatureHashAlgorithmNameWithLegacy = Literal["MD5", "SHA1"] | SignatureHashAlgorithmName
""":attr:`~django_ca.typehints.SignatureHashAlgorithmName` plus insecure legacy algorithms (MD5 and SHA1).

This value is used when displaying data which may include legacy signatures.
"""

#: Serialized values of :py:class:`~cg:cryptography.x509.certificate_transparency.LogEntryType` instances.
LogEntryTypeName = Literal["precertificate", "x509_certificate"]

#: Serialized access method for :py:class:`~cg:cryptography.x509.AccessDescription` instances.
AccessMethodName = Literal["ocsp", "ca_issuers", "ca_repository"]

#: Extension keys for extensions that may be configured by the user when issuing certificates.
ConfigurableExtensionKey = Literal[
    "admissions",
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
    "private_key_usage_period",
    "subject_alternative_name",
    "tls_feature",
]

#: Extension keys for extensions that may occur in an end entity certificate.
#:
#: This literal includes keys from :py:attr:`~django_ca.typehints.ConfigurableExtensionKey` and adds the keys
#: for extensions that are either derived from the issuer or the certificates public key or that must not
#: be configured by a user.
EndEntityCertificateExtensionKey = (
    ConfigurableExtensionKey
    | Literal[
        "authority_key_identifier",  # derived from the issuer
        "basic_constraints",  # must not be configured by a user
        "precertificate_signed_certificate_timestamps",  # added by the CA
        "signed_certificate_timestamps",  # added by the CA
        "subject_information_access",
        "subject_key_identifier",  # derived from the certificates public key
    ]
)

#: Extension keys for extensions that may occur in any certificate.
#:
#: This literal includes keys from :py:attr:`~django_ca.typehints.EndEntityCertificateExtensionKey` and adds
#: the keys for extensions only occur in certificate authorities.
CertificateExtensionKey = (
    EndEntityCertificateExtensionKey
    | Literal[
        "inhibit_any_policy",
        "name_constraints",
        "policy_constraints",
        "unknown",
    ]
)

#: Extension keys for all known x509 Extensions.
#:
#: This literal includes keys from :py:attr:`~django_ca.typehints.ConfigurableExtensionKey` and includes
#: extensions that may occur in certificate authorities or CRLs.
ExtensionKey = (
    CertificateExtensionKey
    | Literal[
        "crl_number",
        "delta_crl_indicator",
        "issuing_distribution_point",
        "policy_mappings",
        "subject_directory_attributes",
    ]
)

KeyUsage = Literal[
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
"""List of possible values for :py:class:`~cg:cryptography.x509.KeyUsage` instances."""

DistributionPointReason = Literal[
    "aa_compromise",
    "affiliation_changed",
    "ca_compromise",
    "certificate_hold",
    "cessation_of_operation",
    "key_compromise",
    "privilege_withdrawn",
    "superseded",
]

OtherName = Literal[
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
"""Valid OtherName types"""

EllipticCurveName = Literal[
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
"""Valid elliptic curve names."""

CertificateRevocationListEncoding = Literal[Encoding.PEM, Encoding.DER]
CertificateRevocationListEncodingNames = Literal["PEM", "DER"]


################
# Type aliases #
################
#: :py:class:`~cg:cryptography.x509.ExtensionType` classes that can be configured by the user.
ConfigurableExtensionType = (
    x509.Admissions
    | x509.AuthorityInformationAccess
    | x509.CertificatePolicies
    | x509.CRLDistributionPoints
    | x509.ExtendedKeyUsage
    | x509.FreshestCRL
    | x509.IssuerAlternativeName
    | x509.KeyUsage
    | x509.MSCertificateTemplate
    | x509.OCSPNoCheck
    | x509.PrecertPoison
    | x509.PrivateKeyUsagePeriod
    | x509.SubjectAlternativeName
    | x509.TLSFeature
)

#: :py:class:`~cg:cryptography.x509.ExtensionType` classes that may appear in an end entity certificate.
#:
#: This union is based on :py:attr:`~django_ca.typehints.ConfigurableExtensionType` and adds extension
#: types that are either derived from the issuer or the certificates public key or that must not be
#: configured by the user.
EndEntityCertificateExtensionType = (
    ConfigurableExtensionType
    | x509.AuthorityKeyIdentifier
    | x509.BasicConstraints
    | x509.PrecertificateSignedCertificateTimestamps
    | x509.SignedCertificateTimestamps
    | x509.SubjectInformationAccess
    | x509.SubjectKeyIdentifier
)

#: :py:class:`~cg:cryptography.x509.ExtensionType` classes that may appear in any certificate.
#:
#: This union is based on :py:attr:`~django_ca.typehints.EndEntityCertificateExtensionType` and adds extension
#: types that may appear in certificate authorities.
CertificateExtensionType = (
    EndEntityCertificateExtensionType
    | x509.InhibitAnyPolicy
    | x509.NameConstraints
    | x509.PolicyConstraints
    | x509.UnrecognizedExtension
)


ConfigurableExtension = (
    x509.Extension[x509.Admissions]
    | x509.Extension[x509.AuthorityInformationAccess]
    | x509.Extension[x509.CertificatePolicies]
    | x509.Extension[x509.CRLDistributionPoints]
    | x509.Extension[x509.ExtendedKeyUsage]
    | x509.Extension[x509.FreshestCRL]
    | x509.Extension[x509.IssuerAlternativeName]
    | x509.Extension[x509.KeyUsage]
    | x509.Extension[x509.MSCertificateTemplate]
    | x509.Extension[x509.OCSPNoCheck]
    | x509.Extension[x509.PrecertPoison]
    | x509.Extension[x509.PrivateKeyUsagePeriod]
    | x509.Extension[x509.SubjectAlternativeName]
    | x509.Extension[x509.TLSFeature]
)

EndEntityCertificateExtension = (
    ConfigurableExtension
    | x509.Extension[x509.AuthorityKeyIdentifier]
    | x509.Extension[x509.BasicConstraints]
    | x509.Extension[x509.PrecertificateSignedCertificateTimestamps]
    | x509.Extension[x509.SignedCertificateTimestamps]
    | x509.Extension[x509.SubjectInformationAccess]
    | x509.Extension[x509.SubjectKeyIdentifier]
)

CertificateExtension = (
    EndEntityCertificateExtension
    | x509.Extension[x509.InhibitAnyPolicy]
    | x509.Extension[x509.NameConstraints]
    | x509.Extension[x509.PolicyConstraints]
    | x509.Extension[x509.UnrecognizedExtension]
)

ConfigurableExtensionDict = dict[x509.ObjectIdentifier, ConfigurableExtension]
EndEntityCertificateExtensionDict = dict[x509.ObjectIdentifier, EndEntityCertificateExtension]
CertificateExtensionDict = dict[x509.ObjectIdentifier, CertificateExtension]

# Type aliases for protected subclass returned by add_argument_group().
ArgumentGroup = argparse._ArgumentGroup  # pylint: disable=protected-access

# An CommandParser (subclass of argparse.ArgumentParser) or an argument group added by add_argument_group().
ActionsContainer = CommandParser | ArgumentGroup


############
# TypeVars #
############
# pylint: disable-next=invalid-name  # Should match class, but pylint is more sensitive here
X509CertMixinTypeVar = TypeVar("X509CertMixinTypeVar", bound="models.X509CertMixin")

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


class SerializedPydanticNameAttribute(TypedDict):
    """Serialized version of a Pydantic name attribute."""

    oid: str
    value: str


SerializedPydanticName = list[SerializedPydanticNameAttribute]


class SerializedPydanticExtension(TypedDict):
    """Serialized pydantic extension."""

    type: EndEntityCertificateExtensionKey
    critical: bool
    value: Any


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


SerializedPolicyQualifier = str | SerializedUserNotice
SerializedPolicyQualifiers = list[SerializedPolicyQualifier]


class SerializedPolicyInformation(TypedDict):
    """Serialized variant of a PolicyInformation extension."""

    policy_identifier: str
    policy_qualifiers: SerializedPolicyQualifiers | None


#####################
# Type alternatives #
#####################
# Collect Union[] typehints that occur multiple times, e.g. multiple x509.ExtensionType classes that behave
# the same way. Typehints in this section are named "...Type".

AlternativeNameExtensionType = x509.SubjectAlternativeName | x509.IssuerAlternativeName
CRLExtensionType = x509.FreshestCRL | x509.CRLDistributionPoints
InformationAccessExtensionType = x509.AuthorityInformationAccess | x509.SubjectInformationAccess
SignedCertificateTimestampType = (
    x509.PrecertificateSignedCertificateTimestamps | x509.SignedCertificateTimestamps
)


#: Union of all IP address types
IPAddressType = ipaddress.IPv4Address | ipaddress.IPv6Address | ipaddress.IPv4Network | ipaddress.IPv6Network

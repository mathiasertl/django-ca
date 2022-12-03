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

"""Extension classes wrapping various X.509 extensions.

The classes in this module wrap cryptography extensions, but allow adding/removing values, creating extensions
in a more pythonic manner and provide access functions."""

from typing import Any, Dict, Type

from cryptography import x509
from cryptography.hazmat._oid import _OID_NAMES as OID_NAMES

from ..constants import EXTENSION_NAMES
from .base import Extension
from .extensions import (
    AuthorityInformationAccess,
    AuthorityKeyIdentifier,
    BasicConstraints,
    CertificatePolicies,
    CRLDistributionPoints,
    ExtendedKeyUsage,
    FreshestCRL,
    InhibitAnyPolicy,
    IssuerAlternativeName,
    KeyUsage,
    NameConstraints,
    OCSPNoCheck,
    PolicyConstraints,
    PrecertificateSignedCertificateTimestamps,
    PrecertPoison,
    SubjectAlternativeName,
    SubjectKeyIdentifier,
    TLSFeature,
)
from .parse import parse_extension
from .serialize import serialize_extension
from .text import extension_as_text

# NOTE: for some reason, extension classes are Extension[Any] in the dictionary.
KEY_TO_EXTENSION: Dict[str, Type[Extension[Any, Any, Any]]] = {
    AuthorityInformationAccess.key: AuthorityInformationAccess,
    AuthorityKeyIdentifier.key: AuthorityKeyIdentifier,
    BasicConstraints.key: BasicConstraints,
    CRLDistributionPoints.key: CRLDistributionPoints,
    CertificatePolicies.key: CertificatePolicies,
    ExtendedKeyUsage.key: ExtendedKeyUsage,
    FreshestCRL.key: FreshestCRL,
    InhibitAnyPolicy.key: InhibitAnyPolicy,
    IssuerAlternativeName.key: IssuerAlternativeName,
    KeyUsage.key: KeyUsage,
    NameConstraints.key: NameConstraints,
    OCSPNoCheck.key: OCSPNoCheck,
    PolicyConstraints.key: PolicyConstraints,
    PrecertPoison.key: PrecertPoison,
    PrecertificateSignedCertificateTimestamps.key: PrecertificateSignedCertificateTimestamps,
    SubjectAlternativeName.key: SubjectAlternativeName,
    SubjectKeyIdentifier.key: SubjectKeyIdentifier,
    TLSFeature.key: TLSFeature,
}

OID_TO_EXTENSION: Dict[x509.ObjectIdentifier, Type[Extension[x509.ExtensionType, Any, Any]]] = {
    e.oid: e for e in KEY_TO_EXTENSION.values()
}

#: Tuple of extensions that can be set when creating a new certificate
CERTIFICATE_EXTENSIONS = tuple(
    sorted(
        [
            "authority_information_access",
            "crl_distribution_points",
            "extended_key_usage",
            "freshest_crl",
            "issuer_alternative_name",
            "key_usage",
            "ocsp_no_check",
            "tls_feature",
        ]
    )
)


def get_extension_name(oid: x509.ObjectIdentifier) -> str:
    """Function to get the name of an extension from the extensions OID.

    >>> get_extension_name(ExtensionOID.BASIC_CONSTRAINTS)
    'Basic Constraints'
    >>> get_extension_name(x509.ObjectIdentifier("1.2.3"))
    'Unknown extension (1.2.3)'

    """

    if oid in EXTENSION_NAMES:
        return EXTENSION_NAMES[oid]

    return OID_NAMES.get(oid, f"Unknown extension ({oid.dotted_string})")


__all__ = [
    "extension_as_text",
    "get_extension_name",
    "parse_extension",
    "serialize_extension",
    "Extension",
    "AuthorityInformationAccess",
    "AuthorityKeyIdentifier",
    "BasicConstraints",
    "CRLDistributionPoints",
    "CertificatePolicies",
    "ExtendedKeyUsage",
    "FreshestCRL",
    "InhibitAnyPolicy",
    "IssuerAlternativeName",
    "KeyUsage",
    "NameConstraints",
    "OCSPNoCheck",
    "PolicyConstraints",
    "PrecertPoison",
    "PrecertificateSignedCertificateTimestamps",
    "SubjectAlternativeName",
    "SubjectKeyIdentifier",
    "TLSFeature",
]

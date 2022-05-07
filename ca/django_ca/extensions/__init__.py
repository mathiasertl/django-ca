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

import typing
from typing import Any
from typing import Dict
from typing import Type

from cryptography import x509
from cryptography.hazmat._oid import _OID_NAMES as OID_NAMES
from cryptography.x509.oid import ExtensionOID

from .base import Extension
from .extensions import AuthorityInformationAccess
from .extensions import AuthorityKeyIdentifier
from .extensions import BasicConstraints
from .extensions import CertificatePolicies
from .extensions import CRLDistributionPoints
from .extensions import ExtendedKeyUsage
from .extensions import FreshestCRL
from .extensions import InhibitAnyPolicy
from .extensions import IssuerAlternativeName
from .extensions import KeyUsage
from .extensions import NameConstraints
from .extensions import OCSPNoCheck
from .extensions import PolicyConstraints
from .extensions import PrecertificateSignedCertificateTimestamps
from .extensions import PrecertPoison
from .extensions import SubjectAlternativeName
from .extensions import SubjectKeyIdentifier
from .extensions import TLSFeature

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


# TODO: Validate completeness of these
OID_DEFAULT_CRITICAL: typing.Dict[x509.ObjectIdentifier, bool] = {
    ExtensionOID.ISSUER_ALTERNATIVE_NAME: False,
    ExtensionOID.SUBJECT_ALTERNATIVE_NAME: False,
}

OID_TO_KEY: typing.Dict[x509.ObjectIdentifier, str] = {
    ExtensionOID.ISSUER_ALTERNATIVE_NAME: "issuer_alternative_name",
    ExtensionOID.SUBJECT_ALTERNATIVE_NAME: "subject_alternative_name",
}


def get_extension_name(oid: x509.ObjectIdentifier) -> str:
    """Function to get the name of an extension from the extensions OID.

    >>> get_extension_name(ExtensionOID.BASIC_CONSTRAINTS)
    'BasicConstraints'
    """

    if oid in OID_TO_EXTENSION:
        return OID_TO_EXTENSION[oid].name

    return OID_NAMES.get(oid, f"Unknown extension ({oid.dotted_string})")


__all__ = [
    "get_extension_name",
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

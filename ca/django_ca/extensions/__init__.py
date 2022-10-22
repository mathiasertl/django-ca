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
from collections import defaultdict
from typing import Any, Dict, Type

from cryptography import x509
from cryptography.hazmat._oid import _OID_NAMES as OID_NAMES
from cryptography.x509.oid import ExtensionOID

from django.utils.translation import gettext_lazy as _

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
KEY_TO_OID = {key: ext.oid for key, ext in KEY_TO_EXTENSION.items()}

OID_TO_EXTENSION: Dict[x509.ObjectIdentifier, Type[Extension[x509.ExtensionType, Any, Any]]] = {
    e.oid: e for e in KEY_TO_EXTENSION.values()
}


# TODO: Validate completeness of these
OID_DEFAULT_CRITICAL: typing.Dict[x509.ObjectIdentifier, bool] = {
    ExtensionOID.AUTHORITY_INFORMATION_ACCESS: False,  # MUST mark this extension as non-critical.
    ExtensionOID.CRL_DISTRIBUTION_POINTS: False,  # The extension SHOULD be non-critical
    ExtensionOID.EXTENDED_KEY_USAGE: False,  # at issuers discretion, but non-critical in the real world.
    ExtensionOID.ISSUER_ALTERNATIVE_NAME: False,  # SHOULD mark this extension as non-critical.
    ExtensionOID.KEY_USAGE: True,  # SHOULD mark this extension as critical.
    ExtensionOID.SUBJECT_ALTERNATIVE_NAME: False,  # SHOULD mark the extension as non-critical.
    ExtensionOID.OCSP_NO_CHECK: False,  # RFC 2560: SHOULD be a non-critical
    ExtensionOID.TLS_FEATURE: False,  # RFC 7633: MUST NOT be marked critical
}

OID_TO_KEY: typing.Dict[x509.ObjectIdentifier, str] = {
    ExtensionOID.ISSUER_ALTERNATIVE_NAME: "issuer_alternative_name",
    ExtensionOID.SUBJECT_ALTERNATIVE_NAME: "subject_alternative_name",
}

OID_CRITICAL_HELP: typing.Dict[x509.ObjectIdentifier, str] = {
    ExtensionOID.AUTHORITY_INFORMATION_ACCESS: _("MUST be non-critical"),
    ExtensionOID.CRL_DISTRIBUTION_POINTS: _("SHOULD be non-critical"),
    ExtensionOID.EXTENDED_KEY_USAGE: _("MAY, at your discretion, be either critical or non-critical"),
    ExtensionOID.ISSUER_ALTERNATIVE_NAME: _("SHOULD be non-critical"),
    ExtensionOID.KEY_USAGE: _("SHOULD be non-critical"),
    ExtensionOID.OCSP_NO_CHECK: _("SHOULD be a non-critical"),  # defined in RFC 2560
    ExtensionOID.TLS_FEATURE: _("MUST NOT be marked critical"),  # defined in RFC 7633
}


OID_RFC_DEFINITION = defaultdict(
    lambda: 5280, {ExtensionOID.OCSP_NO_CHECK: 2560, ExtensionOID.TLS_FEATURE: 7633}
)


#: Tuple of extensions that can be set when creating a new certificate
CERTIFICATE_EXTENSIONS = tuple(
    sorted(
        [
            "authority_information_access",
            "crl_distribution_points",
            "extended_key_usage",
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

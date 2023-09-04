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

"""Utility functions used in testing."""
import typing
from datetime import datetime
from typing import Iterable, Optional, Union

from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

from django_ca.models import X509CertMixin


def authority_information_access(
    ca_issuers: Optional[Iterable[x509.GeneralName]] = None,
    ocsp: Optional[Iterable[x509.GeneralName]] = None,
    critical: bool = False,
) -> x509.Extension[x509.AuthorityInformationAccess]:
    """Shortcut for getting a AuthorityInformationAccess extension."""
    access_descriptions = []

    # NOTE: OCSP is first because OID is lexicographically smaller
    if ocsp is not None:  # pragma: no branch
        access_descriptions += [
            x509.AccessDescription(access_method=AuthorityInformationAccessOID.OCSP, access_location=name)
            for name in ocsp
        ]
    if ca_issuers is not None:  # pragma: no branch
        access_descriptions += [
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.CA_ISSUERS, access_location=issuer
            )
            for issuer in ca_issuers
        ]

    value = x509.AuthorityInformationAccess(access_descriptions)

    return x509.Extension(oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS, critical=critical, value=value)


def basic_constraints(
    ca: bool = False, path_length: Optional[int] = None, critical: bool = True
) -> x509.Extension[x509.BasicConstraints]:
    """Shortcut for getting a BasicConstraints extension."""
    return x509.Extension(
        oid=ExtensionOID.BASIC_CONSTRAINTS,
        critical=critical,
        value=x509.BasicConstraints(ca=ca, path_length=path_length),
    )


def certificate_policies(
    *policies: x509.PolicyInformation, critical: bool = False
) -> x509.Extension[x509.CertificatePolicies]:
    """Shortcut for getting a Certificate Policy extension"""
    return x509.Extension(
        oid=ExtensionOID.CERTIFICATE_POLICIES, critical=critical, value=x509.CertificatePolicies(policies)
    )


def crl_distribution_points(
    *distribution_points: x509.DistributionPoint, critical: bool = False
) -> x509.Extension[x509.CRLDistributionPoints]:
    """Shortcut for getting a CRLDistributionPoint extension."""
    value = x509.CRLDistributionPoints(distribution_points)
    return x509.Extension(oid=ExtensionOID.CRL_DISTRIBUTION_POINTS, critical=critical, value=value)


def distribution_point(
    full_name: Optional[Iterable[x509.GeneralName]] = None,
    relative_name: Optional[x509.RelativeDistinguishedName] = None,
    reasons: Optional[typing.FrozenSet[x509.ReasonFlags]] = None,
    crl_issuer: Optional[Iterable[x509.GeneralName]] = None,
) -> x509.DistributionPoint:
    """Shortcut for generating a single distribution point."""
    return x509.DistributionPoint(
        full_name=full_name, relative_name=relative_name, reasons=reasons, crl_issuer=crl_issuer
    )


def extended_key_usage(
    *usages: x509.ObjectIdentifier, critical: bool = False
) -> x509.Extension[x509.ExtendedKeyUsage]:
    """Shortcut for getting an ExtendedKeyUsage extension."""
    return x509.Extension(
        oid=ExtensionOID.EXTENDED_KEY_USAGE, critical=critical, value=x509.ExtendedKeyUsage(usages)
    )


def freshest_crl(
    *distribution_points: x509.DistributionPoint, critical: bool = False
) -> x509.Extension[x509.FreshestCRL]:
    """Shortcut for getting a CRLDistributionPoints extension."""
    return x509.Extension(
        oid=ExtensionOID.FRESHEST_CRL, critical=critical, value=x509.FreshestCRL(distribution_points)
    )


def iso_format(value: datetime, timespec: str = "seconds") -> str:
    """Convert a timestamp to ISO, with 'Z' instead of '+00:00'."""
    return value.isoformat(timespec=timespec).replace("+00:00", "Z")


def issuer_alternative_name(
    *names: x509.GeneralName, critical: bool = False
) -> x509.Extension[x509.IssuerAlternativeName]:
    """Shortcut for getting a IssuerAlternativeName extension."""
    return x509.Extension(
        oid=ExtensionOID.ISSUER_ALTERNATIVE_NAME,
        critical=critical,
        value=x509.IssuerAlternativeName(names),
    )


def key_usage(**usages: bool) -> x509.Extension[x509.KeyUsage]:
    """Shortcut for getting a KeyUsage extension."""
    critical = usages.pop("critical", True)
    usages.setdefault("content_commitment", False)
    usages.setdefault("crl_sign", False)
    usages.setdefault("data_encipherment", False)
    usages.setdefault("decipher_only", False)
    usages.setdefault("digital_signature", False)
    usages.setdefault("encipher_only", False)
    usages.setdefault("key_agreement", False)
    usages.setdefault("key_cert_sign", False)
    usages.setdefault("key_encipherment", False)
    return x509.Extension(oid=ExtensionOID.KEY_USAGE, critical=critical, value=x509.KeyUsage(**usages))


def name_constraints(
    permitted: Optional[Iterable[x509.GeneralName]] = None,
    excluded: Optional[Iterable[x509.GeneralName]] = None,
    critical: bool = True,
) -> x509.Extension[x509.NameConstraints]:
    """Shortcut for getting a NameConstraints extension."""
    return x509.Extension(
        oid=ExtensionOID.NAME_CONSTRAINTS,
        value=x509.NameConstraints(permitted_subtrees=permitted, excluded_subtrees=excluded),
        critical=critical,
    )


def ocsp_no_check(critical: bool = False) -> x509.Extension[x509.OCSPNoCheck]:
    """Shortcut for getting a OCSPNoCheck extension."""
    return x509.Extension(oid=ExtensionOID.OCSP_NO_CHECK, critical=critical, value=x509.OCSPNoCheck())


def precert_poison() -> x509.Extension[x509.PrecertPoison]:
    """Shortcut for getting a PrecertPoison extension."""
    return x509.Extension(oid=ExtensionOID.PRECERT_POISON, critical=True, value=x509.PrecertPoison())


def subject_alternative_name(
    *names: x509.GeneralName, critical: bool = False
) -> x509.Extension[x509.SubjectAlternativeName]:
    """Shortcut for getting a SubjectAlternativeName extension."""
    return x509.Extension(
        oid=ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
        critical=critical,
        value=x509.SubjectAlternativeName(names),
    )


def subject_key_identifier(
    cert: Union[X509CertMixin, x509.Certificate]
) -> x509.Extension[x509.SubjectKeyIdentifier]:
    """Shortcut for getting a SubjectKeyIdentifier extension."""
    if isinstance(cert, X509CertMixin):
        cert = cert.pub.loaded

    ski = x509.SubjectKeyIdentifier.from_public_key(cert.public_key())
    return x509.Extension(oid=ExtensionOID.SUBJECT_KEY_IDENTIFIER, critical=False, value=ski)


def tls_feature(*features: x509.TLSFeatureType, critical: bool = False) -> x509.Extension[x509.TLSFeature]:
    """Shortcut for getting a TLSFeature extension."""
    return x509.Extension(oid=ExtensionOID.TLS_FEATURE, critical=critical, value=x509.TLSFeature(features))

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

"""Functions to render extensions as text."""

import textwrap

from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID

from .. import typehints
from ..constants import EXTENDED_KEY_USAGE_NAMES
from ..utils import bytes_to_hex, format_general_name, format_name
from .utils import key_usage_items, signed_certificate_timestamp_values


def _authority_information_access_as_text(value: typehints.InformationAccessExtensionType) -> str:
    lines = []
    issuers = [ad for ad in value if ad.access_method == AuthorityInformationAccessOID.CA_ISSUERS]
    ocsp = [ad for ad in value if ad.access_method == AuthorityInformationAccessOID.OCSP]
    if issuers:
        lines.append("CA Issuers:")
        lines += [f"  * {format_general_name(ad.access_location)}" for ad in issuers]
    if ocsp:
        lines.append("OCSP:")
        lines += [f"  * {format_general_name(ad.access_location)}" for ad in ocsp]
    return "\n".join(lines)


def _authority_key_identifier_as_text(value: x509.AuthorityKeyIdentifier) -> str:
    lines = []
    if value.key_identifier:
        lines.append(f"* KeyID: {bytes_to_hex(value.key_identifier)}")
    if value.authority_cert_issuer:
        lines.append("* Issuer:")
        lines += [f"  * {format_general_name(aci)}" for aci in value.authority_cert_issuer]
    if value.authority_cert_serial_number is not None:
        lines.append(f"* Serial: {value.authority_cert_serial_number}")
    return "\n".join(lines)


def _basic_constraints_as_text(value: x509.BasicConstraints) -> str:
    if value.ca is True:
        text = "CA:TRUE"
    else:
        text = "CA:FALSE"
    if value.path_length is not None:
        text += f", pathlen:{value.path_length}"

    return text


def _certificate_policies_as_text(value: x509.CertificatePolicies) -> str:
    lines = []

    # pylint: disable-next=too-many-nested-blocks
    for policy in value:
        lines.append(f"* Policy Identifier: {policy.policy_identifier.dotted_string}")

        if policy.policy_qualifiers:
            lines.append("  Policy Qualifiers:")
            for qualifier in policy.policy_qualifiers:
                if isinstance(qualifier, str):
                    lines += textwrap.wrap(qualifier, 76, initial_indent="  * ", subsequent_indent="    ")
                else:
                    lines.append("  * User Notice:")
                    if qualifier.explicit_text:
                        lines += textwrap.wrap(
                            f"Explicit Text: {qualifier.explicit_text}\n",
                            initial_indent="    * ",
                            subsequent_indent="        ",
                            width=76,
                        )
                    if qualifier.notice_reference:
                        lines.append("    * Notice Reference:")
                        if qualifier.notice_reference.organization:  # pragma: no branch
                            lines.append(f"      * Organization: {qualifier.notice_reference.organization}")
                        if qualifier.notice_reference.notice_numbers:
                            lines.append(
                                f"      * Notice Numbers: {qualifier.notice_reference.notice_numbers}"
                            )
        else:
            lines.append("  No Policy Qualifiers")
    return "\n".join(lines)


def _distribution_points_as_text(value: typehints.CRLExtensionType) -> str:
    lines = []
    for dpoint in value:
        lines.append("* DistributionPoint:")

        if dpoint.full_name:
            lines.append("  * Full Name:")
            lines += [f"    * {format_general_name(name)}" for name in dpoint.full_name]
        elif dpoint.relative_name:
            lines.append(f"  * Relative Name: {format_name(dpoint.relative_name)}")
        else:  # pragma: no cover; either full_name or relative_name must be not-None.
            raise ValueError("Either full_name or relative_name must be not None.")

        if dpoint.crl_issuer:
            lines.append("  * CRL Issuer:")
            lines += [f"    * {format_general_name(issuer)}" for issuer in dpoint.crl_issuer]
        if dpoint.reasons:
            reasons = ", ".join(sorted([r.name for r in dpoint.reasons]))
            lines.append(f"  * Reasons: {reasons}")
    return "\n".join(lines)


def _key_usage_as_text(value: x509.KeyUsage) -> str:
    return "\n".join(f"* {name}" for name in sorted(key_usage_items(value)))


def _name_constraints_as_text(value: x509.NameConstraints) -> str:
    lines = []
    if value.permitted_subtrees:
        lines.append("Permitted:")
        lines += [f"  * {format_general_name(name)}" for name in value.permitted_subtrees]
    if value.excluded_subtrees:
        lines.append("Excluded:")
        lines += [f"  * {format_general_name(name)}" for name in value.excluded_subtrees]
    return "\n".join(lines)


def _policy_constraints_as_text(value: x509.PolicyConstraints) -> str:
    lines = []
    if value.inhibit_policy_mapping is not None:
        lines.append(f"* InhibitPolicyMapping: {value.inhibit_policy_mapping}")
    if value.require_explicit_policy is not None:
        lines.append(f"* RequireExplicitPolicy: {value.require_explicit_policy}")

    return "\n".join(lines)


def _signed_certificate_timestamps_as_text(value: typehints.SignedCertificateTimestampType) -> str:
    lines = []
    for sct in value:
        entry_type, version, log_id, timestamp = signed_certificate_timestamp_values(sct)

        lines += [
            f"* {entry_type} ({version}):",
            f"    Timestamp: {timestamp}",
            f"    Log ID: {log_id}",
        ]

    return "\n".join(lines)


def _tls_feature_as_text(value: x509.TLSFeature) -> str:
    lines = []
    for feature in value:
        if feature == x509.TLSFeatureType.status_request:
            lines.append("* OCSPMustStaple")
        elif feature == x509.TLSFeatureType.status_request_v2:
            lines.append("* MultipleCertStatusRequest")
        else:  # pragma: no cover
            # COVERAGE NOTE: we support all types, so this should never be raised. The descriptive error
            # message is just here in case a new thing ever comes up.
            raise ValueError(f"Unknown TLSFeatureType encountered: {feature}")
    return "\n".join(sorted(lines))


def extension_as_text(value: x509.ExtensionType) -> str:  # pylint: disable=too-many-return-statements
    """Return the given extension value as human-readable text."""
    if isinstance(value, (x509.OCSPNoCheck, x509.PrecertPoison)):
        return "Yes"  # no need for extra function
    if isinstance(value, (x509.FreshestCRL, x509.CRLDistributionPoints)):
        return _distribution_points_as_text(value)
    if isinstance(value, (x509.IssuerAlternativeName, x509.SubjectAlternativeName)):
        return "\n".join(f"* {format_general_name(name)}" for name in value)
    if isinstance(value, (x509.PrecertificateSignedCertificateTimestamps, x509.SignedCertificateTimestamps)):
        return _signed_certificate_timestamps_as_text(value)
    if isinstance(value, (x509.AuthorityInformationAccess, x509.SubjectInformationAccess)):
        return _authority_information_access_as_text(value)
    if isinstance(value, x509.AuthorityKeyIdentifier):
        return _authority_key_identifier_as_text(value)
    if isinstance(value, x509.BasicConstraints):
        return _basic_constraints_as_text(value)
    if isinstance(value, x509.CertificatePolicies):
        return _certificate_policies_as_text(value)
    if isinstance(value, x509.ExtendedKeyUsage):
        return "\n".join(sorted(f"* {EXTENDED_KEY_USAGE_NAMES[usage]}" for usage in value))
    if isinstance(value, x509.InhibitAnyPolicy):
        return str(value.skip_certs)
    if isinstance(value, x509.KeyUsage):
        return _key_usage_as_text(value)
    if isinstance(value, x509.NameConstraints):
        return _name_constraints_as_text(value)
    if isinstance(value, x509.PolicyConstraints):
        return _policy_constraints_as_text(value)
    if isinstance(value, x509.SubjectKeyIdentifier):
        return bytes_to_hex(value.key_identifier)
    if isinstance(value, x509.TLSFeature):
        return _tls_feature_as_text(value)
    if isinstance(value, x509.UnrecognizedExtension):
        return bytes_to_hex(value.value)
    if isinstance(value, x509.ExtensionType):
        raise TypeError(
            f"{value.__class__.__name__} (oid: {value.oid.dotted_string}): Unknown extension type."
        )
    raise TypeError(f"{value.__class__.__name__}: Not a cryptography.x509.ExtensionType.")

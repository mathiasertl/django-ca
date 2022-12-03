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

"""``django_ca.extensions.serialize`` contains functions to serialize extensions."""

import binascii
from typing import Any, Dict, List, Optional

from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID

from .. import typehints
from ..constants import EXTENDED_KEY_USAGE_NAMES, KEY_USAGE_NAMES, LOG_ENTRY_TYPE_KEYS
from ..typehints import (
    PolicyQualifier,
    SerializedExtension,
    SerializedPolicyInformation,
    SerializedPolicyQualifier,
    SerializedPolicyQualifiers,
    SerializedUserNotice,
)
from ..utils import bytes_to_hex, format_general_name, format_name


def _authority_information_access_serialized(
    value: typehints.InformationAccessExtensionType,
) -> Dict[str, List[str]]:
    descriptions = {}
    issuers = [ad for ad in value if ad.access_method == AuthorityInformationAccessOID.CA_ISSUERS]
    ocsp = [ad for ad in value if ad.access_method == AuthorityInformationAccessOID.OCSP]
    if issuers:
        descriptions["issuers"] = [format_general_name(ad.access_location) for ad in issuers]
    if ocsp:
        descriptions["ocsp"] = [format_general_name(ad.access_location) for ad in ocsp]
    return descriptions


def _authority_key_identifier_serialized(
    value: x509.AuthorityKeyIdentifier,
) -> typehints.SerializedAuthorityKeyIdentifier:
    serialized: typehints.SerializedAuthorityKeyIdentifier = {}
    if value.key_identifier:
        serialized["key_identifier"] = bytes_to_hex(value.key_identifier)
    if value.authority_cert_serial_number is not None:
        serialized["authority_cert_serial_number"] = value.authority_cert_serial_number
    if value.authority_cert_issuer:
        serialized["authority_cert_issuer"] = [
            format_general_name(aci) for aci in value.authority_cert_issuer
        ]
    return serialized


def _basic_constraints_serialized(value: x509.BasicConstraints) -> typehints.SerializedBasicConstraints:
    serialized: typehints.SerializedBasicConstraints = {"ca": value.ca}
    if value.ca is True:
        serialized["pathlen"] = value.path_length
    return serialized


def _serialize_policy_qualifier(qualifier: PolicyQualifier) -> SerializedPolicyQualifier:
    if isinstance(qualifier, str):
        return qualifier

    value: SerializedUserNotice = {}
    if qualifier.explicit_text:
        value["explicit_text"] = qualifier.explicit_text

    if qualifier.notice_reference is not None:
        value["notice_reference"] = {
            "notice_numbers": qualifier.notice_reference.notice_numbers,
        }
        if qualifier.notice_reference.organization is not None:
            value["notice_reference"]["organization"] = qualifier.notice_reference.organization
    return value


def _serialize_policy_information(policy_information: x509.PolicyInformation) -> SerializedPolicyInformation:
    policy_qualifiers: Optional[SerializedPolicyQualifiers] = None
    if policy_information.policy_qualifiers is not None:
        policy_qualifiers = [_serialize_policy_qualifier(q) for q in policy_information.policy_qualifiers]

    serialized: SerializedPolicyInformation = {
        "policy_identifier": policy_information.policy_identifier.dotted_string,
        "policy_qualifiers": policy_qualifiers,
    }
    return serialized


def _certificate_policies_serialized(value: x509.CertificatePolicies) -> List[SerializedPolicyInformation]:
    return [_serialize_policy_information(pi) for pi in value]


def _distribution_points_serialized(
    value: typehints.CRLExtensionType,
) -> List[typehints.SerializedDistributionPoint]:
    points: List[typehints.SerializedDistributionPoint] = []

    for dpoint in value:
        point: typehints.SerializedDistributionPoint = {}
        if dpoint.full_name:
            point["full_name"] = [format_general_name(name) for name in dpoint.full_name]
        elif dpoint.relative_name:  # pragma: no branch  # Distribution Point has only these two
            point["relative_name"] = format_name(dpoint.relative_name)

        if dpoint.crl_issuer:
            point["crl_issuer"] = [format_general_name(name) for name in dpoint.crl_issuer]
        if dpoint.reasons:
            point["reasons"] = sorted([r.name for r in dpoint.reasons])

        points.append(point)
    return points


def _key_usage_serialized(value: x509.KeyUsage) -> List[str]:
    values: List[str] = []
    for attr in KEY_USAGE_NAMES:
        try:
            if getattr(value, attr):
                values.append(attr)
        except ValueError:
            # x509.KeyUsage raises ValueError on some attributes to ensure consistency
            pass
    return sorted(values)


def _name_constraints_serialized(value: x509.NameConstraints) -> typehints.SerializedNameConstraints:
    serialized: typehints.SerializedNameConstraints = {}
    if value.permitted_subtrees:
        serialized["permitted"] = [format_general_name(name) for name in value.permitted_subtrees]
    if value.excluded_subtrees:
        serialized["excluded"] = [format_general_name(name) for name in value.excluded_subtrees]
    return serialized


def _policy_constraints_serialized(value: x509.PolicyConstraints) -> typehints.SerializedPolicyConstraints:
    serialized: typehints.SerializedPolicyConstraints = {}
    if value.inhibit_policy_mapping is not None:
        serialized["inhibit_policy_mapping"] = value.inhibit_policy_mapping
    if value.require_explicit_policy is not None:
        serialized["require_explicit_policy"] = value.require_explicit_policy
    return serialized


def _signed_certificate_timestamps_serialized(
    value: typehints.SignedCertificateTimestampType,
) -> List[typehints.SerializedSignedCertificateTimestamp]:
    timeformat = "%Y-%m-%d %H:%M:%S.%f"
    return [
        {
            "log_id": binascii.hexlify(sct.log_id).decode("utf-8"),
            "timestamp": sct.timestamp.strftime(timeformat),
            "type": LOG_ENTRY_TYPE_KEYS[sct.entry_type],
            "version": sct.version.name,
        }
        for sct in value
    ]


def _tls_feature_serialized(value: x509.TLSFeature) -> List[str]:
    serialized: List[str] = [feature.name for feature in value]
    return serialized


def _serialize_extension(  # pylint: disable=too-many-return-statements
    value: x509.ExtensionType,
) -> Any:
    if isinstance(value, (x509.OCSPNoCheck, x509.PrecertPoison)):
        return None
    if isinstance(value, (x509.IssuerAlternativeName, x509.SubjectAlternativeName)):
        return [format_general_name(name) for name in value]
    if isinstance(value, (x509.AuthorityInformationAccess, x509.SubjectInformationAccess)):
        return _authority_information_access_serialized(value)
    if isinstance(value, (x509.FreshestCRL, x509.CRLDistributionPoints)):
        return _distribution_points_serialized(value)
    if isinstance(value, (x509.PrecertificateSignedCertificateTimestamps, x509.SignedCertificateTimestamps)):
        return _signed_certificate_timestamps_serialized(value)
    if isinstance(value, x509.AuthorityKeyIdentifier):
        return _authority_key_identifier_serialized(value)
    if isinstance(value, x509.BasicConstraints):
        return _basic_constraints_serialized(value)
    if isinstance(value, x509.CertificatePolicies):
        return _certificate_policies_serialized(value)
    if isinstance(value, x509.ExtendedKeyUsage):
        return sorted([EXTENDED_KEY_USAGE_NAMES[usage] for usage in value])
    if isinstance(value, x509.InhibitAnyPolicy):
        return value.skip_certs
    if isinstance(value, x509.KeyUsage):
        return _key_usage_serialized(value)
    if isinstance(value, x509.NameConstraints):
        return _name_constraints_serialized(value)
    if isinstance(value, x509.PolicyConstraints):
        return _policy_constraints_serialized(value)
    if isinstance(value, x509.SubjectKeyIdentifier):
        return bytes_to_hex(value.key_identifier)
    if isinstance(value, x509.TLSFeature):
        return _tls_feature_serialized(value)
    if isinstance(value, x509.UnrecognizedExtension):
        return bytes_to_hex(value.value)
    if isinstance(value, x509.ExtensionType):
        raise TypeError(
            f"{value.__class__.__name__} (oid: {value.oid.dotted_string}): Unknown extension type."
        )
    raise TypeError(f"{value.__class__.__name__}: Not a cryptography.x509.ExtensionType.")


def serialize_extension(extension: x509.Extension[x509.ExtensionType]) -> SerializedExtension:
    """Serialize an extension to a dictionary.

    This is the inverse of :py:func:`~django_ca.extensions.parse_extension` and is used to serialize
    extension information for API calls in the admin interface.
    """

    value = _serialize_extension(extension.value)
    serialized: SerializedExtension = {"critical": extension.critical, "value": value}
    return serialized

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

"""Module to parse serialized extensions into cryptography objects."""

import typing

from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID

from ..constants import EXTENDED_KEY_USAGE_NAMES, EXTENSION_DEFAULT_CRITICAL, KEY_USAGE_NAMES
from ..typehints import (
    ParsableAuthorityInformationAccess,
    ParsableAuthorityKeyIdentifier,
    ParsableBasicConstraints,
    ParsableDistributionPoint,
    ParsableExtension,
    ParsableGeneralNameList,
    ParsableNameConstraints,
    ParsableNoticeReference,
    ParsablePolicyConstraints,
    ParsablePolicyInformation,
    ParsableSubjectKeyIdentifier,
    ParsableUserNotice,
)
from ..utils import hex_to_bytes, parse_general_name, x509_relative_name
from .utils import TLS_FEATURE_NAME_MAPPING, DistributionPoint

##########################################
# Parsers for sub-elements of extensions #
##########################################


def _parse_pathlen(value: typing.Optional[typing.Union[int, str]]) -> typing.Optional[int]:
    """Parse `value` as path length (either an int, a str of an int or None)."""
    if value is not None:
        return int(value)
    return value


def _parse_notice_reference(
    value: typing.Optional[typing.Union[x509.NoticeReference, ParsableNoticeReference]],
) -> typing.Optional[x509.NoticeReference]:
    if not value:
        return None
    if isinstance(value, x509.NoticeReference):
        return value

    return x509.NoticeReference(
        organization=value.get("organization"), notice_numbers=value["notice_numbers"]
    )


def _parse_user_notice(value: ParsableUserNotice) -> x509.UserNotice:
    notice_reference = _parse_notice_reference(value.get("notice_reference"))
    return x509.UserNotice(notice_reference=notice_reference, explicit_text=value.get("explicit_text"))


def _parse_policy_qualifiers(
    value: typing.Optional[typing.Iterable[typing.Union[str, x509.UserNotice, ParsableUserNotice]]]
) -> typing.Optional[typing.List[typing.Union[str, x509.UserNotice]]]:
    if not value:
        return None

    qualifiers: typing.List[typing.Union[str, x509.UserNotice]] = []
    for qual in value:
        if isinstance(qual, str):
            qualifiers.append(qual)
        elif isinstance(qual, x509.UserNotice):
            qualifiers.append(qual)
        else:
            qualifiers.append(_parse_user_notice(qual))
    return qualifiers


def _parse_reason(reason: typing.Union[str, x509.ReasonFlags]) -> x509.ReasonFlags:
    if isinstance(reason, str):
        return x509.ReasonFlags[reason]
    return reason


def _parse_distribution_points(
    value: typing.Iterable[typing.Union[x509.DistributionPoint, ParsableDistributionPoint]]
) -> typing.Iterator[x509.DistributionPoint]:
    for dpoint in value:
        if isinstance(dpoint, x509.DistributionPoint):
            yield dpoint
        elif isinstance(dpoint, DistributionPoint):
            yield dpoint.for_extension_type
        else:
            full_name = relative_name = reasons = crl_issuer = None

            unparsed_full_name = dpoint.get("full_name")
            if unparsed_full_name is not None:
                full_name = [parse_general_name(name) for name in unparsed_full_name]

            if dpoint.get("relative_name"):
                if isinstance(dpoint["relative_name"], x509.RelativeDistinguishedName):
                    relative_name = dpoint["relative_name"]
                else:
                    relative_name = x509_relative_name(dpoint["relative_name"])

            if dpoint.get("crl_issuer"):
                crl_issuer = [parse_general_name(name) for name in dpoint["crl_issuer"]]

            if dpoint.get("reasons"):
                reasons = frozenset(_parse_reason(r) for r in dpoint["reasons"])

            yield x509.DistributionPoint(
                full_name=full_name, relative_name=relative_name, reasons=reasons, crl_issuer=crl_issuer
            )


#####################
# Extensions parsers#
#####################
def _parse_authority_key_identifier(value: ParsableAuthorityKeyIdentifier) -> x509.AuthorityKeyIdentifier:
    key_id = issuer = serial_number = None

    if isinstance(value, (bytes, str)):
        key_id = value
    else:  # dict
        key_id = value.get("key_identifier")

        if value.get("authority_cert_issuer", []):
            issuer = [parse_general_name(name) for name in value["authority_cert_issuer"]]

        serial_number = value.get("authority_cert_serial_number")
        if serial_number is not None and not isinstance(serial_number, int):
            serial_number = int(serial_number)

    if isinstance(key_id, str):
        key_id = hex_to_bytes(key_id)

    return x509.AuthorityKeyIdentifier(
        key_identifier=key_id, authority_cert_issuer=issuer, authority_cert_serial_number=serial_number
    )


def _parse_authority_information_access(
    value: ParsableAuthorityInformationAccess,
) -> x509.AuthorityInformationAccess:
    access_descriptions: typing.List[x509.AccessDescription] = []
    issuers: typing.Optional[ParsableGeneralNameList] = value.get("issuers")
    if issuers is None:
        issuers = []

    for name in issuers:
        access_descriptions.append(
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                access_location=parse_general_name(name),
            )
        )
    ocsp: typing.Optional[ParsableGeneralNameList] = value.get("ocsp")
    if ocsp is None:
        ocsp = []
    for name in ocsp:
        access_descriptions.append(
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.OCSP,
                access_location=parse_general_name(name),
            )
        )

    return x509.AuthorityInformationAccess(descriptions=access_descriptions)


def _parse_basic_constraints(value: ParsableBasicConstraints) -> x509.BasicConstraints:
    ca = bool(value.get("ca", False))
    pathlen = None
    if ca is True:
        pathlen = _parse_pathlen(value.get("pathlen"))
    return x509.BasicConstraints(ca=value["ca"], path_length=pathlen)


def _parse_certificate_policies(
    value: typing.Iterable[typing.Union[x509.PolicyInformation, ParsablePolicyInformation]]
) -> x509.CertificatePolicies:
    policies: typing.List[x509.PolicyInformation] = []
    for pol in value:
        if isinstance(pol, x509.PolicyInformation):
            policies.append(pol)
            continue

        policy_identifier = pol.get("policy_identifier")
        if isinstance(policy_identifier, str):
            parsed_policy_identifier = x509.ObjectIdentifier(policy_identifier)
        else:
            # TYPE NOTE: bug in current typehints module: policy_identifier cannot be None
            parsed_policy_identifier = policy_identifier  # type: ignore[assignment]

        qualifiers = _parse_policy_qualifiers(pol.get("policy_qualifiers"))
        policies.append(
            x509.PolicyInformation(policy_identifier=parsed_policy_identifier, policy_qualifiers=qualifiers)
        )

    return x509.CertificatePolicies(policies)


def _parse_crl_distribution_points(
    value: typing.Iterable[typing.Union[x509.DistributionPoint, ParsableDistributionPoint]]
) -> x509.CRLDistributionPoints:
    return x509.CRLDistributionPoints(distribution_points=_parse_distribution_points(value))


def _parse_extended_key_usage(
    value: typing.Iterable[typing.Union[str, x509.ObjectIdentifier]]
) -> x509.ExtendedKeyUsage:
    mapping = {v: k for k, v in EXTENDED_KEY_USAGE_NAMES.items()}
    usages: typing.List[x509.ObjectIdentifier] = []
    for unparsed in value:
        if isinstance(unparsed, str):
            usages.append(mapping[unparsed])
        else:
            usages.append(unparsed)

    return x509.ExtendedKeyUsage(usages=sorted(usages, key=lambda u: EXTENDED_KEY_USAGE_NAMES[u]))


def _parse_freshest_crl(
    value: typing.Iterable[typing.Union[x509.DistributionPoint, ParsableDistributionPoint]]
) -> x509.FreshestCRL:
    return x509.FreshestCRL(distribution_points=_parse_distribution_points(value))


def _parse_key_usage(value: typing.Iterator[str]) -> x509.KeyUsage:
    kwargs = {k: k in value or v in value for k, v in KEY_USAGE_NAMES.items()}
    return x509.KeyUsage(**kwargs)


def _parse_name_constraints(value: ParsableNameConstraints) -> x509.NameConstraints:
    permitted = value.get("permitted")
    if not permitted:
        permitted_subtrees = None
    else:
        permitted_subtrees = [parse_general_name(name) for name in permitted]

    excluded = value.get("excluded")
    if not excluded:
        excluded_subtrees = None
    else:
        excluded_subtrees = [parse_general_name(name) for name in excluded]
    return x509.NameConstraints(permitted_subtrees=permitted_subtrees, excluded_subtrees=excluded_subtrees)


def _parse_policy_constraints(value: ParsablePolicyConstraints) -> x509.PolicyConstraints:
    return x509.PolicyConstraints(
        require_explicit_policy=value.get("require_explicit_policy"),
        inhibit_policy_mapping=value.get("inhibit_policy_mapping"),
    )


def _parse_subject_key_identifier(value: ParsableSubjectKeyIdentifier) -> x509.SubjectKeyIdentifier:
    if isinstance(value, x509.SubjectKeyIdentifier):
        return value
    if isinstance(value, str):
        value = hex_to_bytes(value)
    return x509.SubjectKeyIdentifier(digest=value)


def _parse_tls_feature(value: typing.Iterable[typing.Union[x509.TLSFeatureType, str]]) -> x509.TLSFeature:
    features: typing.List[x509.TLSFeatureType] = []
    for feature in value:
        if isinstance(feature, str):
            feature = TLS_FEATURE_NAME_MAPPING[feature]
        features.append(feature)

    # TYPE NOTE: In Python3.11, mypy thinks f.name is "Literal['status_request']?" instead of str
    features = sorted(features, key=lambda f: f.name)  # type: ignore[no-any-return]
    return x509.TLSFeature(features=features)


def parse_extension(  # pylint: disable=too-many-branches  # there's just many extensions
    key: str, value: typing.Union[x509.Extension[x509.ExtensionType], x509.ExtensionType, ParsableExtension]
) -> x509.Extension[x509.ExtensionType]:
    """Parse a serialized extension into a cryptography object.

    This function is used by :doc:`profiles` to parse configured extensions into standard cryptography
    extensions. If you need to parse a similar object, use this function.

    The `value` is usually a ``dict`` as described in profiles but for convenience, may also be a
    :py:class:`~cg:cryptography.x509.Extension`, in which case the extension is returned unchanged. If you
    pass a :py:class:`~cg:cryptography.x509.ExtensionType`, an extension with the default critical value is
    returned.

    >>> parse_extension("key_usage", {'critical': True, 'value': ['keyCertSign']})  # doctest: +ELLIPSIS
    <Extension(..., critical=True, value=<KeyUsage(... key_cert_sign=True, ...)>)>

    Parameters
    ----------
    key : str
        The `key` is the extension key used in the dictionary to name the extension, it must match one of the
        keys in :py:data:`~django_ca.constants.EXTENSION_KEYS`.
    value : dict, |ExtensionType| or |Extension|
        The value that describes the extension. See :doc:`/profiles` for more information.
    """
    if isinstance(value, x509.Extension):
        return value

    if isinstance(value, x509.ExtensionType):
        return x509.Extension(oid=value.oid, critical=EXTENSION_DEFAULT_CRITICAL[value.oid], value=value)

    if key == "authority_key_identifier":
        parsed: x509.ExtensionType = _parse_authority_key_identifier(value["value"])
    elif key == "authority_information_access":
        parsed = _parse_authority_information_access(value["value"])
    elif key == "basic_constraints":
        parsed = _parse_basic_constraints(value["value"])
    elif key == "certificate_policies":
        parsed = _parse_certificate_policies(value["value"])
    elif key == "crl_distribution_points":
        parsed = _parse_crl_distribution_points(value["value"])
    elif key == "freshest_crl":
        parsed = _parse_freshest_crl(value["value"])
    elif key == "extended_key_usage":
        parsed = _parse_extended_key_usage(value["value"])
    elif key == "issuer_alternative_name":
        parsed = x509.IssuerAlternativeName([parse_general_name(name) for name in value["value"]])
    elif key == "key_usage":
        parsed = _parse_key_usage(value["value"])
    elif key == "name_constraints":
        parsed = _parse_name_constraints(value["value"])
    elif key == "ocsp_no_check":
        parsed = x509.OCSPNoCheck()
    elif key == "inhibit_any_policy":
        parsed = x509.InhibitAnyPolicy(skip_certs=value["value"])
    elif key == "policy_constraints":
        parsed = _parse_policy_constraints(value["value"])
    elif key == "precert_poison":
        parsed = x509.PrecertPoison()
    elif key == "subject_alternative_name":
        parsed = x509.SubjectAlternativeName([parse_general_name(name) for name in value["value"]])
    elif key == "subject_key_identifier":
        parsed = _parse_subject_key_identifier(value["value"])
    elif key == "tls_feature":
        parsed = _parse_tls_feature(value["value"])
    elif key in ("precertificate_signed_certificate_timestamps", "signed_certificate_timestamps"):
        # https://github.com/pyca/cryptography/issues/7824
        raise ValueError(f"{key}: Cannot parse extensions of this type.")
    else:
        raise ValueError(f"{key}: Unknown extension key.")

    critical = value.get("critical", EXTENSION_DEFAULT_CRITICAL[parsed.oid])
    return x509.Extension(oid=parsed.oid, critical=critical, value=parsed)

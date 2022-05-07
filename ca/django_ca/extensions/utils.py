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

"""``django_ca.extensions.utils`` contains various utility classes used by X.509 extensions."""

import textwrap
import typing
from typing import Any
from typing import FrozenSet
from typing import Iterable
from typing import List
from typing import Optional
from typing import Set
from typing import Union

from cryptography import x509
from cryptography.x509 import ObjectIdentifier
from cryptography.x509.certificate_transparency import LogEntryType
from cryptography.x509.certificate_transparency import SignedCertificateTimestamp
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.x509.oid import ExtendedKeyUsageOID as _ExtendedKeyUsageOID

from django.template.loader import render_to_string

from ..typehints import ParsableDistributionPoint
from ..typehints import ParsablePolicyIdentifier
from ..typehints import ParsablePolicyInformation
from ..typehints import ParsablePolicyQualifier
from ..typehints import PolicyQualifier
from ..typehints import SerializedDistributionPoint
from ..typehints import SerializedPolicyInformation
from ..typehints import SerializedPolicyQualifier
from ..typehints import SerializedPolicyQualifiers
from ..typehints import SerializedUserNotice
from ..utils import bytes_to_hex
from ..utils import format_general_name
from ..utils import format_name
from ..utils import parse_general_name
from ..utils import x509_relative_name


class DistributionPoint:
    """Class representing a Distribution Point.

    This class is used internally by extensions that have a list of Distribution Points, e.g. the :
    :py:class:`~django_ca.extensions.CRLDistributionPoints` extension. The class accepts either a
    :py:class:`cg:cryptography.x509.DistributionPoint` or a ``dict``. Note that in the latter case, you can
    also pass a list of ``str`` as ``full_name`` or ``crl_issuer``::

        >>> DistributionPoint(x509.DistributionPoint(
        ...     full_name=[x509.UniformResourceIdentifier('http://ca.example.com/crl')],
        ...     relative_name=None, crl_issuer=None, reasons=None
        ... ))
        <DistributionPoint: full_name=['URI:http://ca.example.com/crl']>
        >>> DistributionPoint({'full_name': ['http://example.com']})
        <DistributionPoint: full_name=['URI:http://example.com']>
        >>> DistributionPoint({'full_name': ['http://example.com']})
        <DistributionPoint: full_name=['URI:http://example.com']>
        >>> DistributionPoint({
        ...     'relative_name': '/CN=example.com',
        ...     'crl_issuer': ['http://example.com'],
        ...     'reasons': ['key_compromise', 'ca_compromise'],
        ... })  # doctest: +NORMALIZE_WHITESPACE
        <DistributionPoint: relative_name='/CN=example.com', crl_issuer=['URI:http://example.com'],
                            reasons=['ca_compromise', 'key_compromise']>

    .. seealso::

        `RFC 5280, section 4.2.1.13 <https://tools.ietf.org/html/rfc5280#section-4.2.1.13>`_
    """

    full_name: Optional[typing.List[x509.GeneralName]] = None
    relative_name: Optional[x509.RelativeDistinguishedName] = None
    crl_issuer: Optional[typing.List[x509.GeneralName]] = None
    reasons: Optional[Set[x509.ReasonFlags]] = None

    def __init__(
        self, data: Optional[Union[x509.DistributionPoint, ParsableDistributionPoint]] = None
    ) -> None:
        if data is None:
            data = {}

        if isinstance(data, x509.DistributionPoint):
            if data.full_name is not None:
                self.full_name = data.full_name
            self.relative_name = data.relative_name
            if data.crl_issuer is not None:
                self.crl_issuer = data.crl_issuer
            if data.reasons is not None:
                self.reasons = set(data.reasons)
        elif isinstance(data, dict):
            full_name = data.get("full_name")
            if full_name is not None:
                self.full_name = [parse_general_name(name) for name in full_name]

            crl_issuer = data.get("crl_issuer")
            if crl_issuer is not None:
                self.crl_issuer = [parse_general_name(name) for name in crl_issuer]

            relative_name = data.get("relative_name")
            if isinstance(relative_name, str):
                self.relative_name = x509_relative_name(relative_name)
            else:
                self.relative_name = relative_name

            if "reasons" in data:
                self.reasons = {self._parse_reason(r) for r in data["reasons"]}

            if self.full_name and self.relative_name:
                raise ValueError("full_name and relative_name cannot both have a value")
        else:
            raise ValueError("data must be x509.DistributionPoint or dict")

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, DistributionPoint)
            and self.full_name == other.full_name
            and self.relative_name == other.relative_name
            and self.crl_issuer == other.crl_issuer
            and self.reasons == other.reasons
        )

    def __get_values(self) -> List[str]:
        values: List[str] = []
        if self.full_name:
            names = [format_general_name(name) for name in self.full_name]
            values.append(f"full_name={names}")
        if self.relative_name:
            values.append(f"relative_name='{format_name(self.relative_name)}'")
        if self.crl_issuer:
            names = [format_general_name(name) for name in self.crl_issuer]
            values.append(f"crl_issuer={names}")
        if self.reasons:
            values.append(f"reasons={sorted([r.name for r in self.reasons])}")
        return values

    def __hash__(self) -> int:
        full_name = tuple(self.full_name) if self.full_name else None
        crl_issuer = tuple(self.crl_issuer) if self.crl_issuer else None
        reasons = tuple(self.reasons) if self.reasons else None
        return hash((full_name, self.relative_name, crl_issuer, reasons))

    def __repr__(self) -> str:
        values = ", ".join(self.__get_values())
        return f"<DistributionPoint: {values}>"

    def __str__(self) -> str:
        return repr(self)

    def _parse_reason(self, reason: Union[str, x509.ReasonFlags]) -> x509.ReasonFlags:
        if isinstance(reason, str):
            return x509.ReasonFlags[reason]
        return reason

    @property
    def for_extension_type(self) -> x509.DistributionPoint:
        """Convert instance to a suitable cryptography class."""
        reasons: Optional[FrozenSet[x509.ReasonFlags]] = frozenset(self.reasons) if self.reasons else None
        return x509.DistributionPoint(
            full_name=self.full_name,
            relative_name=self.relative_name,
            crl_issuer=self.crl_issuer,
            reasons=reasons,
        )

    def serialize(self) -> SerializedDistributionPoint:
        """Serialize this distribution point."""
        val: SerializedDistributionPoint = {}

        if self.full_name:
            val["full_name"] = [format_general_name(name) for name in self.full_name]
        if self.relative_name is not None:
            val["relative_name"] = format_name(self.relative_name)
        if self.crl_issuer:
            val["crl_issuer"] = [format_general_name(name) for name in self.crl_issuer]
        if self.reasons is not None:
            val["reasons"] = list(sorted([r.name for r in self.reasons]))
        return val


class PolicyInformation(typing.MutableSequence[PolicyQualifier]):
    """Class representing a PolicyInformation object.

    This class is internally used by the :py:class:`~django_ca.extensions.CertificatePolicies` extension.

    You can pass a :py:class:`~cg:cryptography.x509.PolicyInformation` instance or a dictionary representing
    that instance::

        >>> PolicyInformation({'policy_identifier': '2.5.29.32.0', 'policy_qualifiers': ['text1']})
        <PolicyInformation(oid=2.5.29.32.0, qualifiers=['text1'])>
        >>> PolicyInformation({
        ...     'policy_identifier': '2.5.29.32.0',
        ...     'policy_qualifiers': [{'explicit_text': 'text2', }],
        ... })
        <PolicyInformation(oid=2.5.29.32.0, qualifiers=[{'explicit_text': 'text2'}])>
        >>> PolicyInformation({
        ...     'policy_identifier': '2.5',
        ...     'policy_qualifiers': [{
        ...         'notice_reference': {
        ...             'organization': 't3',
        ...             'notice_numbers': [1, ],
        ...         }
        ...     }],
        ... })  # doctest: +ELLIPSIS
        <PolicyInformation(oid=2.5, qualifiers=[{'notice_reference': {...}}])>
    """

    _policy_identifier: Optional[x509.ObjectIdentifier]
    policy_qualifiers: Optional[List[PolicyQualifier]]

    def __init__(
        self,
        data: Optional[Union[x509.PolicyInformation, ParsablePolicyInformation]] = None,
    ) -> None:
        if isinstance(data, x509.PolicyInformation):
            self.policy_identifier = data.policy_identifier
            self.policy_qualifiers = data.policy_qualifiers
        elif isinstance(data, dict):
            self.policy_identifier = data["policy_identifier"]
            self.policy_qualifiers = self.parse_policy_qualifiers(data.get("policy_qualifiers"))
        elif data is None:
            self.policy_identifier = None
            self.policy_qualifiers = None
        else:
            raise ValueError("PolicyInformation data must be either x509.PolicyInformation or dict")

    def __contains__(self, value: ParsablePolicyQualifier) -> bool:  # type: ignore[override]
        if self.policy_qualifiers is None:
            return False
        try:
            return self._parse_policy_qualifier(value) in self.policy_qualifiers
        except ValueError:  # not parsable
            return False

    def __delitem__(self, key: Union[int, slice]) -> None:
        if self.policy_qualifiers is None:
            raise IndexError("list assignment index out of range")
        del self.policy_qualifiers[key]
        if not self.policy_qualifiers:
            self.policy_qualifiers = None

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, PolicyInformation)
            and self.policy_identifier == other.policy_identifier
            and self.policy_qualifiers == other.policy_qualifiers
        )

    @typing.overload  # type: ignore[override] # should return non-serialized version
    def __getitem__(self, key: int) -> SerializedPolicyQualifier:
        ...

    @typing.overload
    def __getitem__(self, key: slice) -> List[SerializedPolicyQualifier]:
        ...

    def __getitem__(
        self, key: Union[int, slice]
    ) -> Union[List[SerializedPolicyQualifier], SerializedPolicyQualifier]:
        """Implement item getter (e.g ``pi[0]`` or ``pi[0:1]``)."""

        if self.policy_qualifiers is None:
            raise IndexError("list index out of range")
        if isinstance(key, int):
            return self._serialize_policy_qualifier(self.policy_qualifiers[key])

        return [self._serialize_policy_qualifier(k) for k in self.policy_qualifiers[key]]

    def __hash__(self) -> int:
        if self.policy_qualifiers is None:
            tup = None
        else:
            tup = tuple(self.policy_qualifiers)

        return hash((self.policy_identifier, tup))

    def __iter__(self) -> typing.Iterator[PolicyQualifier]:
        if self.policy_qualifiers is None:
            return iter([])
        return iter(self.policy_qualifiers)

    def __len__(self) -> int:
        if self.policy_qualifiers is None:
            return 0
        return len(self.policy_qualifiers)

    def __repr__(self) -> str:
        if self.policy_identifier is None:
            ident = "None"
        else:
            ident = self.policy_identifier.dotted_string

        return f"<PolicyInformation(oid={ident}, qualifiers={self.serialize_policy_qualifiers()})>"

    def __setitem__(
        self,
        key: typing.Union[int, slice],
        value: typing.Union[ParsablePolicyQualifier, typing.Iterable[ParsablePolicyQualifier]],
    ) -> None:
        """Implement item getter (e.g ``pi[0]`` or ``pi[0:1]``)."""
        if isinstance(key, slice) and isinstance(value, typing.Iterable):
            qualifiers = [self._parse_policy_qualifier(v) for v in value]
            if self.policy_qualifiers is None:
                self.policy_qualifiers = []
            self.policy_qualifiers[key] = qualifiers
        elif isinstance(key, int):
            if self.policy_qualifiers is None:
                # Note: same as for examle "list()[0] = 3"
                raise ValueError("Index out of range")

            # NOTE: cast() here b/c Parsable... may also be an Iterable, so we cannot use isinstance() to
            #       narrow the scope known to mypy.
            qualifier = self._parse_policy_qualifier(typing.cast(ParsablePolicyQualifier, value))
            self.policy_qualifiers[key] = qualifier
        else:
            raise TypeError(f"{key}/{value}: Invalid key/value type")

    def __str__(self) -> str:
        return repr(self)

    def append(self, value: ParsablePolicyQualifier) -> None:
        """Append the given policy qualifier."""
        if self.policy_qualifiers is None:
            self.policy_qualifiers = []
        self.policy_qualifiers.append(self._parse_policy_qualifier(value))

    def clear(self) -> None:
        """Clear all qualifiers from this information."""
        self.policy_qualifiers = None

    def count(self, value: ParsablePolicyQualifier) -> int:
        """Count qualifiers from this information."""
        if self.policy_qualifiers is None:
            return 0

        try:
            parsed_value = self._parse_policy_qualifier(value)
        except ValueError:
            return 0

        return self.policy_qualifiers.count(parsed_value)

    def extend(self, values: Iterable[ParsablePolicyQualifier]) -> None:
        """Extend qualifiers with given iterable."""
        if self.policy_qualifiers is None:
            self.policy_qualifiers = []

        self.policy_qualifiers.extend([self._parse_policy_qualifier(v) for v in values])

    @property
    def for_extension_type(self) -> x509.PolicyInformation:
        """Convert instance to a suitable cryptography class."""
        return x509.PolicyInformation(
            policy_identifier=self.policy_identifier, policy_qualifiers=self.policy_qualifiers
        )

    def insert(self, index: int, value: ParsablePolicyQualifier) -> None:
        """Insert qualifier at given index."""
        if self.policy_qualifiers is None:
            self.policy_qualifiers = []
        self.policy_qualifiers.insert(index, self._parse_policy_qualifier(value))

    def _parse_policy_qualifier(self, qualifier: ParsablePolicyQualifier) -> PolicyQualifier:

        if isinstance(qualifier, str):
            return qualifier
        if isinstance(qualifier, x509.UserNotice):
            return qualifier
        if isinstance(qualifier, dict):
            explicit_text = qualifier.get("explicit_text")

            notice_reference = qualifier.get("notice_reference")
            if isinstance(notice_reference, dict):
                notice_reference = x509.NoticeReference(
                    organization=notice_reference.get("organization"),
                    notice_numbers=[int(i) for i in notice_reference.get("notice_numbers", [])],
                )
            elif notice_reference is None:
                pass  # extra branch to ensure test coverage
            elif isinstance(notice_reference, x509.NoticeReference):
                pass  # extra branch to ensure test coverage
            else:
                raise ValueError("NoticeReference must be either None, a dict or an x509.NoticeReference")

            return x509.UserNotice(explicit_text=explicit_text, notice_reference=notice_reference)
        raise ValueError("PolicyQualifier must be string, dict or x509.UserNotice")

    def parse_policy_qualifiers(
        self, qualifiers: Optional[Iterable[ParsablePolicyQualifier]]
    ) -> Optional[List[PolicyQualifier]]:
        """Parse given list of policy qualifiers."""
        if qualifiers is None:
            return None
        return [self._parse_policy_qualifier(q) for q in qualifiers]

    def get_policy_identifier(self) -> Optional[x509.ObjectIdentifier]:
        """Property for the policy identifier.

        Note that you can set any parsable value, it will always be an object identifier::

            >>> pi = PolicyInformation()
            >>> pi.policy_identifier = '1.2.3'
            >>> pi.policy_identifier
            <ObjectIdentifier(oid=1.2.3, name=Unknown OID)>
        """
        return self._policy_identifier

    def _set_policy_identifier(self, value: ParsablePolicyIdentifier) -> None:
        if isinstance(value, str):
            self._policy_identifier = ObjectIdentifier(value)
        else:
            self._policy_identifier = value

    policy_identifier = property(get_policy_identifier, _set_policy_identifier)

    # NOTE: should return non-serialized version instead
    def pop(self, index: int = -1) -> SerializedPolicyQualifier:  # type: ignore[override]
        """Pop qualifier from given index."""
        if self.policy_qualifiers is None:
            return [].pop()

        val = self._serialize_policy_qualifier(self.policy_qualifiers.pop(index))

        if not self.policy_qualifiers:  # if list is now empty, set to none
            self.policy_qualifiers = None

        return val

    def remove(self, value: ParsablePolicyQualifier) -> PolicyQualifier:  # type: ignore[override]
        """Remove the given qualifier from this policy information.

        Note that unlike list.remove(), this value returns the parsed value.
        """
        if self.policy_qualifiers is None:
            # Shortcut to raise the same Value error as if the element is not in the list
            raise ValueError(f"{value}: not in list.")

        parsed_value = self._parse_policy_qualifier(value)
        self.policy_qualifiers.remove(parsed_value)

        if not self.policy_qualifiers:  # if list is now empty, set to none
            self.policy_qualifiers = None

        return parsed_value

    def _serialize_policy_qualifier(self, qualifier: PolicyQualifier) -> SerializedPolicyQualifier:
        if isinstance(qualifier, str):
            return qualifier

        value: SerializedUserNotice = {}
        if qualifier.explicit_text:
            value["explicit_text"] = qualifier.explicit_text

        if qualifier.notice_reference:
            value["notice_reference"] = {
                "notice_numbers": qualifier.notice_reference.notice_numbers,
            }
            if qualifier.notice_reference.organization is not None:
                value["notice_reference"]["organization"] = qualifier.notice_reference.organization
        return value

    def serialize_policy_qualifiers(self) -> Optional[SerializedPolicyQualifiers]:
        """Serialize policy qualifiers."""
        if self.policy_qualifiers is None:
            return None

        return [self._serialize_policy_qualifier(q) for q in self.policy_qualifiers]

    def serialize(self) -> SerializedPolicyInformation:
        """Serialize this policy information."""
        return {
            "policy_identifier": self.policy_identifier.dotted_string,
            "policy_qualifiers": self.serialize_policy_qualifiers(),
        }


class ExtendedKeyUsageOID(_ExtendedKeyUsageOID):
    """Extend the OIDs known to cryptography with what users needed over the years."""

    # Defined in RFC 3280, occurs in TrustID Server A52 CA
    IPSEC_END_SYSTEM = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.5")
    IPSEC_TUNNEL = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.6")
    IPSEC_USER = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.7")

    # Used by PKINIT logon on Windows (see  github #46)
    SMARTCARD_LOGON = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.2")
    KERBEROS_CONSTRAINED_DELEGATION = x509.ObjectIdentifier("1.3.6.1.5.2.3.5")  # or msKCD

    # mobilee Driving Licence or mDL (see ISO/IEC DIS 18013-5, GitHub PR #81)
    MDL_DOCUMENT_SIGNER = x509.ObjectIdentifier("1.0.18013.5.1.2")
    MDL_JWS_CERTIFICATE = x509.ObjectIdentifier("1.0.18013.5.1.3")


# ExtendedKeyUsageOID.IPSEC_IKE should be statically integrated into EXTENDED_KEY_USAGE_NAMES once support for
# cryptography<37.0 is dropped.
if hasattr(ExtendedKeyUsageOID, "IPSEC_IKE"):  # pragma: only cryptography>=37.0
    _ipsec_ike_oid = ExtendedKeyUsageOID.IPSEC_IKE
else:  # pragma: only cryptography<37.0
    _ipsec_ike_oid = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.17")

EXTENDED_KEY_USAGE_NAMES = {
    ExtendedKeyUsageOID.SERVER_AUTH: "serverAuth",
    ExtendedKeyUsageOID.CLIENT_AUTH: "clientAuth",
    ExtendedKeyUsageOID.CODE_SIGNING: "codeSigning",
    ExtendedKeyUsageOID.EMAIL_PROTECTION: "emailProtection",
    ExtendedKeyUsageOID.TIME_STAMPING: "timeStamping",
    ExtendedKeyUsageOID.OCSP_SIGNING: "OCSPSigning",
    ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE: "anyExtendedKeyUsage",
    ExtendedKeyUsageOID.SMARTCARD_LOGON: "smartcardLogon",
    ExtendedKeyUsageOID.KERBEROS_CONSTRAINED_DELEGATION: "msKDC",
    ExtendedKeyUsageOID.IPSEC_END_SYSTEM: "ipsecEndSystem",
    ExtendedKeyUsageOID.IPSEC_TUNNEL: "ipsecTunnel",
    ExtendedKeyUsageOID.IPSEC_USER: "ipsecUser",
    ExtendedKeyUsageOID.MDL_DOCUMENT_SIGNER: "mdlDS",
    ExtendedKeyUsageOID.MDL_JWS_CERTIFICATE: "mdlJWS",
    _ipsec_ike_oid: "ipsecIKE",
}


KEY_USAGE_NAMES = {
    "crl_sign": "cRLSign",
    "data_encipherment": "dataEncipherment",
    "decipher_only": "decipherOnly",
    "digital_signature": "digitalSignature",
    "encipher_only": "encipherOnly",
    "key_agreement": "keyAgreement",
    "key_cert_sign": "keyCertSign",
    "key_encipherment": "keyEncipherment",
    "content_commitment": "nonRepudiation",  # http://marc.info/?t=107176106300005&r=1&w=2
}


def _authority_information_access_as_text(value: x509.AuthorityInformationAccess) -> str:
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


def _distribution_points_as_text(value: typing.List[x509.DistributionPoint]) -> str:
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


def key_usage_items(value: x509.KeyUsage) -> typing.Iterator[str]:
    """Get a list of basic key usages."""
    for attr, name in KEY_USAGE_NAMES.items():
        try:
            if getattr(value, attr):
                yield name
        except ValueError:
            # x509.KeyUsage raises ValueError on some attributes to ensure consistency
            pass


def _key_usage_as_text(value: x509.KeyUsage) -> str:
    return "\n".join(f"* {name}" for name in key_usage_items(value))


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


def signed_certificate_timestamp_values(sct: SignedCertificateTimestamp) -> typing.Tuple[str, str, str, str]:
    """Get values from a SignedCertificateTimestamp as a tuple of strings."""
    if sct.entry_type == LogEntryType.PRE_CERTIFICATE:
        entry_type = "Precertificate"
    elif sct.entry_type == LogEntryType.X509_CERTIFICATE:  # pragma: no cover  # Unseen in the wild
        entry_type = "x509 certificate"
    else:  # pragma: no cover  # We support everything that has been specified so far
        entry_type = "unknown"
    return entry_type, sct.version.name, bytes_to_hex(sct.log_id), sct.timestamp.isoformat(" ")


def _signed_certificate_timestamps_as_text(value: typing.List[SignedCertificateTimestamp]) -> str:
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
        return _distribution_points_as_text(list(value))
    if isinstance(value, (x509.IssuerAlternativeName, x509.SubjectAlternativeName)):
        return "\n".join(f"* {format_general_name(name)}" for name in value)
    if isinstance(value, (x509.PrecertificateSignedCertificateTimestamps, x509.SignedCertificateTimestamps)):
        return _signed_certificate_timestamps_as_text(list(value))
    if isinstance(value, x509.AuthorityInformationAccess):
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
    raise TypeError("Unknown extension type.")  # pragma: no cover


def extension_as_admin_html(extension: x509.Extension[x509.ExtensionType]) -> str:
    """Convert an extension to HTML code suitable for the admin interface."""
    template = f"django_ca/admin/extensions/{extension.oid.dotted_string}.html"
    if isinstance(extension.value, x509.UnrecognizedExtension):
        template = "django_ca/admin/extensions/unrecognized_extension.html"

    return render_to_string([template], context={"extension": extension, "x509": x509})

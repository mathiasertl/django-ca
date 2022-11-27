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

import typing
from typing import Any, FrozenSet, Iterable, List, Optional, Set, Tuple, Union

from cryptography import x509
from cryptography.x509 import ObjectIdentifier
from cryptography.x509.certificate_transparency import LogEntryType, SignedCertificateTimestamp

from django.template.loader import render_to_string

from .. import typehints
from ..constants import KEY_USAGE_NAMES
from ..typehints import (
    ParsableDistributionPoint,
    ParsablePolicyIdentifier,
    ParsablePolicyInformation,
    ParsablePolicyQualifier,
    PolicyQualifier,
    SerializedPolicyInformation,
    SerializedPolicyQualifier,
    SerializedPolicyQualifiers,
    SerializedUserNotice,
)
from ..utils import bytes_to_hex, format_general_name, format_name, parse_general_name, x509_relative_name


class DistributionPoint:
    """Class representing a Distribution Point.

    This class is used internally by extensions that have a list of Distribution Points, e.g. the :
    ``django_ca.extensions.CRLDistributionPoints`` extension. The class accepts either a
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

    full_name: Optional[List[x509.GeneralName]] = None
    relative_name: Optional[x509.RelativeDistinguishedName] = None
    crl_issuer: Optional[List[x509.GeneralName]] = None
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

    def serialize(self) -> typehints.SerializedDistributionPoint:
        """Serialize this distribution point."""
        val: typehints.SerializedDistributionPoint = {}

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

    This class is internally used by the ``django_ca.extensions.CertificatePolicies`` extension.

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
        key: Union[int, slice],
        value: Union[ParsablePolicyQualifier, Iterable[ParsablePolicyQualifier]],
    ) -> None:
        """Implement item getter (e.g ``pi[0]`` or ``pi[0:1]``)."""
        if isinstance(key, slice) and isinstance(value, Iterable):
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


TLS_FEATURE_NAME_MAPPING = {
    # https://tools.ietf.org/html/rfc6066.html:
    "OCSPMustStaple": x509.TLSFeatureType.status_request,
    "status_request": x509.TLSFeatureType.status_request,
    # https://tools.ietf.org/html/rfc6961.html (not commonly used):
    "MultipleCertStatusRequest": x509.TLSFeatureType.status_request_v2,
    "status_request_v2": x509.TLSFeatureType.status_request_v2,
}


def extension_as_admin_html(extension: x509.Extension[x509.ExtensionType]) -> str:
    """Convert an extension to HTML code suitable for the admin interface."""
    template = f"django_ca/admin/extensions/{extension.oid.dotted_string}.html"
    if isinstance(extension.value, x509.UnrecognizedExtension):
        template = "django_ca/admin/extensions/unrecognized_extension.html"

    return render_to_string([template], context={"extension": extension, "x509": x509})


def key_usage_items(value: x509.KeyUsage) -> typing.Iterator[str]:
    """Get a list of basic key usages."""
    for attr, name in KEY_USAGE_NAMES.items():
        try:
            if getattr(value, attr):
                yield name
        except ValueError:
            # x509.KeyUsage raises ValueError on some attributes to ensure consistency
            pass


def signed_certificate_timestamp_values(sct: SignedCertificateTimestamp) -> Tuple[str, str, str, str]:
    """Get values from a SignedCertificateTimestamp as a tuple of strings."""
    if sct.entry_type == LogEntryType.PRE_CERTIFICATE:
        entry_type = "Precertificate"
    elif sct.entry_type == LogEntryType.X509_CERTIFICATE:  # pragma: no cover  # Unseen in the wild
        entry_type = "x509 certificate"
    else:  # pragma: no cover  # We support everything that has been specified so far
        entry_type = "unknown"
    return entry_type, sct.version.name, bytes_to_hex(sct.log_id), sct.timestamp.isoformat(" ")

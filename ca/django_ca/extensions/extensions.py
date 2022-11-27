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

"""Module providing wrapper classes for various x509 extensions.

The classes in this module wrap cryptography extensions, but allow adding/removing values, creating extensions
in a more pythonic manner and provide access functions."""

from typing import ClassVar, Optional, Set, Tuple, Union

from cryptography import x509
from cryptography.x509 import TLSFeatureType
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

from ..constants import EXTENDED_KEY_USAGE_NAMES, KEY_USAGE_NAMES
from ..typehints import (
    ParsableAuthorityInformationAccess,
    ParsableAuthorityKeyIdentifier,
    ParsableBasicConstraints,
    ParsableExtension,
    ParsableGeneralNameList,
    ParsableNameConstraints,
    ParsablePolicyConstraints,
    ParsablePolicyInformation,
    ParsableSubjectKeyIdentifier,
    SerializedAuthorityInformationAccess,
    SerializedAuthorityKeyIdentifier,
    SerializedBasicConstraints,
    SerializedNameConstraints,
    SerializedPolicyConstraints,
    SerializedPolicyInformation,
)
from ..utils import GeneralNameList, bytes_to_hex, hex_to_bytes
from .base import (
    AlternativeNameExtension,
    CRLDistributionPointsBase,
    Extension,
    ListExtension,
    NullExtension,
    OrderedSetExtension,
    SignedCertificateTimestampsBase,
)
from .utils import PolicyInformation

# Placeholder until we fill in something good
ParsableValueDummy = str


class AuthorityInformationAccess(
    Extension[
        x509.AuthorityInformationAccess,
        ParsableAuthorityInformationAccess,
        SerializedAuthorityInformationAccess,
    ]
):
    """Class representing a AuthorityInformationAccess extension.

    .. seealso::

        `RFC 5280, section 4.2.2.1 <https://tools.ietf.org/html/rfc5280#section-4.2.2.1>`_

    The value passed to this extension should be a ``dict`` with an ``ocsp`` and ``issuers`` key, both are
    optional::

        >>> AuthorityInformationAccess({'value': {
        ...     'ocsp': ['http://ocsp.example.com'],
        ...     'issuers': ['http://issuer.example.com'],
        ... }})  # doctest: +NORMALIZE_WHITESPACE
        <AuthorityInformationAccess: issuers=['URI:http://issuer.example.com'],
        ocsp=['URI:http://ocsp.example.com'], critical=False>

    You can set/get the OCSP/issuers at runtime and dynamically use either strings or
    :py:class:`~cryptography.x509.GeneralName` as values::

        >>> aia = AuthorityInformationAccess()
        >>> aia.issuers = ['http://issuer.example.com']
        >>> aia.ocsp = [x509.UniformResourceIdentifier('http://ocsp.example.com/')]
        >>> aia  # doctest: +NORMALIZE_WHITESPACE
        <AuthorityInformationAccess: issuers=['URI:http://issuer.example.com'],
        ocsp=['URI:http://ocsp.example.com/'], critical=False>
    """

    key = "authority_information_access"
    """Key used in CA_PROFILES."""

    name: ClassVar[str] = "AuthorityInformationAccess"
    oid: ClassVar[x509.ObjectIdentifier] = ExtensionOID.AUTHORITY_INFORMATION_ACCESS
    _ocsp: GeneralNameList
    _issuers: GeneralNameList

    def __bool__(self) -> bool:
        return bool(self._ocsp) or bool(self._issuers)

    def hash_value(self) -> Tuple[Tuple[x509.GeneralName, ...], Tuple[x509.GeneralName, ...]]:
        return tuple(self._issuers), tuple(self._ocsp)

    def repr_value(self) -> str:
        return f"issuers={self._issuers.serialize()}, ocsp={self._ocsp.serialize()}"

    def _get_issuers(self) -> GeneralNameList:
        """Issuers named by this extension."""
        return self._issuers

    def _set_issuers(self, value: Union[GeneralNameList, ParsableGeneralNameList]) -> None:
        if not isinstance(value, GeneralNameList):
            value = GeneralNameList(value)
        self._issuers = value

    @property
    def extension_type(self) -> x509.AuthorityInformationAccess:
        descs = [x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, v) for v in self._issuers]
        descs += [x509.AccessDescription(AuthorityInformationAccessOID.OCSP, v) for v in self._ocsp]
        return x509.AuthorityInformationAccess(descriptions=descs)

    def from_extension(self, value: x509.AuthorityInformationAccess) -> None:
        self.issuers = [
            v.access_location for v in value if v.access_method == AuthorityInformationAccessOID.CA_ISSUERS
        ]
        self.ocsp = [
            v.access_location for v in value if v.access_method == AuthorityInformationAccessOID.OCSP
        ]

    def from_dict(self, value: ParsableAuthorityInformationAccess) -> None:
        self.issuers = value.get("issuers")
        self.ocsp = value.get("ocsp")

    def _get_ocsp(self) -> GeneralNameList:
        """OCSP endpoints described by this extension."""
        return self._ocsp

    def _set_ocsp(self, value: Union[GeneralNameList, ParsableGeneralNameList]) -> None:
        if not isinstance(value, GeneralNameList):
            value = GeneralNameList(value)
        self._ocsp = value

    def serialize_value(self) -> SerializedAuthorityInformationAccess:
        value: SerializedAuthorityInformationAccess = {}
        if self._issuers:
            value["issuers"] = self._issuers.serialize()
        if self._ocsp:
            value["ocsp"] = self._ocsp.serialize()
        return value

    issuers = property(_get_issuers, _set_issuers)
    ocsp = property(_get_ocsp, _set_ocsp)


class AuthorityKeyIdentifier(
    Extension[x509.AuthorityKeyIdentifier, ParsableAuthorityKeyIdentifier, SerializedAuthorityKeyIdentifier]
):
    """Class representing a AuthorityKeyIdentifier extension.

    This extension identifies the signing CA, so it is not usually defined in a profile or instantiated by a
    user. This extension will automatically be added by django-ca. If it is, the value must be a str or
    bytes::

        >>> AuthorityKeyIdentifier({'value': '33:33:33:33:33:33'})
        <AuthorityKeyIdentifier: keyid: 33:33:33:33:33:33, critical=False>
        >>> AuthorityKeyIdentifier({'value': b'333333'})
        <AuthorityKeyIdentifier: keyid: 33:33:33:33:33:33, critical=False>

    If you want to set an ``authorityCertIssuer`` and ``authorityCertIssuer``, you can also pass a ``dict``
    instead::

        >>> AuthorityKeyIdentifier({'value': {
        ...     'key_identifier': b'0',
        ...     'authority_cert_issuer': ['example.com'],
        ...     'authority_cert_serial_number': 1,
        ... }})
        <AuthorityKeyIdentifier: keyid: 30, issuer: ['DNS:example.com'], serial: 1, critical=False>

    .. seealso::

        `RFC 5280, section 4.2.1.1 <https://tools.ietf.org/html/rfc5280#section-4.2.1.1>`_
    """

    key = "authority_key_identifier"
    """Key used in CA_PROFILES."""

    name: ClassVar[str] = "AuthorityKeyIdentifier"
    oid: ClassVar[x509.ObjectIdentifier] = ExtensionOID.AUTHORITY_KEY_IDENTIFIER
    key_identifier: Optional[bytes] = None
    authority_cert_issuer: GeneralNameList
    authority_cert_serial_number: Optional[int] = None

    def __init__(
        self,
        value: Optional[
            Union["x509.Extension[x509.AuthorityKeyIdentifier]", ParsableExtension, "SubjectKeyIdentifier"]
        ] = None,
    ) -> None:
        if isinstance(value, SubjectKeyIdentifier):
            self.deprecate()
            self.critical = self.default_critical
            self.from_subject_key_identifier(value)
            self._test_value()
        else:
            super().__init__(value)

    def hash_value(self) -> Tuple[Optional[bytes], Tuple[x509.GeneralName, ...], Optional[int]]:
        return self.key_identifier, tuple(self.authority_cert_issuer), self.authority_cert_serial_number

    def repr_value(self) -> str:
        values = []
        if self.key_identifier is not None:
            values.append(f"keyid: {bytes_to_hex(self.key_identifier)}")
        if self.authority_cert_issuer:
            values.append(f"issuer: {self.authority_cert_issuer.serialize()}")
        if self.authority_cert_serial_number is not None:
            values.append(f"serial: {self.authority_cert_serial_number}")

        return ", ".join(values)

    @property
    def extension_type(self) -> x509.AuthorityKeyIdentifier:
        issuer: Optional[GeneralNameList] = self.authority_cert_issuer
        if not issuer:
            issuer = None

        return x509.AuthorityKeyIdentifier(
            key_identifier=self.key_identifier,
            authority_cert_issuer=issuer,
            authority_cert_serial_number=self.authority_cert_serial_number,
        )

    def from_dict(self, value: ParsableAuthorityKeyIdentifier) -> None:
        if isinstance(value, (bytes, str)):
            self.key_identifier = self.parse_keyid(value)
            self.authority_cert_issuer = GeneralNameList()
        else:
            self.key_identifier = self.parse_keyid(value.get("key_identifier"))
            self.authority_cert_issuer = GeneralNameList(value.get("authority_cert_issuer"))
            serial_number = value.get("authority_cert_serial_number")
            if isinstance(serial_number, str):
                serial_number = int(serial_number)
            self.authority_cert_serial_number = serial_number

    def from_extension(self, value: x509.AuthorityKeyIdentifier) -> None:
        self.key_identifier = value.key_identifier
        self.authority_cert_issuer = GeneralNameList(value.authority_cert_issuer)
        self.authority_cert_serial_number = value.authority_cert_serial_number

    def from_subject_key_identifier(self, ext: "SubjectKeyIdentifier") -> None:
        """Create an extension based on SubjectKeyIdentifier extension."""
        self.key_identifier = ext.value
        self.authority_cert_issuer = GeneralNameList()
        self.authority_cert_serial_number = None

    def parse_keyid(self, value: Optional[Union[str, bytes]]) -> Optional[bytes]:
        """Parse the given key id (may be None)."""
        if isinstance(value, bytes):
            return value
        if value is not None:
            return hex_to_bytes(value)
        return None  # or mypy and pylint complain

    def serialize_value(self) -> SerializedAuthorityKeyIdentifier:
        value: SerializedAuthorityKeyIdentifier = {}
        if self.key_identifier is not None:
            value["key_identifier"] = bytes_to_hex(self.key_identifier)
        if self.authority_cert_issuer:
            value["authority_cert_issuer"] = self.authority_cert_issuer.serialize()
        if self.authority_cert_serial_number is not None:
            value["authority_cert_serial_number"] = self.authority_cert_serial_number

        return value


class BasicConstraints(
    Extension[x509.BasicConstraints, ParsableBasicConstraints, SerializedBasicConstraints]
):
    """Class representing a BasicConstraints extension.

    This class has the boolean attributes ``ca`` and the attribute ``pathlen``, which is either ``None`` or an
    ``int``. Note that this extension is marked as critical by default if you pass a dict to the constructor::

        >>> bc = BasicConstraints({'value': {'ca': True, 'pathlen': 4}})
        >>> (bc.ca, bc.pathlen, bc.critical)
        (True, 4, True)

    .. seealso::

        `RFC 5280, section 4.2.1.9 <https://tools.ietf.org/html/rfc5280#section-4.2.1.9>`_
    """

    key = "basic_constraints"
    """Key used in CA_PROFILES."""

    name: ClassVar[str] = "BasicConstraints"
    oid: ClassVar[x509.ObjectIdentifier] = ExtensionOID.BASIC_CONSTRAINTS
    ca: bool
    pathlen: Optional[int]
    default_critical = True
    """This extension is marked as critical by default."""

    def hash_value(self) -> Tuple[bool, Optional[int]]:
        return self.ca, self.pathlen

    def repr_value(self) -> str:
        val = f"ca={self.ca}"
        if self.ca:
            val += f", pathlen={self.pathlen}"
        return val

    def from_extension(self, value: x509.BasicConstraints) -> None:
        self.ca = value.ca
        self.pathlen = value.path_length

    def from_dict(self, value: ParsableBasicConstraints) -> None:
        self.ca = bool(value.get("ca", False))
        if self.ca:
            self.pathlen = self.parse_pathlen(value.get("pathlen"))
        else:  # if ca is not True, we don't use the pathlen
            self.pathlen = None

    @property
    def extension_type(self) -> x509.BasicConstraints:
        return x509.BasicConstraints(ca=self.ca, path_length=self.pathlen)

    def parse_pathlen(self, value: Optional[Union[int, str]]) -> Optional[int]:
        """Parse `value` as path length (either an int, a str of an int or None)."""
        if value is not None:
            try:
                return int(value)
            except ValueError as ex:
                raise ValueError(f'Could not parse pathlen: "{value}"') from ex
        return value

    def serialize_value(self) -> SerializedBasicConstraints:
        value: SerializedBasicConstraints = {"ca": self.ca}
        if self.ca:
            value["pathlen"] = self.pathlen
        return value


class CRLDistributionPoints(CRLDistributionPointsBase[x509.CRLDistributionPoints]):
    """Class representing a CRLDistributionPoints extension.

    This extension identifies where a client can retrieve a Certificate Revocation List (CRL).

    The value passed to this extension should be a ``list`` of
    ``django_ca.extensions.utils.DistributionPoint`` instances. Naturally, you can also pass those in
    serialized form::

        >>> CRLDistributionPoints({'value': [
        ...     {'full_name': ['http://crl.example.com']}
        ... ]})  # doctest: +NORMALIZE_WHITESPACE
        <CRLDistributionPoints: [<DistributionPoint: full_name=['URI:http://crl.example.com']>],
        critical=False>

    .. seealso::

        `RFC 5280, section 4.2.1.13 <https://tools.ietf.org/html/rfc5280#section-4.2.1.13>`_
    """

    key = "crl_distribution_points"
    """Key used in CA_PROFILES."""

    name: ClassVar[str] = "CRLDistributionPoints"
    oid: ClassVar[x509.ObjectIdentifier] = ExtensionOID.CRL_DISTRIBUTION_POINTS

    @property
    def extension_type(self) -> x509.CRLDistributionPoints:
        return x509.CRLDistributionPoints(distribution_points=[dp.for_extension_type for dp in self.value])


class CertificatePolicies(
    ListExtension[
        x509.CertificatePolicies,
        Union[PolicyInformation, ParsablePolicyInformation],
        SerializedPolicyInformation,
        PolicyInformation,
    ]
):
    """Class representing a Certificate Policies extension.

    The value passed to this extension should be a ``list`` of
    ``django_ca.extensions.utils.PolicyInformation`` instances. Naturally, you can also pass those in
    serialized form::

        >>> CertificatePolicies({'value': [{
        ...     'policy_identifier': '2.5.29.32.0',
        ...     'policy_qualifier': ['policy1'],
        ... }]})
        <CertificatePolicies: 1 policy, critical=False>

    .. seealso::

        `RFC 5280, section 4.2.1.4 <https://tools.ietf.org/html/rfc5280#section-4.2.1.4>`_
    """

    key = "certificate_policies"
    """Key used in CA_PROFILES."""

    name: ClassVar[str] = "CertificatePolicies"
    oid: ClassVar[x509.ObjectIdentifier] = ExtensionOID.CERTIFICATE_POLICIES

    def __hash__(self) -> int:
        return hash(
            (
                tuple(self.value),
                self.critical,
            )
        )

    def repr_value(self) -> str:
        if len(self.value) == 1:
            return "1 policy"
        return f"{len(self.value)} policies"

    @property
    def extension_type(self) -> x509.CertificatePolicies:
        return x509.CertificatePolicies(policies=[p.for_extension_type for p in self.value])

    def parse_value(self, value: Union[PolicyInformation, ParsablePolicyInformation]) -> PolicyInformation:
        if isinstance(value, PolicyInformation):
            return value
        return PolicyInformation(value)

    def serialize_item(self, value: PolicyInformation) -> SerializedPolicyInformation:
        return value.serialize()


class FreshestCRL(CRLDistributionPointsBase[x509.FreshestCRL]):
    """Class representing a FreshestCRL extension.

    This extension handles identically to the ``django_ca.extensions.CRLDistributionPoints``
    extension::

        >>> FreshestCRL({'value': [
        ...     {'full_name': ['http://crl.example.com']}
        ... ]})  # doctest: +NORMALIZE_WHITESPACE
        <FreshestCRL: [<DistributionPoint: full_name=['URI:http://crl.example.com']>],
        critical=False>

    .. seealso::

        `RFC 5280, section 4.2.1.15 <https://tools.ietf.org/html/rfc5280#section-4.2.1.15>`_
    """

    key = "freshest_crl"
    """Key used in CA_PROFILES."""

    name: ClassVar[str] = "FreshestCRL"
    oid: ClassVar[x509.ObjectIdentifier] = ExtensionOID.FRESHEST_CRL

    @property
    def extension_type(self) -> x509.FreshestCRL:
        return x509.FreshestCRL(distribution_points=[dp.for_extension_type for dp in self.value])


class IssuerAlternativeName(AlternativeNameExtension[x509.IssuerAlternativeName]):
    """Class representing an Issuer Alternative Name extension.

    This extension is usually marked as non-critical.

    >>> IssuerAlternativeName({'value': ['https://example.com']})
    <IssuerAlternativeName: ['URI:https://example.com'], critical=False>

    .. seealso::

       `RFC 5280, section 4.2.1.7 <https://tools.ietf.org/html/rfc5280#section-4.2.1.7>`_
    """

    key = "issuer_alternative_name"
    """Key used in CA_PROFILES."""

    name: ClassVar[str] = "IssuerAlternativeName"
    oid: ClassVar[x509.ObjectIdentifier] = ExtensionOID.ISSUER_ALTERNATIVE_NAME

    @property
    def extension_type(self) -> x509.IssuerAlternativeName:
        return x509.IssuerAlternativeName(self.value)


class KeyUsage(OrderedSetExtension[x509.KeyUsage, str, str, str]):
    """Class representing a KeyUsage extension, which defines the purpose of a certificate.

    This extension is usually marked as critical and RFC 5280 defines that conforming CAs SHOULD mark it as
    critical. The value ``keyAgreement`` is always added if ``encipherOnly`` or ``decipherOnly`` is present,
    since the value of this extension is not meaningful otherwise.

    >>> KeyUsage({'value': ['encipherOnly'], 'critical': True})
    <KeyUsage: ['encipherOnly', 'keyAgreement'], critical=True>
    >>> KeyUsage({'value': ['decipherOnly'], 'critical': True})
    <KeyUsage: ['decipherOnly', 'keyAgreement'], critical=True>

    .. seealso::

        `RFC 5280, section 4.2.1.3 <https://tools.ietf.org/html/rfc5280#section-4.2.1.3>`_
    """

    default_critical = True
    """This extension is marked as critical by default."""

    key = "key_usage"
    """Key used in CA_PROFILES."""

    name: ClassVar[str] = "KeyUsage"
    oid: ClassVar[x509.ObjectIdentifier] = ExtensionOID.KEY_USAGE
    CRYPTOGRAPHY_MAPPING = {v: k for k, v in KEY_USAGE_NAMES.items()}
    _CRYPTOGRAPHY_MAPPING_REVERSED = KEY_USAGE_NAMES
    KNOWN_VALUES = set(CRYPTOGRAPHY_MAPPING.values())

    KNOWN_PARAMETERS = sorted(CRYPTOGRAPHY_MAPPING)
    """Known values that can be passed to this extension."""

    CHOICES = (
        ("cRLSign", "CRL Sign"),
        ("dataEncipherment", "dataEncipherment"),
        ("decipherOnly", "decipherOnly"),
        ("digitalSignature", "Digital Signature"),
        ("encipherOnly", "encipherOnly"),
        ("keyAgreement", "Key Agreement"),
        ("keyCertSign", "Certificate Sign"),
        ("keyEncipherment", "Key Encipherment"),
        ("nonRepudiation", "nonRepudiation"),
    )

    def _test_value(self) -> None:
        # decipherOnly only makes sense if keyAgreement is True
        if "decipher_only" in self.value and "key_agreement" not in self.value:
            self.value.add("key_agreement")
        if "encipher_only" in self.value and "key_agreement" not in self.value:
            self.value.add("key_agreement")

    def from_extension(self, value: x509.KeyUsage) -> None:
        self.value = set()

        for val in self.KNOWN_VALUES:
            try:
                if getattr(value, val):
                    self.value.add(val)
            except ValueError:
                # cryptography throws a ValueError if encipher_only/decipher_only is accessed and
                # key_agreement is not set.
                pass

    @property
    def extension_type(self) -> x509.KeyUsage:
        kwargs = {v: (v in self.value) for v in self.KNOWN_VALUES}
        return x509.KeyUsage(**kwargs)

    def parse_value(self, value: str) -> str:
        if value in self.KNOWN_VALUES:
            return value
        try:
            return self.CRYPTOGRAPHY_MAPPING[value]
        except KeyError as ex:
            raise ValueError(f"Unknown value: {value}") from ex
        # Just a safe-guard to make sure that the function always returns or raises a ValueError
        raise ValueError(f"Unknown value: {value}")  # pragma: no cover  # function returns/raises before

    def serialize_item(self, value: str) -> str:
        return value


class ExtendedKeyUsage(
    OrderedSetExtension[x509.ExtendedKeyUsage, Union[x509.ObjectIdentifier, str], str, x509.ObjectIdentifier]
):
    """Class representing a ExtendedKeyUsage extension."""

    key = "extended_key_usage"
    """Key used in CA_PROFILES."""

    name: ClassVar[str] = "ExtendedKeyUsage"
    oid: ClassVar[x509.ObjectIdentifier] = ExtensionOID.EXTENDED_KEY_USAGE
    _CRYPTOGRAPHY_MAPPING_REVERSED = EXTENDED_KEY_USAGE_NAMES
    CRYPTOGRAPHY_MAPPING = {v: k for k, v in EXTENDED_KEY_USAGE_NAMES.items()}

    KNOWN_PARAMETERS = sorted(EXTENDED_KEY_USAGE_NAMES.values())
    """Known values that can be passed to this extension."""

    # Used by the HTML form select field
    CHOICES = (
        ("serverAuth", "SSL/TLS Web Server Authentication"),
        ("clientAuth", "SSL/TLS Web Client Authentication"),
        ("codeSigning", "Code signing"),
        ("emailProtection", "E-mail Protection (S/MIME)"),
        ("timeStamping", "Trusted Timestamping"),
        ("OCSPSigning", "OCSP Signing"),
        ("certificateTransparency", "Certificate Transparency"),
        ("smartcardLogon", "Smart card logon"),
        ("msKDC", "Kerberos Domain Controller"),
        ("ipsecEndSystem", "IPSec EndSystem"),
        ("ipsecIKE", "IPSec Internet Key Exchange"),
        ("ipsecTunnel", "IPSec Tunnel"),
        ("ipsecUser", "IPSec User"),
        ("mdlDS", "mdlDS"),
        ("mdlJWS", "mdlJWS"),
        ("anyExtendedKeyUsage", "Any Extended Key Usage"),
    )

    def from_extension(self, value: x509.ExtendedKeyUsage) -> None:
        self.value = set(value)

    @property
    def extension_type(self) -> x509.ExtendedKeyUsage:
        # call serialize_item() to ensure consistent sort order
        return x509.ExtendedKeyUsage(sorted(self.value, key=self.serialize_item))

    def serialize_item(self, value: x509.ObjectIdentifier) -> str:
        return EXTENDED_KEY_USAGE_NAMES[value]

    def parse_value(self, value: Union[x509.ObjectIdentifier, str]) -> x509.ObjectIdentifier:
        if isinstance(value, x509.ObjectIdentifier) and value in EXTENDED_KEY_USAGE_NAMES:
            return value
        if isinstance(value, str) and value in self.CRYPTOGRAPHY_MAPPING:
            return self.CRYPTOGRAPHY_MAPPING[value]
        raise ValueError(f"Unknown value: {value}")


class InhibitAnyPolicy(Extension[x509.InhibitAnyPolicy, int, int]):
    """Class representing a InhibitAnyPolicy extension.

    Example::

        >>> InhibitAnyPolicy({'value': 1})  # normal value dict is supported
        <InhibitAnyPolicy: 1, critical=True>
        >>> ext = InhibitAnyPolicy(3)  # a simple int is also okay
        >>> ext
        <InhibitAnyPolicy: 3, critical=True>
        >>> ext.skip_certs = 5
        >>> ext.skip_certs
        5

    .. seealso::

       `RFC 5280, section 4.2.1.14 <https://tools.ietf.org/html/rfc5280#section-4.2.1.14>`_

    """

    key = "inhibit_any_policy"
    """Key used in CA_PROFILES."""

    name: ClassVar[str] = "InhibitAnyPolicy"
    oid: ClassVar[x509.ObjectIdentifier] = ExtensionOID.INHIBIT_ANY_POLICY
    skip_certs: int

    default_value: ClassVar[int] = 0
    default_critical = True
    """This extension is marked as critical by default (RFC 5280 requires this extension to be marked as
    critical)."""

    def __init__(
        self,
        value: Optional[Union["x509.Extension[x509.InhibitAnyPolicy]", ParsableExtension, int]] = None,
    ) -> None:
        if isinstance(value, int):
            self.deprecate()
            self.critical = self.default_critical
            self.skip_certs = value
            self._test_value()
        else:
            super().__init__(value)

    def hash_value(self) -> int:
        return self.skip_certs

    def repr_value(self) -> str:
        return str(self.skip_certs)

    def _test_value(self) -> None:
        if not isinstance(self.skip_certs, int):
            raise ValueError(f"{self.skip_certs}: must be an int")
        if self.skip_certs < 0:
            raise ValueError(f"{self.skip_certs}: must be a positive int")

    @property
    def extension_type(self) -> x509.InhibitAnyPolicy:
        return x509.InhibitAnyPolicy(skip_certs=self.skip_certs)

    def from_dict(self, value: int) -> None:
        self.skip_certs = value

    def from_extension(self, value: x509.InhibitAnyPolicy) -> None:
        self.skip_certs = value.skip_certs

    def serialize_value(self) -> int:
        return self.skip_certs


class PolicyConstraints(
    Extension[x509.PolicyConstraints, ParsablePolicyConstraints, SerializedPolicyConstraints]
):
    """Class representing a PolicyConstraints extension.

    Example::

        >>> ext = PolicyConstraints({'value': {'require_explicit_policy': 1, 'inhibit_policy_mapping': 2}})
        >>> ext
        <PolicyConstraints: inhibit_policy_mapping=2, require_explicit_policy=1, critical=True>
        >>> ext.require_explicit_policy
        1
        >>> ext.inhibit_policy_mapping = 5
        >>> ext.inhibit_policy_mapping
        5

    .. seealso::

       `RFC 5280, section 4.2.1.11 <https://tools.ietf.org/html/rfc5280#section-4.2.1.11>`_

    """

    key = "policy_constraints"
    """Key used in CA_PROFILES."""

    name: ClassVar[str] = "PolicyConstraints"
    oid: ClassVar[x509.ObjectIdentifier] = ExtensionOID.POLICY_CONSTRAINTS
    require_explicit_policy: Optional[int]
    inhibit_policy_mapping: Optional[int]

    default_critical = True
    """This extension is marked as critical by default (RFC 5280 requires this)."""

    def hash_value(self) -> Tuple[Optional[int], Optional[int]]:
        return self.require_explicit_policy, self.inhibit_policy_mapping

    def repr_value(self) -> str:
        values = []
        if self.inhibit_policy_mapping is not None:
            values.append(f"inhibit_policy_mapping={self.inhibit_policy_mapping}")
        if self.require_explicit_policy is not None:
            values.append(f"require_explicit_policy={self.require_explicit_policy}")
        return ", ".join(values)

    def _test_value(self) -> None:
        rep = self.require_explicit_policy
        ipm = self.inhibit_policy_mapping
        if rep is not None:
            if not isinstance(rep, int):
                raise ValueError(f"{rep}: require_explicit_policy must be int or None")
            if rep < 0:
                raise ValueError(f"{rep}: require_explicit_policy must be a positive int")
        if ipm is not None:
            if not isinstance(ipm, int):
                raise ValueError(f"{ipm}: inhibit_policy_mapping must be int or None")
            if ipm < 0:
                raise ValueError(f"{ipm}: inhibit_policy_mapping must be a positive int")

    @property
    def extension_type(self) -> x509.PolicyConstraints:
        return x509.PolicyConstraints(
            require_explicit_policy=self.require_explicit_policy,
            inhibit_policy_mapping=self.inhibit_policy_mapping,
        )

    def from_dict(self, value: ParsablePolicyConstraints) -> None:
        self.require_explicit_policy = value.get("require_explicit_policy")
        self.inhibit_policy_mapping = value.get("inhibit_policy_mapping")

    def from_extension(self, value: x509.PolicyConstraints) -> None:
        self.require_explicit_policy = value.require_explicit_policy
        self.inhibit_policy_mapping = value.inhibit_policy_mapping

    def serialize_value(self) -> SerializedPolicyConstraints:
        value: SerializedPolicyConstraints = {}
        if self.inhibit_policy_mapping is not None:
            value["inhibit_policy_mapping"] = self.inhibit_policy_mapping
        if self.require_explicit_policy is not None:
            value["require_explicit_policy"] = self.require_explicit_policy
        return value


class NameConstraints(Extension[x509.NameConstraints, ParsableNameConstraints, SerializedNameConstraints]):
    """Class representing a NameConstraints extension.

    Unlike most other extensions, this extension does not accept a string as value, but you can pass a list
    containing the permitted/excluded subtrees as lists. Similar to
    ``django_ca.extensions.SubjectAlternativeName``, you can pass both strings or instances of
    :py:class:`~cg:cryptography.x509.GeneralName`::

        >>> NameConstraints({'value': {
        ...     'permitted': ['DNS:.com', 'example.org'],
        ...     'excluded': [x509.DNSName('.net')]
        ... }})
        <NameConstraints: permitted=['DNS:.com', 'DNS:example.org'], excluded=['DNS:.net'], critical=True>


    We also have permitted/excluded getters/setters to easily configure this extension::

        >>> nc = NameConstraints()
        >>> nc.permitted = ['example.com']
        >>> nc.excluded = ['example.net']
        >>> nc
        <NameConstraints: permitted=['DNS:example.com'], excluded=['DNS:example.net'], critical=True>
        >>> nc.permitted, nc.excluded
        (<GeneralNameList: ['DNS:example.com']>, <GeneralNameList: ['DNS:example.net']>)

    .. seealso::

       `RFC 5280, section 4.2.1.10 <https://tools.ietf.org/html/rfc5280#section-4.2.1.10>`_

    """

    key = "name_constraints"
    """Key used in CA_PROFILES."""

    name: ClassVar[str] = "NameConstraints"
    default_critical = True
    """This extension is marked as critical by default."""

    oid: ClassVar[x509.ObjectIdentifier] = ExtensionOID.NAME_CONSTRAINTS
    _permitted: GeneralNameList
    _excluded: GeneralNameList

    def __bool__(self) -> bool:
        return bool(self._permitted) or bool(self._excluded)

    def hash_value(self) -> Tuple[Tuple[x509.GeneralName, ...], Tuple[x509.GeneralName, ...]]:
        return tuple(self._permitted), tuple(self._excluded)

    def repr_value(self) -> str:
        permitted = list(self._permitted.serialize())
        excluded = list(self._excluded.serialize())

        return f"permitted={permitted}, excluded={excluded}"

    def get_excluded(self) -> GeneralNameList:
        """The ``excluded`` value of this instance."""
        return self._excluded

    def set_excluded(self, value: Union[GeneralNameList, ParsableGeneralNameList]) -> None:
        """Set he ``excluded`` value of this instance."""
        if not isinstance(value, GeneralNameList):
            value = GeneralNameList(value)
        self._excluded = value

    @property
    def extension_type(self) -> x509.NameConstraints:
        permitted = self._permitted or None
        excluded = self._excluded or None
        return x509.NameConstraints(permitted_subtrees=permitted, excluded_subtrees=excluded)

    def from_extension(self, value: x509.NameConstraints) -> None:
        self.permitted = value.permitted_subtrees
        self.excluded = value.excluded_subtrees

    def from_dict(self, value: ParsableNameConstraints) -> None:
        self.permitted = GeneralNameList(value.get("permitted"))
        self.excluded = GeneralNameList(value.get("excluded"))

    def get_permitted(self) -> GeneralNameList:
        """The ``permitted`` value of this instance."""
        return self._permitted

    def set_permitted(self, value: Union[GeneralNameList, ParsableGeneralNameList]) -> None:
        """Set  the ``permitted`` value of this instance."""
        if not isinstance(value, GeneralNameList):
            value = GeneralNameList(value)
        self._permitted = value

    def serialize_value(self) -> SerializedNameConstraints:
        serialized: SerializedNameConstraints = {}
        if self.permitted:
            serialized["permitted"] = self._permitted.serialize()
        if self.excluded:
            serialized["excluded"] = self._excluded.serialize()
        return serialized

    # Do not use @property for read/write properties where the setter has a different type
    #   https://github.com/python/mypy/issues/3004
    excluded = property(get_excluded, set_excluded)
    permitted = property(get_permitted, set_permitted)


class OCSPNoCheck(NullExtension[x509.OCSPNoCheck]):
    """Extension to indicate that an OCSP client should (blindly) trust the certificate for it's lifetime.

    As a NullExtension, any value is ignored and you can pass a simple empty ``dict`` (or nothing at all) to
    the extension::

        >>> OCSPNoCheck()
        <OCSPNoCheck: critical=False>
        >>> OCSPNoCheck({'critical': True})  # unlike PrecertPoison, you can still mark it as critical
        <OCSPNoCheck: critical=True>

    This extension is only meaningful in an OCSP responder certificate.

    .. seealso::

       `RFC 6990, section 4.2.2.2.1 <https://tools.ietf.org/html/rfc6960#section-4.2.2.2>`_
    """

    ext_class = x509.OCSPNoCheck
    key = "ocsp_no_check"
    """Key used in CA_PROFILES."""

    name: ClassVar[str] = "OCSPNoCheck"
    oid: ClassVar[x509.ObjectIdentifier] = ExtensionOID.OCSP_NO_CHECK


class PrecertPoison(NullExtension[x509.PrecertPoison]):
    """Extension to indicate that the certificate is a submission to a certificate transparency log.

    Note that creating this extension will raise ``ValueError`` if it is not marked as critical:

        >>> PrecertPoison()
        <PrecertPoison: critical=True>
        >>> PrecertPoison({'critical': False})
        Traceback (most recent call last):
            ...
        ValueError: PrecertPoison must always be marked as critical

    .. seealso::

       `RFC 6962, section 3.1 <https://tools.ietf.org/html/rfc6962#section-3.1>`_
    """

    default_critical = True
    """This extension is marked as critical by default."""

    key = "precert_poison"
    """Key used in CA_PROFILES."""

    name: ClassVar[str] = "PrecertPoison"
    oid: ClassVar[x509.ObjectIdentifier] = ExtensionOID.PRECERT_POISON
    ext_class = x509.PrecertPoison

    def __init__(self, value: None = None) -> None:
        super().__init__(value=value)

        if self.critical is not True:
            raise ValueError("PrecertPoison must always be marked as critical")


class PrecertificateSignedCertificateTimestamps(
    SignedCertificateTimestampsBase[x509.PrecertificateSignedCertificateTimestamps]
):
    """Class representing signed certificate timestamps in a Precertificate.

    This extension is included in certificates sent to a certificate transparency log.

    This class cannot be instantiated by anything but
    :py:class:`cg:cryptography.x509.PrecertificateSignedCertificateTimestamps`. Please see
    ``django_ca.extensions.base.SignedCertificateTimestampsBase`` for more information.
    """

    # pylint: disable=abstract-method; methods that raise NotImplemented are recognized as abstract

    key = "precertificate_signed_certificate_timestamps"
    """Key used in CA_PROFILES."""

    extension_cls = x509.PrecertificateSignedCertificateTimestamps
    name: ClassVar[str] = "PrecertificateSignedCertificateTimestamps"
    oid: ClassVar[x509.ObjectIdentifier] = ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS


class SubjectAlternativeName(AlternativeNameExtension[x509.SubjectAlternativeName]):
    """Class representing an Subject Alternative Name extension.

    This extension is usually marked as non-critical.

    >>> SubjectAlternativeName({'value': ['example.com']})
    <SubjectAlternativeName: ['DNS:example.com'], critical=False>

    .. seealso::

       `RFC 5280, section 4.2.1.6 <https://tools.ietf.org/html/rfc5280#section-4.2.1.6>`_
    """

    key = "subject_alternative_name"
    """Key used in CA_PROFILES."""

    name: ClassVar[str] = "SubjectAlternativeName"
    oid: ClassVar[x509.ObjectIdentifier] = ExtensionOID.SUBJECT_ALTERNATIVE_NAME

    def get_common_name(self) -> Optional[str]:
        """Get a value suitable for use as CommonName in a subject, or None if no such value is found.

        This function returns a string representation of the first value that is not a DirectoryName,
        RegisteredID or OtherName.
        """

        for name in self.value:
            if isinstance(name, (x509.DirectoryName, x509.RegisteredID, x509.OtherName)):
                continue

            return str(name.value)  # IPAddress might have a different object, for example
        return None

    @property
    def extension_type(self) -> x509.SubjectAlternativeName:
        return x509.SubjectAlternativeName(self.value)


class SubjectKeyIdentifier(Extension[x509.SubjectKeyIdentifier, ParsableSubjectKeyIdentifier, str]):
    """Class representing a SubjectKeyIdentifier extension.

    This extension identifies the certificate, so it is not usually defined in a profile or instantiated by a
    user. This extension will automatically be added by django-ca. If you ever handle this extension directly,
    the value must be a str or bytes::

        >>> SubjectKeyIdentifier({'value': '33:33:33:33:33:33'})
        <SubjectKeyIdentifier: b'333333', critical=False>
        >>> SubjectKeyIdentifier({'value': b'333333'})
        <SubjectKeyIdentifier: b'333333', critical=False>
    """

    key = "subject_key_identifier"
    """Key used in CA_PROFILES."""

    name: ClassVar[str] = "SubjectKeyIdentifier"
    oid: ClassVar[x509.ObjectIdentifier] = ExtensionOID.SUBJECT_KEY_IDENTIFIER
    value: bytes

    def __init__(
        self,
        value: Optional[
            Union["x509.Extension[x509.SubjectKeyIdentifier]", ParsableExtension, x509.SubjectKeyIdentifier]
        ] = None,
    ) -> None:
        if isinstance(value, x509.SubjectKeyIdentifier):
            self.deprecate()
            self.critical = self.default_critical
            self.value = value.digest
        else:
            super().__init__(value)

    def hash_value(self) -> bytes:
        return self.value

    def repr_value(self) -> str:
        return bytes_to_hex(self.value)

    @property
    def extension_type(self) -> x509.SubjectKeyIdentifier:
        return x509.SubjectKeyIdentifier(digest=self.value)

    def from_dict(self, value: ParsableSubjectKeyIdentifier) -> None:
        if isinstance(value, x509.SubjectKeyIdentifier):
            self.value = value.digest
        elif isinstance(value, str):
            self.value = hex_to_bytes(value)
        else:
            self.value = value

    def from_extension(self, value: x509.SubjectKeyIdentifier) -> None:
        self.value = value.digest

    def serialize_value(self) -> str:
        return bytes_to_hex(self.value)


class TLSFeature(OrderedSetExtension[x509.TLSFeature, Union[TLSFeatureType, str], str, TLSFeatureType]):
    """Class representing a TLSFeature extension.

    As a ``django_ca.extensions.base.OrderedSetExtension``, this extension handles much like it's other sister
    extensions::

        >>> TLSFeature({'value': ['OCSPMustStaple']})
        <TLSFeature: ['OCSPMustStaple'], critical=False>
        >>> tf = TLSFeature({'value': ['OCSPMustStaple']})
        >>> tf.add('MultipleCertStatusRequest')
        >>> tf
        <TLSFeature: ['MultipleCertStatusRequest', 'OCSPMustStaple'], critical=False>
    """

    key = "tls_feature"
    """Key used in CA_PROFILES."""

    name: ClassVar[str] = "TLSFeature"
    oid: ClassVar[x509.ObjectIdentifier] = ExtensionOID.TLS_FEATURE
    value: Set[TLSFeatureType]
    CHOICES = (
        ("OCSPMustStaple", "OCSP Must-Staple"),
        ("MultipleCertStatusRequest", "Multiple Certificate Status Request"),
    )
    CRYPTOGRAPHY_MAPPING = {
        # https://tools.ietf.org/html/rfc6066.html:
        "OCSPMustStaple": TLSFeatureType.status_request,
        "status_request": TLSFeatureType.status_request,
        # https://tools.ietf.org/html/rfc6961.html (not commonly used):
        "MultipleCertStatusRequest": TLSFeatureType.status_request_v2,
        "status_request_v2": TLSFeatureType.status_request_v2,
    }
    SERIALIZER_MAPPING = {
        TLSFeatureType.status_request: "OCSPMustStaple",
        TLSFeatureType.status_request_v2: "MultipleCertStatusRequest",
    }
    KNOWN_PARAMETERS = sorted(CRYPTOGRAPHY_MAPPING)
    """Known values that can be passed to this extension."""

    def from_extension(self, value: x509.TLSFeature) -> None:
        self.value = set(value)

    @property
    def extension_type(self) -> x509.TLSFeature:
        # call serialize_item() to ensure consistent sort order
        return x509.TLSFeature(sorted(self.value, key=self.serialize_item))

    def repr_value(self) -> str:
        values = [f"'{self.SERIALIZER_MAPPING[value]}'" for value in self.value]
        joined = ", ".join(sorted(values))
        return f"[{joined}]"

    def serialize_item(self, value: TLSFeatureType) -> str:
        return str(value.name)

    def parse_value(self, value: Union[TLSFeatureType, str]) -> TLSFeatureType:
        if isinstance(value, TLSFeatureType):
            return value
        if isinstance(value, str) and value in self.CRYPTOGRAPHY_MAPPING:
            return self.CRYPTOGRAPHY_MAPPING[value]
        raise ValueError(f"Unknown value: {value}")

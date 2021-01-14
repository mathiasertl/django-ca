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

# pylint: disable=unsubscriptable-object; https://github.com/PyCQA/pylint/issues/3882

"""Module providing wrapper classes for various x509 extensions.

The classes in this module wrap cryptography extensions, but allow adding/removing values, creating extensions
in a more pythonic manner and provide access functions."""

import binascii
import textwrap

from cryptography import x509
from cryptography.x509 import ObjectIdentifier
from cryptography.x509 import TLSFeatureType
from cryptography.x509.certificate_transparency import LogEntryType
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.oid import ExtensionOID

from ..utils import GeneralNameList
from ..utils import bytes_to_hex
from ..utils import hex_to_bytes
from .base import AlternativeNameExtension
from .base import CRLDistributionPointsBase
from .base import Extension
from .base import KeyIdExtension
from .base import ListExtension
from .base import NullExtension
from .base import OrderedSetExtension
from .utils import PolicyInformation


class AuthorityInformationAccess(Extension):
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
    key = 'authority_information_access'
    """Key used in CA_PROFILES."""

    name = 'AuthorityInformationAccess'
    oid = ExtensionOID.AUTHORITY_INFORMATION_ACCESS

    def __bool__(self):
        return bool(self.value['ocsp']) or bool(self.value['issuers'])

    def __eq__(self, other):
        return isinstance(other, type(self)) \
            and self.value['issuers'] == other.value['issuers'] \
            and self.value['ocsp'] == other.value['ocsp'] \
            and self.critical == other.critical

    def __hash__(self):
        return hash((tuple(self.value['issuers']), tuple(self.value['ocsp']), self.critical, ))

    def _repr_value(self):
        issuers = list(self.value['issuers'].serialize())
        ocsp = list(self.value['ocsp'].serialize())

        return 'issuers=%r, ocsp=%r' % (issuers, ocsp)

    def as_text(self):
        text = ''
        if self.value['issuers']:
            text += 'CA Issuers:\n'
            for name in self.value['issuers'].serialize():
                text += '  * %s\n' % name
        if self.value['ocsp']:
            text += 'OCSP:\n'
            for name in self.value['ocsp'].serialize():
                text += '  * %s\n' % name

        return text.strip()

    @property
    def extension_type(self):
        """Test"""
        descs = [x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, v)
                 for v in self.value['issuers']]
        descs += [x509.AccessDescription(AuthorityInformationAccessOID.OCSP, v)
                  for v in self.value['ocsp']]
        return x509.AuthorityInformationAccess(descriptions=descs)

    def from_extension(self, value):
        issuers = [v.access_location for v in value.value
                   if v.access_method == AuthorityInformationAccessOID.CA_ISSUERS]
        ocsp = [v.access_location for v in value.value
                if v.access_method == AuthorityInformationAccessOID.OCSP]

        self.value = {'issuers': GeneralNameList(issuers), 'ocsp': GeneralNameList(ocsp)}

    def from_dict(self, value):
        dict_value = value.get('value', {})
        self.value = {
            'issuers': GeneralNameList(dict_value.get('issuers', [])),
            'ocsp': GeneralNameList(dict_value.get('ocsp', [])),
        }

    @property
    def issuers(self):
        """The issuers in this extension."""
        return self.value['issuers']

    @issuers.setter
    def issuers(self, value):
        self.value['issuers'] = GeneralNameList.get_from_value(value)

    @property
    def ocsp(self):
        """The OCSP responders in this extension."""
        return self.value['ocsp']

    @ocsp.setter
    def ocsp(self, value):
        self.value['ocsp'] = GeneralNameList.get_from_value(value)

    def serialize(self):
        val = {
            'critical': self.critical,
            'value': {}
        }
        if self.value['issuers']:
            val['value']['issuers'] = list(self.value['issuers'].serialize())
        if self.value['ocsp']:
            val['value']['ocsp'] = list(self.value['ocsp'].serialize())
        return val


class AuthorityKeyIdentifier(Extension):
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

    key = 'authority_key_identifier'
    """Key used in CA_PROFILES."""

    name = 'AuthorityKeyIdentifier'
    oid = ExtensionOID.AUTHORITY_KEY_IDENTIFIER

    def __hash__(self):
        issuer = self.value['authority_cert_issuer']
        if issuer is not None:
            issuer = tuple(issuer)

        return hash((self.value['key_identifier'], issuer, self.value['authority_cert_serial_number'],
                     self.critical))

    def _repr_value(self):
        values = []
        if self.value['key_identifier'] is not None:
            values.append('keyid: %s' % bytes_to_hex(self.value['key_identifier']))
        if self.value['authority_cert_issuer'] is not None:
            values.append('issuer: %r' % list(self.value['authority_cert_issuer'].serialize()))
        if self.value['authority_cert_serial_number'] is not None:
            values.append('serial: %s' % self.value['authority_cert_serial_number'])

        return ', '.join(values)

    def as_text(self):
        values = []
        if self.value['key_identifier'] is not None:
            values.append('* KeyID: %s' % bytes_to_hex(self.value['key_identifier']))
        if self.value['authority_cert_issuer'] is not None:
            values.append('* Issuer:')
            values += [textwrap.indent(v, '  * ') for v in self.value['authority_cert_issuer'].serialize()]
        if self.value['authority_cert_serial_number'] is not None:
            values.append('* Serial: %s' % self.value['authority_cert_serial_number'])

        return '\n'.join(values)

    @property
    def authority_cert_issuer(self):
        """Get the issuer of the Authority (if any)."""
        return self.value['authority_cert_issuer']

    @authority_cert_issuer.setter
    def authority_cert_issuer(self, value):
        self.value['authority_cert_issuer'] = GeneralNameList.get_from_value(value)

    @property
    def authority_cert_serial_number(self):
        """Get the serial number of the Authority."""
        return self.value['authority_cert_serial_number']

    @authority_cert_serial_number.setter
    def authority_cert_serial_number(self, value):
        self.value['authority_cert_serial_number'] = value

    @property
    def extension_type(self):
        return x509.AuthorityKeyIdentifier(
            key_identifier=self.value.get('key_identifier'),
            authority_cert_issuer=self.value.get('authority_cert_issuer'),
            authority_cert_serial_number=self.value.get('authority_cert_serial_number'))

    def from_dict(self, value):
        value = value.get('value', {})

        if isinstance(value, (bytes, str)) is True:
            self.value = {
                'key_identifier': self.parse_keyid(value),
                'authority_cert_issuer': None,
                'authority_cert_serial_number': None,
            }
        else:
            self.value = {
                'key_identifier': self.parse_keyid(value.get('key_identifier')),
                'authority_cert_issuer': GeneralNameList.get_from_value(value.get('authority_cert_issuer')),
                'authority_cert_serial_number': value.get('authority_cert_serial_number'),
            }

    def from_extension(self, value):
        self.value = {
            'key_identifier': value.value.key_identifier,
            'authority_cert_issuer': GeneralNameList.get_from_value(value.value.authority_cert_issuer),
            'authority_cert_serial_number': value.value.authority_cert_serial_number,
        }

    def from_other(self, value):
        if isinstance(value, SubjectKeyIdentifier):
            self.critical = self.default_critical
            self.from_subject_key_identifier(value)
            self._test_value()
        else:
            super().from_other(value)

    def from_subject_key_identifier(self, ext):
        """Create an extension based on SubjectKeyIdentifier extension."""
        # pylint: disable=attribute-defined-outside-init; func is designed to be called by init
        self.value = {
            'key_identifier': ext.value,
            'authority_cert_issuer': None,
            'authority_cert_serial_number': None,
        }

    @property
    def key_identifier(self):
        """Get the key identifier for this extension."""
        return self.value['key_identifier']

    @key_identifier.setter
    def key_identifier(self, value):
        self.value['key_identifier'] = self.parse_keyid(value)

    def parse_keyid(self, value):  # pylint: disable=inconsistent-return-statements
        """Parse the given key id (may be None)."""
        if isinstance(value, bytes):
            return value
        if value is not None:
            return hex_to_bytes(value)

    def serialize(self):
        val = {
            'critical': self.critical,
            'value': {},
        }

        if self.value['key_identifier'] is not None:
            val['value']['key_identifier'] = bytes_to_hex(self.value['key_identifier'])
        if self.value['authority_cert_issuer'] is not None:
            val['value']['authority_cert_issuer'] = list(self.value['authority_cert_issuer'].serialize())
        if self.value['authority_cert_serial_number'] is not None:
            val['value']['authority_cert_serial_number'] = self.value['authority_cert_serial_number']

        return val


class BasicConstraints(Extension):
    """Class representing a BasicConstraints extension.

    This class has the boolean attributes ``ca`` and the attribute ``pathlen``, which is either ``None`` or an
    ``int``. Note that this extension is marked as critical by default if you pass a dict to the constructor::

        >>> bc = BasicConstraints({'value': {'ca': True, 'pathlen': 4}})
        >>> (bc.ca, bc.pathlen, bc.critical)
        (True, 4, True)

    .. seealso::

        `RFC 5280, section 4.2.1.9 <https://tools.ietf.org/html/rfc5280#section-4.2.1.9>`_
    """

    key = 'basic_constraints'
    """Key used in CA_PROFILES."""

    name = 'BasicConstraints'
    oid = ExtensionOID.BASIC_CONSTRAINTS
    default_critical = True
    """This extension is marked as critical by default."""

    def __hash__(self):
        return hash((self.value['ca'], self.value['pathlen'], self.critical, ))

    def _repr_value(self):
        val = 'ca=%s' % self.value['ca']
        if self.value['ca']:
            val += ', pathlen=%s' % self.value['pathlen']
        return val

    @property
    def ca(self):
        """The ``ca`` property of this extension."""
        return self.value['ca']

    @ca.setter
    def ca(self, value):
        self.value['ca'] = bool(value)

    def from_extension(self, value):
        self.value = {
            'ca': value.value.ca,
            'pathlen': value.value.path_length,
        }

    def from_dict(self, value):
        value = value.get('value', {})
        ca = bool(value.get('ca', False))
        if ca:
            pathlen = self.parse_pathlen(value.get('pathlen', None))
        else:  # if ca is not True, we don't use the pathlen
            pathlen = None

        self.value = {'ca': ca, 'pathlen': pathlen, }

    @property
    def extension_type(self):
        return x509.BasicConstraints(ca=self.value['ca'], path_length=self.value['pathlen'])

    def as_text(self):
        if self.value['ca'] is True:
            val = 'CA:TRUE'
        else:
            val = 'CA:FALSE'
        if self.value['pathlen'] is not None:
            val += ', pathlen:%s' % self.value['pathlen']

        return val

    def parse_pathlen(self, value):
        """Parse a pathlen from the given value (either an int, a str of an int or None)."""
        if value is not None:
            try:
                return int(value)
            except ValueError as e:
                raise ValueError('Could not parse pathlen: "%s"' % value) from e
        return value

    @property
    def pathlen(self):
        """The ``pathlen`` value of this instance."""
        return self.value['pathlen']

    @pathlen.setter
    def pathlen(self, value):
        self.value['pathlen'] = self.parse_pathlen(value)

    def serialize(self):
        value = {
            'critical': self.critical,
            'value': {
                'ca': self.value['ca'],
            }
        }
        if self.value['ca']:
            value['value']['pathlen'] = self.value['pathlen']
        return value


class CRLDistributionPoints(CRLDistributionPointsBase):
    """Class representing a CRLDistributionPoints extension.

    This extension identifies where a client can retrieve a Certificate Revocation List (CRL).

    The value passed to this extension should be a ``list`` of
    :py:class:`~django_ca.extensions.utils.DistributionPoint` instances. Naturally, you can also pass those in
    serialized form::

        >>> CRLDistributionPoints({'value': [
        ...     {'full_name': ['http://crl.example.com']}
        ... ]})  # doctest: +NORMALIZE_WHITESPACE
        <CRLDistributionPoints: [<DistributionPoint: full_name=['URI:http://crl.example.com']>],
        critical=False>

    .. seealso::

        `RFC 5280, section 4.2.1.13 <https://tools.ietf.org/html/rfc5280#section-4.2.1.13>`_
    """
    key = 'crl_distribution_points'
    """Key used in CA_PROFILES."""

    name = 'CRLDistributionPoints'
    oid = ExtensionOID.CRL_DISTRIBUTION_POINTS


class CertificatePolicies(ListExtension):
    """Class representing a Certificate Policies extension.

    The value passed to this extension should be a ``list`` of
    :py:class:`~django_ca.extensions.utils.PolicyInformation` instances. Naturally, you can also pass those in
    serialized form::

        >>> CertificatePolicies({'value': [{
        ...     'policy_identifier': '2.5.29.32.0',
        ...     'policy_qualifier': ['policy1'],
        ... }]})
        <CertificatePolicies: 1 policy, critical=False>

    .. seealso::

        `RFC 5280, section 4.2.1.4 <https://tools.ietf.org/html/rfc5280#section-4.2.1.4>`_
    """
    key = 'certificate_policies'
    """Key used in CA_PROFILES."""

    name = 'CertificatePolicies'
    oid = ExtensionOID.CERTIFICATE_POLICIES

    def __hash__(self):
        return hash((tuple(self.value), self.critical, ))

    def _repr_value(self):
        if len(self.value) == 1:
            return '1 policy'
        return '%s policies' % len(self.value)

    def as_text(self):
        return '\n'.join('* %s' % textwrap.indent(p.as_text(), '  ').strip() for p in self.value)

    @property
    def extension_type(self):
        return x509.CertificatePolicies(policies=[p.for_extension_type for p in self.value])

    def parse_value(self, value):
        if isinstance(value, PolicyInformation):
            return value
        return PolicyInformation(value)

    def serialize(self):
        return {
            'value': [p.serialize() for p in self.value],
            'critical': self.critical,
        }


class FreshestCRL(CRLDistributionPointsBase):
    """Class representing a FreshestCRL extension.

    This extension handles identically to the :py:class:`~django_ca.extensions.CRLDistributionPoints`
    extension::

        >>> FreshestCRL({'value': [
        ...     {'full_name': ['http://crl.example.com']}
        ... ]})  # doctest: +NORMALIZE_WHITESPACE
        <FreshestCRL: [<DistributionPoint: full_name=['URI:http://crl.example.com']>],
        critical=False>

    .. seealso::

        `RFC 5280, section 4.2.1.15 <https://tools.ietf.org/html/rfc5280#section-4.2.1.15>`_
    """
    key = 'freshest_crl'
    """Key used in CA_PROFILES."""

    name = 'FreshestCRL'
    oid = ExtensionOID.FRESHEST_CRL

    @property
    def extension_type(self):
        return x509.FreshestCRL(distribution_points=[dp.for_extension_type for dp in self.value])


class IssuerAlternativeName(AlternativeNameExtension):
    """Class representing an Issuer Alternative Name extension.

    This extension is usually marked as non-critical.

    >>> IssuerAlternativeName({'value': ['https://example.com']})
    <IssuerAlternativeName: ['URI:https://example.com'], critical=False>

    .. seealso::

       `RFC 5280, section 4.2.1.7 <https://tools.ietf.org/html/rfc5280#section-4.2.1.7>`_
    """

    key = 'issuer_alternative_name'
    """Key used in CA_PROFILES."""

    name = 'IssuerAlternativeName'
    oid = ExtensionOID.ISSUER_ALTERNATIVE_NAME

    @property
    def extension_type(self):
        return x509.IssuerAlternativeName(self.value)


class KeyUsage(OrderedSetExtension):
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

    key = 'key_usage'
    """Key used in CA_PROFILES."""

    name = 'KeyUsage'
    oid = ExtensionOID.KEY_USAGE
    CRYPTOGRAPHY_MAPPING = {
        'cRLSign': 'crl_sign',
        'dataEncipherment': 'data_encipherment',
        'decipherOnly': 'decipher_only',
        'digitalSignature': 'digital_signature',
        'encipherOnly': 'encipher_only',
        'keyAgreement': 'key_agreement',
        'keyCertSign': 'key_cert_sign',
        'keyEncipherment': 'key_encipherment',
        'nonRepudiation': 'content_commitment',  # http://marc.info/?t=107176106300005&r=1&w=2
    }
    _CRYPTOGRAPHY_MAPPING_REVERSED = {v: k for k, v in CRYPTOGRAPHY_MAPPING.items()}
    KNOWN_VALUES = set(CRYPTOGRAPHY_MAPPING.values())

    KNOWN_PARAMETERS = sorted(CRYPTOGRAPHY_MAPPING)
    """Known values that can be passed to this extension."""

    CHOICES = (
        ('cRLSign', 'CRL Sign'),
        ('dataEncipherment', 'dataEncipherment'),
        ('decipherOnly', 'decipherOnly'),
        ('digitalSignature', 'Digital Signature'),
        ('encipherOnly', 'encipherOnly'),
        ('keyAgreement', 'Key Agreement'),
        ('keyCertSign', 'Certificate Sign'),
        ('keyEncipherment', 'Key Encipherment'),
        ('nonRepudiation', 'nonRepudiation'),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # decipherOnly only makes sense if keyAgreement is True
        if 'decipher_only' in self.value and 'key_agreement' not in self.value:
            self.value.add('key_agreement')
        if 'encipher_only' in self.value and 'key_agreement' not in self.value:
            self.value.add('key_agreement')

    def from_extension(self, value):
        self.value = set()

        for val in self.KNOWN_VALUES:
            try:
                if getattr(value.value, val):
                    self.value.add(val)
            except ValueError:
                # cryptography throws a ValueError if encipher_only/decipher_only is accessed and
                # key_agreement is not set.
                pass

    @property
    def extension_type(self):
        kwargs = {v: (v in self.value) for v in self.KNOWN_VALUES}
        return x509.KeyUsage(**kwargs)

    def parse_value(self, value):
        if value in self.KNOWN_VALUES:
            return value
        try:
            return self.CRYPTOGRAPHY_MAPPING[value]
        except KeyError as e:
            raise ValueError('Unknown value: %s' % value) from e
        raise ValueError('Unknown value: %s' % value)  # pragma: no cover - function returns/raises before

    def serialize_value(self, value):
        return self._CRYPTOGRAPHY_MAPPING_REVERSED[value]


class ExtendedKeyUsage(OrderedSetExtension):
    """Class representing a ExtendedKeyUsage extension."""

    key = 'extended_key_usage'
    """Key used in CA_PROFILES."""

    name = 'ExtendedKeyUsage'
    oid = ExtensionOID.EXTENDED_KEY_USAGE
    CRYPTOGRAPHY_MAPPING = {
        'serverAuth': ExtendedKeyUsageOID.SERVER_AUTH,
        'clientAuth': ExtendedKeyUsageOID.CLIENT_AUTH,
        'codeSigning': ExtendedKeyUsageOID.CODE_SIGNING,
        'emailProtection': ExtendedKeyUsageOID.EMAIL_PROTECTION,
        'timeStamping': ExtendedKeyUsageOID.TIME_STAMPING,
        'OCSPSigning': ExtendedKeyUsageOID.OCSP_SIGNING,
        'anyExtendedKeyUsage': ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE,
        'smartcardLogon': ObjectIdentifier("1.3.6.1.4.1.311.20.2.2"),
        'msKDC': ObjectIdentifier("1.3.6.1.5.2.3.5"),

        # Defined in RFC 3280, occurs in TrustID Server A52 CA
        'ipsecEndSystem': ObjectIdentifier('1.3.6.1.5.5.7.3.5'),
        'ipsecTunnel': ObjectIdentifier('1.3.6.1.5.5.7.3.6'),
        'ipsecUser': ObjectIdentifier('1.3.6.1.5.5.7.3.7'),
    }
    _CRYPTOGRAPHY_MAPPING_REVERSED = {v: k for k, v in CRYPTOGRAPHY_MAPPING.items()}

    KNOWN_PARAMETERS = sorted(CRYPTOGRAPHY_MAPPING)
    """Known values that can be passed to this extension."""

    # Used by the HTML form select field
    CHOICES = (
        ('serverAuth', 'SSL/TLS Web Server Authentication'),
        ('clientAuth', 'SSL/TLS Web Client Authentication'),
        ('codeSigning', 'Code signing'),
        ('emailProtection', 'E-mail Protection (S/MIME)'),
        ('timeStamping', 'Trusted Timestamping'),
        ('OCSPSigning', 'OCSP Signing'),
        ('smartcardLogon', 'Smart card logon'),
        ('msKDC', 'Kerberos Domain Controller'),
        ('ipsecEndSystem', 'IPSec EndSystem'),
        ('ipsecTunnel', 'IPSec Tunnel'),
        ('ipsecUser', 'IPSec User'),
        ('anyExtendedKeyUsage', 'Any Extended Key Usage'),
    )

    def from_extension(self, value):
        self.value = set(value.value)

    @property
    def extension_type(self):
        # call serialize_value() to ensure consistent sort order
        return x509.ExtendedKeyUsage(sorted(self.value, key=self.serialize_value))

    def serialize_value(self, value):
        return self._CRYPTOGRAPHY_MAPPING_REVERSED[value]

    def parse_value(self, value):
        if isinstance(value, ObjectIdentifier) and value in self._CRYPTOGRAPHY_MAPPING_REVERSED:
            return value
        if isinstance(value, str) and value in self.CRYPTOGRAPHY_MAPPING:
            return self.CRYPTOGRAPHY_MAPPING[value]
        raise ValueError('Unknown value: %s' % value)


class InhibitAnyPolicy(Extension):
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

    key = 'inhibit_any_policy'
    """Key used in CA_PROFILES."""

    name = 'InhibitAnyPolicy'
    oid = ExtensionOID.INHIBIT_ANY_POLICY

    default_critical = True
    """This extension is marked as critical by default (RFC 5280 requires this extension to be marked as
    critical)."""

    def _test_value(self):
        if not isinstance(self.value, int):
            raise ValueError('%s: must be an int' % self.value)
        if self.value < 0:
            raise ValueError('%s: must be a positive int' % self.value)

    def as_text(self):
        return str(self.value)

    @property
    def extension_type(self):
        return x509.InhibitAnyPolicy(skip_certs=self.value)

    def from_dict(self, value):
        self.value = value.get('value')

    def from_extension(self, value):
        self.value = value.value.skip_certs

    def from_int(self, value):
        """Parser allowing creation of an instance just from an int."""
        self.value = value

    def from_other(self, value):
        if isinstance(value, int):
            self.critical = self.default_critical
            self.from_int(value)
            self._test_value()
        else:
            super().from_other(value)

    @property
    def skip_certs(self):
        """The ``skip_certs`` value of this instance."""
        return self.value

    @skip_certs.setter
    def skip_certs(self, value):
        if not isinstance(value, int):
            raise ValueError('%s: must be an int' % value)
        if value < 0:
            raise ValueError('%s: must be a positive int' % value)
        self.value = value


class PolicyConstraints(Extension):
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

    key = 'policy_constraints'
    """Key used in CA_PROFILES."""

    name = 'PolicyConstraints'
    oid = ExtensionOID.POLICY_CONSTRAINTS

    default_critical = True
    """This extension is marked as critical by default (RFC 5280 requires this extension to be marked as
    critical)."""

    def __hash__(self):
        return hash((self.value['require_explicit_policy'], self.value['inhibit_policy_mapping'],
                     self.critical, ))

    def _repr_value(self):
        if self.value['require_explicit_policy'] is None and self.value['inhibit_policy_mapping'] is None:
            return '-'
        values = []
        if self.value['inhibit_policy_mapping'] is not None:
            values.append('inhibit_policy_mapping=%s' % self.value['inhibit_policy_mapping'])
        if self.value['require_explicit_policy'] is not None:
            values.append('require_explicit_policy=%s' % self.value['require_explicit_policy'])
        return ', '.join(values)

    def _test_value(self):
        rep = self.value['require_explicit_policy']
        ipm = self.value['inhibit_policy_mapping']
        if rep is not None:
            if not isinstance(rep, int):
                raise ValueError("%s: require_explicit_policy must be int or None" % rep)
            if rep < 0:
                raise ValueError('%s: require_explicit_policy must be a positive int' % rep)
        if ipm is not None:
            if not isinstance(ipm, int):
                raise ValueError("%s: inhibit_policy_mapping must be int or None" % ipm)
            if ipm < 0:
                raise ValueError('%s: inhibit_policy_mapping must be a positive int' % ipm)

    def as_text(self):
        lines = []
        if self.value['inhibit_policy_mapping'] is not None:
            lines.append('* InhibitPolicyMapping: %s' % self.value['inhibit_policy_mapping'])
        if self.value['require_explicit_policy'] is not None:
            lines.append('* RequireExplicitPolicy: %s' % self.value['require_explicit_policy'])

        return '\n'.join(lines)

    @property
    def extension_type(self):
        return x509.PolicyConstraints(require_explicit_policy=self.value['require_explicit_policy'],
                                      inhibit_policy_mapping=self.value['inhibit_policy_mapping'])

    def from_dict(self, value):
        value = value.get('value', {})
        self.value = {
            'require_explicit_policy': value.get('require_explicit_policy'),
            'inhibit_policy_mapping': value.get('inhibit_policy_mapping'),
        }

    def from_extension(self, value):
        self.value = {
            'require_explicit_policy': value.value.require_explicit_policy,
            'inhibit_policy_mapping': value.value.inhibit_policy_mapping,
        }

    @property
    def inhibit_policy_mapping(self):
        """The ``inhibit_policy_mapping`` value of this instance."""
        return self.value['inhibit_policy_mapping']

    @inhibit_policy_mapping.setter
    def inhibit_policy_mapping(self, value):
        if value is not None:
            if not isinstance(value, int):
                raise ValueError("%s: inhibit_policy_mapping must be int or None" % value)
            if value < 0:
                raise ValueError('%s: inhibit_policy_mapping must be a positive int' % value)
        self.value['inhibit_policy_mapping'] = value

    @property
    def require_explicit_policy(self):
        """The ``require_explicit_policy`` value of this instance."""
        return self.value['require_explicit_policy']

    @require_explicit_policy.setter
    def require_explicit_policy(self, value):
        if value is not None:
            if not isinstance(value, int):
                raise ValueError("%s: require_explicit_policy must be int or None" % value)
            if value < 0:
                raise ValueError('%s: require_explicit_policy must be a positive int' % value)
        self.value['require_explicit_policy'] = value

    def serialize(self):
        value = {}
        if self.value['inhibit_policy_mapping'] is not None:
            value['inhibit_policy_mapping'] = self.value['inhibit_policy_mapping']
        if self.value['require_explicit_policy'] is not None:
            value['require_explicit_policy'] = self.value['require_explicit_policy']
        return {
            'critical': self.critical,
            'value': value,
        }


class NameConstraints(Extension):
    """Class representing a NameConstraints extension.

    Unlike most other extensions, this extension does not accept a string as value, but you can pass a list
    containing the permitted/excluded subtrees as lists. Similar to
    :py:class:`~django_ca.extensions.SubjectAlternativeName`, you can pass both strings or instances of
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
    key = 'name_constraints'
    """Key used in CA_PROFILES."""

    name = 'NameConstraints'
    default_critical = True
    """This extension is marked as critical by default."""

    oid = ExtensionOID.NAME_CONSTRAINTS

    def __bool__(self):
        return bool(self.value['permitted']) or bool(self.value['excluded'])

    def __hash__(self):
        return hash((tuple(self.value['permitted']), tuple(self.value['excluded']), self.critical, ))

    def _repr_value(self):
        permitted = list(self.value['permitted'].serialize())
        excluded = list(self.value['excluded'].serialize())

        return 'permitted=%r, excluded=%r' % (permitted, excluded)

    def as_text(self):
        text = ''
        if self.value['permitted']:
            text += 'Permitted:\n'
            for name in self.value['permitted'].serialize():
                text += '  * %s\n' % name
        if self.value['excluded']:
            text += 'Excluded:\n'
            for name in self.value['excluded'].serialize():
                text += '  * %s\n' % name

        return text

    @property
    def excluded(self):
        """The ``excluded`` value of this instance."""
        return self.value['excluded']

    @excluded.setter
    def excluded(self, value):
        self.value['excluded'] = GeneralNameList.get_from_value(value, GeneralNameList())

    @property
    def extension_type(self):
        return x509.NameConstraints(permitted_subtrees=self.value['permitted'],
                                    excluded_subtrees=self.value['excluded'])

    def from_extension(self, value):
        self.value = {
            'permitted': GeneralNameList.get_from_value(value.value.permitted_subtrees, GeneralNameList()),
            'excluded': GeneralNameList.get_from_value(value.value.excluded_subtrees, GeneralNameList()),
        }

    def from_dict(self, value):
        value = value.get('value', {})
        self.value = {
            'permitted': GeneralNameList.get_from_value(value.get('permitted', []), GeneralNameList()),
            'excluded': GeneralNameList.get_from_value(value.get('excluded', []), GeneralNameList()),
        }

    @property
    def permitted(self):
        """The ``permitted`` value of this instance."""
        return self.value['permitted']

    @permitted.setter
    def permitted(self, value):
        self.value['permitted'] = GeneralNameList.get_from_value(value, GeneralNameList())

    def serialize(self):
        return {
            'critical': self.critical,
            'value': {
                'permitted': list(self.value['permitted'].serialize()),
                'excluded': list(self.value['excluded'].serialize()),
            },
        }


class OCSPNoCheck(NullExtension):
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
    key = 'ocsp_no_check'
    """Key used in CA_PROFILES."""

    name = 'OCSPNoCheck'
    oid = ExtensionOID.OCSP_NO_CHECK


class PrecertPoison(NullExtension):
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

    key = 'precert_poison'
    """Key used in CA_PROFILES."""

    name = 'PrecertPoison'
    oid = ExtensionOID.PRECERT_POISON
    ext_class = x509.PrecertPoison

    def __init__(self, value=None):
        super().__init__(value=value)

        if self.critical is not True:
            raise ValueError('PrecertPoison must always be marked as critical')


class PrecertificateSignedCertificateTimestamps(ListExtension):
    """Class representing signed certificate timestamps.

    This extension can be used to verify that a certificate is included in a Certificate Transparency log.

    .. NOTE::

        Cryptography currently does not provide a way to create instances of this extension without already
        having a certificate that provides this extension.

        https://github.com/pyca/cryptography/issues/4820

    .. seealso::

       `RFC 6962 <https://tools.ietf.org/html/rfc6962.html>`_
    """
    key = 'precertificate_signed_certificate_timestamps'
    """Key used in CA_PROFILES."""

    name = 'PrecertificateSignedCertificateTimestamps'
    oid = ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS
    _timeformat = '%Y-%m-%d %H:%M:%S.%f'
    LOG_ENTRY_TYPE_MAPPING = {
        LogEntryType.PRE_CERTIFICATE: 'precertificate',
        LogEntryType.X509_CERTIFICATE: 'x509_certificate'
    }
    value: x509.PrecertificateSignedCertificateTimestamps

    def __contains__(self, value):
        if isinstance(value, dict):
            return value in self.serialize()['value']
        return value in self.value

    def __delitem__(self, key):  # type: ignore
        raise NotImplementedError

    def __hash__(self):
        # serialize_iterable returns a dict, which is unhashable
        return hash((tuple(self.value), self.critical, ))

    def _repr_value(self):
        if len(self.value) == 1:  # pragma: no cover - we cannot currently create such an extension
            return '1 timestamp'
        return '%s timestamps' % len(self.value)

    def __setitem__(self, key, value):  # type: ignore
        raise NotImplementedError

    def human_readable_timestamps(self):
        """Convert SCTs into a generator of serializable dicts."""
        for sct in self.value:
            if sct.entry_type == LogEntryType.PRE_CERTIFICATE:
                entry_type = 'Precertificate'
            elif sct.entry_type == LogEntryType.X509_CERTIFICATE:  # pragma: no cover - unseen in the wild
                entry_type = 'x509 certificate'
            else:  # pragma: no cover
                # we support everything that has been specified so far
                entry_type = 'unknown'

            yield {
                'log_id': binascii.hexlify(sct.log_id).decode('utf-8'),
                'sct': sct,
                'timestamp': sct.timestamp.isoformat(str(' ')),
                'type': entry_type,
                'version': sct.version.name,
            }

    def as_text(self):
        lines = []
        for val in self.human_readable_timestamps():
            line = '* {type} ({version}):\n    Timestamp: {timestamp}\n    Log ID: {log_id}'.format(**val)
            lines.append(line)

        return '\n'.join(lines)

    def count(self, value):
        if isinstance(value, dict):
            return self.serialize()['value'].count(value)
        return self.value._signed_certificate_timestamps.count(value)  # pylint: disable=protected-access

    def extend(self, iterable):
        raise NotImplementedError

    @property
    def extension_type(self):
        return self.value

    def from_extension(self, value):
        self.value = value.value

    def insert(self, index, value):
        raise NotImplementedError

    def pop(self, index=-1):
        raise NotImplementedError

    def remove(self, value):
        raise NotImplementedError

    def serialize_value(self, value):
        return {
            'type': PrecertificateSignedCertificateTimestamps.LOG_ENTRY_TYPE_MAPPING[value.entry_type],
            'timestamp': value.timestamp.strftime(self._timeformat),
            'log_id': binascii.hexlify(value.log_id).decode('utf-8'),
            'version': value.version.name,
        }


class SubjectAlternativeName(AlternativeNameExtension):
    """Class representing an Subject Alternative Name extension.

    This extension is usually marked as non-critical.

    >>> SubjectAlternativeName({'value': ['example.com']})
    <SubjectAlternativeName: ['DNS:example.com'], critical=False>

    .. seealso::

       `RFC 5280, section 4.2.1.6 <https://tools.ietf.org/html/rfc5280#section-4.2.1.6>`_
    """
    key = 'subject_alternative_name'
    """Key used in CA_PROFILES."""

    name = 'SubjectAlternativeName'
    oid = ExtensionOID.SUBJECT_ALTERNATIVE_NAME

    def get_common_name(self):
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
    def extension_type(self):
        return x509.SubjectAlternativeName(self.value)


class SubjectKeyIdentifier(KeyIdExtension):
    """Class representing a SubjectKeyIdentifier extension.

    This extension identifies the certificate, so it is not usually defined in a profile or instantiated by a
    user. This extension will automatically be added by django-ca. If you ever handle this extension directly,
    the value must be a str or bytes::

        >>> SubjectKeyIdentifier({'value': '33:33:33:33:33:33'})
        <SubjectKeyIdentifier: b'333333', critical=False>
        >>> SubjectKeyIdentifier({'value': b'333333'})
        <SubjectKeyIdentifier: b'333333', critical=False>
    """

    key = 'subject_key_identifier'
    """Key used in CA_PROFILES."""

    name = 'SubjectKeyIdentifier'
    oid = ExtensionOID.SUBJECT_KEY_IDENTIFIER

    @property
    def extension_type(self):
        return x509.SubjectKeyIdentifier(digest=self.value)

    def from_other(self, value: x509.SubjectKeyIdentifier):
        if isinstance(value, x509.SubjectKeyIdentifier):
            self.critical = self.default_critical
            self.value = value.digest
            self._test_value()
        else:
            super().from_other(value)

    def from_extension(self, value: x509.SubjectKeyIdentifier):
        self.value = value.value.digest


class TLSFeature(OrderedSetExtension):
    """Class representing a TLSFeature extension.

    As a :py:class:`~django_ca.extensions.base.OrderedSetExtension`, this extension handles much like it's
    other sister extensions::

        >>> TLSFeature({'value': ['OCSPMustStaple']})
        <TLSFeature: ['OCSPMustStaple'], critical=False>
        >>> tf = TLSFeature({'value': ['OCSPMustStaple']})
        >>> tf.add('MultipleCertStatusRequest')
        >>> tf
        <TLSFeature: ['MultipleCertStatusRequest', 'OCSPMustStaple'], critical=False>
    """

    key = 'tls_feature'
    """Key used in CA_PROFILES."""

    name = 'TLSFeature'
    oid = ExtensionOID.TLS_FEATURE
    CHOICES = (
        ('OCSPMustStaple', 'OCSP Must-Staple'),
        ('MultipleCertStatusRequest', 'Multiple Certificate Status Request'),
    )
    CRYPTOGRAPHY_MAPPING = {
        # https://tools.ietf.org/html/rfc6066.html:
        'OCSPMustStaple': TLSFeatureType.status_request,
        # https://tools.ietf.org/html/rfc6961.html (not commonly used):
        'MultipleCertStatusRequest': TLSFeatureType.status_request_v2,
    }
    _CRYPTOGRAPHY_MAPPING_REVERSED = {v: k for k, v in CRYPTOGRAPHY_MAPPING.items()}
    KNOWN_PARAMETERS = sorted(CRYPTOGRAPHY_MAPPING)
    """Known values that can be passed to this extension."""

    def from_extension(self, value: x509.TLSFeature):
        self.value = set(value.value)

    @property
    def extension_type(self):
        # call serialize_value() to ensure consistent sort order
        return x509.TLSFeature(sorted(self.value, key=self.serialize_value))

    def serialize_value(self, value: TLSFeatureType):
        return self._CRYPTOGRAPHY_MAPPING_REVERSED[value]

    def parse_value(self, value):
        if isinstance(value, TLSFeatureType):
            return value
        if isinstance(value, str) and value in self.CRYPTOGRAPHY_MAPPING:
            return self.CRYPTOGRAPHY_MAPPING[value]
        raise ValueError('Unknown value: %s' % value)

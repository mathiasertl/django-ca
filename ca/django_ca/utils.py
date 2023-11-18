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

"""Reusable utility functions used throughout django-ca."""

import binascii
import re
import shlex
import typing
import warnings
from datetime import datetime, timedelta, timezone as tz
from ipaddress import ip_address, ip_network
from typing import Iterator, List, Optional, Tuple, Type, Union
from urllib.parse import urlparse

import idna

import asn1crypto.core
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import NameOID

from django.core.files.storage import get_storage_class
from django.core.validators import URLValidator
from django.utils import timezone

from django_ca import ca_settings, constants
from django_ca.constants import NAME_OID_DISPLAY_NAMES
from django_ca.deprecation import RemovedInDjangoCA129Warning
from django_ca.typehints import (
    AllowedHashTypes,
    Expires,
    ParsableGeneralName,
    ParsableHash,
    ParsableKeyType,
    ParsableName,
    SerializedName,
)

#: Regular expression to match general names.
GENERAL_NAME_RE = re.compile("^(email|URI|IP|DNS|RID|dirName|otherName):(.*)", flags=re.I)

#: Regular expression matching certificate serials as hex
SERIAL_RE = re.compile("^([0-9A-F][0-9A-F]:?)+[0-9A-F][0-9A-F]?$")

UNSAFE_NAME_CHARS = re.compile(r'[\\/\'"]')

SAN_NAME_MAPPINGS = {
    x509.DNSName: "DNS",
    x509.RFC822Name: "email",
    x509.DirectoryName: "dirname",
    x509.UniformResourceIdentifier: "URI",
    x509.IPAddress: "IP",
    x509.RegisteredID: "RID",
    x509.OtherName: "otherName",
}

# Sources for OIDs that can be duplicate:
# * https://www.ibm.com/docs/en/ibm-mq/7.5?topic=certificates-distinguished-names - OU and DC
# * multiple_ous cert from the test suite.
#
# WARNING: sync any updates here to ca_settings._check_name().
#: OIDs that can occur multiple times in a certificate
MULTIPLE_OIDS = (NameOID.DOMAIN_COMPONENT, NameOID.ORGANIZATIONAL_UNIT_NAME, NameOID.STREET_ADDRESS)

# uppercase values as keys for normalizing case
NAME_CASE_MAPPINGS = {k.upper(): v for k, v in constants.NAME_OID_TYPES.items()}


def encode_url(url: str) -> str:
    """IDNA encoding for domains in URLs.

    Examples::

        >>> encode_url('https://example.com')
        'https://example.com'
        >>> encode_url('https://exämple.com/foobar')
        'https://xn--exmple-cua.com/foobar'
        >>> encode_url('https://exämple.com:8000/foobar')
        'https://xn--exmple-cua.com:8000/foobar'
    """
    parsed = urlparse(url)
    if parsed.hostname and parsed.port:
        hostname = idna.encode(parsed.hostname).decode("utf-8")
        # pylint: disable-next=protected-access  # no public API for this
        parsed = parsed._replace(netloc=f"{hostname}:{parsed.port}")
    else:
        # pylint: disable-next=protected-access  # no public API for this
        parsed = parsed._replace(netloc=idna.encode(parsed.netloc).decode("utf-8"))
    return parsed.geturl()


def encode_dns(name: str) -> str:
    """IDNA encoding for domains.

    Examples::

        >>> encode_dns('example.com')
        'example.com'
        >>> encode_dns('exämple.com')
        'xn--exmple-cua.com'
        >>> encode_dns('.exämple.com')
        '.xn--exmple-cua.com'
        >>> encode_dns('*.exämple.com')
        '*.xn--exmple-cua.com'
    """
    if name.startswith("*."):
        return f"*.{idna.encode(name[2:]).decode('utf-8')}"
    if name.startswith("."):
        return f".{idna.encode(name[1:]).decode('utf-8')}"
    return idna.encode(name).decode("utf-8")


def format_name(subject: Union[x509.Name, x509.RelativeDistinguishedName]) -> str:
    """Convert a x509 name or relative name into the canonical form for distinguished names.

    .. deprecated:: 1.27.0

       This function is deprecated in 1.27.0 and will be removed in 1.29.0.
    """
    warnings.warn(
        "This function is deprecated and will be removed in 1.29.0.", category=RemovedInDjangoCA129Warning
    )

    def _format_value(val: str) -> str:
        # If val contains no unsafe chars, return it unchanged
        if UNSAFE_NAME_CHARS.search(val) is None:
            return val
        return '"' + val.replace('"', r"\"").replace(r"\\", r"\\\\") + '"'

    items = [
        (constants.NAME_OID_SHORTCUTS.get(s.oid, constants.NAME_OID_NAMES[s.oid]), s.value) for s in subject
    ]

    values = "/".join([f"{k}={_format_value(v)}" for k, v in items])  # type: ignore[arg-type]
    return f"/{values}"


def parse_name_rfc4514(value: str) -> x509.Name:
    """Parse an RFC 4514 formatted string into a :py:class:`~cg:cryptography.x509.Name`.

    This function is intended to be the inverse of :py:func:`~django_ca.utils.format_name_rfc4514`, and will
    also parse the name in the order as given in the string and understands the same OID mappings.

    >>> parse_name_rfc4514("CN=example.com")
    <Name(CN=example.com)>
    >>> parse_name_rfc4514("C=AT,O=MyOrg,OU=MyOrgUnit,CN=example.com")
    <Name(C=AT,O=MyOrg,OU=MyOrgUnit,CN=example.com)>
    """
    name = x509.Name.from_rfc4514_string(value, {v: k for k, v in constants.RFC4514_NAME_OVERRIDES.items()})
    return check_name(x509.Name(reversed(list(name))))


def format_name_rfc4514(subject: Union[x509.Name, x509.RelativeDistinguishedName]) -> str:
    """Format the given (relative distinguished) name as RFC4514 compatible string.

    This function deviates from RFC 4514 by displaying the name attributes as they appear in the certificate,
    and *not* in reverse order (which is not used anywhere else). It also adds OID name mappings from
    :py:attr:`~django_ca.constants.NAME_OID_NAMES` to the output string.

    >>> format_name_rfc4514(
    ...     x509.Name(
    ...         [
    ...             x509.NameAttribute(NameOID.COUNTRY_NAME, "AT"),
    ...             x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
    ...             x509.NameAttribute(NameOID.EMAIL_ADDRESS, "user@example.com"),
    ...         ]
    ...     )
    ... )
    'C=AT,CN=example.com,emailAddress=user@example.com'

    """
    # Get reverse-order subject
    subject = subject.__class__(reversed(list(subject)))
    return subject.rfc4514_string(attr_name_overrides=constants.RFC4514_NAME_OVERRIDES)


def _serialize_name_attribute_value(name_attribute: x509.NameAttribute) -> str:
    if isinstance(name_attribute.value, bytes):
        return bytes_to_hex(name_attribute.value)
    return name_attribute.value


def serialize_name(name: Union[x509.Name, x509.RelativeDistinguishedName]) -> SerializedName:
    """Serialize a :py:class:`~cg:cryptography.x509.Name`.

    The value also accepts a :py:class:`~cg:cryptography.x509.RelativeDistinguishedName`.

    The returned value is a list of tuples, each consisting of two strings. If an attribute contains
    ``bytes``, it is converted using :py:func:`~django_ca.utils.bytes_to_hex`.

    Examples::

        >>> serialize_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'example.com')]))
        [{'oid': '2.5.4.3', 'value': 'example.com'}]
        >>> serialize_name(x509.RelativeDistinguishedName([
        ...     x509.NameAttribute(NameOID.COUNTRY_NAME, 'AT'),
        ...     x509.NameAttribute(NameOID.COMMON_NAME, 'example.com'),
        ... ]))
        [{'oid': '2.5.4.6', 'value': 'AT'}, {'oid': '2.5.4.3', 'value': 'example.com'}]
    """
    return [{"oid": attr.oid.dotted_string, "value": _serialize_name_attribute_value(attr)} for attr in name]


def name_for_display(name: Union[x509.Name, x509.RelativeDistinguishedName]) -> List[Tuple[str, str]]:
    """Convert a |Name| or |RelativeDistinguishedName| into a list of key/value pairs for display.

    This function is used as a helper function to loop over the elements of a name to prepare them for
    consistent display.

    The function converts the OID into a readable string (e.g. "commonName (CN)") with any unknown OIDs
    converted to a dotted string. If the value is not a string, it is converted to a hex string.

    >>> name_for_display(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'example.com')]))
    [('commonName (CN)', 'example.com')]
    """
    return [
        (NAME_OID_DISPLAY_NAMES.get(attr.oid, attr.oid.dotted_string), _serialize_name_attribute_value(attr))
        for attr in name
    ]


def parse_serialized_name_attributes(name: SerializedName) -> List[x509.NameAttribute]:
    """Parse a serialized list of name attributes into a list of NameAttributes.

    This function takes care of parsing hex-encoded byte values name attributes that are known to use bytes
    (currently only :py:attr:`NameOID.X500_UNIQUE_IDENTIFIER
    <cg:cryptography.x509.oid.NameOID.X500_UNIQUE_IDENTIFIER>`).

    >>> parse_serialized_name_attributes([{"oid": "2.5.4.3", "value": "example.com"}])
    [<NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.3, name=commonName)>, value='example.com')>]

    This function is more or less the inverse of :py:func:`~django_ca.utils.serialize_name`, except that it
    returns a list of :py:class:`~cg:cryptography.x509.NameAttribute` instances (``serialize_name()`` takes a
    :py:class:`~cg:cryptography.x509.Name` or :py:class:`~cg:cryptography.x509.RelativeDistinguishedName`)
    and byte-values for unknown OIDs will **not** be correctly parsed.
    """
    attrs: List[x509.NameAttribute] = []
    for attr_dict in name:
        oid = x509.ObjectIdentifier(attr_dict["oid"])
        value = attr_dict["value"]

        if oid == NameOID.X500_UNIQUE_IDENTIFIER:
            attrs.append(x509.NameAttribute(oid=oid, value=hex_to_bytes(value), _type=_ASN1Type.BitString))
        else:
            attrs.append(x509.NameAttribute(oid=oid, value=value))

    return attrs


def format_general_name(name: x509.GeneralName) -> str:
    """Format a single general name.

    >>> import ipaddress
    >>> format_general_name(x509.DNSName('example.com'))
    'DNS:example.com'
    >>> format_general_name(x509.IPAddress(ipaddress.IPv4Address('127.0.0.1')))
    'IP:127.0.0.1'
    """
    if isinstance(name, x509.DirectoryName):
        value = format_name_rfc4514(name.value)
    else:
        value = name.value
    return f"{SAN_NAME_MAPPINGS[type(name)]}:{value}"


def is_power2(num: int) -> bool:
    """Return True if `num` is a power of 2.

    >>> is_power2(4)
    True
    >>> is_power2(3)
    False
    """
    return num != 0 and ((num & (num - 1)) == 0)


def multiline_url_validator(value: str) -> None:
    """Validate that a TextField contains one valid URL per line.

    .. seealso:: https://docs.djangoproject.com/en/1.9/ref/validators/
    """
    validator = URLValidator()

    for line in value.splitlines():
        validator(line)


def add_colons(value: str, pad: str = "0") -> str:
    """Add colons after every second digit.

    This function is used in functions to prettify serials.

    >>> add_colons('teststring')
    'te:st:st:ri:ng'

    Parameters
    ----------
    value : str
        The string to add colons to
    pad : str, optional
        If not an empty string, pad the string so that the last element always has two characters. The default
        is ``"0"``.
    """
    if len(value) % 2 == 1 and pad:
        value = f"{pad}{value}"

    return ":".join([value[i : i + 2] for i in range(0, len(value), 2)])


def int_to_hex(i: int) -> str:
    """Create a hex-representation of the given serial.

    >>> int_to_hex(12345678)
    'BC614E'
    """
    return hex(i)[2:].upper()


def bytes_to_hex(value: bytes) -> str:
    """Convert a bytes array to hex.

    >>> bytes_to_hex(b'test')
    '74:65:73:74'
    """
    return add_colons(binascii.hexlify(value).upper().decode("utf-8"))


def hex_to_bytes(value: str) -> bytes:
    """Convert a hex number to bytes.

    This should be the inverse of :py:func:`~django_ca.utils.bytes_to_hex`.

    >>> hex_to_bytes('74:65:73:74')
    b'test'
    """
    return binascii.unhexlify(value.replace(":", ""))


def check_name(name: x509.Name) -> x509.Name:
    """Check if `name` is a valid x509 Name.

    This method raises ``ValueError`` if the CommonName contains an empty value or if any attribute not in
    :py:attr:`~django_ca.utils.MULTIPLE_OIDS` occurs multiple times.

    The method returns the name unchanged for convenience.
    """
    seen = set()

    # for oid in set(oids):
    for attr in name:
        oid = attr.oid

        # Check if any fields are duplicate where this is not allowed (e.g. multiple CommonName fields)
        if oid in seen and oid not in MULTIPLE_OIDS:
            raise ValueError(f'Subject contains multiple "{constants.NAME_OID_NAMES[attr.oid]}" fields')
        seen.add(oid)

        if oid == NameOID.COMMON_NAME and not attr.value:
            raise ValueError("CommonName must not be an empty value")
    return name


def sanitize_serial(value: str) -> str:
    """Sanitize a serial provided by user/untrusted input.

    This function is intended to be used to get a serial as used internally by **django-ca** from untrusted
    user input. Internally, serials are stored in upper case and without ``:`` and leading zeros, but user
    output adds at least ``:``.

    Examples
    --------
        >>> sanitize_serial('01:aB')
        '1AB'
    """
    serial = value.upper().replace(":", "")
    if serial != "0":
        serial = serial.lstrip("0")
    if re.search("[^0-9A-F]", serial):
        raise ValueError(f"{value}: Serial has invalid characters")
    return serial


def parse_name_x509(name: ParsableName) -> Tuple[x509.NameAttribute, ...]:
    """Parses a subject string as used in OpenSSLs command line utilities.

    .. versionchanged:: 1.20.0

       This function no longer returns the subject in pseudo-sorted order.

    The ``name`` is expected to be close to the subject format commonly used by OpenSSL, for example
    ``/C=AT/L=Vienna/CN=example.com/emailAddress=user@example.com``. The function does its best to be lenient
    on deviations from the format, object identifiers are case-insensitive, whitespace at the start and end is
    stripped and the subject does not have to start with a slash (``/``).

    >>> parse_name_x509([("CN", "example.com")])
    (<NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.3, name=commonName)>, value='example.com')>,)
    >>> parse_name_x509(
    ...     [("c", "AT"), ("l", "Vienna"), ("o", "quoting/works"), ("CN", "example.com")]
    ... )  # doctest: +NORMALIZE_WHITESPACE
    (<NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.6, name=countryName)>, value='AT')>,
     <NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.7, name=localityName)>, value='Vienna')>,
     <NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.10, name=organizationName)>, value='quoting/works')>,
     <NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.3, name=commonName)>, value='example.com')>)
    """
    if isinstance(name, str):
        # TYPE NOTE: mypy detects t.split() as Tuple[str, ...] and does not recognize the maxsplit parameter
        name = tuple(tuple(t.split("=", 1)) for t in split_str(name.strip(), "/"))  # type: ignore[misc]

    # TODO: allow dotted strings!
    try:
        items = tuple((NAME_CASE_MAPPINGS[t[0].strip().upper()], t[1].strip()) for t in name)
    except KeyError as e:
        raise ValueError(f"Unknown x509 name field: {e.args[0]}") from e

    return tuple(x509.NameAttribute(oid, value) for oid, value in items)


def x509_name(name: ParsableName) -> x509.Name:
    """Parses a string or iterable of two-tuples into a :py:class:`x509.Name <cg:cryptography.x509.Name>`.

    >>> x509_name([('C', 'AT'), ('CN', 'example.com')])
    <Name(C=AT,CN=example.com)>
    """
    return check_name(x509.Name(parse_name_x509(name)))


def merge_x509_names(base: x509.Name, update: x509.Name) -> x509.Name:
    """Merge two :py:class:`x509.Name <cg:cryptography.x509.Name>` instances.

    This function will return a new :py:class:`x509.Name <cg:cryptography.x509.Name>` based on `base`, with
    the attributes from `update` added. If an attribute type occurs in both names, the one from `update` take
    precedence.

    The resulting name will be sorted based on :ref:`settings-ca-default-name-order`, regardless of order of
    `base` or `update`.

    Example::

        >>> base = x509.Name([
        ...     x509.NameAttribute(NameOID.COUNTRY_NAME, "AT"),
        ...     x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Org"),
        ...     x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Example Org Unit"),
        ... ])
        >>> update = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'example.com')])
        >>> merge_x509_names(base, update)
        <Name(C=AT,O=Example Org,OU=Example Org Unit,CN=example.com)>
    """
    attributes: List[x509.NameAttribute] = []
    if any(name_attr.oid not in ca_settings.CA_DEFAULT_NAME_ORDER for name_attr in base):
        raise ValueError(f"{format_name_rfc4514(base)}: Unsortable name")
    if any(name_attr.oid not in ca_settings.CA_DEFAULT_NAME_ORDER for name_attr in update):
        raise ValueError(f"{format_name_rfc4514(update)}: Unsortable name")

    for oid in ca_settings.CA_DEFAULT_NAME_ORDER:
        update_attributes = update.get_attributes_for_oid(oid)
        if update_attributes:
            if oid in MULTIPLE_OIDS:
                attributes += update_attributes
            else:
                attributes.append(update_attributes[0])
            continue

        base_attributes = base.get_attributes_for_oid(oid)
        if base_attributes:
            if oid in MULTIPLE_OIDS:
                attributes += base_attributes
            else:
                attributes.append(base_attributes[0])
            continue

    return x509.Name(attributes)


def validate_email(addr: str) -> str:
    """Validate an email address.

    This function raises ``ValueError`` if the email address is not valid.

    >>> validate_email("user@example.com")
    'user@example.com'
    >>> validate_email("user@exämple.com")
    'user@xn--exmple-cua.com'

    """
    if "@" not in addr:
        raise ValueError(f"Invalid email address: {addr}")

    node, domain = addr.rsplit("@", 1)

    if not node:
        raise ValueError(f"{addr}: node part is empty")

    try:
        domain = idna.encode(domain).decode("utf-8")
    except idna.IDNAError as e:
        raise ValueError(f"Invalid domain: {domain}") from e

    return f"{node}@{domain}"


def validate_hostname(hostname: str, allow_port: bool = False) -> str:
    """Validate a hostname, optionally with a given port.

    >>> validate_hostname('example.com')
    'example.com'
    >>> validate_hostname('example.com:8000', allow_port=True)
    'example.com:8000'

    Parameters
    ----------
    hostname : str
        The hostname to validate.
    allow_port : bool, optional
        If ``True``, the hostname can also contain an optional port number, e.g. "example.com:8000".

    Raises
    ------
    ValueError
        If hostname or port are not valid.

    """
    port = None
    if allow_port is True and ":" in hostname:
        hostname, port_str = hostname.rsplit(":", 1)

        try:
            port = int(port_str)
        except ValueError as ex:
            raise ValueError(f"{port_str}: Port must be an integer") from ex

        if port < 1 or port > 65535:
            raise ValueError(f"{port}: Port must be between 1 and 65535")

    try:
        encoded: str = idna.encode(hostname).decode("utf-8")
    except idna.IDNAError as ex:
        raise ValueError(f"{hostname}: Not a valid hostname") from ex

    if allow_port is True and port is not None:
        return f"{encoded}:{port}"
    return encoded


@typing.overload
def validate_private_key_parameters(
    key_type: typing.Literal["DSA", "RSA"],
    key_size: Optional[int],
    elliptic_curve: Optional[ec.EllipticCurve],
) -> Tuple[int, None]:
    ...


@typing.overload
def validate_private_key_parameters(
    key_type: typing.Literal["EC"],
    key_size: Optional[int],
    elliptic_curve: Optional[ec.EllipticCurve],
) -> Tuple[None, ec.EllipticCurve]:
    ...


@typing.overload
def validate_private_key_parameters(
    key_type: typing.Literal["Ed448", "Ed25519"],
    key_size: Optional[int],
    elliptic_curve: Optional[ec.EllipticCurve],
) -> Tuple[None, None]:
    ...


def validate_private_key_parameters(
    key_type: ParsableKeyType, key_size: Optional[int], elliptic_curve: Optional[ec.EllipticCurve]
) -> Tuple[Optional[int], Optional[ec.EllipticCurve]]:
    """Validate parameters for private key generation.

    This function can be used to fail early if invalid parameters are passed, before the private key is
    generated.

    >>> validate_private_key_parameters("RSA", 4096, None)
    (4096, None)
    >>> validate_private_key_parameters("Ed448", 4096, None)  # Ed448 does not care about the key size
    Traceback (most recent call last):
        ...
    ValueError: Key size is not supported for Ed448 keys.
    >>> validate_private_key_parameters('RSA', 4000, None)
    Traceback (most recent call last):
        ...
    ValueError: 4000: Key size must be a power of two
    """
    if key_type not in constants.PARSABLE_KEY_TYPES:
        raise ValueError(f"{key_type}: Unknown key type")

    if key_type in ("RSA", "DSA"):
        if key_size is None:
            key_size = ca_settings.CA_DEFAULT_KEY_SIZE
        if not isinstance(key_size, int):
            raise ValueError(f"{key_size}: Key size must be an int.")
        if is_power2(key_size) is False:
            raise ValueError(f"{key_size}: Key size must be a power of two")
        if key_size < ca_settings.CA_MIN_KEY_SIZE:
            raise ValueError(f"{key_size}: Key size must be least {ca_settings.CA_MIN_KEY_SIZE} bits")

    if key_type == "EC":
        if key_size is not None:
            raise ValueError(f"Key size is not supported for {key_type} keys.")
        if elliptic_curve is None:
            elliptic_curve = ca_settings.CA_DEFAULT_ELLIPTIC_CURVE()
        if not isinstance(elliptic_curve, ec.EllipticCurve):
            raise ValueError(f"{elliptic_curve}: Must be a subclass of ec.EllipticCurve")

    if key_type in ("Ed448", "Ed25519"):
        if key_size is not None:
            raise ValueError(f"Key size is not supported for {key_type} keys.")
        if elliptic_curve is not None:
            raise ValueError(f"Elliptic curves are not supported for {key_type} keys.")
    return key_size, elliptic_curve


def validate_public_key_parameters(
    key_type: ParsableKeyType, algorithm: Optional[AllowedHashTypes]
) -> Optional[AllowedHashTypes]:
    """Validate parameters for signing a certificate.

    This function can be used to fail early if invalid parameters are passed.

    >>> validate_public_key_parameters("RSA", hashes.SHA256())  # doctest: +ELLIPSIS
    <cryptography.hazmat.primitives.hashes.SHA256 object at 0x...>
    >>> validate_public_key_parameters("Ed448", None)
    >>> validate_public_key_parameters("Ed448", hashes.SHA256())
    Traceback (most recent call last):
        ...
    ValueError: Ed448 keys do not allow an algorithm for signing.
    """
    if key_type not in constants.PARSABLE_KEY_TYPES:
        raise ValueError(f"{key_type}: Unknown key type")

    if key_type in ("RSA", "DSA", "EC"):
        if algorithm is None:
            if key_type == "DSA":
                return ca_settings.CA_DEFAULT_DSA_SIGNATURE_HASH_ALGORITHM
            return ca_settings.CA_DEFAULT_SIGNATURE_HASH_ALGORITHM

        if not isinstance(algorithm, hashes.HashAlgorithm):
            raise ValueError(f"{key_type}: algorithm must be an instance of hashes.HashAlgorithm.")
    elif algorithm is not None:  # Ed448 and Ed25519 keys do not allow hash algorithms
        raise ValueError(f"{key_type} keys do not allow an algorithm for signing.")
    return algorithm


@typing.overload
def generate_private_key(
    key_size: Optional[int],
    key_type: typing.Literal["DSA"],
    elliptic_curve: Optional[ec.EllipticCurve],
) -> dsa.DSAPrivateKey:
    ...


@typing.overload
def generate_private_key(
    key_size: Optional[int],
    key_type: typing.Literal["RSA"],
    elliptic_curve: Optional[ec.EllipticCurve],
) -> rsa.RSAPrivateKey:
    ...


@typing.overload
def generate_private_key(
    key_size: Optional[int],
    key_type: typing.Literal["EC"],
    elliptic_curve: Optional[ec.EllipticCurve],
) -> ec.EllipticCurvePrivateKey:
    ...


@typing.overload
def generate_private_key(
    key_size: Optional[int],
    key_type: typing.Literal["Ed25519"],
    elliptic_curve: Optional[ec.EllipticCurve],
) -> ed25519.Ed25519PrivateKey:
    ...


@typing.overload
def generate_private_key(
    key_size: Optional[int],
    key_type: typing.Literal["Ed448"],
    elliptic_curve: Optional[ec.EllipticCurve],
) -> ed448.Ed448PrivateKey:
    ...


def generate_private_key(
    key_size: Optional[int],
    key_type: ParsableKeyType,
    elliptic_curve: Optional[ec.EllipticCurve],
) -> CertificateIssuerPrivateKeyTypes:
    """Generate a private key.

    This function assumes that you called :py:func:`~django_ca.utils.validate_private_key_parameters` on the
    input values and does not do any sanity checks on its own.

    Parameters
    ----------
    key_size : int
        The size of the private key. The value is  ignored if ``key_type`` is not ``"DSA"`` or ``"RSA"``.
    key_type : {'RSA', 'DSA', 'EC', 'Ed25519', 'Ed448'}
        The type of the private key.
    elliptic_curve : :py:class:`~cg:cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve`
        An elliptic curve to use for EC keys. This parameter is ignored if ``key_type`` is not ``"EC"``.
        Defaults to the :ref:`CA_DEFAULT_ELLIPTIC_CURVE <settings-ca-default-elliptic-curve>`.

    Returns
    -------
    key
        A private key of the appropriate type.
    """
    # NOTE: validate_private_key_parameters() is repetitively moved into the if statements so that mypy
    #   detects the right types.
    if key_type == "DSA":
        key_size, elliptic_curve = validate_private_key_parameters(key_type, key_size, elliptic_curve)
        return dsa.generate_private_key(key_size=key_size)
    if key_type == "RSA":
        key_size, elliptic_curve = validate_private_key_parameters(key_type, key_size, elliptic_curve)
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    if key_type == "EC":
        key_size, elliptic_curve = validate_private_key_parameters(key_type, key_size, elliptic_curve)
        return ec.generate_private_key(elliptic_curve)
    if key_type == "Ed25519":
        validate_private_key_parameters(key_type, key_size, elliptic_curve)
        return ed25519.Ed25519PrivateKey.generate()
    if key_type == "Ed448":
        validate_private_key_parameters(key_type, key_size, elliptic_curve)
        return ed448.Ed448PrivateKey.generate()

    # COVERAGE NOTE: Unreachable code, as all possible key_types are handled above and
    #   validate_private_key_parameters would raise for any other key types.
    raise ValueError(f"{key_type}: Unknown key type.")


def parse_general_name(name: ParsableGeneralName) -> x509.GeneralName:
    """Parse a general name from user input.

    This function will do its best to detect the intended type of any value passed to it:

    >>> parse_general_name('example.com')
    <DNSName(value='example.com')>
    >>> parse_general_name('*.example.com')
    <DNSName(value='*.example.com')>
    >>> parse_general_name('.example.com')  # Syntax used e.g. for NameConstraints: All levels of subdomains
    <DNSName(value='.example.com')>
    >>> parse_general_name('user@example.com')
    <RFC822Name(value='user@example.com')>
    >>> parse_general_name('https://example.com')
    <UniformResourceIdentifier(value='https://example.com')>
    >>> parse_general_name('1.2.3.4')
    <IPAddress(value=1.2.3.4)>
    >>> parse_general_name('fd00::1')
    <IPAddress(value=fd00::1)>

    The default fallback is to assume a :py:class:`~cg:cryptography.x509.DNSName`. If this doesn't
    work, an exception will be raised:

    >>> parse_general_name('foo..bar`*123')  # doctest: +ELLIPSIS
    Traceback (most recent call last):
        ...
    ValueError: Could not parse name: foo..bar`*123

    If you want to override detection, you can prefix the name to match :py:const:`GENERAL_NAME_RE`:

    >>> parse_general_name('email:user@example.com')
    <RFC822Name(value='user@example.com')>
    >>> parse_general_name('URI:https://example.com')
    <UniformResourceIdentifier(value='https://example.com')>
    >>> parse_general_name('dirname:CN=example.com')
    <DirectoryName(value=<Name(CN=example.com)>)>

    Some more exotic values can only be generated by using this prefix:

    >>> parse_general_name('rid:2.5.4.3')
    <RegisteredID(value=<ObjectIdentifier(oid=2.5.4.3, name=commonName)>)>
    >>> parse_general_name('otherName:2.5.4.3;UTF8:example.com')
    <OtherName(type_id=<ObjectIdentifier(oid=2.5.4.3, name=commonName)>, value=b'\\x0c\\x0bexample.com')>

    If you give a prefixed value, this function is less forgiving of any typos and does not catch any
    exceptions:

    >>> parse_general_name('email:foo@bar com')
    Traceback (most recent call last):
        ...
    ValueError: Invalid domain: bar com

    """
    # pylint: disable=too-many-return-statements,too-many-branches,too-many-statements

    if isinstance(name, x509.GeneralName):
        return name
    if not isinstance(name, str):
        raise ValueError(
            f"Cannot parse general name {name}: Must be of type str (was: {type(name).__name__})."
        )

    typ = None
    match = GENERAL_NAME_RE.match(name)
    if match is not None:
        typ, name = match.groups()
        typ = typ.lower()

    if typ is None:
        if re.match("[a-z0-9]{2,}://", name):  # Looks like a URI
            try:
                return x509.UniformResourceIdentifier(encode_url(name))
            except idna.IDNAError:
                pass

        if "@" in name:  # Looks like an Email address
            try:
                return x509.RFC822Name(validate_email(name))
            except ValueError:
                pass

        # Try to parse this as IPAddress/Network
        try:
            return x509.IPAddress(ip_address(name))
        except ValueError:
            pass
        try:
            return x509.IPAddress(ip_network(name))
        except ValueError:
            pass

        # Almost anything passes as DNS name, so this is our default fallback
        try:
            return x509.DNSName(encode_dns(name))
        except idna.IDNAError as e:
            raise ValueError(f"Could not parse name: {name}") from e

    if typ == "uri":
        try:
            return x509.UniformResourceIdentifier(encode_url(name))
        except idna.IDNAError as e:
            raise ValueError(f"Could not parse DNS name in URL: {name}") from e
    elif typ == "email":
        return x509.RFC822Name(validate_email(name))  # validate_email already raises ValueError
    elif typ == "ip":
        try:
            return x509.IPAddress(ip_address(name))
        except ValueError:
            pass

        try:
            return x509.IPAddress(ip_network(name))
        except ValueError:
            pass

        raise ValueError("Could not parse IP address.")
    elif typ == "rid":
        return x509.RegisteredID(x509.ObjectIdentifier(name))
    elif typ == "othername":
        try:
            dotted_string, asn1_typ_and_value = name.split(";", 1)
            oid = x509.ObjectIdentifier(dotted_string)
            asn_typ, asn1_value = asn1_typ_and_value.split(":", 1)
        except ValueError as ex:
            raise ValueError(f"Incorrect otherName format: {name}") from ex

        # Get DER representation of the value for x509.OtherName()
        if asn_typ in ("UTF8", "UTF8String"):
            der_value = asn1crypto.core.UTF8String(asn1_value).dump()
        elif asn_typ in ("UNIV", "UNIVERSALSTRING"):
            der_value = asn1crypto.core.UniversalString(asn1_value).dump()
        elif asn_typ in ("IA5", "IA5STRING"):
            der_value = asn1crypto.core.IA5String(asn1_value).dump()
        elif asn_typ in ("BOOL", "BOOLEAN"):
            # nconf allows for true, y, yes, false, n and no as valid values
            if asn1_value.lower() in ("true", "y", "yes"):
                der_value = asn1crypto.core.Boolean(True).dump()
            elif asn1_value.lower() in ("false", "n", "no"):
                der_value = asn1crypto.core.Boolean(False).dump()
            else:
                raise ValueError(
                    f"Unsupported {asn_typ} specification for otherName: {asn1_value}: Must be TRUE or FALSE"
                )
        elif asn_typ in ("UTC", "UTCTIME"):
            parsed_datetime = datetime.strptime(asn1_value, "%y%m%d%H%M%SZ").replace(tzinfo=tz.utc)
            der_value = asn1crypto.core.UTCTime(parsed_datetime).dump()
        elif asn_typ in ("GENTIME", "GENERALIZEDTIME"):
            parsed_datetime = datetime.strptime(asn1_value, "%Y%m%d%H%M%SZ").replace(tzinfo=tz.utc)
            der_value = asn1crypto.core.GeneralizedTime(parsed_datetime).dump()
        elif asn_typ == "NULL":
            if asn1_value:
                raise ValueError("Invalid NULL specification for otherName: Value must not be present")
            der_value = asn1crypto.core.Null().dump()
        elif asn_typ in ("INT", "INTEGER"):
            if asn1_value.startswith("0x"):
                der_value = asn1crypto.core.Integer(int(asn1_value, 16)).dump()
            else:
                der_value = asn1crypto.core.Integer(int(asn1_value)).dump()
        elif asn_typ == "OctetString":
            der_value = asn1crypto.core.OctetString(bytes(bytearray.fromhex(asn1_value))).dump()
        else:
            raise ValueError(f"Unsupported ASN type in otherName: {asn_typ}")

        return x509.OtherName(oid, der_value)
    elif typ == "dirname":
        return x509.DirectoryName(parse_name_rfc4514(name))
    else:
        try:
            return x509.DNSName(encode_dns(name))
        except idna.IDNAError as e:
            raise ValueError(f"Could not parse DNS name: {name}") from e


def parse_hash_algorithm(value: Union[Type[AllowedHashTypes], ParsableHash] = None) -> AllowedHashTypes:
    """Parse a hash algorithm value.

    .. deprecated:: 1.25.0

       This function will be removed in ``django-ca==1.27.0``. Use standard hash algorithm names instead.

    The most common use case is to pass a str naming a class in
    :py:mod:`~cg:cryptography.hazmat.primitives.hashes`.
    For convenience, passing ``None`` will return the value of
    :ref:`settings-ca-default-signature-hash-algorithm`, and passing an
    :py:class:`~cg:cryptography.hazmat.primitives.hashes.HashAlgorithm` will return that
    instance unchanged.

    Example usage::

        >>> parse_hash_algorithm()  # doctest: +ELLIPSIS
        <cryptography.hazmat.primitives.hashes.SHA512 object at ...>
        >>> parse_hash_algorithm('SHA512')  # doctest: +ELLIPSIS
        <cryptography.hazmat.primitives.hashes.SHA512 object at ...>
        >>> parse_hash_algorithm(' SHA512 ')  # doctest: +ELLIPSIS
        <cryptography.hazmat.primitives.hashes.SHA512 object at ...>
        >>> parse_hash_algorithm(hashes.SHA512)  # doctest: +ELLIPSIS
        <cryptography.hazmat.primitives.hashes.SHA512 object at ...>
        >>> parse_hash_algorithm(hashes.SHA512())  # doctest: +ELLIPSIS
        <cryptography.hazmat.primitives.hashes.SHA512 object at ...>
        >>> parse_hash_algorithm('Wrong')  # doctest: +ELLIPSIS
        Traceback (most recent call last):
            ...
        ValueError: Unknown hash algorithm: Wrong

    Parameters
    ----------
    value : str or :py:class:`~cg:cryptography.hazmat.primitives.hashes.HashAlgorithm`, optional
        The value to parse, the function description on how possible values are used.

    Returns
    -------
    algorithm
        A :py:class:`~cg:cryptography.hazmat.primitives.hashes.HashAlgorithm` instance.

    Raises
    ------
    ValueError
        If an unknown object is passed or if ``value`` does not name a known algorithm
    """
    if value is None:
        return ca_settings.CA_DEFAULT_SIGNATURE_HASH_ALGORITHM
    if isinstance(value, type) and issubclass(value, hashes.HashAlgorithm):
        if value in constants.HASH_ALGORITHM_NAMES:
            return typing.cast(AllowedHashTypes, value())
        raise ValueError(f"{value.__name__}: Algorithm is not allowed for signing")
    if isinstance(value, hashes.HashAlgorithm):
        if type(value) in constants.HASH_ALGORITHM_NAMES:
            return typing.cast(AllowedHashTypes, value)
        name = type(value).__name__
        raise ValueError(f"{name}: Algorithm is not allowed for signing")
    if isinstance(value, str):
        try:
            algo: Type[AllowedHashTypes] = getattr(hashes, value.strip())
            return algo()
        except AttributeError as e:
            raise ValueError(f"Unknown hash algorithm: {value}") from e

    raise ValueError(f"Unknown type passed: {type(value).__name__}")


def parse_encoding(value: Optional[Union[str, Encoding]] = None) -> Encoding:
    """Parse a value to a valid encoding.

    This function accepts either a member of
    :py:class:`~cg:cryptography.hazmat.primitives.serialization.Encoding` or a string describing a member. If
    no value is passed, it will assume ``PEM`` as a default value. Note that ``"ASN1"`` is treated as an alias
    for ``"DER"``.

        >>> parse_encoding()
        <Encoding.PEM: 'PEM'>
        >>> parse_encoding('DER')
        <Encoding.DER: 'DER'>
        >>> parse_encoding(Encoding.PEM)
        <Encoding.PEM: 'PEM'>
    """
    if value is None:
        return ca_settings.CA_DEFAULT_ENCODING
    if isinstance(value, Encoding):
        return value
    if isinstance(value, str):
        if value == "ASN1":
            value = "DER"

        try:
            return Encoding[value]
        except KeyError as e:
            raise ValueError(f"Unknown encoding: {value}") from e

    raise ValueError(f"Unknown type passed: {type(value).__name__}")


def parse_expires(expires: Expires = None) -> datetime:
    """Parse a value specifying an expiry into a concrete datetime.

    This function always returns a timezone-aware datetime object with UTC as a timezone.
    """
    now = datetime.now(tz=tz.utc).replace(second=0, microsecond=0)

    if isinstance(expires, int):
        return now + timedelta(days=expires)
    if isinstance(expires, timedelta):
        return now + expires
    if isinstance(expires, datetime):
        if timezone.is_naive(expires):
            # Should never happen, as all callers of this function already pass a tz-aware timestamp.
            raise ValueError("expires must not be a naive datetime")

        # NOTE: A datetime is passed when creating an intermediate CA and the expiry is limited by the expiry
        # of the parent CA.
        return expires.replace(second=0, microsecond=0).astimezone(tz.utc)

    return now + ca_settings.CA_DEFAULT_EXPIRES


def parse_key_curve(value: str) -> ec.EllipticCurve:
    """Parse a string an :py:class:`~cg:cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve` instance.

    This function is intended to parse user input, so it ignores case.

    Example usage::

        >>> parse_key_curve('SECP256R1')  # doctest: +ELLIPSIS
        <cryptography.hazmat.primitives.asymmetric.ec.SECP256R1 object at ...>
        >>> parse_key_curve('SECP384R1')  # doctest: +ELLIPSIS
        <cryptography.hazmat.primitives.asymmetric.ec.SECP384R1 object at ...>
        >>> parse_key_curve('secp384r1')  # doctest: +ELLIPSIS
        <cryptography.hazmat.primitives.asymmetric.ec.SECP384R1 object at ...>

    Parameters
    ----------
    value : str
        The name of the curve (case-insensitive).

    Returns
    -------
    curve
        An :py:class:`~cg:cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve` instance.

    Raises
    ------
    ValueError
        If the named curve is not supported.
    """
    try:
        curves = {k.lower(): v for k, v in constants.ELLIPTIC_CURVE_TYPES.items()}
        return curves[value.strip().lower()]()
    except KeyError as ex:
        raise ValueError(f"{value}: Not a known Elliptic Curve") from ex


def get_cert_builder(expires: datetime, serial: Optional[int] = None) -> x509.CertificateBuilder:
    """Get a basic X.509 certificate builder object.

    Parameters
    ----------
    expires : datetime
        When this certificate is supposed to expire, as a timezone-aware datetime object.
    serial : int, optional
        Serial for the certificate. If not passed, a serial will be randomly generated using
        :py:func:`~cg:cryptography.x509.random_serial_number`.
    """
    now = datetime.now(tz.utc).replace(second=0, microsecond=0)

    # NOTE: Explicitly passing a serial is used when creating a CA, where we want to add extensions where the
    # value references the serial.
    if serial is None:
        serial = x509.random_serial_number()

    if timezone.is_naive(expires):
        raise ValueError("expires must not be a naive datetime")
    if expires <= now:
        raise ValueError("expires must be in the future")

    # strip seconds and microseconds
    expires = expires.replace(second=0, microsecond=0)

    # cryptography expects timezone-naive objects in UTC, so we convert them.
    now = timezone.make_naive(now, timezone=tz.utc)
    expires = timezone.make_naive(expires, timezone=tz.utc)

    builder = x509.CertificateBuilder()
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(expires)
    builder = builder.serial_number(serial)

    return builder


def read_file(path: str) -> bytes:
    """Read the file from the given path.

    If ``path`` is an absolute path, reads a file from the local file system. For relative paths, read the
    file using the storage backend configured using :ref:`CA_FILE_STORAGE <settings-ca-file-storage>`.
    """
    stream = ca_storage.open(path)

    try:
        data: bytes = stream.read()  # pragma: no branch
        return data
    finally:
        stream.close()


# Note used currently, but left here for future reference
# def write_private_file(path, data):
#    """Function to write binary data to a file that will only be readable to the user."""
#
#    with os.fdopen(os.open(path, os.O_CREAT | os.O_WRONLY, 0o400), 'wb') as fh:
#        fh.write(data)


def split_str(val: str, sep: str) -> Iterator[str]:
    """Split a character on the given set of characters.

    Example::

        >>> list(split_str('foo,bar', ', '))
        ['foo', 'bar']
        >>> list(split_str('foo\\\\,bar1', ','))  # escape a separator
        ['foo,bar1']
        >>> list(split_str('foo,"bar,bla"', ','))  # do not split on quoted separator
        ['foo', 'bar,bla']

    Note that `sep` gives one or more separator characters, not a single separator string::

        >>> list(split_str("foo,bar bla", ", "))
        ['foo', 'bar', 'bla']

    Unlike ``str.split()``, separators at the start/end of a string are simply ignored, as are multiple
    subsequent separators::

        >>> list(split_str("/C=AT//ST=Vienna///OU=something//CN=example.com/", "/"))
        ['C=AT', 'ST=Vienna', 'OU=something', 'CN=example.com']

    Parameters
    ----------
    val : str
        The string to split.
    sep: str
        String of characters that are considered separators.
    """
    lex = shlex.shlex(val, posix=True)
    lex.commenters = ""
    lex.whitespace = sep
    lex.whitespace_split = True
    yield from lex


def get_crl_cache_key(serial: str, encoding: Encoding = Encoding.DER, scope: Optional[str] = None) -> str:
    """Get the cache key for a CRL with the given parameters."""
    return f"crl_{serial}_{encoding.name}_{scope}"


ca_storage_cls = get_storage_class(ca_settings.CA_FILE_STORAGE)

# NOINSPECTION NOTE: ca_storage_class is typed to the base class (django.core.files.storage.Storage), which
#   does not accept any arguments. PyCharm thinks you can't pass any argument here, but in reality it's up to
#   the user.
# noinspection PyArgumentList
ca_storage = ca_storage_cls(**ca_settings.CA_FILE_STORAGE_KWARGS)

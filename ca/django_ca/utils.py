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

"""Reusable utility functions used throughout django-ca."""

import binascii
import re
import shlex
import typing
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
from typing import Optional, Tuple, Type, Union
from urllib.parse import urlparse

import idna

import asn1crypto.core
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import PRIVATE_KEY_TYPES
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from django.core.files.storage import get_storage_class
from django.core.validators import URLValidator
from django.utils import timezone as tz

from django_ca import ca_settings, constants
from django_ca.typehints import (
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
#: OIDs that can occur multiple times in a certificate
MULTIPLE_OIDS = (NameOID.DOMAIN_COMPONENT, NameOID.ORGANIZATIONAL_UNIT_NAME, NameOID.STREET_ADDRESS)

# uppercase values as keys for normalizing case
NAME_CASE_MAPPINGS = {k.upper(): v for k, v in constants.NAME_OID_TYPES.items()}


ADMIN_SUBJECT_OIDS = (
    NameOID.COUNTRY_NAME,
    NameOID.STATE_OR_PROVINCE_NAME,
    NameOID.LOCALITY_NAME,
    NameOID.ORGANIZATION_NAME,
    NameOID.ORGANIZATIONAL_UNIT_NAME,
    NameOID.COMMON_NAME,
    NameOID.EMAIL_ADDRESS,
)


def make_naive(timestamp: datetime) -> datetime:
    """Like :py:func:`~django.utils.timezone.make_naive`, but does not return an error if already naive."""
    if tz.is_naive(timestamp) is False:
        return tz.make_naive(timestamp)
    return timestamp


def sort_name(name: x509.Name) -> x509.Name:
    """Returns the subject in the correct order for a x509 subject."""
    try:
        return x509.Name(sorted(name, key=lambda attr: constants.CA_DEFAULT_NAME_ORDER.index(attr.oid)))
    except ValueError:
        return name


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
        parsed = parsed._replace(netloc=f"{hostname}:{parsed.port}")
    else:
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

    This function does not take care of sorting the subject in any meaningful order.

    Examples::

        >>> format_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'example.com')]))
        '/CN=example.com'
    """

    def _format_value(val: str) -> str:
        # If val contains no unsafe chars, return it unchanged
        if UNSAFE_NAME_CHARS.search(val) is None:
            return val
        return '"' + val.replace('"', r"\"").replace(r"\\", r"\\\\") + '"'

    items = [(constants.NAME_OID_NAMES[s.oid], s.value) for s in subject]

    values = "/".join([f"{k}={_format_value(v)}" for k, v in items])  # type: ignore[arg-type]
    return f"/{values}"


def serialize_name(name: Union[x509.Name, x509.RelativeDistinguishedName]) -> SerializedName:
    """Serialize a :py:class:`~cg:cryptography.x509.Name`.

    The value also accepts a :py:class:`~cg:cryptography.x509.RelativeDistinguishedName`.

    The returned value is a list of tuples, each consisting of two strings. If an attribute contains
    ``bytes``, it is converted using :py:func:`~django_ca.utils.bytes_to_hex`.

    Examples::

        >>> serialize_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'example.com')]))
        [('CN', 'example.com')]
        >>> serialize_name(x509.RelativeDistinguishedName([
        ...     x509.NameAttribute(NameOID.COUNTRY_NAME, 'AT'),
        ...     x509.NameAttribute(NameOID.COMMON_NAME, 'example.com'),
        ... ]))
        [('C', 'AT'), ('CN', 'example.com')]
    """
    items: SerializedName = []
    for attr in name:
        value = attr.value
        if isinstance(value, bytes):
            value = bytes_to_hex(value)
        items.append((constants.NAME_OID_NAMES[attr.oid], value))
    return items


def format_general_name(name: x509.GeneralName) -> str:
    """Format a single general name.

    >>> import ipaddress
    >>> format_general_name(x509.DNSName('example.com'))
    'DNS:example.com'
    >>> format_general_name(x509.IPAddress(ipaddress.IPv4Address('127.0.0.1')))
    'IP:127.0.0.1'
    """

    if isinstance(name, x509.DirectoryName):
        value = format_name(name.value)
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

    Examples:

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

    >>> parse_name_x509('/CN=example.com')
    (<NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.3, name=commonName)>, value='example.com')>,)
    >>> parse_name_x509('c=AT/l= Vienna/o="quoting/works"/CN=example.com')  # doctest: +NORMALIZE_WHITESPACE
    (<NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.6, name=countryName)>, value='AT')>,
     <NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.7, name=localityName)>, value='Vienna')>,
     <NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.10, name=organizationName)>, value='quoting/works')>,
     <NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.3, name=commonName)>, value='example.com')>)

    The function also handles whitespace, quoting and slashes correctly:

    >>> parse_name_x509('L="Vienna / District"/CN=example.com')  # doctest: +NORMALIZE_WHITESPACE
    (<NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.7, name=localityName)>, value='Vienna / District')>,
     <NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.3, name=commonName)>, value='example.com')>)

    Examples of where this string is used are:

    .. code-block:: console

        # openssl req -new -key priv.key -out csr -utf8 -batch -sha256 -subj '/C=AT/CN=example.com'
        # openssl x509 -in cert.pem -noout -subject -nameopt compat
        /C=AT/L=Vienna/CN=example.com
    """

    if isinstance(name, str):
        # TYPE NOTE: mypy detects t.split() as Tuple[str, ...] and does not recognize the maxsplit parameter
        name = tuple(tuple(t.split("=", 1)) for t in split_str(name.strip(), "/"))  # type: ignore[misc]

    try:
        items = tuple((NAME_CASE_MAPPINGS[t[0].strip().upper()], t[1].strip()) for t in name)
    except KeyError as e:
        raise ValueError(f"Unknown x509 name field: {e.args[0]}") from e

    return tuple(x509.NameAttribute(oid, value) for oid, value in items)


def x509_name(name: ParsableName) -> x509.Name:
    """Parses a string or iterable of two-tuples into a :py:class:`x509.Name <cg:cryptography.x509.Name>`.

    >>> x509_name('/C=AT/CN=example.com')
    <Name(C=AT,CN=example.com)>
    >>> x509_name([('C', 'AT'), ('CN', 'example.com')])
    <Name(C=AT,CN=example.com)>
    """
    return check_name(x509.Name(parse_name_x509(name)))


def x509_relative_name(name: ParsableName) -> x509.RelativeDistinguishedName:
    """Parse a relative name (RDN) into a :py:class:`~cg:cryptography.x509.RelativeDistinguishedName`.

    >>> x509_relative_name('/CN=example.com')
    <RelativeDistinguishedName(CN=example.com)>
    """

    return x509.RelativeDistinguishedName(parse_name_x509(name))


def validate_email(addr: str) -> str:
    """Validate an email address.

    This function raises ``ValueError`` if the email address is not valid.

    >>> validate_email('foo@bar.com')
    'foo@bar.com'
    >>> validate_email('foo@bar com')
    Traceback (most recent call last):
        ...
    ValueError: Invalid domain: bar com

    """
    if "@" not in addr:
        raise ValueError(f"Invalid email address: {addr}")

    node, domain = addr.rsplit("@", 1)
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
    key_type: ParsableKeyType, algorithm: Optional[hashes.HashAlgorithm]
) -> Optional[hashes.HashAlgorithm]:
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
) -> PRIVATE_KEY_TYPES:
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
        key_size, elliptic_curve = validate_private_key_parameters(key_type, key_size, elliptic_curve)
        return ed25519.Ed25519PrivateKey.generate()
    if key_type == "Ed448":
        key_size, elliptic_curve = validate_private_key_parameters(key_type, key_size, elliptic_curve)
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
    >>> parse_general_name('/CN=example.com')
    <DirectoryName(value=<Name(CN=example.com)>)>

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
    >>> parse_general_name('dirname:/CN=example.com')
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

        if name.strip().startswith("/"):  # maybe it's a dirname?
            return x509.DirectoryName(x509_name(name))

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
        match = re.match("(.*?);(.*?):(.*)", name)
        if match is not None:
            oid, asn_typ, val = match.groups()

            # Get DER representation of the value for x509.OtherName()
            if asn_typ in ("UTF8", "UTF8String"):
                parsed_value = asn1crypto.core.UTF8String(val).dump()
            elif asn_typ in ("UNIV", "UNIVERSALSTRING"):
                parsed_value = asn1crypto.core.UniversalString(val).dump()
            elif asn_typ in ("IA5", "IA5STRING"):
                parsed_value = asn1crypto.core.IA5String(val).dump()
            elif asn_typ in ("BOOL", "BOOLEAN"):
                # nconf allows for true, y, yes, false, n and no as valid values
                if val.lower() in ("true", "y", "yes"):
                    parsed_value = asn1crypto.core.Boolean(True).dump()
                elif val.lower() in ("false", "n", "no"):
                    parsed_value = asn1crypto.core.Boolean(False).dump()
                else:
                    raise ValueError(
                        f"Unsupported {asn_typ} specification for otherName: {val}: Must be TRUE or FALSE"
                    )
            elif asn_typ in ("UTC", "UTCTIME"):
                parsed_datetime = datetime.strptime(val, "%y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
                parsed_value = asn1crypto.core.UTCTime(parsed_datetime).dump()
            elif asn_typ in ("GENTIME", "GENERALIZEDTIME"):
                parsed_datetime = datetime.strptime(val, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
                parsed_value = asn1crypto.core.GeneralizedTime(parsed_datetime).dump()
            elif asn_typ == "NULL":
                if val:
                    raise ValueError("Invalid NULL specification for otherName: Value must not be present")
                parsed_value = asn1crypto.core.Null().dump()
            elif asn_typ in ("INT", "INTEGER"):
                if val.startswith("0x"):
                    parsed_value = asn1crypto.core.Integer(int(val, 16)).dump()
                else:
                    parsed_value = asn1crypto.core.Integer(int(val)).dump()
            elif asn_typ == "OctetString":
                parsed_value = asn1crypto.core.OctetString(bytes(bytearray.fromhex(val))).dump()
            else:
                raise ValueError(f"Unsupported ASN type in otherName: {asn_typ}")

            # NOTE: cryptography docs are not really clear on what kind of bytes x509.OtherName() expects, but
            #       the test suite explicitly use b"derdata" as value, indicating DER encoded data.
            return x509.OtherName(x509.ObjectIdentifier(oid), parsed_value)

        raise ValueError(f"Incorrect otherName format: {name}")
    elif typ == "dirname":
        return x509.DirectoryName(x509_name(name))
    else:
        try:
            return x509.DNSName(encode_dns(name))
        except idna.IDNAError as e:
            raise ValueError(f"Could not parse DNS name: {name}") from e


def parse_hash_algorithm(
    value: Union[typing.Type[hashes.HashAlgorithm], ParsableHash] = None
) -> hashes.HashAlgorithm:
    """Parse a hash algorithm value.

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
        If an unknown object is passed or if ``value`` does not name a known algorithm.
    """
    if value is None:
        return ca_settings.CA_DEFAULT_SIGNATURE_HASH_ALGORITHM
    if isinstance(value, type) and issubclass(value, hashes.HashAlgorithm):
        return value()
    if isinstance(value, hashes.HashAlgorithm):
        return value
    if isinstance(value, str):
        if value in constants.HASH_ALGORITHM_KEY_TYPES:
            return constants.HASH_ALGORITHM_KEY_TYPES[value]()
        try:
            algo: Type[hashes.HashAlgorithm] = getattr(hashes, value.strip())
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
    """Parse a value specifying an expiry into a concrete datetime."""

    now = datetime.utcnow().replace(second=0, microsecond=0)

    if isinstance(expires, int):
        return now + timedelta(days=expires)
    if isinstance(expires, timedelta):
        return now + expires
    if isinstance(expires, datetime):
        # NOTE: A datetime is passed when creating an intermediate CA and the expiry is limited by the expiry
        # of the parent CA.
        return expires.replace(second=0, microsecond=0)

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
        The name of the curve (case insensitive).

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
        raise ValueError(f"{value}: Not a known Eliptic Curve") from ex


def get_cert_builder(expires: datetime, serial: Optional[int] = None) -> x509.CertificateBuilder:
    """Get a basic X.509 certificate builder object.

    Parameters
    ----------

    expires : datetime
        Serial number to set for this certificate. Use :py:func:`~cg:cryptography.x509.random_serial_number`
        to generate such a value. By default, a value will be generated.
    serial : int, optional
        Serial for the certificate. If not passed, a serial will be randomly generated using
        :py:func:`~cg:cryptography.x509.random_serial_number`.
    """

    now = datetime.utcnow().replace(second=0, microsecond=0)

    # NOTE: Explicitly passing a serial is used when creating a CA, where we want to add extensions where the
    # value references the serial.
    if serial is None:
        serial = x509.random_serial_number()

    expires = make_naive(expires)
    if expires <= now:
        raise ValueError("expires must be in the future")

    # strip seconds and microseconds
    expires = expires.replace(second=0, microsecond=0)

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
        # NOTE: In the python:3.9-rc-alpine3.10 Docker image, this is marked as a missed branch :-(
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


def split_str(val: str, sep: str) -> typing.Iterator[str]:
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


def get_crl_cache_key(
    serial: str,
    algorithm: Optional[hashes.HashAlgorithm] = hashes.SHA512(),
    encoding: Encoding = Encoding.DER,
    scope: Optional[str] = None,
) -> str:
    """Get the cache key for a CRL with the given parameters."""
    if algorithm is None:
        algorithm_name = "None"
    else:
        algorithm_name = algorithm.name

    return f"crl_{serial}_{algorithm_name}_{encoding.name}_{scope}"


ca_storage_cls = get_storage_class(ca_settings.CA_FILE_STORAGE)

# NOINSPECTION NOTE: ca_storage_class is typed to the base class (django.core.files.storage.Storage), which
#   does not accept any arguments. PyCharm thinks you can't pass any argument here, but in reality it's up to
#   the user.
# noinspection PyArgumentList
ca_storage = ca_storage_cls(**ca_settings.CA_FILE_STORAGE_KWARGS)

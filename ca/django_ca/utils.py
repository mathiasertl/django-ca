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

"""Central functions to load CA key and cert as PKey/X509 objects."""

import binascii
import os
import re
import shlex
from datetime import datetime
from datetime import timedelta
from ipaddress import ip_address
from ipaddress import ip_network
from urllib.parse import urlparse

import idna

from asn1crypto.core import OctetString
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from django.core.files.storage import get_storage_class
from django.core.serializers.json import DjangoJSONEncoder
from django.core.validators import URLValidator
from django.utils.encoding import force_bytes
from django.utils.encoding import force_str
from django.utils.functional import Promise
from django.utils.translation import gettext_lazy as _

from . import ca_settings

# List of possible subject fields, in order
SUBJECT_FIELDS = ['C', 'ST', 'L', 'O', 'OU', 'CN', 'emailAddress', ]

# Description strings for various X509 extensions, taken from "man x509v3_config".
EXTENDED_KEY_USAGE_DESC = _('Purposes for which the certificate public key can be used for.')
KEY_USAGE_DESC = _('Permitted key usages.')

#: Regular expression to match RDNs out of a full x509 name.
NAME_RE = re.compile(r'(?:/+|\A)\s*(?P<field>[^\s]*?)\s*'
                     r'=(?P<quote>[\'"])?\s*(?P<content>(?(quote).*?|[^/]*))\s*'
                     r'(?(quote)(?<!\\)(?P=quote))', re.I)

#: Regular expression to match general names.
GENERAL_NAME_RE = re.compile('^(email|URI|IP|DNS|RID|dirName|otherName):(.*)', flags=re.I)

#: Regular expression matching hexlified certificate serials
SERIAL_RE = re.compile('^([0-9A-F][0-9A-F]:?)+[0-9A-F][0-9A-F]?$')

SAN_NAME_MAPPINGS = {
    x509.DNSName: 'DNS',
    x509.RFC822Name: 'email',
    x509.DirectoryName: 'dirname',
    x509.UniformResourceIdentifier: 'URI',
    x509.IPAddress: 'IP',
    x509.RegisteredID: 'RID',
    x509.OtherName: 'otherName',
}

#: Map OID objects to IDs used in subject strings
OID_NAME_MAPPINGS = {
    NameOID.COUNTRY_NAME: 'C',
    NameOID.STATE_OR_PROVINCE_NAME: 'ST',
    NameOID.LOCALITY_NAME: 'L',
    NameOID.ORGANIZATION_NAME: 'O',
    NameOID.ORGANIZATIONAL_UNIT_NAME: 'OU',
    NameOID.COMMON_NAME: 'CN',
    NameOID.EMAIL_ADDRESS: 'emailAddress',
    NameOID.SERIAL_NUMBER: 'serialNumber',
    NameOID.JURISDICTION_COUNTRY_NAME: 'jurisdictionCountryName',
    NameOID.JURISDICTION_STATE_OR_PROVINCE_NAME: 'jurisdictionStateOrProvinceName',
    NameOID.BUSINESS_CATEGORY: "businessCategory",
    NameOID.POSTAL_CODE: "postalCode",
    NameOID.STREET_ADDRESS: "streetAddress",
}

# same, but reversed
NAME_OID_MAPPINGS = {v: k for k, v in OID_NAME_MAPPINGS.items()}

# Some OIDs can occur multiple times
MULTIPLE_OIDS = (
    NameOID.ORGANIZATIONAL_UNIT_NAME,
    NameOID.STREET_ADDRESS,
)

# uppercase values as keys for normalizing case
NAME_CASE_MAPPINGS = {v.upper(): v for v in OID_NAME_MAPPINGS.values()}


class LazyEncoder(DjangoJSONEncoder):
    """Encoder that also encodes strings translated with gettext_lazy."""

    def default(self, o):
        if isinstance(o, Promise):
            return force_str(o)
        return super().default(o)


def sort_name(subject):
    """Returns the subject in the correct order for a x509 subject."""
    return sorted(subject, key=lambda e: SUBJECT_FIELDS.index(e[0]))


def encode_url(url):
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
    if parsed.port:
        hostname = idna.encode(parsed.hostname).decode('utf-8')
        parsed = parsed._replace(netloc='%s:%s' % (hostname, parsed.port))
    else:
        parsed = parsed._replace(netloc=idna.encode(parsed.netloc).decode('utf-8'))
    return parsed.geturl()


def encode_dns(name):
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
    if name.startswith('*.'):
        return '*.%s' % idna.encode(name[2:]).decode('utf-8')
    if name.startswith('.'):
        return '.%s' % idna.encode(name[1:]).decode('utf-8')
    return idna.encode(name).decode('utf-8')


def format_name(subject):
    """Convert a subject into the canonical form for distinguished names.

    This function does not take care of sorting the subject in any meaningful order.

    Examples::

        >>> format_name([('CN', 'example.com'), ])
        '/CN=example.com'
        >>> format_name([('CN', 'example.com'), ('O', "My Organization"), ])
        '/CN=example.com/O=My Organization'
    """
    if isinstance(subject, x509.Name):
        subject = [(OID_NAME_MAPPINGS[s.oid], s.value) for s in subject]

    return '/%s' % ('/'.join(['%s=%s' % (force_str(k), force_str(v)) for k, v in subject]))


def format_relative_name(name):
    """Convert a relative name (RDN) into a canonical form.

    Examples::

        >>> format_relative_name([('C', 'AT'), ('CN', 'example.com')])
        '/C=AT/CN=example.com'
        >>> format_relative_name(x509.RelativeDistinguishedName([
        ...     x509.NameAttribute(NameOID.COMMON_NAME, 'example.com')
        ... ]))
        '/CN=example.com'
    """
    if isinstance(name, x509.RelativeDistinguishedName):
        name = [(OID_NAME_MAPPINGS[s.oid], s.value) for s in name]

    return '/%s' % ('/'.join(['%s=%s' % (force_str(k), force_str(v)) for k, v in name]))


def format_general_name(name):
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
    return '%s:%s' % (SAN_NAME_MAPPINGS[type(name)], value)


def is_power2(num):
    """Return True if num is a power of 2.

    >>> is_power2(4)
    True
    >>> is_power2(3)
    False
    """
    return num != 0 and ((num & (num - 1)) == 0)


def multiline_url_validator(value):
    """Validate that a TextField contains one valid URL per line.

    .. seealso:: https://docs.djangoproject.com/en/1.9/ref/validators/
    """
    validator = URLValidator()

    for line in value.splitlines():
        validator(line)


def add_colons(value, pad='0'):
    """Add colons after every second digit.

    This function is used in functions to prettify serials.

    >>> add_colons('teststring')
    'te:st:st:ri:ng'

    Parameters
    ----------

    s : str
        The string to add colons to
    pad : str, default
        If not None, pad the string so that the last element always has two characters. The default is
        ``"0"``.
    """

    if len(value) % 2 == 1 and pad is not None:
        value = '%s%s' % (pad, value)

    return ':'.join([value[i:i + 2] for i in range(0, len(value), 2)])


def int_to_hex(i):
    """Create a hex-representation of the given serial.

    >>> int_to_hex(12345678)
    'BC614E'
    """
    return hex(i)[2:].upper()


def bytes_to_hex(value):
    """Convert a bytes array to hex.

    >>> bytes_to_hex(b'test')
    '74:65:73:74'
    """
    return add_colons(binascii.hexlify(value).upper().decode('utf-8'))


def hex_to_bytes(value):
    """Convert a hex number to bytes.

    This should be the inverse of :py:func:`~django_ca.utils.bytes_to_hex`.

    >>> hex_to_bytes('74:65:73:74')
    b'test'
    """
    return binascii.unhexlify(value.replace(':', ''))


def sanitize_serial(value):
    """Sanitize a serial provided by user/untrusted input.

    This function is intended to be used to get a serial as used internaly by **django-ca** from untrusted
    user input. Internally, serials are stored in upper case and without ``:`` and leading zeros, but user
    output adds at least ``:``.

    Examples:

        >>> sanitize_serial('01:aB')
        '1AB'
    """

    serial = value.upper().replace(':', '')
    if serial != '0':
        serial = serial.lstrip('0')
    if re.search('[^0-9A-F]', serial):
        raise ValueError('%s: Serial has invalid characters' % value)
    return serial


def parse_name(name):
    """Parses a subject string as used in OpenSSLs command line utilities.

    The ``name`` is expected to be close to the subject format commonly used by OpenSSL, for example
    ``/C=AT/L=Vienna/CN=example.com/emailAddress=user@example.com``. The function does its best to be lenient
    on deviations from the format, object identifiers are case-insensitive (e.g. ``cn`` is the same as ``CN``,
    whitespace at the start and end is stripped and the subject does not have to start with a slash (``/``).

    >>> parse_name('/CN=example.com')
    [('CN', 'example.com')]
    >>> parse_name('c=AT/l= Vienna/o="ex org"/CN=example.com')
    [('C', 'AT'), ('L', 'Vienna'), ('O', 'ex org'), ('CN', 'example.com')]

    Dictionary keys are normalized to the values of :py:const:`OID_NAME_MAPPINGS` and keys will be sorted
    based on x509 name specifications regardless of the given order:

    >>> parse_name('L="Vienna / District"/EMAILaddress=user@example.com')
    [('L', 'Vienna / District'), ('emailAddress', 'user@example.com')]
    >>> parse_name('/C=AT/CN=example.com') == parse_name('/CN=example.com/C=AT')
    True

    Due to the magic of :py:const:`NAME_RE`, the function even supports quoting strings and including slashes,
    so strings like ``/OU="Org / Org Unit"/CN=example.com`` will work as expected.

    >>> parse_name('L="Vienna / District"/CN=example.com')
    [('L', 'Vienna / District'), ('CN', 'example.com')]

    But note that it's still easy to trick this function, if you really want to. The following example is
    *not* a valid subject, the location is just bogus, and whatever you were expecting as output, it's
    certainly different:

    >>> parse_name('L="Vienna " District"/CN=example.com')
    [('L', 'Vienna'), ('CN', 'example.com')]

    Examples of where this string is used are:

    .. code-block:: console

        # openssl req -new -key priv.key -out csr -utf8 -batch -sha256 -subj '/C=AT/CN=example.com'
        # openssl x509 -in cert.pem -noout -subject -nameopt compat
        /C=AT/L=Vienna/CN=example.com
    """
    name = name.strip()
    if not name:  # empty subjects are ok
        return []

    try:
        items = [(NAME_CASE_MAPPINGS[t[0].upper()], force_str(t[2])) for t in NAME_RE.findall(name)]
    except KeyError as e:
        raise ValueError('Unknown x509 name field: %s' % e.args[0]) from e

    # Check that no OIDs not in MULTIPLE_OIDS occur more then once
    for key, oid in NAME_OID_MAPPINGS.items():
        if sum(1 for t in items if t[0] == key) > 1 and oid not in MULTIPLE_OIDS:
            raise ValueError('Subject contains multiple "%s" fields' % key)

    return sort_name(items)


def x509_name(name):
    """Parses a subject into a :py:class:`x509.Name <cg:cryptography.x509.Name>`.

    If ``name`` is a string, :py:func:`parse_name` is used to parse it.

    >>> x509_name('/C=AT/CN=example.com')
    <Name(C=AT,CN=example.com)>
    >>> x509_name([('C', 'AT'), ('CN', 'example.com')])
    <Name(C=AT,CN=example.com)>
    """
    if isinstance(name, str):
        name = parse_name(name)

    return x509.Name([x509.NameAttribute(NAME_OID_MAPPINGS[typ], force_str(value)) for typ, value in name])


def x509_relative_name(name):
    """Parse a relative name (RDN) into a :py:class:`~cg:cryptography.x509.RelativeDistinguishedName`.

    >>> x509_relative_name('/CN=example.com')
    <RelativeDistinguishedName(CN=example.com)>
    >>> x509_relative_name([('CN', 'example.com')])
    <RelativeDistinguishedName(CN=example.com)>
    """
    if isinstance(name, x509.RelativeDistinguishedName):
        return name
    if isinstance(name, str):
        name = parse_name(name)

    return x509.RelativeDistinguishedName([
        x509.NameAttribute(NAME_OID_MAPPINGS[typ], force_str(value)) for typ, value in name
    ])


def validate_email(addr):
    """Validate an email address.

    This function raises ``ValueError`` if the email address is not valid.

    >>> validate_email('foo@bar.com')
    'foo@bar.com'
    >>> validate_email('foo@bar com')
    Traceback (most recent call last):
        ...
    ValueError: Invalid domain: bar com

    """
    if '@' not in addr:
        raise ValueError('Invalid email address: %s' % addr)

    node, domain = addr.rsplit('@', 1)
    try:
        domain = idna.encode(domain).decode('utf-8')
    except idna.core.IDNAError as e:
        raise ValueError('Invalid domain: %s' % domain) from e

    return '%s@%s' % (node, domain)


def validate_hostname(hostname, allow_port=False):
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
    if allow_port is True and ':' in hostname:
        hostname, port = hostname.rsplit(':', 1)

        try:
            port = int(port)
        except ValueError as e:
            raise ValueError('%s: Port must be an integer' % port) from e
        else:
            if port < 1 or port > 65535:
                raise ValueError('%s: Port must be between 1 and 65535' % port)

    try:
        encoded = idna.encode(hostname).decode('utf-8')
    except idna.IDNAError as e:
        raise ValueError('%s: Not a valid hostname' % hostname) from e

    if allow_port is True and port is not None:
        return '%s:%s' % (encoded, port)
    return encoded


def validate_key_parameters(key_size=None, key_type='RSA', ecc_curve=None):
    """Validate parameters for private key generation and return sanitized values.

    This function can be used to fail early if invalid parameters are passed, before the private key is
    generated.

    >>> validate_key_parameters()  # defaults
    (1024, 'RSA', None)
    >>> validate_key_parameters(4096, 'ECC', None)  # doctest: +ELLIPSIS
    (None, 'ECC', <cryptography.hazmat.primitives.asymmetric.ec.SECP256R1 object at ...>)
    >>> validate_key_parameters(4000, 'RSA', None)
    Traceback (most recent call last):
        ...
    ValueError: 4000: Key size must be a power of two
    """
    if key_type is None:
        key_type = 'RSA'

    if key_type == 'ECC':
        key_size = None
        ecc_curve = parse_key_curve(ecc_curve)
    elif key_type in ['DSA', 'RSA']:
        if key_size is None:
            key_size = ca_settings.CA_DEFAULT_KEY_SIZE

        if not is_power2(key_size):
            raise ValueError("%s: Key size must be a power of two" % key_size)
        if key_size < ca_settings.CA_MIN_KEY_SIZE:
            raise ValueError("%s: Key size must be least %s bits" % (
                key_size, ca_settings.CA_MIN_KEY_SIZE))
    else:
        raise ValueError('%s: Unknown key type' % key_type)

    return key_size, key_type, ecc_curve


def generate_private_key(key_size, key_type, ecc_curve):
    """Generate a private key.

    This function assumes that you called :py:func:`~django_ca.utils.validate_key_parameters` on the input
    values and does not do any sanity checks on its own.

    Parameters
    ----------

    key_size : int
        The size of the private key (not used for ECC keys).
    key_type : {'RSA', 'DSA', 'ECC'}
        The type of the private key.
    ecc_curve : :py:class:`~cg:cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve`
        The ECC curve to use for an ECC key.

    Returns
    -------

    key
        A private key of the appropriate type.
    """
    if key_type == 'DSA':
        private_key = dsa.generate_private_key(key_size=key_size, backend=default_backend())
    elif key_type == 'ECC':
        private_key = ec.generate_private_key(ecc_curve, default_backend())
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size,
                                               backend=default_backend())

    return private_key


def parse_general_name(name):
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
    <OtherName(type_id=<ObjectIdentifier(oid=2.5.4.3, name=commonName)>, value=b'example.com')>

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
        raise ValueError('Cannot parse general name %s: Must be of type str (was: %s).' %
                         (name, type(name).__name__))

    typ = None
    match = GENERAL_NAME_RE.match(name)
    if match is not None:
        typ, name = match.groups()
        typ = typ.lower()

    if typ is None:
        if re.match('[a-z0-9]{2,}://', name):  # Looks like a URI
            try:
                return x509.UniformResourceIdentifier(encode_url(name))
            except idna.IDNAError:
                pass

        if '@' in name:  # Looks like an Email address
            try:
                return x509.RFC822Name(validate_email(name))
            except ValueError:
                pass

        if name.strip().startswith('/'):  # maybe it's a dirname?
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
            raise ValueError('Could not parse name: %s' % name) from e

    if typ == 'uri':
        try:
            return x509.UniformResourceIdentifier(encode_url(name))
        except idna.IDNAError as e:
            raise ValueError('Could not parse DNS name in URL: %s' % name) from e
    elif typ == 'email':
        return x509.RFC822Name(validate_email(name))  # validate_email already raises ValueError
    elif typ == 'ip':
        try:
            return x509.IPAddress(ip_address(name))
        except ValueError:
            pass

        try:
            return x509.IPAddress(ip_network(name))
        except ValueError:
            pass

        raise ValueError('Could not parse IP address.')
    elif typ == 'rid':
        return x509.RegisteredID(x509.ObjectIdentifier(name))
    elif typ == 'othername':
        regex = "(.*);(.*):(.*)"
        if re.match(regex, name) is not None:
            oid, asn_typ, val = re.match(regex, name).groups()
            oid = x509.ObjectIdentifier(oid)
            if asn_typ == 'UTF8':
                val = val.encode('utf-8')
            elif asn_typ == 'OctetString':
                val = bytes(bytearray.fromhex(val))
                val = OctetString(val).dump()
            else:
                raise ValueError('Unsupported ASN type in otherName: %s' % asn_typ)
            val = force_bytes(val)
            return x509.OtherName(oid, val)

        raise ValueError('Incorrect otherName format: %s' % name)
    elif typ == 'dirname':
        return x509.DirectoryName(x509_name(name))
    else:
        try:
            return x509.DNSName(encode_dns(name))
        except idna.IDNAError as e:
            raise ValueError('Could not parse DNS name: %s' % name) from e


def parse_hash_algorithm(value=None):
    """Parse a hash algorithm value.

    The most common use case is to pass a str naming a class in
    :py:mod:`~cg:cryptography.hazmat.primitives.hashes`.

    For convenience, passing ``None`` will return the value of :ref:`CA_DIGEST_ALGORITHM
    <settings-ca-digest-algorithm>`, and passing an
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
        >>> parse_hash_algorithm(object())  # doctest: +ELLIPSIS
        Traceback (most recent call last):
            ...
        ValueError: Unknown type passed: object

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
        return ca_settings.CA_DIGEST_ALGORITHM
    if isinstance(value, type) and issubclass(value, hashes.HashAlgorithm):
        return value()
    if isinstance(value, hashes.HashAlgorithm):
        return value
    if isinstance(value, str):
        try:
            return getattr(hashes, value.strip())()
        except AttributeError as e:
            raise ValueError('Unknown hash algorithm: %s' % value) from e

    raise ValueError('Unknown type passed: %s' % type(value).__name__)


def parse_encoding(value=None):
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
        if value == 'ASN1':
            value = 'DER'

        try:
            return getattr(Encoding, value)
        except AttributeError as e:
            raise ValueError('Unknown encoding: %s' % value) from e

    raise ValueError('Unknown type passed: %s' % type(value).__name__)


def parse_key_curve(value=None):
    """Parse an elliptic curve value.

    This function uses a value identifying an elliptic curve to return an
    :py:class:`~cg:cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve` instance. The name must match a
    class name of one of the classes named under "Elliptic Curves" in
    :any:`cg:hazmat/primitives/asymmetric/ec`.

    For convenience, passing ``None`` will return the value of :ref:`CA_DEFAULT_ECC_CURVE
    <settings-ca-default-ecc-curve>`, and passing an
    :py:class:`~cg:cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve` will return that instance
    unchanged.

    Example usage::

        >>> parse_key_curve('SECP256R1')  # doctest: +ELLIPSIS
        <cryptography.hazmat.primitives.asymmetric.ec.SECP256R1 object at ...>
        >>> parse_key_curve('SECP384R1')  # doctest: +ELLIPSIS
        <cryptography.hazmat.primitives.asymmetric.ec.SECP384R1 object at ...>
        >>> parse_key_curve(ec.SECP256R1())  # doctest: +ELLIPSIS
        <cryptography.hazmat.primitives.asymmetric.ec.SECP256R1 object at ...>
        >>> parse_key_curve()  # doctest: +ELLIPSIS
        <cryptography.hazmat.primitives.asymmetric.ec.SECP256R1 object at ...>

    Parameters
    ----------

    value : str, otional
        The name of the curve or ``None`` to return the default curve.

    Returns
    -------

    curve
        An :py:class:`~cg:cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve` instance.

    Raises
    ------

    ValueError
        If the named curve is not supported.
    """
    if isinstance(value, ec.EllipticCurve):
        return value  # name was already parsed
    if value is None:
        return ca_settings.CA_DEFAULT_ECC_CURVE

    curve = getattr(ec, value.strip(), type)
    if not issubclass(curve, ec.EllipticCurve):
        raise ValueError('%s: Not a known Eliptic Curve' % value)
    return curve()


def get_cert_builder(expires, serial=None):
    """Get a basic X509 cert builder object.

    .. TODO:: deprecate support for passing datetime as expires

    Parameters
    ----------

    expires : datetime or timedelta
        When this certificate will expire.
    serial : int, optional
        Serial number to set for this certificate. Use :py:func:`~cg:cryptography.x509.random_serial_number`
        to generate such a value. By default, a value will be generated.
    """
    now = datetime.utcnow().replace(second=0, microsecond=0)

    if serial is None:
        serial = x509.random_serial_number()
    if expires is None:
        expires = now + ca_settings.CA_DEFAULT_EXPIRES
    elif isinstance(expires, timedelta):
        expires = now + expires
    else:
        expires = expires.replace(second=0, microsecond=0)

    builder = x509.CertificateBuilder()
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(expires)
    builder = builder.serial_number(serial)

    return builder


def read_file(path):
    """Read the file from the given path.

    If ``path`` is an absolute path, reads a file from the local filesystem. For relative paths, read the file
    using the storage backend configured using :ref:`CA_FILE_STORAGE <settings-ca-file-storage>`.
    """
    if os.path.isabs(path):
        with open(path, 'rb') as stream:
            return stream.read()

    stream = ca_storage.open(path)

    try:
        # NOTE: In the python:3.9-rc-alpine3.10 Docker image, this is marked as a missed branch :-(
        return stream.read()  # pragma: no branch
    finally:
        stream.close()


# Note used currently, but left here for future reference
#def write_private_file(path, data):
#    """Function to write binary data to a file that will only be readable to the user."""
#
#    with os.fdopen(os.open(path, os.O_CREAT | os.O_WRONLY, 0o400), 'wb') as fh:
#        fh.write(data)


def shlex_split(val, sep):
    """Split a character on the given set of characters.

    Example::

        >>> shlex_split('foo,bar', ', ')
        ['foo', 'bar']
        >>> shlex_split('foo\\\\,bar1', ',')  # escape a separator
        ['foo,bar1']
        >>> shlex_split('"foo,bar", bla', ', ')
        ['foo,bar', 'bla']
        >>> shlex_split('foo,"bar,bla"', ',')
        ['foo', 'bar,bla']
    """
    lex = shlex.shlex(val, posix=True)
    lex.whitespace = sep
    lex.whitespace_split = True
    return list(lex)


class GeneralNameList(list):
    """List that holds :py:class:`~cg:cryptography.x509.GeneralName` instances and parses ``str`` when added.

    A ``GeneralNameList`` is a ``list`` subclass that will always only hold
    :py:class:`~cg:cryptography.x509.GeneralName` instances, but any ``str`` passed to it will be passed to
    :py:func:`~django_ca.utils.parse_general_name`::

        >>> from cryptography import x509
        >>> l = GeneralNameList(['example.com'])
        >>> l += ['DNS:example.net', x509.DNSName('example.org')]
        >>> print(l)
        <GeneralNameList: ['DNS:example.com', 'DNS:example.net', 'DNS:example.org']>
        >>> 'example.com' in l, 'DNS:example.com' in l, x509.DNSName('example.com') in l
        (True, True, True)
        >>> l == ['example.com', 'example.net', 'example.org']
        True
        >>> l == [x509.DNSName('example.com'), 'example.net', 'DNS:example.org']
        True

    """
    def __init__(self, iterable=tuple()):
        if isinstance(iterable, (str, x509.GeneralName)):
            iterable = [iterable]

        super().__init__(parse_general_name(v) for v in iterable)

    def serialize(self):
        """Generate a list of formatted names."""
        for val in self:
            yield format_general_name(val)

    def __add__(self, value):  # self + other_list
        if isinstance(value, GeneralNameList) is False:
            value = GeneralNameList(value)
        return GeneralNameList(list(self) + list(value))

    def __contains__(self, value):  # value in self
        try:
            value = parse_general_name(value)
        except ValueError:
            return False

        return list.__contains__(self, value)

    def __eq__(self, other):  # value == other
        if isinstance(other, GeneralNameList) is False and isinstance(other, list) is True:
            other = GeneralNameList(other)
        return list.__eq__(self, other)

    def __iadd__(self, value):  # self += value
        return list.__iadd__(self, (parse_general_name(v) for v in value))

    def __repr__(self):
        return '<GeneralNameList: %r>' % [format_general_name(v) for v in self]

    def __setitem__(self, key, value):  # l[0] = 'example.com'
        if isinstance(key, slice):  # l[0:1] = ['example.com']
            list.__setitem__(self, key, (parse_general_name(v) for v in value))
        else:
            list.__setitem__(self, key, parse_general_name(value))

    def append(self, o):
        list.append(self, parse_general_name(o))

    def count(self, value):
        try:
            value = parse_general_name(value)
        except ValueError:
            return 0

        return list.count(self, value)

    def extend(self, iterable):
        list.extend(self, (parse_general_name(i) for i in iterable))

    def index(self, value, *args):
        return list.index(self, parse_general_name(value), *args)

    def insert(self, index, o):
        list.insert(self, index, parse_general_name(o))

    def remove(self, value):
        list.remove(self, parse_general_name(value))


def get_crl_cache_key(serial, algorithm=hashes.SHA512, encoding=Encoding.DER, scope=None):
    """Function to get a cache key for a CRL with the given parameters."""

    return 'crl_%s_%s_%s_%s' % (serial, algorithm.name, encoding.name, scope)


ca_storage = get_storage_class(ca_settings.CA_FILE_STORAGE)(**ca_settings.CA_FILE_STORAGE_KWARGS)

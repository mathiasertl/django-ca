# -*- coding: utf-8 -*-
#
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

import os
import re
import shlex
from copy import deepcopy
from datetime import datetime
from datetime import timedelta
from ipaddress import ip_address
from ipaddress import ip_network

import idna

from asn1crypto.core import OctetString
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from django.conf import settings
from django.core.serializers.json import DjangoJSONEncoder
from django.core.validators import URLValidator
from django.utils import six
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.encoding import force_text
from django.utils.functional import Promise
from django.utils.translation import ugettext_lazy as _
from django.core.files.storage import default_storage

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
_datetime_format = '%Y%m%d%H%M%SZ'

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
}

# same, but reversed
NAME_OID_MAPPINGS = {v: k for k, v in OID_NAME_MAPPINGS.items()}

# Some OIDs can occur multiple times
MULTIPLE_OIDS = (
    NameOID.ORGANIZATIONAL_UNIT_NAME,
)

# uppercase values as keys for normalizing case
NAME_CASE_MAPPINGS = {v.upper(): v for v in OID_NAME_MAPPINGS.values()}


class LazyEncoder(DjangoJSONEncoder):
    """Encoder that also encodes strings translated with ugettext_lazy."""

    def default(self, obj):
        if isinstance(obj, Promise):
            return force_text(obj)
        return super(LazyEncoder, self).default(obj)


def sort_name(subject):
    """Returns the subject in the correct order for a x509 subject."""
    return sorted(subject, key=lambda e: SUBJECT_FIELDS.index(e[0]))


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

    return '/%s' % ('/'.join(['%s=%s' % (force_text(k), force_text(v)) for k, v in subject]))


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


def format_general_names(names):
    """Format a list of general names.

    >>> import ipaddress
    >>> format_general_names([x509.DNSName('example.com')])
    'DNS:example.com'
    >>> format_general_names([x509.IPAddress(ipaddress.IPv4Address('127.0.0.1'))])
    'IP:127.0.0.1'
    >>> format_general_names([x509.DirectoryName(
    ...     x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'example.com')]))])
    'dirname:/CN=example.com'
    >>> format_general_names([x509.DNSName('example.com'), x509.DNSName('example.net')])
    'DNS:example.com, DNS:example.net'
    """

    return ', '.join([format_general_name(n) for n in names])


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


def add_colons(s):
    """Add colons after every second digit.

    This function is used in functions to prettify serials.

    >>> add_colons('teststring')
    'te:st:st:ri:ng'
    """
    return ':'.join([s[i:i + 2] for i in range(0, len(s), 2)])


def int_to_hex(i):
    """Create a hex-representation of the given serial.

    >>> int_to_hex(12345678)
    'BC:61:4E'
    """
    s = hex(i)[2:].upper()
    if six.PY2 is True and isinstance(i, long):  # pragma: only py2  # NOQA
        # Strip the "L" suffix, since hex(1L) -> 0x1L.
        # NOTE: Do not convert to int earlier. int(<very-large-long>) is still long
        s = s[:-1]
    return add_colons(s)


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
        items = [(NAME_CASE_MAPPINGS[t[0].upper()], force_text(t[2])) for t in NAME_RE.findall(name)]
    except KeyError as e:
        raise ValueError('Unknown x509 name field: %s' % e.args[0])

    # Check that no OIDs not in MULTIPLE_OIDS occur more then once
    for key, oid in NAME_OID_MAPPINGS.items():
        if sum(1 for t in items if t[0] == key) > 1 and oid not in MULTIPLE_OIDS:
            raise ValueError('Subject contains multiple "%s" fields' % key)

    return sort_name(items)


def x509_name(name):
    """Parses a subject into a :py:class:`x509.Name <cg:cryptography.x509.Name>`.

    If ``name`` is a string, :py:func:`parse_name` is used to parse it.

    >>> x509_name('/C=AT/CN=example.com')  # doctest: +NORMALIZE_WHITESPACE
    <Name([<NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.6, name=countryName)>, value='AT')>,
           <NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.3, name=commonName)>, value='example.com')>])>
    >>> x509_name([('C', 'AT'), ('CN', 'example.com')])  # doctest: +NORMALIZE_WHITESPACE
    <Name([<NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.6, name=countryName)>, value='AT')>,
           <NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.3, name=commonName)>, value='example.com')>])>
    """
    if isinstance(name, six.string_types):
        name = parse_name(name)

    return x509.Name([x509.NameAttribute(NAME_OID_MAPPINGS[typ], force_text(value)) for typ, value in name])


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

    node, domain = addr.split('@', 1)
    try:
        domain = idna.encode(force_text(domain))
    except idna.core.IDNAError:
        raise ValueError('Invalid domain: %s' % domain)

    return '%s@%s' % (node, force_text(domain))


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
    >>> parse_general_name('/CN=example.com')  # doctest: +NORMALIZE_WHITESPACE
    <DirectoryName(value=<Name([<NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.3, name=commonName)>,
                                               value='example.com')>])>)>

    The default fallback is to assume a :py:class:`~cg:cryptography.x509.DNSName`. If this doesn't
    work, an exception will be raised:

    >>> parse_general_name('foo..bar`*123')  # doctest: +ELLIPSIS
    Traceback (most recent call last):
        ...
    idna.core.IDNAError: ...

    If you want to override detection, you can prefix the name to match :py:const:`GENERAL_NAME_RE`:

    >>> parse_general_name('email:user@example.com')
    <RFC822Name(value='user@example.com')>
    >>> parse_general_name('URI:https://example.com')
    <UniformResourceIdentifier(value='https://example.com')>
    >>> parse_general_name('dirname:/CN=example.com')  # doctest: +NORMALIZE_WHITESPACE
    <DirectoryName(value=<Name([<NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.3, name=commonName)>,
                                               value='example.com')>])>)>

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
    name = force_text(name)
    typ = None
    match = GENERAL_NAME_RE.match(name)
    if match is not None:
        typ, name = match.groups()
        typ = typ.lower()

    if typ is None:
        if re.match('[a-z0-9]{2,}://', name):  # Looks like a URI
            try:
                return x509.UniformResourceIdentifier(name)
            except Exception:  # pragma: no cover - this really accepts anything
                pass

        if '@' in name:  # Looks like an Email address
            try:
                return x509.RFC822Name(validate_email(name))
            except Exception:
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

        # Try to encode as domain name. DNSName() does not validate the domain name, but this check will fail.
        if name.startswith('*.'):
            idna.encode(name[2:])
        elif name.startswith('.'):
            idna.encode(name[1:])
        else:
            idna.encode(name)

        # Almost anything passes as DNS name, so this is our default fallback
        return x509.DNSName(name)

    if typ == 'uri':
        return x509.UniformResourceIdentifier(name)
    elif typ == 'email':
        return x509.RFC822Name(validate_email(name))
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
        else:
            raise ValueError('Incorrect otherName format: %s' % name)
    elif typ == 'dirname':
        return x509.DirectoryName(x509_name(name))
    else:
        # Try to encode the domain name. DNSName() does not validate the domain name, but this
        # check will fail.
        if name.startswith('*.'):
            idna.encode(name[2:])
        elif name.startswith('.'):
            idna.encode(name[1:])
        else:
            idna.encode(name)

        return x509.DNSName(name)


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
    elif isinstance(value, type) and issubclass(value, hashes.HashAlgorithm):
        return value()
    elif isinstance(value, hashes.HashAlgorithm):
        return value
    elif isinstance(value, six.string_types):
        try:
            return getattr(hashes, value.strip())()
        except AttributeError:
            raise ValueError('Unknown hash algorithm: %s' % value)
    else:
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


def get_expires(value=None, now=None):
    if now is None:
        now = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    if value is None:
        value = ca_settings.CA_DEFAULT_EXPIRES

    # If USE_TZ is True, we make the object timezone aware, otherwise comparing goes wrong.
    if settings.USE_TZ:
        now = timezone.make_aware(now)

    return now + timedelta(days=value + 1)


def get_cert_builder(expires):
    """Get a basic X509 cert builder object.

    Parameters
    ----------

    expires : datetime
        When this certificate will expire.
    """
    now = datetime.utcnow().replace(second=0, microsecond=0)

    if expires is None:
        expires = get_expires(expires, now=now)
    expires = expires.replace(second=0, microsecond=0)

    builder = x509.CertificateBuilder()
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(expires)
    builder = builder.serial_number(x509.random_serial_number())

    return builder


def get_default_subject(name):
    """Get the default subject for the given profile."""

    profile = deepcopy(ca_settings.CA_PROFILES[name])
    return profile['subject']


if six.PY2:  # pragma: only py2
    class PermissionError(IOError, OSError):
        pass


def write_private_file(path, data):
    """Function to write binary data to a file that will only be readable to the user."""

    try:
        with default_storage.open(path, 'wb') as fh:
        #os.fdopen(os.open(path, os.O_CREAT | os.O_WRONLY, 0o400), 'wb') as fh:
            fh.write(data)
        try:
            os.chmod(default_storage.path(path), 0o400)
        except NotImplementedError:
            # If file is not stored in the filesystem, this will fail
            pass
    except PermissionError:  # pragma: only py3
        # In py3, we want to raise Exception unchanged, so there would be no need for this block.
        # BUT (IOError, OSError) - see below - also matches, so we capture it here
        raise
    except (IOError, OSError) as e:  # pragma: only py2
        raise PermissionError(e.errno)


def shlex_split(s, sep):
    """Split a character on the given set of characters.

    Example::

        >>> shlex_split('foo,bar', ', ')
        ['foo', 'bar']
        >>> shlex_split("foo\\\,bar1", ',')  # escape a separator
        ['foo,bar1']
        >>> shlex_split('"foo,bar", bla', ', ')
        ['foo,bar', 'bla']
        >>> shlex_split('foo,"bar bla"', ',')
        ['foo', 'bar bla']
    """  # NOQA - flake8 complains about the backslash-escape in the doctest otherwise
    lex = shlex.shlex(s, posix=True)
    lex.whitespace = sep
    lex.whitespace_split = True
    return [l for l in lex]

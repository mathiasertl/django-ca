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

import re
from collections import Iterable
from collections import OrderedDict
from copy import deepcopy
from datetime import datetime
from ipaddress import ip_address
from ipaddress import ip_network

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.oid import NameOID

from django.core.serializers.json import DjangoJSONEncoder
from django.core.validators import URLValidator
from django.utils import six
from django.utils.encoding import force_bytes
from django.utils.encoding import force_text
from django.utils.functional import Promise
from django.utils.translation import ugettext_lazy as _

from django_ca import ca_settings

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

# uppercase values as keys for normalizing case
NAME_CASE_MAPPINGS = {v.upper(): v for v in OID_NAME_MAPPINGS.values()}

KEY_USAGE_MAPPING = {
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


EXTENDED_KEY_USAGE_MAPPING = {
    'serverAuth': ExtendedKeyUsageOID.SERVER_AUTH,
    'clientAuth': ExtendedKeyUsageOID.CLIENT_AUTH,
    'codeSigning': ExtendedKeyUsageOID.CODE_SIGNING,
    'emailProtection': ExtendedKeyUsageOID.EMAIL_PROTECTION,
    'timeStamping': ExtendedKeyUsageOID.TIME_STAMPING,
    'OCSPSigning': ExtendedKeyUsageOID.OCSP_SIGNING,
}
EXTENDED_KEY_USAGE_REVERSED = {v: k for k, v in EXTENDED_KEY_USAGE_MAPPING.items()}


class LazyEncoder(DjangoJSONEncoder):
    """Encoder that also encodes strings translated with ugettext_lazy."""

    def default(self, obj):
        if isinstance(obj, Promise):
            return force_text(obj)
        return super(LazyEncoder, self).default(obj)


def sort_subject_dict(d):
    """Returns an itemized dictionary in the correct order for a x509 subject."""
    return sorted(d.items(), key=lambda e: SUBJECT_FIELDS.index(e[0]))


def format_name(subject):
    """Convert a subject into the canonical form for distinguished names.

    Examples::

        >>> format_name([('CN', 'example.com'), ])
        '/CN=example.com'
    """
    if isinstance(subject, x509.Name):
        subject = [(OID_NAME_MAPPINGS[s.oid], s.value) for s in subject]

    return '/%s' % ('/'.join(['%s=%s' % (force_text(k), force_text(v)) for k, v in subject]))


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

    formatted = []

    for name in names:
        if isinstance(name, x509.DirectoryName):
            value = format_name(name.value)
        else:
            value = name.value

        formatted.append('%s:%s' % (SAN_NAME_MAPPINGS[type(name)], value))

    return ', '.join(formatted)


def is_power2(num):
    """Return True if num is a power of 2.

    >>> is_power2(4)
    True
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
    return ':'.join(a + b for a, b in zip(s[::2], s[1::2]))


def int_to_hex(i):
    """Create a hex-representation of the given serial.

    >>> int_to_hex(123456789)
    '75:BC:D1'
    """
    s = hex(i)[2:].upper()
    return add_colons(s)


def parse_name(name):
    """Parses a subject string as used in OpenSSLs command line utilities.

    The ``name`` is expected to be close to the subject format commonly used by OpenSSL, for example
    ``/C=AT/L=Vienna/CN=example.com/emailAddress=user@example.com``. The function does its best to be lenient
    on deviations from the format, object identifiers are case-insensitive (e.g. ``cn`` is the same as ``CN``,
    whitespace at the start and end is stripped and the subject does not have to start with a slash (``/``).

    >>> parse_name('/CN=example.com')
    OrderedDict([('CN', 'example.com')])
    >>> parse_name('c=AT/l= Vienna/o="ex org"/CN=example.com')
    OrderedDict([('C', 'AT'), ('L', 'Vienna'), ('O', 'ex org'), ('CN', 'example.com')])

    Dictionary keys are normalized to the values of :py:const:`OID_NAME_MAPPINGS` and keys will be sorted
    based on x509 name specifications regardless of the given order:

    >>> parse_name('L="Vienna / District"/EMAILaddress=user@example.com')
    OrderedDict([('L', 'Vienna / District'), ('emailAddress', 'user@example.com')])
    >>> parse_name('/C=AT/CN=example.com') == parse_name('/CN=example.com/C=AT')
    True

    Due to the magic of :py:const:`NAME_RE`, the function even supports quoting strings and including slashes,
    so strings like ``/OU="Org / Org Unit"/CN=example.com`` will work as expected.

    >>> parse_name('L="Vienna / District"/CN=example.com')
    OrderedDict([('L', 'Vienna / District'), ('CN', 'example.com')])

    But note that it's still easy to trick this function, if you really want to. The following example is
    *not* a valid subject, the location is just bogus, and whatever you were expecting as output, it's
    certainly different:

    >>> parse_name('L="Vienna " District"/CN=example.com')
    OrderedDict([('L', 'Vienna'), ('CN', 'example.com')])

    Examples of where this string is used are:

    .. code-block:: console

        # openssl req -new -key priv.key -out csr -utf8 -batch -sha256 -subj '/C=AT/CN=example.com'
        # openssl x509 -in cert.pem -noout -subject -nameopt compat
        /C=AT/L=Vienna/CN=example.com
    """
    name = name.strip()
    if not name:  # empty subjects are ok
        return {}

    try:
        items = [(NAME_CASE_MAPPINGS[t[0].upper()], force_text(t[2])) for t in NAME_RE.findall(name)]
    except KeyError as e:
        raise ValueError('Unknown x509 name field: %s' % e.args[0])

    parsed = sorted(items, key=lambda e: SUBJECT_FIELDS.index(e[0]))
    return OrderedDict(parsed)


def x509_name(name):
    """Parses a subject string into a :py:class:`x509.Name <cryptography:cryptography.x509.Name>`.

    If ``name`` is a string, :py:func:`parse_name` is used to parse it. A list of tuples or a ``dict``
    (preferrably an :py:class:`~python:collections.OrderedDict`) is also supported.

    >>> x509_name('/C=AT/CN=example.com')  # doctest: +NORMALIZE_WHITESPACE
    <Name([<NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.6, name=countryName)>, value='AT')>,
           <NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.3, name=commonName)>, value='example.com')>])>
    >>> x509_name([('C', 'AT'), ('CN', 'example.com')])  # doctest: +NORMALIZE_WHITESPACE
    <Name([<NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.6, name=countryName)>, value='AT')>,
           <NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.3, name=commonName)>, value='example.com')>])>
    >>> x509_name(OrderedDict([('C', 'AT'), ('CN', 'example.com')]))  # doctest: +NORMALIZE_WHITESPACE
    <Name([<NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.6, name=countryName)>, value='AT')>,
           <NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.3, name=commonName)>, value='example.com')>])>
    >>> x509_name(OrderedDict([('C', 'AT'), ('CN', 'example.com')]))  # doctest: +NORMALIZE_WHITESPACE
    <Name([<NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.6, name=countryName)>, value='AT')>,
           <NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.3, name=commonName)>, value='example.com')>])>
    """
    if isinstance(name, six.string_types):
        name = parse_name(name).items()
    elif isinstance(name, OrderedDict):
        name = name.items()
    elif isinstance(name, dict):
        name = sort_subject_dict(name)

    return x509.Name([x509.NameAttribute(NAME_OID_MAPPINGS[typ], force_text(value)) for typ, value in name])


def parse_general_name(name):
    """Parse a general name from user input.

    This function will do its best to detect the intended type of any value passed to it:

    >>> parse_general_name('example.com')
    <DNSName(value=example.com)>
    >>> parse_general_name('user@example.com')
    <RFC822Name(value=user@example.com)>
    >>> parse_general_name('https://example.com')
    <UniformResourceIdentifier(value=https://example.com)>
    >>> parse_general_name('1.2.3.4')
    <IPAddress(value=1.2.3.4)>
    >>> parse_general_name('/CN=example.com')  # doctest: +NORMALIZE_WHITESPACE
    <DirectoryName(value=<Name([<NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.3, name=commonName)>,
                                               value='example.com')>])>)>

    The default fallback is to assume a :py:class:`~cryptography:cryptography.x509.DNSName`. This isn't
    terribly safe, as almost anything passes:

    >>> parse_general_name('foo..bar`*123')
    <DNSName(value=foo..bar`*123)>

    If you want to override detection, you can prefix the name to match :py:const:`GENERAL_NAME_RE`:

    >>> parse_general_name('email:user@example.com')
    <RFC822Name(value=user@example.com)>
    >>> parse_general_name('URI:https://example.com')
    <UniformResourceIdentifier(value=https://example.com)>
    >>> parse_general_name('dirname:/CN=example.com')  # doctest: +NORMALIZE_WHITESPACE
    <DirectoryName(value=<Name([<NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.3, name=commonName)>,
                                               value='example.com')>])>)>

    Some more exotic values can only be generated by using this prefix:

    >>> parse_general_name('rid:2.5.4.3')
    <RegisteredID(value=<ObjectIdentifier(oid=2.5.4.3, name=commonName)>)>
    >>> parse_general_name('otherName:2.5.4.3,example.com')
    <OtherName(type_id=<ObjectIdentifier(oid=2.5.4.3, name=commonName)>, value=b'example.com')>

    If you give a prefixed value, this function is less forgiving of any typos and does not catch any
    exceptions:

    >>> parse_general_name('foo@')
    <DNSName(value=foo@)>
    >>> parse_general_name('email:foo@')
    Traceback (most recent call last):
        ...
    idna.core.IDNAError: Empty domain
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
            except:  # pragma: no cover - this really accepts anything
                pass

        if '@' in name:  # Looks like an Email address
            try:
                return x509.RFC822Name(name)
            except:
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
        return x509.DNSName(name)

    if typ == 'uri':
        return x509.UniformResourceIdentifier(name)
    elif typ == 'email':
        return x509.RFC822Name(name)
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
        type_id, value = name.split(',', 1)
        type_id = x509.ObjectIdentifier(type_id)
        value = force_bytes(value)
        return x509.OtherName(type_id, value)
    elif typ == 'dirname':
        return x509.DirectoryName(x509_name(name))
    else:
        return x509.DNSName(name)


def get_cert_builder(expires, now=None):
    """Get a basic X509 cert object.

    Parameters
    ----------

    expires : datetime
        When this certificate will expire.
    """
    if now is None:
        now = datetime.utcnow()
    now = now.replace(second=0, microsecond=0)
    expires = expires.replace(second=0, microsecond=0)

    builder = x509.CertificateBuilder()
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(expires)
    builder = builder.serial_number(x509.random_serial_number())

    return builder


def get_cert_profile_kwargs(name=None):
    """Get kwargs suitable for get_cert X509 keyword arguments from the given profile."""

    if name is None:
        name = ca_settings.CA_DEFAULT_PROFILE

    profile = deepcopy(ca_settings.CA_PROFILES[name])
    kwargs = {
        'cn_in_san': profile['cn_in_san'],
        'subject': OrderedDict(sort_subject_dict(profile['subject'])),
    }
    for arg in ['keyUsage', 'extendedKeyUsage']:
        config = profile.get(arg)
        if config is None or not config.get('value'):
            continue

        critical = config.get('critical', 'True')
        value = config['value']
        if isinstance(value, six.string_types):
            kwargs[arg] = (critical, value)
        elif isinstance(value, Iterable):
            kwargs[arg] = (critical, ','.join([force_text(v) for v in value]))
        else:  # pragma: no cover
            kwargs[arg] = (critical, force_text(value))
    return kwargs

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

from __future__ import unicode_literals

import binascii
import re
import textwrap

import six

from cryptography import x509
from cryptography.x509 import TLSFeatureType
from cryptography.x509.certificate_transparency import LogEntryType
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.oid import ObjectIdentifier

from django.utils.encoding import force_text

from . import ca_settings
from .utils import bytes_to_hex
from .utils import format_general_name
from .utils import format_relative_name
from .utils import get_extension_name
from .utils import hex_to_bytes
from .utils import indent
from .utils import parse_general_name
from .utils import shlex_split
from .utils import x509_relative_name


@six.python_2_unicode_compatible
class Extension(object):
    """Convenience class to handle X509 Extensions.

    The class is designed to take whatever format an extension might occur, essentially providing a
    convertible format for extensions that is used in many places throughout the code. It accepts ``str`` if
    e.g. the value was received from the commandline::

        >>> KeyUsage('keyAgreement,keyEncipherment')
        <KeyUsage: ['keyAgreement', 'keyEncipherment'], critical=False>
        >>> KeyUsage('critical,keyAgreement,keyEncipherment')
        <KeyUsage: ['keyAgreement', 'keyEncipherment'], critical=True>

    Or it can be a ``dict`` as used by the :ref:`CA_PROFILES <settings-ca-profiles>` setting::

        >>> KeyUsage({'value': ['keyAgreement', 'keyEncipherment']})
        <KeyUsage: ['keyAgreement', 'keyEncipherment'], critical=False>
        >>> KeyUsage({'critical': True, 'value': ['keyAgreement', 'keyEncipherment']})
        <KeyUsage: ['keyAgreement', 'keyEncipherment'], critical=True>

    ... and finally it can also use a subclass of :py:class:`~cg:cryptography.x509.ExtensionType`
    from ``cryptography``::

        >>> from cryptography import x509
        >>> ExtendedKeyUsage(x509.extensions.Extension(
        ...    oid=ExtensionOID.EXTENDED_KEY_USAGE,
        ...    critical=False,
        ...    value=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
        ... ))
        <ExtendedKeyUsage: ['serverAuth'], critical=False>

    Attributes
    ----------

    name
    value
        Raw value for this extension. The type various from subclass to subclass.

    Parameters
    ----------

    value : list or tuple or dict or str or :py:class:`~cg:cryptography.x509.ExtensionType`
        The value of the extension, the description provides further details.
    """
    oid = None  # must be overwritten by base class
    default_critical = False

    def __init__(self, value):
        if isinstance(value, x509.extensions.Extension):  # e.g. from a cert object
            self.critical = value.critical
            self.from_extension(value)
        elif isinstance(value, dict):  # e.g. from settings
            self.critical = value.get('critical', self.default_critical)
            self.from_dict(value)
            self._test_value()
        elif isinstance(value, six.string_types):  # e.g. from commandline parser
            if value.startswith(str('critical,')):
                self.critical = True
                value = value[9:]
            else:
                self.critical = False
                value = value

            self.from_str(value)
            self._test_value()
        else:
            self.from_other(value)
        if not isinstance(self.critical, bool):
            raise ValueError('%s: Invalid critical value passed' % self.critical)

    def __hash__(self):
        return hash((self.__class__, self.value, self.critical, ))

    def __eq__(self, other):
        return isinstance(other, type(self)) and self.critical == other.critical and self.value == other.value

    def __repr__(self):
        return '<%s: %s, critical=%r>' % (self.__class__.__name__, self.value, self.critical)

    def __str__(self):
        if self.critical:
            return'%s/critical' % self.as_text()
        return self.as_text()

    def from_extension(self, value):
        raise NotImplementedError

    def from_str(self, value):
        self.value = value

    def from_dict(self, value):
        self.value = value['value']

    def from_other(self, value):
        raise ValueError('Value is of unsupported type %s' % type(value).__name__)

    def _test_value(self):
        pass

    @property
    def name(self):
        """A human readable name of this extension."""
        return get_extension_name(self)

    @property
    def extension_type(self):
        """The extension_type for this value."""

        raise NotImplementedError

    def serialize(self):
        """Serialize this extension to a string in a way that it can be passed to a constructor again.

        For example, this should always be True::

            >>> ku = KeyUsage('keyAgreement,keyEncipherment')
            >>> ku == KeyUsage(ku.serialize())
            True
        """

        return {
            'critical': self.critical,
            'value': self.value,
        }

    def as_extension(self):
        """This extension as :py:class:`~cg:cryptography.x509.ExtensionType`."""
        return x509.extensions.Extension(oid=self.oid, critical=self.critical, value=self.extension_type)

    def as_text(self):
        """Human-readable version of the *value*, not including the "critical" flag."""
        return self.value

    def for_builder(self):
        """Return kwargs suitable for a :py:class:`~cg:cryptography.x509.CertificateBuilder`.

        Example::

            >>> kwargs = KeyUsage('keyAgreement,keyEncipherment').for_builder()
            >>> builder.add_extension(**kwargs)  # doctest: +SKIP
        """
        return {'extension': self.extension_type, 'critical': self.critical}


class UnrecognizedExtension(Extension):
    def __init__(self, value, name='', error=''):
        self._error = error
        self._name = name
        super(UnrecognizedExtension, self).__init__(value)

    def from_extension(self, value):
        self.value = value

    @property
    def name(self):
        if self._name:
            return self._name
        return 'Unsupported extension (OID %s)' % (self.value.oid.dotted_string)

    def as_text(self):
        if self._error:
            return 'Could not parse extension (%s)' % self._error
        return 'Could not parse extension'


class NullExtension(Extension):
    """Base class for extensions that have a NULL value.

    Extensions using this base class do not accept a ``str`` as value:

        >>> OCSPNoCheck()
        <OCSPNoCheck: critical=False>
        >>> OCSPNoCheck({'critical': True})
        <OCSPNoCheck: critical=True>
        >>> OCSPNoCheck({'critical': True})
        <OCSPNoCheck: critical=True>
        >>> OCSPNoCheck(x509.extensions.Extension(oid=ExtensionOID.OCSP_NO_CHECK, critical=True, value=None))
        <OCSPNoCheck: critical=True>
    """

    def __init__(self, value=None):
        if not value:
            self.critical = self.default_critical
        else:
            super(NullExtension, self).__init__(value)

    def __hash__(self):
        return hash((self.__class__, self.critical, ))

    def __eq__(self, other):
        return isinstance(other, type(self)) and self.critical == other.critical

    def __repr__(self):
        return '<%s: critical=%r>' % (self.__class__.__name__, self.critical)

    def __str__(self):
        if self.critical:
            return'%s/critical' % self.as_text()
        return self.as_text()

    def as_text(self):
        return self.__class__.__name__

    @property
    def extension_type(self):
        return self.ext_class()

    def from_extension(self, value):
        pass

    def from_dict(self, value):
        pass

    def from_str(self, value):
        raise NotImplementedError

    def serialize(self):
        return {'critical': self.critical}


class ListExtension(Extension):
    """Base class for extensions with multiple ordered values.

    Subclasses behave like a list, and you can also pass a list of values to the constructor:

        >>> san = SubjectAlternativeName(['example.com', 'example.net'])
        >>> san[0]
        'DNS:example.com'

    If the passed value is a list, the critical flag will be set according the the default value
    for this extension.
    """

    def __contains__(self, value):
        return self.parse_value(value) in self.value

    def __delitem__(self, key):
        del self.value[key]

    def __eq__(self, other):
        return isinstance(other, type(self)) and self.critical == other.critical and self.value == other.value

    def __getitem__(self, key):
        if isinstance(key, six.integer_types):
            return self.serialize_value(self.value[key])
        else:
            return [self.serialize_value(v) for v in self.value[key]]

    def __hash__(self):
        return hash((self.__class__, tuple(self.value), self.critical, ))

    def __len__(self):
        return len(self.value)

    def __repr__(self):
        val = [self.serialize_value(v) for v in self.value]

        if six.PY2:  # pragma: no branch, pragma: only py2 - otherwise we have the u'' prefix in output
            val = [str(v) for v in val]

        return '<%s: %r, critical=%r>' % (self.__class__.__name__, val, self.critical)

    def __setitem__(self, key, value):
        if isinstance(key, six.integer_types):
            self.value[key] = self.parse_value(value)
        else:
            self.value[key] = [self.parse_value(v) for v in value]

    def __str__(self):
        val = "%s" % ','.join([self.serialize_value(v) for v in self.value])
        if self.critical:
            return '%s/critical' % val
        return val

    def append(self, value):
        self.value.append(self.parse_value(value))
        self._test_value()

    def clear(self):
        if six.PY2:  # pragma: only py2
            self.value = []
        else:  # pragma: only py3
            self.value.clear()

    def count(self, value):
        try:
            return self.value.count(self.parse_value(value))
        except ValueError:
            return 0

    def extend(self, iterable):
        self.value.extend([self.parse_value(n) for n in iterable])
        self._test_value()

    def from_dict(self, value):
        value = value.get('value')
        if not value:
            self.value = []
            return
        elif isinstance(value, x509.GeneralName) or isinstance(value, six.string_types):
            value = [value]

        self.value = [self.parse_value(v) for v in value]

    def from_extension(self, ext):
        self.value = list(ext.value)

    def from_list(self, value):
        self.value = [self.parse_value(n) for n in value]

    def from_other(self, value):
        if isinstance(value, (list, tuple)):
            self.critical = self.default_critical
            self.from_list(value)
            self._test_value()
        else:
            super(ListExtension, self).from_other(value)

    def from_str(self, value):
        self.value = [self.parse_value(n) for n in shlex_split(value, ', ')]

    def insert(self, index, value):
        self.value.insert(index, self.parse_value(value))

    def parse_value(self, v):
        return v

    def pop(self, index=-1):
        return self.serialize_value(self.value.pop(index))

    def remove(self, v):
        return self.value.remove(self.parse_value(v))

    def serialize(self):
        return {
            'critical': self.critical,
            'value': [self.serialize_value(v) for v in self.value],
        }

    def serialize_value(self, v):
        return v

    def as_text(self):
        return '\n'.join(['* %s' % self.serialize_value(v) for v in self.value])


class KnownValuesExtension(ListExtension):
    """A generic base class for extensions with multiple values with a set of pre-defined valid values.

    This base class is for extensions where we *know* what potential values an extension can have. For
    example, the :py:class:`~django_ca.extensions.KeyUsage` extension has only a certain set of valid values::

        >>> KeyUsage(['keyAgreement', 'keyEncipherment'])
        <KeyUsage: ['keyAgreement', 'keyEncipherment'], critical=False>
        >>> KeyUsage(['wrong-value'])
        Traceback (most recent call last):
            ...
        ValueError: Unknown value(s): wrong-value

    Known values are set in the ``KNOWN_VALUES`` attribute for each class. The constructor will raise
    ``ValueError`` if an unknown value is passed.
    """
    KNOWN_VALUES = set()

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False
        this = list(sorted(self.value))
        that = list(sorted(other.value))
        return isinstance(other, type(self)) and self.critical == other.critical and this == that

    def __hash__(self):
        return hash((self.__class__, tuple(sorted(self.value)), self.critical, ))

    def __repr__(self):
        val = sorted([self.serialize_value(v) for v in self.value])

        if six.PY2:  # pragma: no branch, pragma: only py2 - otherwise we have the u'' prefix in output
            val = [str(v) for v in val]

        return '<%s: %r, critical=%r>' % (self.__class__.__name__, val, self.critical)

    def __str__(self):
        val = "%s" % ','.join(sorted([self.serialize_value(v) for v in self.value]))
        if self.critical:
            return '%s/critical' % val
        return val

    def count(self, value):
        value = self.parse_value(value)
        if value not in self.KNOWN_VALUES:
            raise ValueError('Unknown value: %s' % value)
        return self.value.count(value)

    def _test_value(self):
        diff = set(self.value) - self.KNOWN_VALUES
        if diff:
            raise ValueError('Unknown value(s): %s' % ', '.join(sorted(diff)))


class GeneralNameMixin(object):
    """Mixin to internally store values as ``GeneralName`` instances.

    This mixin ensures that values passed as :py:class:`~cg:cryptography.x509.GeneralName` instances will
    never get parsed. This is useful because there are some instances where names may not be parsed reliably.
    This means that the DNS name here is never converted between the instantiation here and actually adding
    the extension to the certificate::

        >>> san = SubjectAlternativeName([x509.DNSName('example.com')])
        >>> Certificate.objects.init(subjectAltName=...)  # doctest: +SKIP
    """

    def parse_value(self, v):
        if isinstance(v, x509.GeneralName):
            return v
        else:
            return parse_general_name(v)

    def serialize_value(self, v):
        return format_general_name(v)


class AlternativeNameExtension(GeneralNameMixin, ListExtension):
    """Base class for extensions that contain a list of general names.

    This class also allows you to pass :py:class:`~cg:cryptography.x509.GeneralName` instances::

        >>> san = SubjectAlternativeName([x509.DNSName('example.com'), 'example.net'])
        >>> san
        <SubjectAlternativeName: ['DNS:example.com', 'DNS:example.net'], critical=False>
        >>> 'example.com' in san, 'DNS:example.com' in san, x509.DNSName('example.com') in san
        (True, True, True)

    """
    pass


class KeyIdExtension(Extension):
    """Base class for extensions that contain a KeyID as value.

    .. TODO::

        * All subclasses are only instantiated from a cryptography extension, so other values don't work.
    """

    def from_bytes(self, value):  # pragma: only py3
        self.value = value

    def from_dict(self, value):
        self.value = hex_to_bytes(value['value'])

    def from_other(self, value):
        if six.PY3 and isinstance(value, bytes):  # pragma: only py3
            self.critical = self.default_critical
            self.from_bytes(value)
            self._test_value()
        else:
            super(KeyIdExtension, self).from_other(value)

    def from_str(self, value):
        self.value = hex_to_bytes(value)

    def as_text(self):
        return bytes_to_hex(self.value)

    def serialize(self):
        return {
            'critical': self.critical,
            'value': bytes_to_hex(self.value),
        }


class DistributionPoint(GeneralNameMixin):
    """Class representing a Distribution Point.

    This class is used internally by extensions that have a list of Distribution Points, e.g. the :
    :py:class:`~django_ca.extensions.CRLDistributionPoints` extension. The class accepts either a
    :py:class:`cg:cryptography.x509.DistributionPoint` or a ``dict``. Note that in the latter case, you can
    also pass a ``str`` as ``full_name`` or ``crl_issuer`` if there is only one value::

        >>> DistributionPoint(x509.DistributionPoint(
        ...     full_name=[x509.UniformResourceIdentifier('http://ca.example.com/crl')],
        ...     relative_name=None, crl_issuer=None, reasons=None
        ... ))
        <DistributionPoint: full_name=['URI:http://ca.example.com/crl']>
        >>> DistributionPoint({'full_name': ['http://example.com']})
        <DistributionPoint: full_name=['URI:http://example.com']>
        >>> DistributionPoint({'full_name': 'http://example.com'})
        <DistributionPoint: full_name=['URI:http://example.com']>
        >>> DistributionPoint({
        ...     'relative_name': '/CN=example.com',
        ...     'crl_issuer': 'http://example.com',
        ...     'reasons': ['key_compromise', 'ca_compromise'],
        ... })  # doctest: +NORMALIZE_WHITESPACE
        <DistributionPoint: relative_name='/CN=example.com', crl_issuer=['URI:http://example.com'],
                            reasons=['ca_compromise', 'key_compromise']>

    .. seealso::

        `RFC 5280, section 4.2.1.13 <https://tools.ietf.org/html/rfc5280#section-4.2.1.13>`_
    """

    full_name = None
    relative_name = None
    crl_issuer = None
    reasons = None

    def __init__(self, data=None):
        if isinstance(data, x509.DistributionPoint):
            self.full_name = data.full_name
            self.relative_name = data.relative_name
            self.crl_issuer = data.crl_issuer
            self.reasons = data.reasons
        elif isinstance(data, dict):
            self.full_name = data.get('full_name')
            self.relative_name = data.get('relative_name')
            self.crl_issuer = data.get('crl_issuer')
            self.reasons = data.get('reasons')

            if self.full_name is not None and self.relative_name is not None:
                raise ValueError('full_name and relative_name cannot both have a value')

            if self.full_name is not None:
                if isinstance(self.full_name, six.string_types):
                    self.full_name = [self.parse_value(self.full_name)]
                else:
                    self.full_name = [self.parse_value(v) for v in self.full_name]
            if self.relative_name is not None:
                self.relative_name = x509_relative_name(self.relative_name)
            if self.crl_issuer is not None:
                if isinstance(self.crl_issuer, six.string_types):
                    self.crl_issuer = [self.parse_value(self.crl_issuer)]
                else:
                    self.crl_issuer = [self.parse_value(v) for v in self.crl_issuer]
            if self.reasons is not None:
                self.reasons = frozenset([x509.ReasonFlags[r] for r in self.reasons])
        else:
            raise ValueError('data must be x509.DistributionPoint or dict')

    def __eq__(self, other):
        return isinstance(other, DistributionPoint) and self.full_name == other.full_name \
            and self.relative_name == other.relative_name and self.crl_issuer == other.crl_issuer \
            and self.reasons == other.reasons

    def __get_values(self):
        values = []
        if self.full_name:
            values.append('full_name=%s' % [self.serialize_value(n) for n in self.full_name])
        if self.relative_name:
            values.append("relative_name='%s'" % format_relative_name(self.relative_name))
        if self.crl_issuer:
            values.append('crl_issuer=%s' % [self.serialize_value(n) for n in self.crl_issuer])
        if self.reasons:
            values.append('reasons=%s' % sorted([r.name for r in self.reasons]))
        return values

    def __hash__(self):
        full_name = tuple(self.full_name) if self.full_name else None
        crl_issuer = tuple(self.crl_issuer) if self.crl_issuer else None
        reasons = tuple(self.reasons) if self.reasons else None
        return hash((self.__class__, full_name, self.relative_name, crl_issuer, reasons))

    def __repr__(self):
        return '<DistributionPoint: %s>' % ', '.join(self.__get_values())

    def __str__(self):
        return 'DistributionPoint(%s)' % ', '.join(self.__get_values())

    def as_text(self):
        if self.full_name:
            names = [indent('* %s' % self.serialize_value(n), '  ') for n in self.full_name]
            text = '* Full Name:\n%s' % '\n'.join(names)
        else:
            text = '* Relative Name: %s' % format_relative_name(self.relative_name)

        if self.crl_issuer:
            names = [indent('* %s' % self.serialize_value(n), '  ') for n in self.crl_issuer]
            text += '\n* CRL Issuer:\n%s' % '\n'.join(names)
        if self.reasons:
            text += '\n* Reasons: %s' % ', '.join(sorted([r.name for r in self.reasons]))
        return text

    @property
    def for_extension_type(self):
        return x509.DistributionPoint(full_name=self.full_name, relative_name=self.relative_name,
                                      crl_issuer=self.crl_issuer, reasons=self.reasons)

    def serialize(self):
        s = {}

        if self.full_name is not None:
            s['full_name'] = [self.serialize_value(n) for n in self.full_name]
        if self.relative_name is not None:
            s['relative_name'] = format_relative_name(self.relative_name)
        if self.crl_issuer is not None:
            s['crl_issuer'] = [self.serialize_value(n) for n in self.crl_issuer]
        if self.reasons is not None:
            s['reasons'] = list(sorted([r.name for r in self.reasons]))
        return s


class PolicyInformation(object):
    def __init__(self, data=None):
        if isinstance(data, x509.PolicyInformation):
            self.policy_identifier = data.policy_identifier
            self.policy_qualifiers = data.policy_qualifiers
        elif isinstance(data, dict):
            self.policy_identifier = data['policy_identifier']
            self.policy_qualifiers = self.parse_policy_qualifiers(data.get('policy_qualifiers'))
        elif data is None:
            self.policy_identifier = None
            self.policy_qualifiers = None
        else:
            raise ValueError('PolicyInformation data must be either x509.PolicyInformation or dict')

    def __contains__(self, value):
        if self.policy_qualifiers is None:
            return False
        return self.parse_policy_qualifier(value) in self.policy_qualifiers

    def __delitem__(self, key):
        if self.policy_qualifiers is None:
            raise IndexError('list assignment index out of range')
        del self.policy_qualifiers[key]
        if not self.policy_qualifiers:
            self.policy_qualifiers = None

    def __eq__(self, other):
        return isinstance(other, PolicyInformation) and self.policy_identifier == other.policy_identifier \
            and self.policy_qualifiers == other.policy_qualifiers

    def __getitem__(self, key):
        if self.policy_qualifiers is None:
            raise IndexError('list index out of range')
        elif isinstance(key, six.integer_types):
            return self.serialize_policy_qualifier(self.policy_qualifiers[key])
        else:
            return [self.serialize_policy_qualifier(k) for k in self.policy_qualifiers[key]]

    def __hash__(self):
        if self.policy_qualifiers is None:
            t = None
        else:
            t = tuple(self.policy_qualifiers)

        return hash((self.__class__, self.policy_identifier, t))

    def __len__(self):
        if self.policy_qualifiers is None:
            return 0
        return len(self.policy_qualifiers)

    def __str__(self):
        length = len(self)
        if length == 1:
            qual = '1 qualifier'
        else:
            qual = '%s qualifiers' % length

        if self.policy_identifier is None:
            ident = 'None'
        else:
            ident = self.policy_identifier.dotted_string

        return 'PolicyInformation(oid=%s, %s)' % (ident, qual)

    def __repr__(self):
        if self.policy_identifier is None:
            ident = 'None'
        else:
            ident = self.policy_identifier.dotted_string

        return '<PolicyInformation(oid=%s, qualifiers=%r)>' % (ident, self.serialize_policy_qualifiers())

    def append(self, value):
        if self.policy_qualifiers is None:
            self.policy_qualifiers = []
        self.policy_qualifiers.append(self.parse_policy_qualifier(value))

    def as_text(self, width=76):
        if self.policy_identifier is None:
            text = 'Policy Identifier: %s\n' % None
        else:
            text = 'Policy Identifier: %s\n' % self.policy_identifier.dotted_string

        if self.policy_qualifiers:
            text += 'Policy Qualifiers:\n'
            for qualifier in self.policy_qualifiers:
                if isinstance(qualifier, six.string_types):
                    lines = textwrap.wrap(qualifier, initial_indent='* ', subsequent_indent='  ', width=width)
                    text += '%s\n' % '\n'.join(lines)
                else:
                    text += '* UserNotice:\n'
                    if qualifier.explicit_text:
                        text += '\n'.join(textwrap.wrap(
                            'Explicit text: %s\n' % qualifier.explicit_text,
                            initial_indent='  * ', subsequent_indent='    ', width=width - 2
                        )) + '\n'
                    if qualifier.notice_reference:
                        text += '  * Reference:\n'
                        text += '    * Organiziation: %s\n' % qualifier.notice_reference.organization
                        text += '    * Notice Numbers: %s\n' % qualifier.notice_reference.notice_numbers
        else:
            text += 'No Policy Qualifiers'

        return text.strip()

    def clear(self):
        self.policy_qualifiers = None

    def count(self, value):
        try:
            return self.policy_qualifiers.count(self.parse_policy_qualifier(value))
        except (ValueError, AttributeError):
            return 0

    def extend(self, value):
        self.policy_qualifiers.extend([self.parse_policy_qualifier(v) for v in value])

    @property
    def for_extension_type(self):
        return x509.PolicyInformation(policy_identifier=self.policy_identifier,
                                      policy_qualifiers=self.policy_qualifiers)

    def insert(self, index, value):
        if self.policy_qualifiers is None:
            self.policy_qualifiers = []
        return self.policy_qualifiers.insert(index, self.parse_policy_qualifier(value))

    def parse_policy_qualifier(self, qualifier):
        if isinstance(qualifier, six.string_types):
            return force_text(qualifier)
        elif isinstance(qualifier, x509.UserNotice):
            return qualifier
        elif isinstance(qualifier, dict):
            explicit_text = qualifier.get('explicit_text')

            notice_reference = qualifier.get('notice_reference')
            if isinstance(notice_reference, dict):
                notice_reference = x509.NoticeReference(
                    organization=force_text(notice_reference.get('organization', '')),
                    notice_numbers=[int(i) for i in notice_reference.get('notice_numbers', [])]
                )
            elif notice_reference is None:
                pass  # extra branch to ensure test coverage
            elif isinstance(notice_reference, x509.NoticeReference):
                pass  # extra branch to ensure test coverage
            else:
                raise ValueError('NoticeReference must be either None, a dict or an x509.NoticeReference')

            return x509.UserNotice(explicit_text=explicit_text, notice_reference=notice_reference)
        raise ValueError('PolicyQualifier must be string, dict or x509.UserNotice')

    def parse_policy_qualifiers(self, qualifiers):
        if qualifiers is None:
            return None
        return [self.parse_policy_qualifier(q) for q in qualifiers]

    @property
    def policy_identifier(self):
        return self._policy_identifier

    @policy_identifier.setter
    def policy_identifier(self, value):
        if isinstance(value, six.string_types):
            value = ObjectIdentifier(value)
        self._policy_identifier = value

    def pop(self, index=-1):
        if self.policy_qualifiers is None:
            return [].pop()

        val = self.serialize_policy_qualifier(self.policy_qualifiers.pop(index))

        if not self.policy_qualifiers:  # if list is now empty, set to none
            self.policy_qualifiers = None

        return val

    def remove(self, value):
        if self.policy_qualifiers is None:
            return [].remove(None)

        val = self.policy_qualifiers.remove(self.parse_policy_qualifier(value))

        if not self.policy_qualifiers:  # if list is now empty, set to none
            self.policy_qualifiers = None

        return val

    def serialize_policy_qualifier(self, qualifier):
        if isinstance(qualifier, six.string_types):
            return qualifier
        else:
            value = {}
            if qualifier.explicit_text:
                value['explicit_text'] = qualifier.explicit_text
            if qualifier.notice_reference:
                value['notice_reference'] = {
                    'notice_numbers': qualifier.notice_reference.notice_numbers,
                    'organization': qualifier.notice_reference.organization,
                }
            return value

    def serialize_policy_qualifiers(self):
        if self.policy_qualifiers is None:
            return None

        return [self.serialize_policy_qualifier(q) for q in self.policy_qualifiers]

    def serialize(self):
        value = {
            'policy_identifier': self.policy_identifier.dotted_string,
        }
        qualifier = self.serialize_policy_qualifiers()
        if qualifier:
            value['policy_qualifiers'] = qualifier

        return value


class AuthorityInformationAccess(GeneralNameMixin, Extension):
    """Class representing a AuthorityInformationAccess extension.

    .. seealso::

        `RFC 5280, section 4.2.2.1 <https://tools.ietf.org/html/rfc5280#section-4.2.2.1>`_
    """
    oid = ExtensionOID.AUTHORITY_INFORMATION_ACCESS

    def __bool__(self):
        return bool(self.ocsp) or bool(self.issuers)
    if six.PY2:  # pragma: no branch, pragma: only py2
        __nonzero__ = __bool__

    def __eq__(self, other):
        return isinstance(other, type(self)) \
            and self.issuers == other.issuers and self.ocsp == other.ocsp \
            and self.critical == other.critical

    def __hash__(self):
        return hash((self.__class__, tuple(self.issuers), tuple(self.ocsp), self.critical, ))

    def __repr__(self):
        issuers = [self.serialize_value(v) for v in self.issuers]
        ocsp = [self.serialize_value(v) for v in self.ocsp]

        if six.PY2:  # pragma: no branch, pragma: only py2 - otherwise we have the u'' prefix in output
            issuers = [str(v) for v in issuers]
            ocsp = [str(v) for v in ocsp]

        return '<%s: issuers=%s, ocsp=%s, critical=%r>' % (
            self.__class__.__name__, issuers, ocsp, self.critical)

    def __str__(self):
        issuers = [self.serialize_value(v) for v in self.issuers]
        ocsp = [self.serialize_value(v) for v in self.ocsp]

        if six.PY2:  # pragma: no branch, pragma: only py2 - otherwise we have the u'' prefix in output
            issuers = [str(v) for v in issuers]
            ocsp = [str(v) for v in ocsp]

        return 'AuthorityInformationAccess(issuers=%s, ocsp=%s, critical=%s)' % (issuers, ocsp, self.critical)

    def as_text(self):
        text = ''
        if self.issuers:
            text += 'CA Issuers:\n'
            for name in self.issuers:
                text += '  * %s\n' % self.serialize_value(name)
        if self.ocsp:
            text += 'OCSP:\n'
            for name in self.ocsp:
                text += '  * %s\n' % self.serialize_value(name)

        return text

    @property
    def extension_type(self):
        descs = [x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, v) for v in self.issuers]
        descs += [x509.AccessDescription(AuthorityInformationAccessOID.OCSP, v) for v in self.ocsp]
        return x509.AuthorityInformationAccess(descriptions=descs)

    def from_extension(self, value):
        self.issuers = []
        self.ocsp = []

        for desc in value.value:
            if desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                self.issuers.append(desc.access_location)
            elif desc.access_method == AuthorityInformationAccessOID.OCSP:
                self.ocsp.append(desc.access_location)
            else:  # pragma: no cover (cryptography only has the above two)
                raise ValueError('Unknown access method: %s' % desc.access_method)

    def from_dict(self, value):
        value = value.get('value', {})
        self.issuers = [self.parse_value(v) for v in value.get('issuers', [])]
        self.ocsp = [self.parse_value(v) for v in value.get('ocsp', [])]

    def from_list(self, value):
        self.issuers = [self.parse_value(v) for v in value[0]]
        self.ocsp = [self.parse_value(v) for v in value[1]]

    def from_other(self, value):
        if isinstance(value, (list, tuple)):
            self.critical = self.default_critical
            self.from_list(value)
            self._test_value()
        else:
            super(AuthorityInformationAccess, self).from_other(value)

    def from_str(self, value):
        raise NotImplementedError

    def serialize(self):
        return {
            'critical': self.critical,
            'value': {
                'issuers': [self.serialize_value(v) for v in self.issuers],
                'ocsp': [self.serialize_value(v) for v in self.ocsp],
            },
        }


class AuthorityKeyIdentifier(KeyIdExtension):
    """Class representing a AuthorityKeyIdentifier extension.

    .. TODO::

        * This class only supports key_identifier, should also support authority_cert_issuer and
          authority_cert_serial_number (see underlying constructor).
    """

    oid = ExtensionOID.AUTHORITY_KEY_IDENTIFIER

    @property
    def extension_type(self):
        return x509.AuthorityKeyIdentifier(key_identifier=self.value,
                                           authority_cert_issuer=None, authority_cert_serial_number=None)

    def from_subject_key_identifier(self, ext):
        self.value = ext.value

    def from_extension(self, ext):
        self.value = ext.value.key_identifier

    def from_other(self, value):
        if isinstance(value, SubjectKeyIdentifier):
            self.critical = self.default_critical
            self.from_subject_key_identifier(value)
            self._test_value()
        else:
            super(AuthorityKeyIdentifier, self).from_other(value)

    def as_text(self):
        return 'keyid:%s' % super(AuthorityKeyIdentifier, self).as_text()


class BasicConstraints(Extension):
    """Class representing a BasicConstraints extension.

    This class has the boolean attributes ``ca`` and the attribute ``pathlen``, which is either ``None`` or an
    ``int``. Note that this extension is marked as critical by default if you pass a dict to the constructor::

        >>> BasicConstraints('critical,CA:TRUE, pathlen:3')
        <BasicConstraints: 'CA:TRUE, pathlen:3', critical=True>
        >>> bc = BasicConstraints({'value': {'ca': True, 'pathlen': 4}})
        >>> (bc.ca, bc.pathlen, bc.critical)
        (True, 4, True)

        # Note that string parsing ignores case and whitespace and is quite forgiving
        >>> BasicConstraints('critical, ca=true    , pathlen: 3 ')
        <BasicConstraints: 'CA:TRUE, pathlen:3', critical=True>

    .. seealso::

        `RFC 5280, section 4.2.1.9 <https://tools.ietf.org/html/rfc5280#section-4.2.1.9>`_
    """

    oid = ExtensionOID.BASIC_CONSTRAINTS
    default_critical = True

    def __init__(self, *args, **kwargs):
        super(BasicConstraints, self).__init__(*args, **kwargs)
        if self.ca is False and self.pathlen is not None:
            raise ValueError('pathlen must be None when ca is False')

    def __repr__(self):
        return '<%s: %r, critical=%r>' % (self.__class__.__name__, str(self.as_text()), self.critical)

    @property
    def value(self):
        return self.ca, self.pathlen

    def from_extension(self, ext):
        self.ca = ext.value.ca
        self.pathlen = ext.value.path_length

    def from_dict(self, value):
        value = value.get('value', {})
        self.ca = bool(value.get('ca', False))
        if self.ca:
            self.pathlen = value.get('pathlen', None)
        else:  # if ca is not True, we don't use the pathlen
            self.pathlen = None

    def from_str(self, value):
        value = value.strip().lower()
        pathlen = None

        if ',' in value:
            value, pathlen = value.split(',', 1)
            pathlen_match = re.search(r'\s*(?:pathlen\s*[:=]\s*)?([0-9]+)', pathlen.strip(), re.I)
            if pathlen_match is None:
                raise ValueError('Could not parse pathlen: %s' % pathlen.lstrip())
            else:
                pathlen = int(pathlen_match.group(1))
        self.pathlen = pathlen

        value = re.search(r'(?:CA\s*[:=]\s*)?(.*)', value.strip(), re.I).group(1)
        self.ca = value == 'true'

    @property
    def extension_type(self):
        return x509.BasicConstraints(ca=self.ca, path_length=self.pathlen)

    def as_text(self):
        if self.ca is True:
            val = 'CA:TRUE'
        else:
            val = 'CA:FALSE'
        if self.pathlen is not None:
            val += ', pathlen:%s' % self.pathlen

        return val

    def serialize(self):
        value = {
            'critical': self.critical,
            'value': {
                'ca': self.ca,
            }
        }
        if self.ca:
            value['value']['pathlen'] = self.pathlen
        return value


class CRLDistributionPoints(ListExtension):
    """Class representing a CRLDistributionPoints extension.

    This extension identifies where a client can retrieve a Certificate Revocation List (CRL).

    .. seealso::

        `RFC 5280, section 4.2.1.13 <https://tools.ietf.org/html/rfc5280#section-4.2.1.13>`_
    """
    oid = ExtensionOID.CRL_DISTRIBUTION_POINTS

    def __hash__(self):
        return hash((self.__class__, tuple(self.value), self.critical, ))

    def __repr__(self):
        return '<CRLDistributionPoints: [%s], critical=%s>' % (
            ', '.join([repr(v) for v in self.value]), self.critical
        )

    def __str__(self):
        return 'CRLDistributionPoints([%s], critical=%s)' % (
            ', '.join([str(v) for v in self.value]), self.critical
        )

    def as_text(self):
        return '\n'.join('* DistributionPoint:\n%s' % indent(dp.as_text(), '  ') for dp in self.value)

    @property
    def extension_type(self):
        return x509.CRLDistributionPoints(distribution_points=[dp.for_extension_type for dp in self.value])

    def from_extension(self, value):
        self.value = [DistributionPoint(v) for v in value.value]

    def from_dict(self, value):
        self.value = [self.parse_value(v) for v in value.get('value', [])]

    def parse_value(self, v):
        if isinstance(v, DistributionPoint):
            return v
        return DistributionPoint(v)

    def serialize(self):
        return {
            'value': [dp.serialize() for dp in self.value],
            'critical': self.critical,
        }


class CertificatePolicies(ListExtension):
    """Class representing a Certificate Policies extension.

    .. seealso::

        `RFC 5280, section 4.2.1.4 <https://tools.ietf.org/html/rfc5280#section-4.2.1.4>`_
    """
    oid = ExtensionOID.CERTIFICATE_POLICIES

    def __hash__(self):
        return hash((self.__class__, tuple(self.value), self.critical, ))

    def __repr__(self):
        return '<CertificatePolicies: [%s], critical=%s>' % (
            ', '.join([str(v) for v in self.value]), self.critical
        )

    def __str__(self):
        count = len(self)
        if count == 1:
            policies = '1 Policy'
        else:
            policies = '%s Policies' % count

        return 'CertificatePolicies(%s, critical=%s)' % (policies, self.critical)

    def as_text(self):
        return '\n'.join('* %s' % indent(p.as_text(), '  ').strip() for p in self.value)

    @property
    def extension_type(self):
        return x509.CertificatePolicies(policies=[p.for_extension_type for p in self.value])

    def from_extension(self, value):
        self.value = [PolicyInformation(v) for v in value.value]

    def parse_value(self, v):
        if isinstance(v, PolicyInformation):
            return v
        return PolicyInformation(v)

    def serialize(self):
        return {
            'value': [p.serialize() for p in self.value],
            'critical': self.critical,
        }


class IssuerAlternativeName(AlternativeNameExtension):
    """Class representing an Issuer Alternative Name extension.

    This extension is usually marked as non-critical.

    >>> IssuerAlternativeName('https://example.com')
    <IssuerAlternativeName: ['URI:https://example.com'], critical=False>

    .. seealso::

       `RFC 5280, section 4.2.1.7 <https://tools.ietf.org/html/rfc5280#section-4.2.1.7>`_
    """
    oid = ExtensionOID.ISSUER_ALTERNATIVE_NAME

    @property
    def extension_type(self):
        return x509.IssuerAlternativeName(self.value)


class KeyUsage(KnownValuesExtension):
    """Class representing a KeyUsage extension, which defines the purpose of a certificate.

    This extension is usually marked as critical and RFC 5280 defines that confirming CAs SHOULD mark it as
    critical. The value ``keyAgreement`` is always added if ``decipherOnly`` is present, since the value of
    this extension is not meaningful otherwise.

    >>> KeyUsage('critical,encipherOnly')
    <KeyUsage: ['encipherOnly'], critical=True>
    >>> KeyUsage('critical,decipherOnly')
    <KeyUsage: ['decipherOnly', 'keyAgreement'], critical=True>

    .. seealso::

        `RFC 5280, section 4.2.1.3 <https://tools.ietf.org/html/rfc5280#section-4.2.1.3>`_
    """

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
    KNOWN_VALUES = set(CRYPTOGRAPHY_MAPPING)
    """Known values for this extension."""

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
        super(KeyUsage, self).__init__(*args, **kwargs)

        # decipherOnly only makes sense if keyAgreement is True
        if 'decipherOnly' in self.value and 'keyAgreement' not in self.value:
            self.value.append('keyAgreement')

    def from_extension(self, ext):
        self.value = []

        # NOTE: we sort the items here to make sure that the order of self.value is deterministic.
        for k, v in sorted(self.CRYPTOGRAPHY_MAPPING.items()):
            try:
                if getattr(ext.value, v):
                    self.value.append(k)
            except ValueError:
                # cryptography throws a ValueError if encipher_only/decipher_only is accessed and
                # key_agreement is not set.
                pass

    @property
    def extension_type(self):
        kwargs = {v: (k in self.value) for k, v in self.CRYPTOGRAPHY_MAPPING.items()}
        return x509.KeyUsage(**kwargs)


class ExtendedKeyUsage(KnownValuesExtension):
    """Class representing a ExtendedKeyUsage extension."""

    oid = ExtensionOID.EXTENDED_KEY_USAGE
    CRYPTOGRAPHY_MAPPING = {
        'serverAuth': ExtendedKeyUsageOID.SERVER_AUTH,
        'clientAuth': ExtendedKeyUsageOID.CLIENT_AUTH,
        'codeSigning': ExtendedKeyUsageOID.CODE_SIGNING,
        'emailProtection': ExtendedKeyUsageOID.EMAIL_PROTECTION,
        'timeStamping': ExtendedKeyUsageOID.TIME_STAMPING,
        'OCSPSigning': ExtendedKeyUsageOID.OCSP_SIGNING,
        'smartcardLogon': ObjectIdentifier("1.3.6.1.4.1.311.20.2.2"),
        'msKDC': ObjectIdentifier("1.3.6.1.5.2.3.5"),

        # Defined in RFC 3280, occurs in TrustID Server A52 CA
        'ipsecEndSystem': ObjectIdentifier('1.3.6.1.5.5.7.3.5'),
        'ipsecTunnel': ObjectIdentifier('1.3.6.1.5.5.7.3.6'),
        'ipsecUser': ObjectIdentifier('1.3.6.1.5.5.7.3.7'),
    }
    _CRYPTOGRAPHY_MAPPING_REVERSED = {v: k for k, v in CRYPTOGRAPHY_MAPPING.items()}
    KNOWN_VALUES = set(CRYPTOGRAPHY_MAPPING)
    """Known values for this extension."""

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
    )

    def from_extension(self, ext):
        self.value = [self._CRYPTOGRAPHY_MAPPING_REVERSED[u] for u in ext.value]

    @property
    def extension_type(self):
        return x509.ExtendedKeyUsage([self.CRYPTOGRAPHY_MAPPING[u] for u in self.value])


# TODO: this extension is not in fact always critical, but constructor does not allow overriding this value
class NameConstraints(GeneralNameMixin, Extension):
    """Class representing a NameConstraints extenion

    Unlike most other extensions, this extension does not accept a string as value, but you can pass a list
    containing the permitted/excluded subtrees as lists. Similar to
    :py:class:`~django_ca.extensions.SubjectAlternativeName`, you can pass both strings or instances of
    :py:class:`~cg:cryptography.x509.GeneralName`::

        >>> NameConstraints([['DNS:.com', 'example.org'], [x509.DNSName('.net')]])
        <NameConstraints: permitted=['DNS:.com', 'DNS:example.org'], excluded=['DNS:.net'], critical=True>

    .. seealso::

       `RFC 5280, section 4.2.1.10 <https://tools.ietf.org/html/rfc5280#section-4.2.1.10>`_

    """
    default_critical = True
    oid = ExtensionOID.NAME_CONSTRAINTS

    def __bool__(self):
        return bool(self.permitted) or bool(self.excluded)
    if six.PY2:  # pragma: no branch, pragma: only py2
        __nonzero__ = __bool__

    def __eq__(self, other):
        return isinstance(other, type(self)) \
            and self.permitted == other.permitted and self.excluded == other.excluded \
            and self.critical == other.critical

    def __hash__(self):
        return hash((self.__class__, tuple(self.permitted), tuple(self.excluded), self.critical, ))

    def __repr__(self):
        permitted = [self.serialize_value(v) for v in self.permitted]
        excluded = [self.serialize_value(v) for v in self.excluded]

        if six.PY2:  # pragma: no branch, pragma: only py2 - otherwise we have the u'' prefix in output
            permitted = [str(v) for v in permitted]
            excluded = [str(v) for v in excluded]

        return '<%s: permitted=%r, excluded=%r, critical=%r>' % (
            self.__class__.__name__, permitted, excluded, self.critical)

    def __str__(self):
        permitted = [self.serialize_value(v) for v in self.permitted]
        excluded = [self.serialize_value(v) for v in self.excluded]

        if six.PY2:  # pragma: no branch, pragma: only py2 - otherwise we have the u'' prefix in output
            permitted = [str(v) for v in permitted]
            excluded = [str(v) for v in excluded]

        return 'NameConstraints(permitted=%s, excluded=%s, critical=%s)' % (
            permitted, excluded, self.critical)

    def as_text(self):
        text = ''
        if self.permitted:
            text += 'Permitted:\n'
            for name in self.permitted:
                text += '  * %s\n' % self.serialize_value(name)
        if self.excluded:
            text += 'Excluded:\n'
            for name in self.excluded:
                text += '  * %s\n' % self.serialize_value(name)

        return text

    @property
    def extension_type(self):
        return x509.NameConstraints(permitted_subtrees=self.permitted, excluded_subtrees=self.excluded)

    def from_extension(self, value):
        self.permitted = value.value.permitted_subtrees or []
        self.excluded = value.value.excluded_subtrees or []

    def from_list(self, value):
        self.permitted = [self.parse_value(v) for v in value[0]]
        self.excluded = [self.parse_value(v) for v in value[1]]

    def from_other(self, value):
        if isinstance(value, (list, tuple)):
            self.critical = self.default_critical
            self.from_list(value)
            self._test_value()
        else:
            super(NameConstraints, self).from_other(value)

    def from_dict(self, value):
        value = value.get('value', {})
        self.permitted = [self.parse_value(v) for v in value.get('permitted', [])]
        self.excluded = [self.parse_value(v) for v in value.get('excluded', [])]

    def serialize(self):
        return {
            'critical': self.critical,
            'value': {
                'permitted': [self.serialize_value(v) for v in self.permitted],
                'excluded': [self.serialize_value(v) for v in self.excluded],
            },
        }


class OCSPNoCheck(NullExtension):
    """Extension to indicate that an OCSP client should (blindly) trust the certificate for it's lifetime.

    This extension is only meaningful in an OCSP responder certificate.

    .. seealso::

       `RFC 6990, section 4.2.2.2.1 <https://tools.ietf.org/html/rfc6960#section-4.2.2.2>`_
    """
    oid = ExtensionOID.OCSP_NO_CHECK
    ext_class = x509.OCSPNoCheck


if ca_settings.CRYPTOGRAPHY_HAS_PRECERT_POISON:  # pragma: no branch, pragma: only cryptography>=2.4
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
        oid = ExtensionOID.PRECERT_POISON
        ext_class = x509.PrecertPoison

        def __init__(self, value=None):
            super(PrecertPoison, self).__init__(value=value)

            if self.critical is not True:
                raise ValueError('PrecertPoison must always be marked as critical')


class PrecertificateSignedCertificateTimestamps(ListExtension):  # pragma: only SCT
    """Class representing signed certificate timestamps.

    This extension can be used to verify that a certificate is included in a Certificate Transparency log.

    .. NOTE::

        Cryptography currently does not provide a way to create instances of this extension without already
        having a certificate that provides this extension.

        https://github.com/pyca/cryptography/issues/4820

    .. seealso::

       `RFC 6962 <https://tools.ietf.org/html/rfc6962.html>`_
   """
    oid = ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS
    _timeformat = '%Y-%m-%d %H:%M:%S.%f'
    LOG_ENTRY_TYPE_MAPPING = {
        LogEntryType.PRE_CERTIFICATE: 'precertificate',
        LogEntryType.X509_CERTIFICATE: 'x509_certificate'
    }

    def __contains__(self, value):
        if isinstance(value, dict):
            return value in self.serialize()['value']
        return value in self.value

    def __delitem__(self, key):
        raise NotImplementedError

    def __repr__(self):
        # only py2: we only override this method because of u'' prefixes in output
        val = [self.serialize_value(v) for v in self.value]

        if six.PY2:  # pragma: no branch, pragma: only py2 - otherwise we have the u'' prefix in output
            val = [{str(k): str(v) for k, v in e.items()} for e in val]

        return '<%s: %r, critical=%r>' % (self.__class__.__name__, val, self.critical)

    def __setitem__(self, key, value):
        raise NotImplementedError

    def __str__(self):
        val = '<%s entry(s)>' % len(self)
        if self.critical:
            return '%s/critical' % val
        return val

    def human_readable_timestamps(self):
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
        for v in self.human_readable_timestamps():
            line = '* {type} ({version}):\n    Timestamp: {timestamp}\n    Log ID: {log_id}'.format(**v)
            lines.append(line)

        return '\n'.join(lines)

    def count(self, value):
        if isinstance(value, dict):
            return self.serialize()['value'].count(value)
        return self.value._signed_certificate_timestamps.count(value)

    def extend(self, iterable):
        raise NotImplementedError

    @property
    def extension_type(self):
        return self.value

    def from_extension(self, value):
        self.value = value.value

    def from_list(self, value):
        raise NotImplementedError

    def insert(self, index, value):
        raise NotImplementedError

    def pop(self, index=-1):
        raise NotImplementedError

    def remove(self, v):
        raise NotImplementedError

    def serialize(self):
        return {
            u'critical': self.critical,
            'value': [self.serialize_value(v) for v in self.value],
        }

    def serialize_value(self, v):
        return {
            'type': PrecertificateSignedCertificateTimestamps.LOG_ENTRY_TYPE_MAPPING[v.entry_type],
            'timestamp': v.timestamp.strftime(self._timeformat),
            'log_id': binascii.hexlify(v.log_id).decode('utf-8'),
            'version': v.version.name,
        }


class SubjectAlternativeName(AlternativeNameExtension):
    """Class representing an Subject Alternative Name extension.

    This extension is usually marked as non-critical.

    >>> SubjectAlternativeName('example.com')
    <SubjectAlternativeName: ['DNS:example.com'], critical=False>

    .. seealso::

       `RFC 5280, section 4.2.1.6 <https://tools.ietf.org/html/rfc5280#section-4.2.1.6>`_
    """
    oid = ExtensionOID.SUBJECT_ALTERNATIVE_NAME

    @property
    def extension_type(self):
        return x509.SubjectAlternativeName(self.value)


class SubjectKeyIdentifier(KeyIdExtension):
    """Class representing a SubjectKeyIdentifier extension."""

    oid = ExtensionOID.SUBJECT_KEY_IDENTIFIER

    @property
    def extension_type(self):
        return x509.SubjectKeyIdentifier(digest=self.value)

    def from_extension(self, ext):
        self.value = ext.value.digest


class TLSFeature(KnownValuesExtension):
    """Class representing a TLSFeature extension."""

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
    KNOWN_VALUES = set(CRYPTOGRAPHY_MAPPING)
    """Known values for this extension."""

    def from_extension(self, ext):
        self.value = [self._CRYPTOGRAPHY_MAPPING_REVERSED[f] for f in ext.value]

    @property
    def extension_type(self):
        values = [self.CRYPTOGRAPHY_MAPPING[f] for f in self.value]
        return x509.TLSFeature(sorted(values, key=lambda t: t.value))

    def parse_value(self, v):
        if isinstance(v, TLSFeatureType):
            return self._CRYPTOGRAPHY_MAPPING_REVERSED[v]
        return v

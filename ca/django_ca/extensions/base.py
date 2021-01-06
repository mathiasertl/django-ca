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

"""Base classes for x509 extensions."""

# pylint: disable=unsubscriptable-object; https://github.com/PyCQA/pylint/issues/3882

import textwrap
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Union

from cryptography import x509

from ..typehints import AlternativeNameType
from ..typehints import DistributionPointType
from ..utils import GeneralNameList
from ..utils import bytes_to_hex
from ..utils import format_general_name
from ..utils import hex_to_bytes
from .utils import DistributionPoint


class Extension:
    """Convenience class to handle X509 Extensions.

    The value is a ``dict`` as used by the :ref:`CA_PROFILES <settings-ca-profiles>` setting::

        >>> KeyUsage({'value': ['keyAgreement', 'keyEncipherment']})
        <KeyUsage: ['keyAgreement', 'keyEncipherment'], critical=True>
        >>> KeyUsage({'critical': False, 'value': ['key_agreement', 'key_encipherment']})
        <KeyUsage: ['keyAgreement', 'keyEncipherment'], critical=False>

    ... but can also use a subclass of :py:class:`~cg:cryptography.x509.ExtensionType`
    from ``cryptography``::

        >>> from cryptography import x509
        >>> cg_ext = x509.extensions.Extension(
        ...    oid=ExtensionOID.EXTENDED_KEY_USAGE,
        ...    critical=False,
        ...    value=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
        ... )
        >>> ExtendedKeyUsage(cg_ext)
        <ExtendedKeyUsage: ['serverAuth'], critical=False>
        >>> ExtendedKeyUsage({'value': ['serverAuth']})
        <ExtendedKeyUsage: ['serverAuth'], critical=False>

    Attributes
    ----------

    name : str
        A human readable name of this extension
    value
        Raw value for this extension. The type various from subclass to subclass.
    critical : bool
        If this extension is marked as critical
    oid : :py:class:`~cg:cryptography.x509.oid.ExtensionOID`
        The OID for this extension.
    key : str
        The key is a reusable ID used in various parts of the application.
    default_critical : bool
        The default critical value if you pass a dict without the ``"critical"`` key.

    Parameters
    ----------

    value : list or tuple or dict or str or :py:class:`~cg:cryptography.x509.ExtensionType`
        The value of the extension, the description provides further details.
    """
    key = ''  # must be overwritten by actual classes
    """Key used in CA_PROFILES."""

    name = 'Extension'
    oid: x509.ObjectIdentifier = None  # must be overwritten by actual classes
    default_critical = False

    def __init__(self, value=None):
        if value is None:
            value = {}

        if isinstance(value, x509.extensions.Extension):  # e.g. from a cert object
            self.critical = value.critical
            self.from_extension(value)
        elif isinstance(value, dict):  # e.g. from settings
            self.critical = value.get('critical', self.default_critical)
            self.from_dict(value)
            self._test_value()
        else:
            self.from_other(value)
        if not isinstance(self.critical, bool):
            raise ValueError('%s: Invalid critical value passed' % self.critical)

    def __hash__(self):
        return hash((self.value, self.critical, ))

    def __eq__(self, other):
        return isinstance(other, type(self)) and self.critical == other.critical and self.value == other.value

    def __repr__(self):
        return '<%s: %s, critical=%r>' % (self.name, self._repr_value(), self.critical)

    def __str__(self):
        return repr(self)

    def _repr_value(self):
        return self.value

    def from_extension(self, value):
        """Load a wrapper class from a cryptography extension instance.

        Implementing classes are expected to implement this function."""
        raise NotImplementedError

    def from_dict(self, value):
        """Load class from a dictionary."""
        self.value = value['value']

    def from_other(self, value: Any):
        """Load class from any other value type.

        This class can be overwritten to allow loading classes from different types."""
        raise ValueError('Value is of unsupported type %s' % type(value).__name__)

    def _test_value(self) -> None:
        pass

    @property
    def extension_type(self):
        """The extension_type for this value."""

        raise NotImplementedError

    def serialize(self):
        """Serialize this extension to a string in a way that it can be passed to a constructor again.

        For example, this should always be True::

            >>> ku = KeyUsage({'value': ['keyAgreement', 'keyEncipherment']})
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

            >>> kwargs = KeyUsage({'value': ['keyAgreement', 'keyEncipherment']}).for_builder()
            >>> builder.add_extension(**kwargs)  # doctest: +SKIP
        """
        return {'extension': self.extension_type, 'critical': self.critical}


class UnrecognizedExtension(Extension):
    """Class wrapping any extension this module does **not** support."""

    # pylint: disable=abstract-method; We don't know the extension_type

    def __init__(self, value, name='', error=''):
        self._error = error
        self._name = name
        super().__init__(value)

    def from_extension(self, value):
        self.value = value

    @property
    def name(self):
        """Name (best effort) for this extension."""
        if self._name:
            return self._name
        return 'Unsupported extension (OID %s)' % (self.value.oid.dotted_string)

    def as_text(self):
        if self._error:
            return 'Could not parse extension (%s)' % self._error
        return 'Could not parse extension'


class NullExtension(Extension):
    """Base class for extensions that have a NULL value.

    Extensions using this base class will ignore any ``"value"`` key in their dict, only the ``"critical"``
    key is relevant:

        >>> OCSPNoCheck()
        <OCSPNoCheck: critical=False>
        >>> OCSPNoCheck({'critical': True})
        <OCSPNoCheck: critical=True>
        >>> OCSPNoCheck({'critical': True})
        <OCSPNoCheck: critical=True>
        >>> OCSPNoCheck(x509.extensions.Extension(oid=ExtensionOID.OCSP_NO_CHECK, critical=True, value=None))
        <OCSPNoCheck: critical=True>
    """

    def __init__(self, value: Optional[Dict[str, bool]] = None):
        self.value = {}
        if not value:
            self.critical = self.default_critical
        else:
            super().__init__(value)

    def __hash__(self):
        return hash((self.critical, ))

    def __eq__(self, other):
        return isinstance(other, type(self)) and self.critical == other.critical

    def __repr__(self):
        return '<%s: critical=%r>' % (self.__class__.__name__, self.critical)

    def as_text(self):
        return self.name

    @property
    def extension_type(self):
        return self.ext_class()  # pylint: disable=no-member; concrete classes are expected to set this

    def from_extension(self, value):
        pass

    def from_dict(self, value):
        pass

    def serialize(self) -> Dict[str, bool]:
        return {'critical': self.critical}


class IterableExtension(Extension):
    """Base class for iterable extensions.

    Extensions of this class can be used just like any other iterable, e.g.:

        >>> e = IterableExtension({'value': ['foo', 'bar']})
        >>> 'foo' in e
        True
        >>> len(e)
        2
        >>> for val in e:
        ...     print(val)
        foo
        bar
    """

    # pylint: disable=abstract-method; class is itself a base class

    def __contains__(self, value):
        return self.parse_value(value) in self.value

    def __eq__(self, other):
        return isinstance(other, type(self)) and self.critical == other.critical and self.value == other.value

    def __hash__(self):
        return hash((tuple(self.serialize_iterable()), self.critical, ))

    def __iter__(self):
        return iter(self.serialize_iterable())

    def __len__(self):
        return len(self.value)

    def _repr_value(self):
        return self.serialize_iterable()

    def as_text(self):
        return '\n'.join(['* %s' % v for v in self.serialize_iterable()])

    def parse_value(self, value):
        """Parse a single value (presumably from an iterable)."""
        return value

    def serialize(self) -> Dict[str, Any]:
        return {
            'critical': self.critical,
            'value': self.serialize_iterable(),
        }

    def serialize_iterable(self):
        """Serialize the whole iterable contained in this extension."""

        return [self.serialize_value(v) for v in self.value]

    def serialize_value(self, value):
        """Serialize a single value from the iterable contained in this extension."""

        return value


class ListExtension(IterableExtension):
    """Base class for extensions with multiple ordered values."""

    # pylint: disable=abstract-method; class is itself a base class

    def __delitem__(self, key):
        del self.value[key]

    def __getitem__(self, key):
        if isinstance(key, int):
            return self.serialize_value(self.value[key])
        return [self.serialize_value(v) for v in self.value[key]]

    def __setitem__(self, key, value):
        if isinstance(key, int):
            self.value[key] = self.parse_value(value)
        else:
            self.value[key] = [self.parse_value(v) for v in value]

    def from_dict(self, value):
        self.value = [self.parse_value(v) for v in value.get('value', [])]

    def from_extension(self, value):
        self.value = [self.parse_value(v) for v in value.value]

    # Implement functions provided by list(). Class mentions that this provides the same methods.
    # pylint: disable=missing-function-docstring

    def append(self, value):
        self.value.append(self.parse_value(value))
        self._test_value()

    def clear(self):
        self.value.clear()

    def count(self, value):
        try:
            return self.value.count(self.parse_value(value))
        except ValueError:
            return 0

    def extend(self, iterable):
        self.value.extend([self.parse_value(n) for n in iterable])
        self._test_value()

    def insert(self, index, value):
        self.value.insert(index, self.parse_value(value))

    def pop(self, index=-1):
        return self.serialize_value(self.value.pop(index))

    def remove(self, value):
        return self.value.remove(self.parse_value(value))
    # pylint: enable=missing-function-docstring


class OrderedSetExtension(IterableExtension):
    """Base class for extensions that contain a set of values.

    For reproducibility, any serialization will always sort the values contained in this extension.

    Extensions derived from this class can be used like a normal set, for example:

        >>> e = OrderedSetExtension({'value': {'foo', }})
        >>> e.add('bar')
        >>> e
        <OrderedSetExtension: ['bar', 'foo'], critical=False>
        >>> e -= {'foo', }
        >>> e
        <OrderedSetExtension: ['bar'], critical=False>
    """

    # pylint: disable=abstract-method; class is itself a base class

    name = 'OrderedSetExtension'

    def __and__(self, other):  # & operator == intersection()
        value = self.value & self.parse_iterable(other)
        return OrderedSetExtension({'critical': self.critical, 'value': value})

    def __ge__(self, other):  # >= relation == issuperset()
        return self.value >= self.parse_iterable(other)

    def __gt__(self, other):  # > relation
        return self.value > self.parse_iterable(other)

    def __iand__(self, other):  # &= operator == intersection_update()
        self.value &= self.parse_iterable(other)
        return self

    def __ior__(self, other):  # |= operator == update()
        self.value |= self.parse_iterable(other)
        return self

    def __isub__(self, other):
        self.value -= self.parse_iterable(other)
        return self

    def __ixor__(self, other):  # ^= operator == symmetric_difference_update()
        self.value ^= self.parse_iterable(other)

    def __le__(self, other):  # <= relation == issubset()
        return self.value <= self.parse_iterable(other)

    def __lt__(self, other):  # < relation
        return self.value < self.parse_iterable(other)

    def __or__(self, other):  # | operator == union()
        value = self.value.union(self.parse_iterable(other))
        return OrderedSetExtension({'critical': self.critical, 'value': value})

    def __sub__(self, other):
        value = self.value - self.parse_iterable(other)
        return OrderedSetExtension({'critical': self.critical, 'value': value})

    def __xor__(self, other):  # ^ operator == symmetric_difference()
        value = self.value ^ self.parse_iterable(other)
        return OrderedSetExtension({'critical': self.critical, 'value': value})

    def _repr_value(self):
        return [str(v) for v in super()._repr_value()]

    def parse_iterable(self, iterable):
        """Parse values from the given iterable."""
        return set(self.parse_value(i) for i in iterable)

    def from_dict(self, value):
        self.value = self.parse_iterable(value.get('value', set()))

    def serialize_iterable(self):
        return list(sorted(self.serialize_value(v) for v in self.value))

    # Implement functions provided by set(). Class mentions that this provides the same methods.
    # pylint: disable=missing-function-docstring

    def add(self, elem):
        self.value.add(self.parse_value(elem))

    def clear(self):
        self.value.clear()

    def copy(self):
        value = self.value.copy()
        return OrderedSetExtension({'critical': self.critical, 'value': value})

    def difference(self, *others):  # equivalent to & operator
        value = self.value.difference(*[self.parse_iterable(o) for o in others])
        return OrderedSetExtension({'critical': self.critical, 'value': value})

    def difference_update(self, *others):  # equivalent to &= operator
        self.value.difference_update(*[self.parse_iterable(o) for o in others])

    def discard(self, elem):
        self.value.discard(self.parse_value(elem))

    def intersection(self, *others):  # equivalent to & operator
        value = self.value.intersection(*[self.parse_iterable(o) for o in others])
        return OrderedSetExtension({'critical': self.critical, 'value': value})

    def intersection_update(self, *others):  # equivalent to &= operator
        self.value.intersection_update(*[self.parse_iterable(o) for o in others])

    def isdisjoint(self, other):
        return self.value.isdisjoint(self.parse_iterable(other))

    def issubset(self, other):
        return self.value.issubset(self.parse_iterable(other))

    def issuperset(self, other):
        return self.value.issuperset(self.parse_iterable(other))

    def pop(self):
        return self.value.pop()

    def remove(self, elem):
        return self.value.remove(self.parse_value(elem))

    def symmetric_difference(self, other):  # equivalent to ^ operator
        return self ^ other

    def symmetric_difference_update(self, other):
        self ^= other

    def union(self, *others):
        value = self.value.union(*[self.parse_iterable(o) for o in others])
        return OrderedSetExtension({'critical': self.critical, 'value': value})

    def update(self, *others):
        for elem in others:
            self.value.update(self.parse_iterable(elem))

    # pylint: enable=missing-function-docstring


class AlternativeNameExtension(ListExtension):  # pylint: disable=abstract-method
    """Base class for extensions that contain a list of general names.

    This class also allows you to pass :py:class:`~cg:cryptography.x509.GeneralName` instances::

        >>> san = SubjectAlternativeName({'value': [x509.DNSName('example.com'), 'example.net']})
        >>> san
        <SubjectAlternativeName: ['DNS:example.com', 'DNS:example.net'], critical=False>
        >>> 'example.com' in san, 'DNS:example.com' in san, x509.DNSName('example.com') in san
        (True, True, True)

    """
    value: GeneralNameList

    def from_dict(self, value: Union[GeneralNameList, None, Iterable[Union[x509.GeneralName, str]]]) -> None:
        value = value.get('value')
        if isinstance(value, GeneralNameList):
            self.value = value
        elif value is None:
            self.value = GeneralNameList()
        else:
            self.value = GeneralNameList(value)

    def from_extension(self, value: AlternativeNameType) -> None:
        self.value = GeneralNameList(value.value)

    def serialize_value(self, value: x509.GeneralName) -> str:
        return format_general_name(value)


class KeyIdExtension(Extension):
    """Base class for extensions that contain a KeyID as value.

    The value can be a hex str or bytes::

        >>> KeyIdExtension({'value': '33:33'})
        <KeyIdExtension: b'33', critical=False>
        >>> KeyIdExtension({'value': b'33'})
        <KeyIdExtension: b'33', critical=False>
    """
    # pylint: disable=abstract-method; from_extension is not overwridden in this base class
    name = 'KeyIdExtension'

    def from_dict(self, value: Dict[str, Union[str, bytes]]) -> None:
        self.value = value['value']

        if isinstance(self.value, str) and ':' in self.value:
            self.value = hex_to_bytes(self.value)

    def as_text(self) -> str:
        return bytes_to_hex(self.value)

    def serialize(self) -> Dict[str, Union[bool, str]]:
        return {
            'critical': self.critical,
            'value': bytes_to_hex(self.value),
        }


class CRLDistributionPointsBase(ListExtension):
    """Base class for :py:class:`~django_ca.extensions.CRLDistributionPoints` and
    :py:class:`~django_ca.extensions.FreshestCRL`.
    """
    def __hash__(self) -> int:
        return hash((tuple(self.value), self.critical, ))

    def as_text(self) -> str:
        return '\n'.join('* DistributionPoint:\n%s' % textwrap.indent(dp.as_text(), '  ')
                         for dp in self.value)

    @property
    def extension_type(self) -> x509.CRLDistributionPoints:
        return x509.CRLDistributionPoints(distribution_points=[dp.for_extension_type for dp in self.value])

    def parse_value(self, value) -> DistributionPoint:
        if isinstance(value, DistributionPoint):
            return value
        return DistributionPoint(value)

    def serialize(self) -> Dict[str, Union[bool, List[DistributionPointType]]]:
        return {
            'value': [dp.serialize() for dp in self.value],
            'critical': self.critical,
        }

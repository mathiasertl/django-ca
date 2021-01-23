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
from abc import ABC
from abc import abstractmethod
from typing import Any
from typing import Iterable
from typing import Union

from cryptography import x509

from ..typehints import DistributionPointType
from ..typehints import SerializedCRLDistributionPoints
from ..utils import GeneralNameList
from ..utils import format_general_name
from .utils import DistributionPoint


class Extension(ABC):
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


    .. versionchanged:: 1.18.0

       This class is now an abstract base class.

    Parameters
    ----------

    value : list or tuple or dict or str or :py:class:`~cg:cryptography.x509.ExtensionType`
        The value of the extension, the description provides further details.

    Attributes
    ----------

    name
        A human readable name of this extension
    value
        Raw value for this extension. The type various from subclass to subclass.
    critical : bool
        If this extension is marked as critical
    oid
        The OID for this extension.
    key : str
        The key is a reusable ID used in various parts of the application.
    default_critical : bool
        The default critical value if you pass a dict without the ``"critical"`` key.
    """
    key = ''  # must be overwritten by actual classes

    default_critical = False
    name = 'Extension'
    oid: x509.ObjectIdentifier

    def __init__(self, value=None):
        if value is None:
            value = {}

        if isinstance(value, x509.Extension):  # e.g. from a cert object
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

    def __repr__(self) -> str:
        return '<%s: %s, critical=%r>' % (self.name, self.repr_value(), self.critical)

    def __str__(self) -> str:
        return repr(self)

    def _test_value(self) -> None:
        pass

    def as_extension(self):
        """This extension as :py:class:`~cg:cryptography.x509.Extension`."""
        ext = self.extension_type  # extra line to raise NotImplementedError for abstract base classes
        return x509.Extension(oid=self.oid, critical=self.critical, value=ext)

    def as_text(self) -> str:
        """Human-readable version of the *value*, not including the "critical" flag."""
        return self.repr_value()

    @property
    @abstractmethod
    def extension_type(self):
        """cryptography.x509.ExtensionType: The ``ExtensionType`` instance of this extension.

        Implementing classes are expected to implement this function."""

    def for_builder(self):
        """Return kwargs suitable for a :py:class:`~cg:cryptography.x509.CertificateBuilder`.

        Example::

            >>> kwargs = KeyUsage({'value': ['keyAgreement', 'keyEncipherment']}).for_builder()
            >>> builder.add_extension(**kwargs)  # doctest: +SKIP
        """
        return {'extension': self.extension_type, 'critical': self.critical}

    @abstractmethod
    def from_extension(self, value):
        """Load a wrapper class from a cryptography extension instance.

        Implementing classes are expected to implement this function."""

    @abstractmethod
    def from_dict(self, value):
        """Load class from a dictionary.

        Implementing classes are expected to implement this function."""

    def from_other(self, value):
        """Load class from any other value type.

        This class can be overwritten to allow loading classes from different types."""
        raise ValueError('Value is of unsupported type %s' % type(value).__name__)

    @abstractmethod
    def repr_value(self) -> str:
        """String representation of the current value for this extension.

        Implementing classes are expected to implement this function."""

    def serialize(self):
        """Serialize this extension to a string in a way that it can be passed to a constructor again.

        For example, this should always be True::

            >>> ku = KeyUsage({'value': ['keyAgreement', 'keyEncipherment']})
            >>> ku == KeyUsage(ku.serialize())
            True
        """

        return {
            'critical': self.critical,
            'value': self.serialize_value(),
        }

    @abstractmethod
    def serialize_value(self):
        """Serialize the value for this extension.

        Implementing classes are expected to implement this function."""


class UnrecognizedExtension(Extension):
    """Class wrapping any extension this module does **not** support."""

    # pylint: disable=abstract-method; We don't know the extension_type

    def __init__(self, value, name='', error=''):
        self._error = error
        self._name = name
        super().__init__(value)

    def repr_value(self) -> str:
        return '<unprintable>'

    @property
    def extension_type(self):
        return self.value.value

    def from_dict(self, value):
        raise ValueError('%s: Cannot instantiate from dict.' % self.__class__.__name__)

    def from_extension(self, value):
        self.oid = value.oid
        self.value = value

    @property
    def name(self) -> str:
        """Name (best effort) for this extension."""
        if self._name:
            return self._name
        return 'Unsupported extension (OID %s)' % (self.value.oid.dotted_string)

    def as_text(self) -> str:
        if self._error:
            return 'Could not parse extension (%s)' % self._error
        return 'Could not parse extension'

    def serialize_value(self):
        raise ValueError('Cannot serialize an unrecognized extension')


class NullExtension(Extension):
    """Base class for extensions that do not have a value.

    .. versionchanged:: 1.18.0

       This class is now an abstract base class.

    Some extensions, like :py:class:`~django_ca.extensions.OCSPNoCheck` or
    :py:class`~django_ca.extensions.PrecertPoison` do not encode any information, but the presence of the
    extension itself carries meaning.

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

    def __init__(self, value=None):
        self.value = {}
        if not value:
            self.critical = self.default_critical
        else:
            super().__init__(value)

    def __hash__(self) -> int:
        return hash((self.critical, ))

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, type(self)) and self.critical == other.critical

    def __repr__(self) -> str:
        return '<%s: critical=%r>' % (self.__class__.__name__, self.critical)

    def repr_value(self) -> str:
        return ''

    def as_text(self) -> str:
        return self.name

    @property
    def extension_type(self):
        return self.ext_class()  # pylint: disable=no-member; concrete classes are expected to set this

    def from_extension(self, value):
        pass

    def from_dict(self, value):
        pass

    def serialize(self):
        return {'critical': self.critical}

    def serialize_value(self) -> None:
        return


class IterableExtension(Extension):
    """Base class for iterable extensions.

    Extensions of this class can be used just like any other iterable, e.g.:

        >>> e = KeyUsage({'value': ['cRLSign'], 'critical': True})
        >>> 'cRLSign' in e
        True
        >>> len(e)
        1
        >>> for val in e:
        ...     print(val)
        cRLSign
    """

    # pylint: disable=abstract-method; class is itself a base class
    value: Iterable

    def __contains__(self, value):
        return self.parse_value(value) in self.value  # pylint: disable=unsupported-membership-test

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, type(self)) and self.critical == other.critical and self.value == other.value

    def __hash__(self) -> int:
        return hash((tuple(self.serialize_value()), self.critical, ))

    def __iter__(self):
        return iter(self.serialize_value())

    def __len__(self) -> int:
        return len(self.value)

    def repr_value(self) -> str:
        return self.serialize_value()

    def as_text(self) -> str:
        return '\n'.join(['* %s' % v for v in self.serialize_value()])

    def parse_value(self, value):
        """Parse a single value (presumably from an iterable)."""
        return value

    def serialize_value(self):
        """Serialize the whole iterable contained in this extension."""

        return [self.serialize_item(v) for v in self.value]  # pylint: disable=not-an-iterable

    def serialize_item(self, value) -> str:
        """Serialize a single item in the iterable contained in this extension."""

        return value


class ListExtension(IterableExtension):
    """Base class for extensions with multiple ordered values.

    .. versionchanged:: 1.18.0

       This class is now an abstract base class.
    """

    # pylint: disable=abstract-method; class is itself a base class

    def __delitem__(self, key):
        del self.value[key]

    def __getitem__(self, key):
        if isinstance(key, int):
            return self.serialize_item(self.value[key])
        return [self.serialize_item(v) for v in self.value[key]]

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

    def count(self, value: str):
        try:
            return self.value.count(self.parse_value(value))
        except ValueError:
            return 0

    def extend(self, iterable):
        self.value.extend([self.parse_value(n) for n in iterable])
        self._test_value()

    def insert(self, index: int, value):
        self.value.insert(index, self.parse_value(value))

    def pop(self, index: int = -1):
        return self.value.pop(index)

    def remove(self, value):
        return self.value.remove(self.parse_value(value))
    # pylint: enable=missing-function-docstring


class OrderedSetExtension(IterableExtension):
    """Base class for extensions that contain a set of values.

    .. versionchanged:: 1.18.0

       This class is now an abstract base class.

    For reproducibility, any serialization will always sort the values contained in this extension.

    Extensions derived from this class can be used like a normal set, for example:

        >>> e = KeyUsage({'value': {'cRLSign', }})
        >>> e.add('keyAgreement')
        >>> e
        <KeyUsage: ['cRLSign', 'keyAgreement'], critical=True>
        >>> e -= {'keyAgreement', }
        >>> e
        <KeyUsage: ['cRLSign'], critical=True>
    """

    # pylint: disable=abstract-method; class is itself a base class

    name = 'OrderedSetExtension'

    def __and__(self, other):  # & operator == intersection()
        value = self.value & self.parse_iterable(other)
        return self.__class__({'critical': self.critical, 'value': value})

    def __ge__(self, other) -> bool:  # >= relation == issuperset()
        return self.value >= self.parse_iterable(other)

    def __gt__(self, other) -> bool:  # > relation
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

    def __le__(self, other) -> bool:  # <= relation == issubset()
        return self.value <= self.parse_iterable(other)

    def __lt__(self, other) -> bool:  # < relation
        return self.value < self.parse_iterable(other)

    def __or__(self, other):  # | operator == union()
        value = self.value.union(self.parse_iterable(other))
        return self.__class__({'critical': self.critical, 'value': value})

    def __sub__(self, other):  # - operator
        value = self.value - self.parse_iterable(other)
        return self.__class__({'critical': self.critical, 'value': value})

    def __xor__(self, other):  # ^ operator == symmetric_difference()
        value = self.value ^ self.parse_iterable(other)
        return self.__class__({'critical': self.critical, 'value': value})

    def repr_value(self):
        return [str(v) for v in super().repr_value()]

    def parse_iterable(self, iterable):
        """Parse values from the given iterable."""
        return set(self.parse_value(i) for i in iterable)

    def from_dict(self, value):
        self.value = self.parse_iterable(value.get('value', set()))

    def serialize_value(self):
        return list(sorted(self.serialize_item(v) for v in self.value))

    # Implement functions provided by set(). Class mentions that this provides the same methods.
    # pylint: disable=missing-function-docstring

    def add(self, elem):
        self.value.add(self.parse_value(elem))

    def clear(self):
        self.value.clear()

    def copy(self):
        value = self.value.copy()
        return self.__class__({'critical': self.critical, 'value': value})

    def difference(self, *others):  # equivalent to & operator
        value = self.value.difference(*[self.parse_iterable(o) for o in others])
        return self.__class__({'critical': self.critical, 'value': value})

    def difference_update(self, *others):  # equivalent to &= operator
        self.value.difference_update(*[self.parse_iterable(o) for o in others])

    def discard(self, elem):
        self.value.discard(self.parse_value(elem))

    def intersection(self, *others):  # equivalent to & operator
        value = self.value.intersection(*[self.parse_iterable(o) for o in others])
        return self.__class__({'critical': self.critical, 'value': value})

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
        return self.__class__({'critical': self.critical, 'value': value})

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

    def from_dict(self, value):
        value = value.get('value')
        if isinstance(value, GeneralNameList):
            self.value = value
        elif value is None:
            self.value = GeneralNameList()
        else:
            self.value = GeneralNameList(value)

    def from_extension(self, value):
        self.value = GeneralNameList(value.value)

    def serialize_item(self, value):
        return format_general_name(value)


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

    def parse_value(self, value: Union[DistributionPoint, DistributionPointType]) -> DistributionPoint:
        if isinstance(value, DistributionPoint):
            return value
        return DistributionPoint(value)

    def serialize(self) -> SerializedCRLDistributionPoints:
        return {
            'value': [dp.serialize() for dp in self.value],
            'critical': self.critical,
        }

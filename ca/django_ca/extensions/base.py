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
# pylint: disable=missing-function-docstring; https://github.com/PyCQA/pylint/issues/3605

import textwrap
from abc import ABCMeta
from abc import abstractmethod
from typing import Any
from typing import ClassVar
from typing import Collection
from typing import Dict
from typing import Generic
from typing import Hashable
from typing import Iterable
from typing import List
from typing import NoReturn
from typing import Optional
from typing import Set
from typing import Union

import cryptography
from cryptography import x509

from ..typehints import AlternativeNameTypeVar
from ..typehints import ExtensionType
from ..typehints import ExtensionTypeTypeVar
from ..typehints import ParsableDistributionPoint
from ..typehints import ParsableGeneralName
from ..typehints import ParsableGeneralNameList
from ..typehints import ParsableItem
from ..typehints import ParsableNullExtension
from ..typehints import ParsableValue
from ..typehints import SerializedDistributionPoint
from ..typehints import SerializedDistributionPoints
from ..typehints import SerializedExtension
from ..typehints import SerializedItem
from ..typehints import SerializedValue
from ..typehints import UnrecognizedExtensionType
from ..utils import GeneralNameList
from ..utils import format_general_name
from .utils import DistributionPoint


class Extension(Generic[ExtensionTypeTypeVar, ParsableValue, SerializedValue], metaclass=ABCMeta):
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

    key = ""  # must be overwritten by actual classes

    default_critical: bool = False
    default_value: ParsableValue = {}
    name: ClassVar[str]
    oid: ClassVar[x509.ObjectIdentifier]

    def __init__(self, value: Optional[Union[ExtensionType, Dict[str, Any]]] = None) -> None:
        if value is None:
            value = {}

        if isinstance(value, x509.Extension):  # e.g. from a cert object
            self.critical = value.critical
            self.from_extension(value.value)
        elif isinstance(value, dict):  # e.g. from settings
            self.critical = value.get("critical", self.default_critical)
            self.from_dict(value.get("value", self.default_value))

            self._test_value()
        else:
            self.from_other(value)
        if not isinstance(self.critical, bool):
            raise ValueError("%s: Invalid critical value passed" % self.critical)

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, type(self))
            and self.critical == other.critical
            and self.hash_value() == other.hash_value()
        )

    def __hash__(self) -> int:
        return hash(
            (
                self.hash_value(),
                self.critical,
            )
        )

    def __repr__(self) -> str:
        return "<%s: %s, critical=%r>" % (self.name, self.repr_value(), self.critical)

    def __str__(self) -> str:
        return repr(self)

    def _test_value(self) -> None:
        pass

    def as_extension(self) -> ExtensionType:
        """This extension as :py:class:`~cg:cryptography.x509.Extension`."""
        ext = self.extension_type  # extra line to raise NotImplementedError for abstract base classes
        return x509.Extension(oid=self.oid, critical=self.critical, value=ext)

    def as_text(self) -> str:
        """Human-readable version of the *value*, not including the "critical" flag."""
        return self.repr_value()

    @property
    @abstractmethod
    def extension_type(self) -> ExtensionTypeTypeVar:
        """cryptography.x509.ExtensionType: The ``ExtensionType`` instance of this extension.

        Implementing classes are expected to implement this function."""

    def for_builder(self) -> Dict[str, Union[bool, ExtensionTypeTypeVar]]:
        """Return kwargs suitable for a :py:class:`~cg:cryptography.x509.CertificateBuilder`.

        Example::

            >>> ext = KeyUsage({'value': ['keyAgreement', 'keyEncipherment']})
            >>> builder = x509.CertificateBuilder()
            >>> builder.add_extension(*ext.for_builder())  # doctest: +ELLIPSIS
            <cryptography.x509.base.CertificateBuilder object at ...>
        """
        return self.extension_type, self.critical

    @abstractmethod
    def from_extension(self, value: ExtensionTypeTypeVar) -> None:
        """Load a wrapper class from a cryptography extension instance.

        Implementing classes are expected to implement this function."""

    @abstractmethod
    def from_dict(self, value: ParsableValue) -> None:
        """Load class from a dictionary.

        Implementing classes are expected to implement this function."""

    def from_other(self, value: Any) -> None:
        """Load class from any other value type.

        This class can be overwritten to allow loading classes from different types."""
        raise ValueError("Value is of unsupported type %s" % type(value).__name__)

    def hash_value(self) -> Hashable:
        """Return the current extension value in hashable form.

        This function is used for the default implementations for ``hash()`` and the ``==`` equality
        operator.
        """

    @abstractmethod
    def repr_value(self) -> str:
        """String representation of the current value for this extension.

        Implementing classes are expected to implement this function."""

    def serialize(self) -> SerializedExtension:
        """Serialize this extension to a string in a way that it can be passed to a constructor again.

        For example, this should always be True::

            >>> ku = KeyUsage({'value': ['keyAgreement', 'keyEncipherment']})
            >>> ku == KeyUsage(ku.serialize())
            True
        """

        return {
            "critical": self.critical,
            "value": self.serialize_value(),
        }

    @abstractmethod
    def serialize_value(self) -> SerializedValue:
        """Serialize the value for this extension.

        Implementing classes are expected to implement this function."""


class UnrecognizedExtension(Extension[x509.UnrecognizedExtension, None, None]):
    """Class wrapping any extension this module does **not** support."""

    # pylint: disable=abstract-method; We don't know the extension_type
    # pylint: disable=super-init-not-called; UnrecognizedExtension really is a special case

    name: str  # type: ignore[misc]
    oid: x509.ObjectIdentifier  # type: ignore[misc]

    def __init__(self, value: UnrecognizedExtensionType, name: str = "", error: str = ""):
        if not isinstance(value, x509.Extension):
            raise TypeError("Value must be a x509.Extension instance")
        if not isinstance(value.value, x509.UnrecognizedExtension):
            raise TypeError("Extension value must be a x509.UnrecognizedExtension")

        self._error = error
        self.value = value.value
        self.critical = value.critical
        self.oid = value.oid

        if not name:
            name = "Unsupported extension (OID %s)" % (self.oid.dotted_string)
        self.name = name

    def repr_value(self) -> str:
        return "<unprintable>"

    @property
    def extension_type(self) -> x509.UnrecognizedExtension:
        return self.value

    def from_dict(self, value: Any) -> NoReturn:  # pragma: no cover
        raise NotImplementedError

    def from_extension(self, value: Any) -> NoReturn:  # pragma: no cover
        raise NotImplementedError

    def as_text(self) -> str:
        if self._error:
            return "Could not parse extension (%s)" % self._error
        return "Could not parse extension"

    def serialize_value(self) -> NoReturn:
        raise ValueError("Cannot serialize an unrecognized extension")


class NullExtension(Extension[ExtensionTypeTypeVar, None, None]):
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

    name: ClassVar[str]

    def __init__(self, value: Optional[Union[ExtensionTypeTypeVar, ParsableNullExtension]] = None) -> None:
        self.value = {}
        if not value:
            self.critical = self.default_critical
        else:
            super().__init__(value)

    def __hash__(self) -> int:
        return hash((self.critical,))

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, type(self)) and self.critical == other.critical

    def __repr__(self) -> str:
        return "<%s: critical=%r>" % (self.__class__.__name__, self.critical)

    def repr_value(self) -> str:
        return ""

    def as_text(self) -> str:
        return self.name

    @property
    def extension_type(self):
        return self.ext_class()  # pylint: disable=no-member; concrete classes are expected to set this

    def from_extension(self, value: ExtensionTypeTypeVar) -> None:
        pass

    def from_dict(self, value) -> None:
        pass

    def serialize(self):
        return {"critical": self.critical}

    def serialize_value(self) -> None:
        return


class IterableExtension(
    Extension[ExtensionTypeTypeVar, Iterable[ParsableItem], List[SerializedItem]],
    Generic[ExtensionTypeTypeVar, ParsableItem, SerializedItem],
):
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
    value: Collection

    def __contains__(self, value):
        return self.parse_value(value) in self.value  # pylint: disable=unsupported-membership-test

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, type(self)) and self.critical == other.critical and self.value == other.value

    def __hash__(self) -> int:
        return hash(
            (
                tuple(self.serialize_value()),
                self.critical,
            )
        )

    def __iter__(self):
        return iter(self.serialize_value())

    def __len__(self) -> int:
        return len(self.value)

    def repr_value(self) -> str:
        return self.serialize_value()

    def as_text(self) -> str:
        return "\n".join(["* %s" % v for v in self.serialize_value()])

    def parse_value(self, value: ParsableItem):
        """Parse a single value (presumably from an iterable)."""
        return value

    def serialize_value(self) -> List[SerializedItem]:
        """Serialize the whole iterable contained in this extension."""

        return [self.serialize_item(v) for v in self.value]  # pylint: disable=not-an-iterable

    def serialize_item(self, value) -> SerializedItem:
        """Serialize a single item in the iterable contained in this extension."""

        return value


class ListExtension(IterableExtension[ExtensionTypeTypeVar, ParsableItem, SerializedItem]):
    """Base class for extensions with multiple ordered values.

    .. versionchanged:: 1.18.0

       This class is now an abstract base class.
    """

    # pylint: disable=abstract-method; class is itself a base class
    value: List[Any]

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
        self.value = [self.parse_value(v) for v in value]

    def from_extension(self, value):
        self.value = [self.parse_value(v) for v in value]

    # Implement functions provided by list(). Class mentions that this provides the same methods.

    def append(self, value) -> None:
        self.value.append(self.parse_value(value))
        self._test_value()

    def clear(self) -> None:
        self.value.clear()

    def count(self, value: ParsableItem):
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


class OrderedSetExtension(IterableExtension[ExtensionTypeTypeVar, ParsableItem, SerializedItem]):
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

    name = "OrderedSetExtension"
    value: Set

    def __and__(self, other: Iterable[ParsableItem]):  # & operator == intersection()
        value = self.value & self.parse_iterable(other)
        return self.__class__({"critical": self.critical, "value": value})

    def __ge__(self, other: Iterable[ParsableItem]) -> bool:  # >= relation == issuperset()
        return self.value >= self.parse_iterable(other)

    def __gt__(self, other: Iterable[ParsableItem]) -> bool:  # > relation
        return self.value > self.parse_iterable(other)

    def __iand__(self, other: Iterable[ParsableItem]):  # &= operator == intersection_update()
        self.value &= self.parse_iterable(other)
        return self

    def __ior__(self, other: Iterable[ParsableItem]):  # |= operator == update()
        self.value |= self.parse_iterable(other)
        return self

    def __isub__(self, other: Iterable[ParsableItem]):
        self.value -= self.parse_iterable(other)
        return self

    def __ixor__(self, other: Iterable[ParsableItem]) -> None:  # ^= operator == symmetric_difference_update()
        self.value ^= self.parse_iterable(other)

    def __le__(self, other: Iterable[ParsableItem]) -> bool:  # <= relation == issubset()
        return self.value <= self.parse_iterable(other)

    def __lt__(self, other: Iterable[ParsableItem]) -> bool:  # < relation
        return self.value < self.parse_iterable(other)

    def __or__(
        self, other: Iterable[ParsableItem]
    ) -> "OrderedSetExtension[ExtensionTypeTypeVar,ParsableItem, SerializedItem]":  # | operator == union()
        value = self.value.union(self.parse_iterable(other))
        return self.__class__({"critical": self.critical, "value": value})

    def __sub__(
        self, other: Iterable[ParsableItem]
    ) -> "OrderedSetExtension[ExtensionTypeTypeVar,ParsableItem, SerializedItem]":  # - operator
        value = self.value - self.parse_iterable(other)
        return self.__class__({"critical": self.critical, "value": value})

    # ^ operator == symmetric_difference()
    def __xor__(
        self, other: Iterable[ParsableItem]
    ) -> "OrderedSetExtension[ExtensionTypeTypeVar,ParsableItem, SerializedItem]":
        value = self.value ^ self.parse_iterable(other)
        return self.__class__({"critical": self.critical, "value": value})

    def repr_value(self) -> List[str]:
        return [str(v) for v in super().repr_value()]

    def parse_iterable(self, iterable: Iterable[ParsableItem]):
        """Parse values from the given iterable."""
        return set(self.parse_value(i) for i in iterable)

    def from_dict(self, value: Iterable[ParsableItem]) -> None:
        # pylint: disable=attribute-defined-outside-init; https://github.com/PyCQA/pylint/issues/3605
        self.value = self.parse_iterable(value)

    def serialize_value(self) -> List[SerializedItem]:
        return list(sorted(self.serialize_item(v) for v in self.value))

    # Implement functions provided by set(). Class mentions that this provides the same methods.

    def add(self, elem: ParsableItem) -> None:
        self.value.add(self.parse_value(elem))

    def clear(self) -> None:
        self.value.clear()

    def copy(self) -> "OrderedSetExtension[ExtensionTypeTypeVar,ParsableItem, SerializedItem]":
        value = self.value.copy()
        return self.__class__({"critical": self.critical, "value": value})

    def difference(
        self, *others: Iterable[ParsableItem]
    ) -> "OrderedSetExtension[ExtensionTypeTypeVar,ParsableItem, SerializedItem]":  # equivalent to & operator
        value = self.value.difference(*[self.parse_iterable(o) for o in others])
        return self.__class__({"critical": self.critical, "value": value})

    def difference_update(self, *others: Iterable[ParsableItem]) -> None:  # equivalent to &= operator
        self.value.difference_update(*[self.parse_iterable(o) for o in others])

    def discard(self, elem: ParsableItem) -> None:
        self.value.discard(self.parse_value(elem))

    def intersection(
        self, *others: Iterable[ParsableItem]
    ) -> "OrderedSetExtension[ExtensionTypeTypeVar,ParsableItem, SerializedItem]":  # equivalent to & operator
        value = self.value.intersection(*[self.parse_iterable(o) for o in others])
        return self.__class__({"critical": self.critical, "value": value})

    def intersection_update(self, *others: Iterable[ParsableItem]) -> None:  # equivalent to &= operator
        self.value.intersection_update(*[self.parse_iterable(o) for o in others])

    def isdisjoint(self, other: Iterable[ParsableItem]) -> bool:
        return self.value.isdisjoint(self.parse_iterable(other))

    def issubset(self, other: Iterable[ParsableItem]) -> bool:
        return self.value.issubset(self.parse_iterable(other))

    def issuperset(self, other: Iterable[ParsableItem]) -> bool:
        return self.value.issuperset(self.parse_iterable(other))

    def pop(self):
        return self.value.pop()

    def remove(self, elem: ParsableItem):
        return self.value.remove(self.parse_value(elem))

    def symmetric_difference(
        self, other: Iterable[ParsableItem]
    ) -> "OrderedSetExtension[ExtensionTypeTypeVar,ParsableItem, SerializedItem]":  # equivalent to ^ operator
        return self ^ other

    def symmetric_difference_update(self, other: Iterable[ParsableItem]) -> None:
        self ^= other

    def union(
        self, *others: Iterable[ParsableItem]
    ) -> "OrderedSetExtension[ExtensionTypeTypeVar,ParsableItem, SerializedItem]":
        value = self.value.union(*[self.parse_iterable(o) for o in others])
        return self.__class__({"critical": self.critical, "value": value})

    def update(self, *others: Iterable[ParsableItem]) -> None:
        for elem in others:
            self.value.update(self.parse_iterable(elem))


class AlternativeNameExtension(ListExtension[AlternativeNameTypeVar, ParsableGeneralName, str]):
    """Base class for extensions that contain a list of general names.

    This class also allows you to pass :py:class:`~cg:cryptography.x509.GeneralName` instances::

        >>> san = SubjectAlternativeName({'value': [x509.DNSName('example.com'), 'example.net']})
        >>> san
        <SubjectAlternativeName: ['DNS:example.com', 'DNS:example.net'], critical=False>
        >>> 'example.com' in san, 'DNS:example.com' in san, x509.DNSName('example.com') in san
        (True, True, True)

    """

    # pylint: disable=abstract-method; class is itself abstract

    value: GeneralNameList

    def from_dict(self, value: ParsableGeneralNameList) -> None:
        if isinstance(value, GeneralNameList):
            self.value = value
        elif value is None:
            self.value = GeneralNameList()
        else:
            self.value = GeneralNameList(value)

    def from_extension(self, value: AlternativeNameTypeVar) -> None:
        self.value = GeneralNameList(value)

    def serialize_item(self, value: x509.GeneralName) -> str:
        return format_general_name(value)


class CRLDistributionPointsBase(
    ListExtension[ExtensionTypeTypeVar, ParsableDistributionPoint, SerializedDistributionPoint]
):
    """Base class for :py:class:`~django_ca.extensions.CRLDistributionPoints` and
    :py:class:`~django_ca.extensions.FreshestCRL`.
    """

    def __hash__(self) -> int:
        return hash(
            (
                tuple(self.value),
                self.critical,
            )
        )

    def as_text(self) -> str:
        return "\n".join(
            "* DistributionPoint:\n%s" % textwrap.indent(dp.as_text(), "  ") for dp in self.value
        )

    def parse_value(self, value: Union[DistributionPoint, ParsableDistributionPoint]) -> DistributionPoint:
        if isinstance(value, DistributionPoint):
            return value
        return DistributionPoint(value)

    def repr_value(self) -> str:
        # Overwritten so that we can use repr() of utils.DistributionPoint
        return "[%s]" % ", ".join([repr(v) for v in self.value])

    def serialize(self) -> SerializedDistributionPoints:
        return {
            "value": [dp.serialize() for dp in self.value],
            "critical": self.critical,
        }

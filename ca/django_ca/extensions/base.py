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

# pylint: disable=missing-function-docstring; https://github.com/PyCQA/pylint/issues/3605

import abc
import binascii
import collections.abc
import warnings
from typing import (
    Any,
    ClassVar,
    Collection,
    Generic,
    Hashable,
    Iterable,
    Iterator,
    List,
    NoReturn,
    Optional,
    Set,
    Tuple,
    Type,
    Union,
    cast,
    overload,
)

from cryptography import x509
from cryptography.x509.certificate_transparency import LogEntryType, SignedCertificateTimestamp

from ..deprecation import RemovedInDjangoCA124Warning
from ..typehints import (
    AlternativeNameTypeVar,
    ExtensionType,
    ExtensionTypeTypeVar,
    IterableItem,
    ParsableDistributionPoint,
    ParsableExtension,
    ParsableGeneralName,
    ParsableGeneralNameList,
    ParsableItem,
    ParsableSignedCertificateTimestamp,
    ParsableValue,
    SerializedDistributionPoint,
    SerializedDistributionPoints,
    SerializedExtension,
    SerializedItem,
    SerializedNullExtension,
    SerializedSignedCertificateTimestamp,
    SerializedSortableItem,
    SerializedValue,
    SignedCertificateTimestampsBaseTypeVar,
    UnrecognizedExtensionType,
)
from ..utils import GeneralNameList, format_general_name
from .text import extension_as_text
from .utils import DistributionPoint


class Extension(Generic[ExtensionTypeTypeVar, ParsableValue, SerializedValue], metaclass=abc.ABCMeta):
    """Convenience class to handle X509 Extensions.

    The value is a ``dict`` as used by the :ref:`CA_PROFILES <settings-ca-profiles>` setting, but can also use
    a subclass of :py:class:`~cg:cryptography.x509.ExtensionType` from ``cryptography``.

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

    default_critical: ClassVar[bool] = False
    default_value: ClassVar[Any] = {}
    name: ClassVar[str]
    oid: ClassVar[x509.ObjectIdentifier]

    def __init__(
        self, value: Optional[Union["x509.Extension[ExtensionTypeTypeVar]", ParsableExtension]] = None
    ) -> None:
        self.deprecate()
        if value is None:
            value = {}

        if isinstance(value, x509.Extension):  # e.g. from a cert object
            self.critical = value.critical
            self.from_extension(value.value)
        elif isinstance(value, dict):  # e.g. from settings
            self.critical = value.get("critical", self.default_critical)
            self.from_dict(value.get("value", cast(ParsableValue, self.default_value)))

            self._test_value()
        else:
            self.from_other(value)
        if not isinstance(self.critical, bool):
            raise ValueError(f"{self.critical}: Invalid critical value passed")

    def deprecate(self) -> None:
        cls_path = f"{self.__class__.__module__}.{self.__class__.__name__}"
        warnings.warn(
            f"{cls_path} is deprecated and will be removed in django-ca 1.24.0.",
            RemovedInDjangoCA124Warning,
            stacklevel=3,
        )

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
        return f"<{self.name}: {self.repr_value()}, critical={self.critical}>"

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
        return extension_as_text(self.extension_type)

    @property
    @abc.abstractmethod
    def extension_type(self) -> ExtensionTypeTypeVar:
        """The ``ExtensionType`` instance of this extension.

        Implementing classes are expected to implement this function."""

    def for_builder(self) -> Tuple[ExtensionTypeTypeVar, bool]:
        """Return a tuple suitable for a :py:class:`~cg:cryptography.x509.CertificateBuilder`."""
        return self.extension_type, self.critical

    @abc.abstractmethod
    def from_extension(self, value: ExtensionTypeTypeVar) -> None:
        """Load a wrapper class from a cryptography extension instance.

        Implementing classes are expected to implement this function."""

    @abc.abstractmethod
    def from_dict(self, value: ParsableValue) -> None:
        """Load class from a dictionary.

        Implementing classes are expected to implement this function."""

    def from_other(self, value: Any) -> None:
        """Load class from any other value type.

        This class can be overwritten to allow loading classes from different types."""
        raise ValueError(f"Value is of unsupported type {type(value).__name__}")

    def hash_value(self) -> Hashable:
        """Return the current extension value in hashable form.

        This function is used for the default implementations for ``hash()`` and the ``==`` equality
        operator.
        """

    @abc.abstractmethod
    def repr_value(self) -> str:
        """String representation of the current value for this extension.

        Implementing classes are expected to implement this function."""

    def serialize(self) -> SerializedExtension:
        """Serialize this extension to a string in a way that it can be passed to a constructor again."""

        return {
            "critical": self.critical,
            "value": self.serialize_value(),
        }

    @abc.abstractmethod
    def serialize_value(self) -> SerializedValue:
        """Serialize the value for this extension.

        Implementing classes are expected to implement this function."""


class UnrecognizedExtension(Extension[x509.UnrecognizedExtension, None, None]):
    """Class wrapping any extension this module does **not** support."""

    # pylint: disable=super-init-not-called; UnrecognizedExtension really is a special case

    name: str  # type: ignore[misc]
    oid: x509.ObjectIdentifier  # type: ignore[misc]

    # pylint: disable-next=unused-argument
    def __init__(self, value: UnrecognizedExtensionType, name: str = "", error: str = ""):
        self.deprecate()
        if not isinstance(value, x509.Extension):
            raise TypeError("Value must be a x509.Extension instance")
        if not isinstance(value.value, x509.UnrecognizedExtension):
            raise TypeError("Extension value must be a x509.UnrecognizedExtension")

        self._error = error
        self.value = value.value
        self.critical = value.critical
        self.oid = value.oid
        self.name = f"Unsupported extension (OID {self.oid.dotted_string})"

    def repr_value(self) -> str:
        return "<unprintable>"

    @property
    def extension_type(self) -> x509.UnrecognizedExtension:
        return self.value

    def from_dict(self, value: Any) -> NoReturn:
        raise NotImplementedError

    def from_extension(self, value: Any) -> NoReturn:
        raise NotImplementedError

    def serialize_value(self) -> NoReturn:
        raise ValueError("Cannot serialize an unrecognized extension")


class NullExtension(Extension[ExtensionTypeTypeVar, None, None]):
    """Base class for extensions that do not have a value.

    .. versionchanged:: 1.18.0

       This class is now an abstract base class.

    Some extensions, like ``django_ca.extensions.OCSPNoCheck`` or ``django_ca.extensions.PrecertPoison`` do
    not encode any information, but the presence of the extension itself carries meaning.

    Extensions using this base class will ignore any ``"value"`` key in their dict, only the ``"critical"``
    key is relevant.
    """

    ext_class: Type[ExtensionTypeTypeVar]
    name: ClassVar[str]
    value: ClassVar = None

    def __hash__(self) -> int:
        return hash((self.critical,))

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, type(self)) and self.critical == other.critical

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}: critical={self.critical}>"

    def repr_value(self) -> str:
        return ""

    @property
    def extension_type(self) -> ExtensionTypeTypeVar:
        return self.ext_class()

    def from_extension(self, value: ExtensionTypeTypeVar) -> None:
        pass

    def from_dict(self, value: Any) -> None:
        pass

    # type override: only class where value is not set
    def serialize(self) -> SerializedNullExtension:  # type: ignore[override]
        return {"critical": self.critical}

    def serialize_value(self) -> None:
        return


class IterableExtension(
    Extension[ExtensionTypeTypeVar, Iterable[ParsableItem], List[SerializedItem]],
    Generic[ExtensionTypeTypeVar, ParsableItem, SerializedItem, IterableItem],
    metaclass=abc.ABCMeta,
):
    """Base class for iterable extensions.

    Extensions of this class can be used just like any other iterable.
    """

    value: Collection[IterableItem]

    def __contains__(self, value: ParsableItem) -> bool:
        return self.parse_value(value) in self.value

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, type(self)) and self.critical == other.critical and self.value == other.value

    def __hash__(self) -> int:
        return hash(
            (
                tuple(self.serialize_value()),
                self.critical,
            )
        )

    def __iter__(self) -> Iterator[SerializedItem]:
        return iter(self.serialize_value())

    def __len__(self) -> int:
        return len(self.value)

    @abc.abstractmethod
    def clear(self) -> None:
        raise NotImplementedError

    def repr_value(self) -> str:
        joined = ", ".join([repr(v) for v in self.serialize_value()])
        return f"[{joined}]"

    def parse_value(self, value: Union[ParsableItem, IterableItem]) -> IterableItem:
        """Parse a single value (presumably from an iterable)."""
        return cast(IterableItem, value)

    def serialize_value(self) -> List[SerializedItem]:
        """Serialize the whole iterable contained in this extension."""

        return [self.serialize_item(v) for v in self.value]

    def serialize_item(self, value: IterableItem) -> SerializedItem:
        """Serialize a single item in the iterable contained in this extension."""

        return cast(SerializedItem, value)


class ListExtension(IterableExtension[ExtensionTypeTypeVar, ParsableItem, SerializedItem, IterableItem]):
    """Base class for extensions with multiple ordered values.

    .. versionchanged:: 1.18.0

       This class is now an abstract base class.
    """

    # pylint: disable=abstract-method; class is itself a base class
    value: List[IterableItem]

    def __delitem__(self, key: Union[int, slice]) -> None:
        del self.value[key]

    @overload
    def __getitem__(self, key: int) -> SerializedItem:
        ...

    @overload
    def __getitem__(self, key: slice) -> List[SerializedItem]:
        ...

    def __getitem__(self, key: Union[int, slice]) -> Union[SerializedItem, List[SerializedItem]]:
        if isinstance(key, int):
            return self.serialize_item(self.value[key])
        return [self.serialize_item(v) for v in self.value[key]]

    @overload
    def __setitem__(self, key: int, value: ParsableItem) -> None:
        ...

    @overload
    def __setitem__(self, key: slice, value: Iterable[ParsableItem]) -> None:
        ...

    def __setitem__(self, key: Union[int, slice], value: Union[ParsableItem, Iterable[ParsableItem]]) -> None:
        if isinstance(key, slice) and isinstance(value, collections.abc.Iterable):
            self.value[key] = [self.parse_value(v) for v in value]
        elif isinstance(key, int):
            # NOTE: cast() here b/c ParsableItem may also be an Iterable, so we cannot use isinstance() to
            #       narrow the scope known to mypy.
            self.value[key] = self.parse_value(cast(ParsableItem, value))
        else:
            raise TypeError("Can only assign int/item or slice/iterable")

    def from_dict(self, value: Iterable[ParsableItem]) -> None:
        self.value = [self.parse_value(v) for v in value]

    def from_extension(self, value: ExtensionTypeTypeVar) -> None:
        # mypy override: It's not currently possible to augment a bound TypeVar as implementing a Protocol.
        # As such it's impossible to tell mypy that the ExtensionType will be one that implements __iter__.
        self.value = [self.parse_value(v) for v in value]  # type: ignore[attr-defined]

    # Implement functions provided by list(). Class mentions that this provides the same methods.

    def append(self, value: Union[ParsableItem, IterableItem]) -> None:
        self.value.append(self.parse_value(value))
        self._test_value()

    def clear(self) -> None:
        self.value.clear()

    def count(self, value: ParsableItem) -> int:
        try:
            return self.value.count(self.parse_value(value))
        except ValueError:
            return 0

    def extend(self, iterable: Iterable[ParsableItem]) -> None:
        self.value.extend([self.parse_value(n) for n in iterable])
        self._test_value()

    def insert(self, index: int, value: ParsableItem) -> None:
        self.value.insert(index, self.parse_value(value))

    def pop(self, index: int = -1) -> IterableItem:
        return self.value.pop(index)

    def remove(self, value: ParsableItem) -> None:
        self.value.remove(self.parse_value(value))


class OrderedSetExtension(
    IterableExtension[ExtensionTypeTypeVar, ParsableItem, SerializedSortableItem, IterableItem]
):
    """Base class for extensions that contain a set of values.

    For reproducibility, any serialization will always sort the values contained in this extension.

    Extensions derived from this class can be used like a normal set.
    """

    # pylint: disable=abstract-method; class is itself a base class

    name = "OrderedSetExtension"
    value: Set[IterableItem]

    # & operator == intersection()
    def __and__(
        self, other: Iterable[ParsableItem]
    ) -> "OrderedSetExtension[ExtensionTypeTypeVar,ParsableItem, SerializedSortableItem, IterableItem]":
        value = self.value & self.parse_iterable(other)
        return self.__class__({"critical": self.critical, "value": value})

    def __ge__(self, other: Iterable[ParsableItem]) -> bool:  # >= relation == issuperset()
        return self.value >= self.parse_iterable(other)

    def __gt__(self, other: Iterable[ParsableItem]) -> bool:  # > relation
        return self.value > self.parse_iterable(other)

    # &= operator == intersection_update()
    def __iand__(
        self, other: Iterable[ParsableItem]
    ) -> "OrderedSetExtension[ExtensionTypeTypeVar,ParsableItem, SerializedSortableItem, IterableItem]":
        self.value &= self.parse_iterable(other)
        return self

    # |= operator == update()
    def __ior__(
        self, other: Iterable[ParsableItem]
    ) -> "OrderedSetExtension[ExtensionTypeTypeVar,ParsableItem, SerializedSortableItem, IterableItem]":
        self.value |= self.parse_iterable(other)
        return self

    def __isub__(
        self, other: Iterable[ParsableItem]
    ) -> "OrderedSetExtension[ExtensionTypeTypeVar,ParsableItem, SerializedSortableItem, IterableItem]":
        self.value -= self.parse_iterable(other)
        return self

    def __ixor__(self, other: Iterable[ParsableItem]) -> None:  # ^= operator == symmetric_difference_update()
        self.value ^= self.parse_iterable(other)

    def __le__(self, other: Iterable[ParsableItem]) -> bool:  # <= relation == issubset()
        return self.value <= self.parse_iterable(other)

    def __lt__(self, other: Iterable[ParsableItem]) -> bool:  # < relation
        return self.value < self.parse_iterable(other)

    # | operator == union()
    def __or__(
        self, other: Iterable[ParsableItem]
    ) -> "OrderedSetExtension[ExtensionTypeTypeVar,ParsableItem, SerializedSortableItem, IterableItem]":
        value = self.value.union(self.parse_iterable(other))
        return self.__class__({"critical": self.critical, "value": value})

    # - operator
    def __sub__(
        self, other: Iterable[ParsableItem]
    ) -> "OrderedSetExtension[ExtensionTypeTypeVar,ParsableItem, SerializedSortableItem, IterableItem]":
        value = self.value - self.parse_iterable(other)
        return self.__class__({"critical": self.critical, "value": value})

    # ^ operator == symmetric_difference()
    def __xor__(
        self, other: Iterable[ParsableItem]
    ) -> "OrderedSetExtension[ExtensionTypeTypeVar,ParsableItem, SerializedSortableItem, IterableItem]":
        value = self.value ^ self.parse_iterable(other)
        return self.__class__({"critical": self.critical, "value": value})

    def parse_iterable(self, iterable: Iterable[ParsableItem]) -> Set[IterableItem]:
        """Parse values from the given iterable."""
        return set(self.parse_value(i) for i in iterable)

    def from_dict(self, value: Iterable[ParsableItem]) -> None:
        self.value = self.parse_iterable(value)

    def serialize_value(self) -> List[SerializedSortableItem]:
        return list(sorted(self.serialize_item(v) for v in self.value))

    # Implement functions provided by set(). Class mentions that this provides the same methods.

    def add(self, elem: ParsableItem) -> None:
        self.value.add(self.parse_value(elem))

    def clear(self) -> None:
        self.value.clear()

    def copy(
        self,
    ) -> "OrderedSetExtension[ExtensionTypeTypeVar,ParsableItem, SerializedSortableItem, IterableItem]":
        value = self.value.copy()
        return self.__class__({"critical": self.critical, "value": value})

    # equivalent to & operator
    def difference(
        self, *others: Iterable[ParsableItem]
    ) -> "OrderedSetExtension[ExtensionTypeTypeVar,ParsableItem, SerializedSortableItem, IterableItem]":
        value = self.value.difference(*[self.parse_iterable(o) for o in others])
        return self.__class__({"critical": self.critical, "value": value})

    def difference_update(self, *others: Iterable[ParsableItem]) -> None:  # equivalent to &= operator
        self.value.difference_update(*[self.parse_iterable(o) for o in others])

    def discard(self, elem: ParsableItem) -> None:
        self.value.discard(self.parse_value(elem))

    # equivalent to & operator
    def intersection(
        self, *others: Iterable[ParsableItem]
    ) -> "OrderedSetExtension[ExtensionTypeTypeVar,ParsableItem, SerializedSortableItem, IterableItem]":
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

    def pop(self) -> IterableItem:
        return self.value.pop()

    def remove(self, elem: ParsableItem) -> None:
        self.value.remove(self.parse_value(elem))

    # equivalent to ^ operator
    def symmetric_difference(
        self, other: Iterable[ParsableItem]
    ) -> "OrderedSetExtension[ExtensionTypeTypeVar,ParsableItem, SerializedSortableItem, IterableItem]":
        return self ^ other

    def symmetric_difference_update(self, other: Iterable[ParsableItem]) -> None:  # equivalent to ^= operator
        self.value ^= self.parse_iterable(other)

    def union(
        self, *others: Iterable[ParsableItem]
    ) -> "OrderedSetExtension[ExtensionTypeTypeVar,ParsableItem, SerializedSortableItem, IterableItem]":
        value = self.value.union(*[self.parse_iterable(o) for o in others])
        return self.__class__({"critical": self.critical, "value": value})

    def update(self, *others: Iterable[ParsableItem]) -> None:
        for elem in others:
            self.value.update(self.parse_iterable(elem))


class AlternativeNameExtension(
    ListExtension[AlternativeNameTypeVar, ParsableGeneralName, str, x509.GeneralName],
    Generic[AlternativeNameTypeVar],
):
    """Base class for extensions that contain a list of general names.

    This class also allows you to pass :py:class:`~cg:cryptography.x509.GeneralName` instances.
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
    ListExtension[
        ExtensionTypeTypeVar, ParsableDistributionPoint, SerializedDistributionPoint, DistributionPoint
    ],
    Generic[ExtensionTypeTypeVar],
    metaclass=abc.ABCMeta,
):
    """Base class for ``django_ca.extensions.CRLDistributionPoints`` and
    ``django_ca.extensions.FreshestCRL``.
    """

    def __hash__(self) -> int:
        return hash(
            (
                tuple(self.value),
                self.critical,
            )
        )

    def parse_value(self, value: Union[DistributionPoint, ParsableDistributionPoint]) -> DistributionPoint:
        if isinstance(value, DistributionPoint):
            return value
        return DistributionPoint(value)

    def repr_value(self) -> str:
        # Overwritten so that we can use repr() of utils.DistributionPoint
        joined = ", ".join([repr(v) for v in self.value])
        return f"[{joined}]"

    def serialize(self) -> SerializedDistributionPoints:
        return {
            "value": [dp.serialize() for dp in self.value],
            "critical": self.critical,
        }


class SignedCertificateTimestampsBase(
    ListExtension[
        SignedCertificateTimestampsBaseTypeVar,
        ParsableSignedCertificateTimestamp,
        SerializedSignedCertificateTimestamp,
        SignedCertificateTimestamp,
    ],
    Generic[SignedCertificateTimestampsBaseTypeVar],
):
    """Base class for extensions containing signed certificate timestamps.

    Derived classes cannot be instantiated by any custom value, only the matching subclass of
    :py:class:`~cg:cryptography.x509.ExtensionType` is supported. Unfortunately cryptography currently does
    not support creating instances of ``SignedCertificateTimestamp`` (see `issue #4820
    <https://github.com/pyca/cryptography/issues/4820>`_). This extension thus also has no way of
    adding/removing any elements. Any attempt of updating an instance will raise ``NotImplementedError``.

    .. seealso::

       * `RFC 6962 <https://tools.ietf.org/html/rfc6962.html>`_
       * https://certificate.transparency.dev/howctworks/
    """

    _timeformat = "%Y-%m-%d %H:%M:%S.%f"
    LOG_ENTRY_TYPE_MAPPING = {
        LogEntryType.PRE_CERTIFICATE: "precertificate",
        LogEntryType.X509_CERTIFICATE: "x509_certificate",
    }
    extension_cls: Type[SignedCertificateTimestampsBaseTypeVar]
    value: List[SignedCertificateTimestamp]

    def __contains__(self, value: ParsableSignedCertificateTimestamp) -> bool:
        if isinstance(value, dict):
            return value in self.serialize_value()
        return value in self.value

    def __delitem__(self, key):  # type: ignore
        raise NotImplementedError

    def __hash__(self) -> int:
        # serialize_iterable returns a dict, which is unhashable
        return hash(
            (
                tuple(self.value),
                self.critical,
            )
        )

    def repr_value(self) -> str:
        if len(self.value) == 1:  # pragma: no cover  # We cannot currently create such an extension
            return "1 timestamp"
        return f"{len(self.value)} timestamps"

    def __setitem__(self, key, value):  # type: ignore
        raise NotImplementedError

    def count(self, value: ParsableSignedCertificateTimestamp) -> int:
        if isinstance(value, dict):
            return self.serialize_value().count(value)
        return self.value.count(value)

    def extend(self, iterable):  # type: ignore
        raise NotImplementedError

    @property
    def extension_type(self) -> SignedCertificateTimestampsBaseTypeVar:
        return self.extension_cls(self.value)

    def from_extension(self, value: SignedCertificateTimestampsBaseTypeVar) -> None:
        self.value = list(value)

    def insert(self, index, value):  # type: ignore
        raise NotImplementedError

    def pop(self, index=-1):  # type: ignore
        raise NotImplementedError

    def remove(self, value):  # type: ignore
        raise NotImplementedError

    def serialize_item(self, value: SignedCertificateTimestamp) -> SerializedSignedCertificateTimestamp:
        return {
            "log_id": binascii.hexlify(value.log_id).decode("utf-8"),
            "timestamp": value.timestamp.strftime(self._timeformat),
            "type": SignedCertificateTimestampsBase.LOG_ENTRY_TYPE_MAPPING[value.entry_type],
            "version": value.version.name,
        }

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

"""Base classes for testing :py:mod:`django_ca.extensions`."""

import abc
import functools
import json
import operator
import typing

from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier

from django.utils.functional import cached_property
from django.utils.safestring import mark_safe

from ...constants import OID_DEFAULT_CRITICAL
from ...extensions import (
    KEY_TO_EXTENSION,
    OID_TO_EXTENSION,
    CRLDistributionPoints,
    Extension,
    FreshestCRL,
    parse_extension,
)
from ...extensions.base import IterableExtension, ListExtension, NullExtension, OrderedSetExtension
from ...extensions.utils import (
    DistributionPoint,
    extension_as_admin_html,
    extension_as_text,
    serialize_extension,
)
from ...models import X509CertMixin
from ...typehints import CRLExtensionTypeTypeVar, ParsableDistributionPoint, ParsableExtension, TypedDict
from . import dns, rdn, uri
from .mixins import TestCaseMixin, TestCaseProtocol

ExtensionTypeVar = typing.TypeVar("ExtensionTypeVar", bound=Extension)  # type: ignore[type-arg]
NullExtensionTypeVar = typing.TypeVar("NullExtensionTypeVar", bound=NullExtension)  # type: ignore[type-arg]
IterableExtensionTypeVar = typing.TypeVar(
    "IterableExtensionTypeVar", bound=IterableExtension  # type: ignore[type-arg]
)
ListExtensionTypeVar = typing.TypeVar("ListExtensionTypeVar", bound=ListExtension)  # type: ignore[type-arg]
OrderedSetExtensionTypeVar = typing.TypeVar(
    "OrderedSetExtensionTypeVar", bound=OrderedSetExtension  # type: ignore[type-arg]
)
_TestValueDict = TypedDict(
    "_TestValueDict",
    {
        "admin_html": str,
        "values": typing.List[typing.Any],
        "expected": typing.Any,
        "expected_repr": str,
        "expected_serialized": typing.Any,
        "extension_type": x509.ExtensionType,
        "text": "str",
    },
)
DistributionPointsBaseTypeVar = typing.TypeVar(
    "DistributionPointsBaseTypeVar", CRLDistributionPoints, FreshestCRL
)
IterableTypeVar = typing.TypeVar("IterableTypeVar", list, set)  # type: ignore[type-arg]


class TestValueDict(_TestValueDict, total=False):
    """Value used to define generic test cases."""

    expected_djca: typing.Any
    expected_bool: bool


TestValues = typing.Dict[str, TestValueDict]


class AbstractExtensionTestMixin(typing.Generic[ExtensionTypeVar], TestCaseMixin, metaclass=abc.ABCMeta):
    """TestCase mixin for tests that all extensions are expected to pass, including abstract base classes."""

    ext_class: typing.Type[ExtensionTypeVar]
    ext_class_key: str
    ext_class_name: str
    test_values: TestValues
    force_critical: typing.Optional[bool] = None
    repr_tmpl = "<{name}: {value}, critical={critical}>"

    def assertExtensionEqual(  # pylint: disable=invalid-name
        self, first: ExtensionTypeVar, second: ExtensionTypeVar
    ) -> None:
        """Test if an extension is really really equal.

        This function should compare extension internals directly not via the __eq__ function.
        """
        self.assertEqual(first.__class__, second.__class__)
        self.assertEqual(first.critical, second.critical)
        self.assertEqual(first, second)

    def assertSerialized(  # pylint: disable=invalid-name
        self, ext: ExtensionTypeVar, config: TestValueDict, critical: typing.Optional[bool] = None
    ) -> None:
        """Assert that the extension can be serialized as expected."""
        if critical is None:
            critical = self.ext_class.default_critical

        serialized = ext.serialize()
        self.assertEqual(
            serialized,
            {
                "value": config["expected_serialized"],
                "critical": critical,
            },
        )
        json.dumps(serialized)  # make sure that we can actually serialize the value

    @property
    def critical_values(self) -> typing.Iterator[bool]:
        """Loop through all possible values for critical.

        This may or may not include both boolean values depending on ``force_critical``.
        """
        if self.force_critical is not False:  # pragma: no cover; not currently used
            yield True
        if self.force_critical is not True:
            yield False

    def ext(self, value: typing.Any = None, critical: typing.Optional[bool] = None) -> ExtensionTypeVar:
        """Get an extension instance with the given value."""
        if value is None:
            value = {}

        if isinstance(value, x509.extensions.ExtensionType):
            if critical is None:
                critical = self.ext_class.default_critical
            ext = x509.extensions.Extension(oid=self.ext_class.oid, critical=critical, value=value)
            return self.ext_class(ext)

        val: ParsableExtension = {"value": value}
        if critical is not None:
            val["critical"] = critical
        return self.ext_class(val)

    def test_parse(self) -> None:
        for config in self.test_values.values():
            for value in config["values"]:
                critical = OID_DEFAULT_CRITICAL[self.ext_class.oid]
                ext = parse_extension(self.ext_class_key, {"value": value, "critical": critical})
                expected = x509.Extension(
                    oid=self.ext_class.oid, critical=critical, value=config["extension_type"]
                )
                self.assertEqual(ext, expected)
                self.assertEqual(parse_extension(self.ext_class_key, ext), ext)
                self.assertEqual(parse_extension(self.ext_class_key, ext.value), ext)

    @abc.abstractmethod
    def test_config(self) -> None:
        """Test basic extension configuration."""

    def test_hash(self) -> None:
        """Test hash()."""
        for config in self.test_values.values():
            ext = self.ext(config["expected"])
            ext_critical = self.ext(config["expected"], critical=True)
            ext_not_critical = self.ext(config["expected"], critical=False)

            if self.ext_class.default_critical:
                self.assertEqual(hash(ext), hash(ext_critical))
                self.assertNotEqual(hash(ext), hash(ext_not_critical))
            else:
                self.assertEqual(hash(ext), hash(ext_not_critical))
                self.assertNotEqual(hash(ext), hash(ext_critical))
            self.assertNotEqual(hash(ext_critical), hash(ext_not_critical))

            for other_config in self.test_values.values():
                other_ext = self.ext(other_config["expected"])
                other_ext_critical = self.ext(other_config["expected"], critical=True)
                other_ext_not_critical = self.ext(other_config["expected"], critical=False)

                if config["expected"] == other_config["expected"]:
                    self.assertEqual(hash(ext), hash(other_ext))
                    self.assertEqual(hash(ext_critical), hash(other_ext_critical))
                    self.assertEqual(hash(ext_not_critical), hash(other_ext_not_critical))
                else:
                    self.assertNotEqual(hash(ext), hash(other_ext))
                    self.assertNotEqual(hash(ext_critical), hash(other_ext_critical))
                    self.assertNotEqual(hash(ext_not_critical), hash(other_ext_not_critical))

    def test_eq(self) -> None:
        """Test extension equality (``==``)."""
        for values in self.test_values.values():
            ext = self.ext(values["expected"])
            self.assertEqual(ext, ext)
            ext_critical = self.ext(values["expected"], critical=True)
            self.assertEqual(ext_critical, ext_critical)
            ext_not_critical = self.ext(values["expected"], critical=False)
            self.assertEqual(ext_not_critical, ext_not_critical)

            for value in values["values"]:
                ext_1 = self.ext(value)
                self.assertEqual(ext, ext_1)
                ext_2 = self.ext(value, critical=True)
                self.assertEqual(ext_critical, ext_2)
                ext_3 = self.ext(value, critical=False)
                self.assertEqual(ext_not_critical, ext_3)

    def test_init(self) -> None:
        """Test that the constructor behaves equal regardles of input value."""
        for config in self.test_values.values():
            expected = self.ext(config["expected"])

            for value in config["values"]:
                self.assertExtensionEqual(self.ext(value), expected)

            if config.get("extension_type"):
                self.assertExtensionEqual(self.ext(config["extension_type"]), expected)

            # Now the same with explicit critical values
            for critical in self.critical_values:
                expected = self.ext(config["expected"], critical=critical)

                for value in config["values"]:
                    self.assertExtensionEqual(self.ext(value, critical=critical), expected)

                if config.get("extension_type"):
                    self.assertEqual(self.ext(config["extension_type"], critical=critical), expected)

    def test_init_no_bool_critical(self) -> None:
        """Test creating an extension with a non-bool critical value."""
        class_name = "example_class"

        class _Example:
            def __str__(self) -> str:
                return class_name

        for config in self.test_values.values():
            for value in config["values"]:
                if isinstance(value, x509.extensions.ExtensionType):
                    continue  # self.ext() would construct an x509.Extension and the constructor would fail

                with self.assertRaisesRegex(ValueError, f"^{class_name}: Invalid critical value passed$"):
                    self.ext(value, critical=_Example())  # type: ignore[arg-type]

    def test_init_unknown_type(self) -> None:
        """Try creating an extension with a value of unknown type."""

        class _Example:
            pass

        with self.assertRaisesRegex(ValueError, "^Value is of unsupported type _Example$"):
            self.ext_class(_Example())  # type: ignore[arg-type] # what we're testing here

    def test_ne(self) -> None:
        """Test ``!=`` (not-equal) operator."""
        for config in self.test_values.values():
            if self.force_critical is None:
                self.assertNotEqual(
                    self.ext(config["expected"], critical=True), self.ext(config["expected"], critical=False)
                )

            for other_config in self.test_values.values():
                if self.force_critical is None:
                    self.assertNotEqual(
                        self.ext(config["expected"], critical=True),
                        self.ext(other_config["expected"], critical=False),
                    )
                if self.force_critical is None:
                    self.assertNotEqual(
                        self.ext(config["expected"], critical=False),
                        self.ext(other_config["expected"], critical=True),
                    )

                if config["expected"] != other_config["expected"]:
                    self.assertNotEqual(self.ext(config["expected"]), self.ext(other_config["expected"]))

    def test_repr(self) -> None:
        """Test repr()."""
        for config in self.test_values.values():
            for value in config["values"]:
                ext = self.ext(value)
                exp = config["expected_repr"]
                expected = self.repr_tmpl.format(
                    name=self.ext_class_name, value=exp, critical=ext.default_critical
                )
                self.assertEqual(repr(ext), expected)

                for critical in self.critical_values:
                    ext = self.ext(value, critical=critical)
                    expected = self.repr_tmpl.format(name=self.ext_class_name, value=exp, critical=critical)
                    self.assertEqual(repr(ext), expected)

    def test_serialize(self) -> None:
        """Test serialization of extension."""
        for config in self.test_values.values():
            ext = self.ext(config["expected"])
            self.assertSerialized(ext, config)

            for critical in self.critical_values:
                ext = self.ext(config["expected"], critical=critical)
                self.assertSerialized(ext, config, critical=critical)

                ext_type = config["extension_type"]
                cg_ext = x509.Extension(oid=ext_type.oid, critical=critical, value=ext_type)
                expected_serialized = {"critical": critical, "value": config["expected_serialized"]}
                self.assertEqual(serialize_extension(cg_ext), expected_serialized)

    def test_str(self) -> None:
        """Test str()."""
        for config in self.test_values.values():
            for value in config["values"]:
                ext = self.ext(value)
                exp = config["expected_repr"]

                expected = self.repr_tmpl.format(
                    name=self.ext_class_name, value=exp, critical=ext.default_critical
                )
                self.assertEqual(str(ext), expected)

                for critical in self.critical_values:
                    ext = self.ext(value, critical=critical)
                    expected = self.repr_tmpl.format(name=self.ext_class_name, value=exp, critical=critical)
                    self.assertEqual(str(ext), expected)

    def test_as_text(self) -> None:
        """Test rendering an extension as text."""
        for name, config in self.test_values.items():
            self.assertEqual(extension_as_text(config["extension_type"]), config["text"], name)

    def test_as_admin_html(self) -> None:
        """Test rendering an extension as text."""
        for name, config in self.test_values.items():
            ext_value = config["extension_type"]
            ext = x509.Extension(oid=ext_value.oid, critical=True, value=ext_value)
            html = extension_as_admin_html(ext)
            self.assertInHTML(config["admin_html"], mark_safe(html), msg_prefix=html)

    def test_value(self) -> None:
        """Test that value property can be used for the constructor."""
        for config in self.test_values.values():
            ext = self.ext(value=config["expected"])
            # NOTE: Tests for classes that do not set the value attribute override this function
            self.assertExtensionEqual(ext, self.ext(ext.value))  # type: ignore[attr-defined]


class ExtensionTestMixin(typing.Generic[ExtensionTypeVar], AbstractExtensionTestMixin[ExtensionTypeVar]):
    """Override generic implementations to use test_value property."""

    def test_as_extension(self) -> None:
        """Test the as_extension property."""
        for config in self.test_values.values():
            ext = self.ext(config["expected"])
            cg_ext = x509.extensions.Extension(
                oid=self.ext_class.oid,
                critical=self.ext_class.default_critical,
                value=config["extension_type"],
            )
            self.assertEqual(ext.as_extension(), cg_ext)

            for critical in self.critical_values:
                ext = self.ext(config["expected"], critical=critical)
                self.assertEqual(
                    ext.as_extension(),
                    x509.extensions.Extension(
                        oid=self.ext_class.oid, critical=critical, value=config["extension_type"]
                    ),
                )

    def test_config(self) -> None:
        self.assertTrue(issubclass(self.ext_class, Extension))
        self.assertEqual(self.ext_class.key, self.ext_class_key)
        self.assertEqual(self.ext_class.name, self.ext_class_name)

        # Test some basic properties (just to be sure)
        self.assertIsInstance(self.ext_class.oid, ObjectIdentifier)
        self.assertIsInstance(self.ext_class.key, str)
        self.assertGreater(len(self.ext_class.key), 0)
        self.assertIsInstance(self.ext_class.name, str)
        self.assertGreater(len(self.ext_class.name), 0)

        # Test mapping dicts
        self.assertEqual(KEY_TO_EXTENSION[self.ext_class.key], self.ext_class)
        self.assertEqual(OID_TO_EXTENSION[self.ext_class.oid], self.ext_class)

        # test that the model matches
        self.assertTrue(hasattr(X509CertMixin, self.ext_class.key))
        self.assertIsInstance(getattr(X509CertMixin, self.ext_class.key), cached_property)

    def test_extension_type(self) -> None:
        """Test extension_type property."""
        for config in self.test_values.values():
            ext = self.ext(config["expected"])
            self.assertEqual(ext.extension_type, config["extension_type"])

    def test_for_builder(self) -> None:
        """Test the for_builder() method."""
        for config in self.test_values.values():
            ext = self.ext(config["expected"])
            self.assertEqual(ext.for_builder(), (config["extension_type"], self.ext_class.default_critical))

            for critical in self.critical_values:
                ext = self.ext(config["expected"], critical=critical)
                self.assertEqual(ext.for_builder(), (config["extension_type"], critical))


class NullExtensionTestMixin(ExtensionTestMixin[NullExtensionTypeVar]):
    """TestCase mixin for tests that all extensions are expected to pass, including abstract base classes."""

    repr_tmpl = "<{name}: critical={critical}>"

    def assertExtensionEqual(self, first: ExtensionTypeVar, second: ExtensionTypeVar) -> None:
        """Test if an extension is really really equal.

        This function should compare extension internals directly not via the __eq__ function.
        """
        # TODO: could be removed probably?
        self.assertEqual(first.__class__, second.__class__)
        self.assertEqual(first.critical, second.critical)

    def assertSerialized(
        self, ext: NullExtensionTypeVar, config: typing.Any, critical: typing.Optional[bool] = None
    ) -> None:
        if critical is None:
            critical = self.ext_class.default_critical
        self.assertEqual(ext.serialize(), {"critical": critical})

    def test_dummy_functions(self) -> None:
        """``NullExtension`` implements abstract functions for the value which are in reality unused."""
        self.assertIsNone(self.ext_class().serialize_value())
        self.assertEqual(self.ext_class().repr_value(), "")


class IterableExtensionTestMixin(typing.Generic[IterableExtensionTypeVar, IterableTypeVar], TestCaseProtocol):
    """Mixin for testing IterableExtension-based extensions."""

    container_type: typing.Type[IterableTypeVar]
    test_values: TestValues
    ext_class: typing.Type[IterableExtensionTypeVar]
    invalid_values: typing.List[typing.Any] = []

    if typing.TYPE_CHECKING:
        # pylint: disable=missing-function-docstring,unused-argument
        def ext(
            self, value: typing.Any = None, critical: typing.Optional[bool] = None
        ) -> IterableExtensionTypeVar:
            ...

        def assertExtensionEqual(  # pylint: disable=invalid-name
            self, first: IterableExtensionTypeVar, second: IterableExtensionTypeVar
        ) -> None:
            ...

    def assertIsCopy(
        # pylint: disable=invalid-name
        self,
        orig: typing.Any,
        new: typing.Any,
        expected_value: typing.Any,
    ) -> None:
        """Assert that `new` is a different instance then `other` and has possibly updated values."""
        self.assertEqual(new.value, expected_value)
        self.assertIsNot(orig, new)  # assert that this is a different instance
        self.assertIsNot(orig.value, new.value)  # value is also different instance

    def assertSameInstance(  # pylint: disable=invalid-name
        self, orig_id: int, orig_value_id: int, new: IterableExtensionTypeVar, expected_value: typing.Any
    ) -> None:
        """Assert that `new` is still the same instance and has the expected value."""
        self.assertEqual(new.value, expected_value)
        self.assertEqual(id(new), orig_id)  # assert that this is really the same instance
        self.assertEqual(id(new.value), orig_value_id)

    def assertEqualFunction(  # pylint: disable=invalid-name
        self,
        func: typing.Callable[..., typing.Any],
        init: typing.Any,
        value: typing.Any,
        update: bool = True,
        infix: bool = True,
        set_init: typing.Optional[typing.Set[typing.Any]] = None,
        set_value: typing.Any = None,
        raises: typing.Optional[typing.Tuple[typing.Type[Exception], str]] = None,
    ) -> None:
        """Assert that the given function `func` behaves the same way on a set and on the tested extension.

        This example would test if ``set.update()`` and ``self.ext_class.update()`` would behave the same way,
        given a particular initial value and a particular value::

            >>> assertEqualFunction(lambda s, o: s.update(o), {'foo', }, {'bar', }, update=True, infix=False)

        which effectively tests::

            >>> s = {'foo, '}.update({'bar', })
            >>> e = self.ext_class({'value': {'foo, '}}).update({'bar', })
            >>> s == e.value

        If the extension class internally maps the values to internal (e.g. cryptography-based) values, you
        can override the ``set_value`` parameter to pass the equivalent mapped value instead.

        Parameters
        ----------
        func : func
            The function to test
        init : set
            The initial value for the extension and the set.
        value
            The value to apply the function to.
        set_init
            The initial value for the initial set, if different from the extension value.
        set_value
            The value to apply to the set function, if different from the extension value. This is useful if
            the extension internally maps to different values.
        update : bool
            If the function updates the extension in place. If ``True``, `assertEqualFunction`` will test that
            ``f`` will return the same object instance.
        infix : bool
            If the function represents an infix operator (some checks are different in this case).
        raises :
        """
        if set_value is None:
            set_value = value
        if set_init is None:
            set_init = init

        container = self.container_type(set_init)
        ext = self.ext_class({"value": init})

        if update is True:
            orig_id, orig_value_id = id(ext), id(ext.value)

            if raises:
                with self.assertRaisesRegex(*raises):
                    func(container, set_value)
                with self.assertRaisesRegex(*raises):
                    func(ext, value)
            elif infix is True:
                # infix functions from the operator module (e.g. operator.ixor) return the updated value,
                # while the function equivalent returns None. For example:
                #   >>> s.symmetric_difference_update({'foo'}) is None
                #
                # which is equivalent to:
                #   >>> s ^= {'foo'}
                #
                # but:
                #   >>> operator.ixor(s, {'foo'}) == {'foo'}  # and not None, like above
                func(container, set_value)
                func(ext, value)
            else:
                self.assertIsNone(func(container, set_value))  # apply to set
                self.assertIsNone(func(ext, value))

            # Note: Also checked when exception is raised, to make sure that it hasn't changed
            self.assertSameInstance(orig_id, orig_value_id, ext, expected_value=container)
        else:
            ext_updated = func(ext, value)
            self.assertEqual(ext.__class__, ext_updated.__class__)
            s_updated = func(container, set_value)  # apply to set
            self.assertIsCopy(ext, ext_updated, s_updated)

    def test_clear(self) -> None:
        """Test ext.clear()."""
        for values in self.test_values.values():
            ext = self.ext(values["expected"])
            ext.clear()
            self.assertEqual(len(ext.value), 0)

    def test_in(self) -> None:
        """Test the ``in`` operator."""
        for config in self.test_values.values():
            ext = self.ext_class({"value": config["expected"]})
            for values in config["values"]:
                for value in values:
                    self.assertIn(value, ext)

    def test_len(self) -> None:
        """Test len(ext)."""
        for values in self.test_values.values():
            self.assertEqual(len(self.ext_class({"value": values["expected"]})), len(values["expected"]))

    def test_not_in(self) -> None:
        """Test the ``not in`` operator."""
        for config in self.test_values.values():
            for values in config["values"]:
                ext = self.ext_class({"value": set()})

                for value in values:
                    self.assertNotIn(value, ext)
                    self.assertEqual(len(ext), 0)


class ListExtensionTestMixin(
    typing.Generic[ListExtensionTypeVar],
    IterableExtensionTestMixin[ListExtensionTypeVar, list],  # type: ignore[type-arg] # pragma: py<3.8
):
    """Mixin for testing ListExtension-based extensions."""

    # pylint: disable=unnecessary-lambda; assertion functions require passing lambda functions

    container_type = list

    def test_append(self) -> None:
        """Test ext.append()."""
        for config in self.test_values.values():
            if not config["expected"]:
                continue  # we don't have values to append

            for values in config["values"]:
                expected = self.ext(config["expected"])
                ext = self.ext(values[:-1])  # all but the last item
                ext.append(values[-1])
                self.assertExtensionEqual(ext, expected)

    def test_count(self) -> None:
        """Test ext.count()."""
        for config in self.test_values.values():
            ext = self.ext(config["expected"])
            for values in config["values"]:
                for expected_elem, other_elem in zip(config["expected"], values):
                    self.assertEqual(config["expected"].count(expected_elem), ext.count(expected_elem))
                    self.assertEqual(config["expected"].count(expected_elem), ext.count(other_elem))

        for value in self.invalid_values:
            for config in self.test_values.values():
                ext = self.ext(config["expected"])
                self.assertEqual(ext.count(value), 0)

    def test_del(self) -> None:
        """Test item deletion (e.g. ``del ext[0]``)."""
        for config in self.test_values.values():
            ext = self.ext(config["expected"])
            self.assertEqual(len(ext), len(config["expected"]))

            for _val in config["expected"]:  # loop so that we subsequently delete all values
                del ext[0]
            self.assertEqual(len(ext), 0)

            with self.assertRaisesRegex(IndexError, r"^list assignment index out of range$"):
                del ext[0]

    def test_del_slices(self) -> None:
        """Test deleting slices."""
        for config in self.test_values.values():
            ext = self.ext(config["expected"])
            del ext[0:]
            self.assertEqual(len(ext), 0)

    def test_extend(self) -> None:
        """Test ext.extend()."""
        # pylint: disable-next=unnecessary-lambda-assignment  # just much shorter
        func = lambda c, j: c.extend(j)  # NOQA[E371]
        for config in self.test_values.values():
            set_value = config["expected"]
            if "expected_djca" in config:
                set_value = config["expected_djca"]

            self.assertEqualFunction(
                func,
                init=config["expected"],
                value=config["expected"],
                set_init=set_value,
                set_value=set_value,
            )
            self.assertEqualFunction(
                func,
                init=config["expected"],
                value=config["expected"][0:],
                set_init=set_value,
                set_value=set_value[0:],
            )
            self.assertEqualFunction(
                func, config["expected"], config["expected"][1:], set_init=set_value, set_value=set_value[1:]
            )
            self.assertEqualFunction(
                func, config["expected"], config["expected"][:2], set_init=set_value, set_value=set_value[:2]
            )

    def test_getitem(self) -> None:
        """Test item getter (e.g. ``x = ext[0]``)."""
        # pylint: disable-next=unnecessary-lambda-assignment  # just much shorter
        func = lambda c, j: operator.getitem(c, j)  # NOQA[E371]
        for config in self.test_values.values():
            ct_expected = config["expected"]
            if "expected_djca" in config:
                ct_expected = config["expected_djca"]

            for values in config["values"]:
                for i in range(0, len(values)):
                    self.assertEqualFunction(func, values, i, set_init=ct_expected)

                self.assertEqualFunction(
                    func,
                    config["expected"],
                    len(config["expected"]),
                    set_init=ct_expected,
                    raises=(IndexError, r"^list index out of range$"),
                )

    def test_getitem_slices(self) -> None:
        """Test getting slices (e.g. ``x = ext[0:1]``)."""
        # pylint: disable-next=unnecessary-lambda-assignment  # just much shorter
        func = lambda c, j: operator.getitem(c, j)  # NOQA[E371]
        for config in self.test_values.values():
            ct_expected = config["expected"]
            if "expected_djca" in config:
                ct_expected = config["expected_djca"]

            for values in config["values"]:
                self.assertEqualFunction(func, values, slice(1), set_init=ct_expected)
                self.assertEqualFunction(func, values, slice(0, 1), set_init=ct_expected)
                self.assertEqualFunction(func, values, slice(0, 2), set_init=ct_expected)
                self.assertEqualFunction(func, values, slice(0, 2, 2), set_init=ct_expected)

    def test_insert(self) -> None:
        """Test ext.insert()."""
        for config in self.test_values.values():
            ct_expected = config["expected"]
            if "expected_djca" in config:
                ct_expected = config["expected_djca"]

            for values in config["values"]:
                for expected_value, value in zip(ct_expected, values):
                    kwargs = {"infix": False, "set_value": expected_value}
                    self.assertEqualFunction(lambda c, e: c.insert(0, e), [], value, **kwargs)
                    self.assertEqualFunction(
                        lambda c, e: c.insert(0, e), config["expected"], value, set_init=ct_expected, **kwargs
                    )
                    self.assertEqualFunction(
                        lambda c, e: c.insert(1, e), config["expected"], value, set_init=ct_expected, **kwargs
                    )
                    self.assertEqualFunction(
                        lambda c, e: c.insert(9, e), config["expected"], value, set_init=ct_expected, **kwargs
                    )

    def test_pop(self) -> None:
        """Test ext.pop()."""
        for config in self.test_values.values():
            for values in config["values"]:
                ext = self.ext(values)

                if config["expected"]:
                    with self.assertRaisesRegex(IndexError, "^pop index out of range$"):
                        ext.pop(len(config["expected"]))

                exp = reversed(config["expected"])
                if "expected_djca" in config:
                    exp = reversed(config["expected_djca"])

                for expected in exp:
                    self.assertEqual(expected, ext.pop())
                self.assertEqual(len(ext), 0)

        with self.assertRaisesRegex(IndexError, "^pop from empty list$"):
            self.ext([]).pop()

    def test_remove(self) -> None:
        """Test ext.remove()."""
        for config in self.test_values.values():
            for values in config["values"]:
                for expected_value, value in zip(config["expected"], values):
                    kwargs = {"infix": False, "set_value": expected_value}
                    self.assertEqualFunction(lambda c, e: c.remove(e), config["expected"], value, **kwargs)

    def test_setitem(self) -> None:
        """Test setting items (e.g. ``ext[0] = ...``)."""
        # pylint: disable-next=unnecessary-lambda-assignment  # just much shorter
        func = lambda c, j: operator.setitem(c, j[0], j[1])  # NOQA[E731]
        for config in self.test_values.values():
            ct_expected = config["expected"]
            if "expected_djca" in config:
                ct_expected = config["expected_djca"]

            for values in config["values"]:
                for i, val in enumerate(values):
                    self.assertEqualFunction(
                        func,
                        list(config["expected"]),
                        (i, val),
                        set_init=ct_expected,
                        set_value=(i, ct_expected[i]),
                    )

    def test_setitem_slices(self) -> None:
        """Test setting slices."""
        # pylint: disable-next=unnecessary-lambda-assignment  # just much shorter
        func = lambda c, j: operator.setitem(c, j[0], j[1])  # NOQA[E731]
        for config in self.test_values.values():
            ct_expected = config["expected"]
            if "expected_djca" in config:
                ct_expected = config["expected_djca"]

            for values in config["values"]:
                for _i in range(0, len(values)):  # loop to test all possible slices
                    start_slice = slice(0, 1)
                    self.assertEqualFunction(
                        func,
                        list(config["expected"]),
                        (
                            start_slice,
                            values[start_slice],
                        ),
                        set_init=ct_expected,
                        set_value=(start_slice, ct_expected[start_slice]),
                    )

    def test_setitem_typerror(self) -> None:
        """Test setting slices without an iterable."""
        ext = self.ext_class({"value": []})
        with self.assertRaisesRegex(TypeError, r"^Can only assign int/item or slice/iterable$"):
            ext[0:1] = 3  # type: ignore[call-overload] # exactly what we're testing here


class OrderedSetExtensionTestMixin(
    IterableExtensionTestMixin[OrderedSetExtensionTypeVar, set],  # type: ignore[type-arg] # pragma: py<3.8
    typing.Generic[OrderedSetExtensionTypeVar],
):
    """Mixin for OrderedSetExtension based extensions."""

    # pylint: disable=unnecessary-lambda; assertion functions require passing lambda functions
    # pylint: disable=too-many-public-methods; b/c we're testing all those set functions

    container_type = set
    ext_class_name = "OrderedSetExtension"

    def assertSingleValueOperator(  # pylint: disable=invalid-name
        self,
        oper: typing.Callable[[typing.Any, typing.Any], typing.Any],
        update: bool = True,
        infix: bool = True,
    ) -> None:
        """Test that an operator taking a single value works the same way with sets and this extension."""
        for config in self.test_values.values():

            # Apply function to an empty extension
            self.assertEqualFunction(oper, set(), config["expected"], update=update, infix=infix)

            # Apply function to an extension with every "expected" value
            for init_config in self.test_values.values():
                self.assertEqualFunction(
                    oper, init_config["expected"], config["expected"], update=update, infix=infix
                )

            # Test that equivalent values work exactly the same way:
            for test_value in config["values"]:
                # Again, apply function to the empty extension/set
                self.assertEqualFunction(
                    oper, set(), test_value, set_value=config["expected"], update=update, infix=infix
                )

                # Again, apply function to an extension with every "expected" value
                for init_config in self.test_values.values():
                    self.assertEqualFunction(
                        oper,
                        init=init_config["expected"],
                        value=test_value,
                        set_value=config["expected"],
                        update=update,
                        infix=infix,
                    )

    def assertMultipleValuesOperator(  # pylint: disable=invalid-name
        self,
        oper: typing.Callable[[typing.Any, typing.Any], typing.Any],
        update: bool = True,
        infix: bool = True,
    ) -> None:
        """Test that an operator taking a multiple values works the same way with sets and this extension."""
        for first_config in self.test_values.values():
            for second_config in self.test_values.values():
                expected = (set(first_config["expected"]), set(second_config["expected"]))

                # Apply function to an empty extension
                self.assertEqualFunction(oper, set(), expected, update=update, infix=infix)

                for init_config in self.test_values.values():
                    expected_config = (
                        set(init_config["expected"]),
                        set(first_config["expected"]),
                        set(second_config["expected"]),
                    )
                    self.assertEqualFunction(
                        oper, init_config["expected"], expected_config, update=update, infix=infix
                    )

    def assertRelation(  # pylint: disable=invalid-name
        self, oper: typing.Callable[[typing.Any, typing.Any], typing.Any]
    ) -> None:
        """Assert that a extension relation is equal to that of set()."""
        self.assertEqual(oper(set(), set()), oper(self.ext_class({"value": set()}), set()))
        self.assertEqual(
            oper(set(), set()), oper(self.ext_class({"value": set()}), self.ext_class({"value": set()}))
        )

        for config in self.test_values.values():
            self.assertEqual(
                oper(config["expected"], config["expected"]),
                oper(self.ext_class({"value": set(config["expected"])}), set(config["expected"])),
            )
            self.assertEqual(
                oper(config["expected"], config["expected"]),
                oper(
                    self.ext_class({"value": set(config["expected"])}),
                    self.ext_class({"value": set(config["expected"])}),
                ),
            )

            for second_config in self.test_values.values():
                intersection_expected = config["expected"] & second_config["expected"]
                self.assertEqual(
                    oper(config["expected"], intersection_expected),
                    oper(self.ext_class({"value": set(config["expected"])}), intersection_expected),
                )
                self.assertEqual(
                    oper(config["expected"], intersection_expected),
                    oper(
                        self.ext_class({"value": set(config["expected"])}),
                        self.ext_class({"value": intersection_expected}),
                    ),
                )
                self.assertEqual(
                    oper(config["expected"], intersection_expected),
                    oper(
                        self.ext_class({"value": config["expected"]}),
                        self.ext_class({"value": set(intersection_expected)}),
                    ),
                )

                union_expected = config["expected"] | second_config["expected"]
                self.assertEqual(
                    oper(config["expected"], set(union_expected)),
                    oper(self.ext_class({"value": set(config["expected"])}), union_expected),
                )
                self.assertEqual(
                    oper(config["expected"], set(union_expected)),
                    oper(
                        self.ext_class({"value": set(config["expected"])}),
                        self.ext_class({"value": set(union_expected)}),
                    ),
                )
                self.assertEqual(
                    oper(config["expected"], set(union_expected)),
                    oper(self.ext_class({"value": config["expected"]}), set(union_expected)),
                )

                symmetric_diff_expected = config["expected"] ^ second_config["expected"]
                self.assertEqual(
                    oper(config["expected"], set(symmetric_diff_expected)),
                    oper(self.ext_class({"value": set(config["expected"])}), set(symmetric_diff_expected)),
                )
                self.assertEqual(
                    oper(config["expected"], set(symmetric_diff_expected)),
                    oper(
                        self.ext_class({"value": set(config["expected"])}),
                        self.ext_class({"value": set(symmetric_diff_expected)}),
                    ),
                )
                self.assertEqual(
                    oper(set(symmetric_diff_expected), config["expected"]),
                    oper(
                        self.ext_class({"value": set(symmetric_diff_expected)}),
                        self.ext_class({"value": set(config["expected"])}),
                    ),
                )

    def test_add(self) -> None:
        """Test ext.add()."""
        for config in self.test_values.values():
            for values in config["values"]:
                ext = self.ext_class({"value": set()})
                for value in values:
                    ext.add(value)
                    self.assertIn(value, ext)
                    # Note: we cannot assert the length, because values might include alias values

                self.assertEqual(ext, self.ext_class({"value": config["expected"]}))

    def test_copy(self) -> None:
        """Test ext.copy()."""
        for config in self.test_values.values():
            ext = self.ext_class({"value": config["expected"]})
            ext_copy = ext.copy()
            self.assertIsCopy(ext, ext_copy, config["expected"])

    def test_difference(self) -> None:
        """Test ext.difference()."""
        self.assertSingleValueOperator(lambda s, o: s.difference(o), infix=False, update=False)
        self.assertMultipleValuesOperator(lambda s, o: s.difference(*o), infix=False, update=False)

    def test_difference_operator(self) -> None:
        """Test the ``-`` operator."""
        self.assertSingleValueOperator(lambda s, o: operator.sub(s, o), update=False)
        self.assertMultipleValuesOperator(
            lambda s, o: operator.sub(s, functools.reduce(operator.sub, [t.copy() for t in o])), update=False
        )

    def test_difference_update(self) -> None:
        """Test ext.difference_update()."""
        self.assertSingleValueOperator(lambda s, o: s.difference_update(o), infix=False)
        self.assertMultipleValuesOperator(lambda s, o: s.difference_update(*o), infix=False)

    def test_difference_update_operator(self) -> None:
        """Test the ``-=`` operator."""
        self.assertSingleValueOperator(lambda s, o: operator.isub(s, o))
        self.assertMultipleValuesOperator(
            lambda s, o: operator.isub(s, functools.reduce(operator.sub, [t.copy() for t in o]))
        )

    def test_discard(self) -> None:
        """Test  ext.discard()."""
        for config in self.test_values.values():
            for values in config["values"]:
                ext = self.ext_class({"value": config["expected"]})
                ext_empty = self.ext_class({"value": set()})

                for i, value in enumerate(values, start=1):
                    self.assertIn(value, ext)
                    ext.discard(value)
                    self.assertNotIn(value, ext)
                    self.assertEqual(len(ext) + i, len(config["expected"]))

                    self.assertEqual(len(ext_empty), 0)
                    ext_empty.discard(value)
                    self.assertEqual(len(ext_empty), 0)

    def test_greater_then_operator(self) -> None:
        """Test the ``<`` operator."""
        self.assertRelation(lambda s, o: operator.gt(s, o))

    def test_intersection(self) -> None:
        """Test ext.intersection()."""
        self.assertSingleValueOperator(lambda s, o: s.intersection(o), infix=False, update=False)
        self.assertMultipleValuesOperator(lambda s, o: s.intersection(*o), infix=False, update=False)

    def test_intersection_operator(self) -> None:
        """Test the ``&`` operator."""
        self.assertSingleValueOperator(lambda s, o: operator.and_(s, o), update=False)
        self.assertMultipleValuesOperator(
            lambda s, o: operator.and_(s, functools.reduce(operator.and_, [t.copy() for t in o])),
            update=False,
        )

    def test_intersection_update(self) -> None:
        """Test ext.intersection_update()."""
        self.assertSingleValueOperator(lambda s, o: s.intersection_update(o), infix=False)
        self.assertMultipleValuesOperator(lambda s, o: s.intersection_update(*o), infix=False)

    def test_intersection_update_operator(self) -> None:
        """Test the ``&=`` operator."""
        self.assertSingleValueOperator(lambda s, o: operator.iand(s, o))
        self.assertMultipleValuesOperator(
            lambda s, o: operator.iand(s, functools.reduce(operator.and_, [t.copy() for t in o]))
        )

    def test_isdisjoint(self) -> None:
        """Test ext.isdisjoint()."""
        self.assertRelation(lambda s, o: s.isdisjoint(o))

    def test_issubset(self) -> None:
        """Test ext.issubset()."""
        self.assertRelation(lambda s, o: s.issubset(o))

    def test_issubset_operator(self) -> None:
        """Test the ``<=`` operator."""
        self.assertRelation(lambda s, o: operator.le(s, o))

    def test_issuperset(self) -> None:
        """Test ext.issuperset()."""
        self.assertRelation(lambda s, o: s.issuperset(o))

    def test_issuperset_operator(self) -> None:
        """Test the ``>=`` operator."""
        self.assertRelation(lambda s, o: operator.ge(s, o))

    def test_lesser_then_operator(self) -> None:
        """Test the ``<`` operator."""
        self.assertRelation(lambda s, o: operator.lt(s, o))

    def test_pop(self) -> None:
        """Test ext.pop()."""
        for config in self.test_values.values():
            for _values in config["values"]:  # loop so that we pop all values from ext
                ext = self.ext_class({"value": set(config["expected"])})
                self.assertEqual(len(ext), len(config["expected"]))

                while len(ext) > 0:
                    # pop an element
                    orig_length = len(ext)
                    value = ext.pop()

                    self.assertNotIn(value, ext)
                    self.assertEqual(len(ext) + 1, orig_length)  # length shrunk by one

        ext = self.ext_class({"value": set()})
        with self.assertRaisesRegex(KeyError, "^'pop from an empty set'$"):
            ext.pop()

    def test_remove(self) -> None:
        """Test ext.remove()."""
        for config in self.test_values.values():
            for values in config["values"]:
                ext = self.ext_class({"value": set(config["expected"])})

                for i, value in enumerate(values, start=1):
                    self.assertIsNone(ext.remove(value))
                    self.assertNotIn(value, ext)
                    self.assertEqual(len(ext) + i, len(config["expected"]))

                    with self.assertRaises(KeyError):
                        # NOTE: We cannot test the message here because it may be a mapped value
                        ext.remove(value)

    def test_smaller_then_operator(self) -> None:
        """Test the ``<`` operator."""
        self.assertRelation(lambda s, o: operator.lt(s, o))

    def test_symmetric_difference(self) -> None:
        """Test ext.symmetric_difference."""
        self.assertSingleValueOperator(lambda s, o: s.symmetric_difference(o), update=False, infix=False)

    def test_symmetric_difference_operator(self) -> None:
        """Test ``^`` operator (symmetric_difference)."""
        self.assertSingleValueOperator(lambda s, o: operator.xor(s, o), update=False)

    def test_symmetric_difference_update(self) -> None:
        """Test ext.symmetric_difference_update()."""
        self.assertSingleValueOperator(lambda s, o: s.symmetric_difference_update(o), infix=False)

    def test_symmetric_difference_update_operator(self) -> None:
        """Test the ``^=`` operator."""
        self.assertSingleValueOperator(lambda s, o: operator.ixor(s, o))

    def test_union(self) -> None:
        """Test ext.union()."""
        self.assertSingleValueOperator(lambda s, o: s.union(o), infix=False, update=False)
        self.assertMultipleValuesOperator(lambda s, o: s.union(*o), infix=False, update=False)

    def test_union_operator(self) -> None:
        """Test the ``|`` operator``."""
        self.assertSingleValueOperator(lambda s, o: operator.or_(s, o), update=False)
        self.assertMultipleValuesOperator(
            lambda s, o: operator.or_(s, functools.reduce(operator.or_, [t.copy() for t in o])), update=False
        )

    def test_update(self) -> None:
        """Test ext.update()."""
        self.assertSingleValueOperator(lambda s, o: s.update(o), infix=False)
        self.assertMultipleValuesOperator(lambda s, o: s.update(*o), infix=False)

    def test_update_operator(self) -> None:
        """Test the ``|=`` operator."""
        self.assertSingleValueOperator(lambda s, o: operator.ior(s, o))
        self.assertMultipleValuesOperator(
            lambda s, o: operator.ior(s, functools.reduce(operator.ior, [t.copy() for t in o]))
        )


class CRLDistributionPointsTestCaseBase(
    typing.Generic[DistributionPointsBaseTypeVar, CRLExtensionTypeTypeVar],
    ListExtensionTestMixin[DistributionPointsBaseTypeVar],
    ExtensionTestMixin[DistributionPointsBaseTypeVar],
):
    """Base class for test cases for CRL based extensions."""

    ext_class: typing.Type[DistributionPointsBaseTypeVar]
    ext_class_type: typing.Type[CRLExtensionTypeTypeVar]

    uri1 = "http://ca.example.com/crl"
    uri2 = "http://ca.example.net/crl"
    uri3 = "http://ca.example.com/"
    dns1 = "example.org"
    rdn1 = "/CN=example.com"

    s1: ParsableDistributionPoint = {"full_name": [f"URI:{uri1}"]}
    s2: ParsableDistributionPoint = {"full_name": [f"URI:{uri1}", f"DNS:{dns1}"]}
    s3: ParsableDistributionPoint = {"relative_name": rdn1}
    s4: ParsableDistributionPoint = {
        "full_name": [f"URI:{uri2}"],
        "crl_issuer": [f"URI:{uri3}"],
        "reasons": ["ca_compromise", "key_compromise"],
    }
    s5: ParsableDistributionPoint = {
        "full_name": [f"URI:{uri2}"],
        "crl_issuer": [f"URI:{uri3}"],
        "reasons": [x509.ReasonFlags.ca_compromise, x509.ReasonFlags.key_compromise],
    }
    dp1 = DistributionPoint(s1)
    dp2 = DistributionPoint(s2)
    dp3 = DistributionPoint(s3)
    dp4 = DistributionPoint(s4)
    dp5 = DistributionPoint(s5)

    cg_rdn1 = rdn([(NameOID.COMMON_NAME, "example.com")])

    cg_dp1 = x509.DistributionPoint(full_name=[uri(uri1)], relative_name=None, crl_issuer=None, reasons=None)
    cg_dp2 = x509.DistributionPoint(
        full_name=[uri(uri1), dns(dns1)], relative_name=None, crl_issuer=None, reasons=None
    )
    cg_dp3 = x509.DistributionPoint(full_name=None, relative_name=cg_rdn1, crl_issuer=None, reasons=None)
    cg_dp4 = x509.DistributionPoint(
        full_name=[uri(uri2)],
        relative_name=None,
        crl_issuer=[uri(uri3)],
        reasons=frozenset([x509.ReasonFlags.key_compromise, x509.ReasonFlags.ca_compromise]),
    )

    cg_dps1: CRLExtensionTypeTypeVar
    cg_dps2: CRLExtensionTypeTypeVar
    cg_dps3: CRLExtensionTypeTypeVar
    cg_dps4: CRLExtensionTypeTypeVar

    invalid_values = [True, None]

    def setUp(self) -> None:
        self.test_values = {
            "one": {
                "admin_html": f"""DistributionPoint:
  <ul>
      <li>Full Name: URI:{self.uri1}</li>
  </ul>""",
                "values": [
                    [self.s1],
                    [self.dp1],
                    [self.cg_dp1],
                    [{"full_name": [self.uri1]}],
                    [{"full_name": [uri(self.uri1)]}],
                ],
                "expected": [self.s1],
                "expected_djca": [self.dp1],
                "expected_repr": f"[<DistributionPoint: full_name=['URI:{self.uri1}']>]",
                "expected_serialized": [self.s1],
                "extension_type": self.cg_dps1,
                "text": f"* DistributionPoint:\n  * Full Name:\n    * URI:{self.uri1}",
            },
            "two": {
                "admin_html": f"""DistributionPoint:
  <ul>
      <li>Full Name: URI:{self.uri1}, DNS:{self.dns1}</li>
  </ul>""",
                "values": [
                    [self.s2],
                    [self.dp2],
                    [self.cg_dp2],
                    [{"full_name": [self.uri1, self.dns1]}],
                    [{"full_name": [uri(self.uri1), dns(self.dns1)]}],
                ],
                "expected": [self.s2],
                "expected_djca": [self.dp2],
                "expected_repr": f"[<DistributionPoint: full_name=['URI:{self.uri1}', 'DNS:{self.dns1}']>]",
                "expected_serialized": [self.s2],
                "extension_type": self.cg_dps2,
                "text": f"* DistributionPoint:\n  * Full Name:\n    * URI:{self.uri1}\n    * DNS:{self.dns1}",
            },
            "rdn": {
                "admin_html": f"""DistributionPoint:
  <ul>
      <li>Relative Name: {self.rdn1}</li>
  </ul>""",
                "values": [[self.s3], [self.dp3], [self.cg_dp3], [{"relative_name": self.cg_rdn1}]],
                "expected": [self.s3],
                "expected_djca": [self.dp3],
                "expected_repr": f"[<DistributionPoint: relative_name='{self.rdn1}'>]",
                "expected_serialized": [self.s3],
                "extension_type": self.cg_dps3,
                "text": f"* DistributionPoint:\n  * Relative Name: {self.rdn1}",
            },
            "adv": {
                "admin_html": f"""DistributionPoint:
  <ul>
      <li>Full Name: URI:{self.uri2}</li>
      <li>CRL Issuer: URI:{self.uri3}</li>
      <li>Reasons: ca_compromise, key_compromise</li>
  </ul>""",
                "values": [[self.s4], [self.s5], [self.dp4], [self.dp5], [self.cg_dp4]],
                "expected": [self.s4],
                "expected_djca": [self.dp4],
                "expected_repr": f"[<DistributionPoint: full_name=['URI:{self.uri2}'], "
                f"crl_issuer=['URI:{self.uri3}'], reasons=['ca_compromise', 'key_compromise']>]",
                "expected_serialized": [self.s4],
                "extension_type": self.cg_dps4,
                "text": f"""* DistributionPoint:
  * Full Name:
    * URI:{self.uri2}
  * CRL Issuer:
    * URI:{self.uri3}
  * Reasons: ca_compromise, key_compromise""",
            },
        }

    def test_none_value(self) -> None:
        """Test that we can pass a None value for GeneralNameList items."""
        ext = self.ext_class()
        self.assertEqual(ext.extension_type, self.ext_class_type(distribution_points=[]))

        ext.append(DistributionPoint({"full_name": None}))
        self.assertEqual(
            ext.extension_type,
            self.ext_class_type(
                distribution_points=[
                    x509.DistributionPoint(full_name=None, relative_name=None, reasons=None, crl_issuer=None)
                ]
            ),
        )

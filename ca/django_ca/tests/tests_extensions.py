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

"""Test cases for :py:mod:`django_ca.extensions`."""

import doctest
import functools
import json
import operator
import os
import sys

from cryptography import x509
from cryptography.x509 import TLSFeatureType
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import ObjectIdentifier

from django.conf import settings
from django.test import TestCase
from django.utils.functional import cached_property

from ..extensions import KEY_TO_EXTENSION
from ..extensions import OID_TO_EXTENSION
from ..extensions import AuthorityInformationAccess
from ..extensions import AuthorityKeyIdentifier
from ..extensions import BasicConstraints
from ..extensions import CertificatePolicies
from ..extensions import CRLDistributionPoints
from ..extensions import ExtendedKeyUsage
from ..extensions import Extension
from ..extensions import FreshestCRL
from ..extensions import InhibitAnyPolicy
from ..extensions import IssuerAlternativeName
from ..extensions import KeyUsage
from ..extensions import NameConstraints
from ..extensions import OCSPNoCheck
from ..extensions import PolicyConstraints
from ..extensions import PrecertificateSignedCertificateTimestamps
from ..extensions import PrecertPoison
from ..extensions import SubjectAlternativeName
from ..extensions import SubjectKeyIdentifier
from ..extensions import TLSFeature
from ..extensions.base import UnrecognizedExtension
from ..extensions.utils import DistributionPoint
from ..extensions.utils import PolicyInformation
from ..models import X509CertMixin
from ..utils import GeneralNameList
from .base import DjangoCAWithCertTestCase
from .base import certs
from .base import dns
from .base import rdn
from .base import uri


def load_tests(loader, tests, ignore):  # pylint: disable=unused-argument
    """Load doctests."""

    if sys.version_info >= (3, 7):
        # Older python versions return a different str for classes
        docs_path = os.path.join(settings.DOC_DIR, 'python', 'extensions.rst')
        tests.addTests(doctest.DocFileSuite(docs_path, module_relative=False, globs={
            'KEY_TO_EXTENSION': KEY_TO_EXTENSION,
            'OID_TO_EXTENSION': OID_TO_EXTENSION,
        }))

    tests.addTests(doctest.DocTestSuite('django_ca.extensions'))
    tests.addTests(doctest.DocTestSuite('django_ca.extensions.base', extraglobs={
        'ExtendedKeyUsage': ExtendedKeyUsage,
        'ExtendedKeyUsageOID': ExtendedKeyUsageOID,
        'ExtensionOID': ExtensionOID,
        'KeyUsage': KeyUsage,
        'OCSPNoCheck': OCSPNoCheck,
        'SubjectAlternativeName': SubjectAlternativeName,
        'SubjectKeyIdentifier': SubjectKeyIdentifier,
    }))
    tests.addTests(doctest.DocTestSuite('django_ca.extensions.utils'))
    return tests


class AbstractExtensionTestMixin:
    """TestCase mixin for tests that all extensions are expected to pass, including abstract base classes."""

    force_critical = None
    repr_tmpl = '<{name}: {value}, critical={critical}>'

    def assertExtensionEqual(self, first, second):  # pylint: disable=invalid-name
        """Function to test if an extension is really really equal.

        This function should compare extension internals directly not via the __eq__ function.
        """
        self.assertEqual(first.__class__, second.__class__)
        self.assertEqual(first.critical, second.critical)
        self.assertEqual(first, second)

    def assertSerialized(self, ext, config, critical=None):  # pylint: disable=invalid-name
        """Assert that the extension can be serialized as expected."""
        if critical is None:
            critical = self.ext_class.default_critical

        serialized = ext.serialize()
        self.assertEqual(serialized, {
            'value': config['expected_serialized'],
            'critical': critical,
        })
        json.dumps(serialized)  # make sure that we can actually serialize the value

    @property
    def critical_values(self):
        """Loop through all possible values for critical.

        This may or may not include both boolean values depending on ``force_critical``.
        """
        if self.force_critical is not False:
            yield True
        if self.force_critical is not True:
            yield False

    def ext(self, value=None, critical=None):
        """Get an extension instance with the given value."""
        if value is None:
            value = {}

        if isinstance(value, x509.extensions.ExtensionType):
            if critical is None:
                critical = self.ext_class.default_critical
            ext = x509.extensions.Extension(oid=self.ext_class.oid, critical=critical, value=value)
            return self.ext_class(ext)

        val = {'value': value}
        if critical is not None:
            val['critical'] = critical
        return self.ext_class(val)

    def test_as_text(self):
        """Test as_text()."""
        for config in self.test_values.values():
            ext = self.ext(config['expected'])
            self.assertEqual(ext.as_text(), config['expected_text'])

    def test_config(self):
        """Test basic extension configuration."""
        self.assertEqual(self.ext_class.key, '')

    def test_hash(self):
        """Test hash()."""
        for config in self.test_values.values():
            ext = self.ext(config['expected'])
            ext_critical = self.ext(config['expected'], critical=True)
            ext_not_critical = self.ext(config['expected'], critical=False)

            if self.ext_class.default_critical:
                self.assertEqual(hash(ext), hash(ext_critical))
                self.assertNotEqual(hash(ext), hash(ext_not_critical))
            else:
                self.assertEqual(hash(ext), hash(ext_not_critical))
                self.assertNotEqual(hash(ext), hash(ext_critical))
            self.assertNotEqual(hash(ext_critical), hash(ext_not_critical))

            for other_config in self.test_values.values():
                other_ext = self.ext(other_config['expected'])
                other_ext_critical = self.ext(other_config['expected'], critical=True)
                other_ext_not_critical = self.ext(other_config['expected'], critical=False)

                if config['expected'] == other_config['expected']:
                    self.assertEqual(hash(ext), hash(other_ext))
                    self.assertEqual(hash(ext_critical), hash(other_ext_critical))
                    self.assertEqual(hash(ext_not_critical), hash(other_ext_not_critical))
                else:
                    self.assertNotEqual(hash(ext), hash(other_ext))
                    self.assertNotEqual(hash(ext_critical), hash(other_ext_critical))
                    self.assertNotEqual(hash(ext_not_critical), hash(other_ext_not_critical))

    def test_eq(self):
        """Test extension equality (``==``)."""
        for values in self.test_values.values():
            ext = self.ext(values['expected'])
            self.assertEqual(ext, ext)
            ext_critical = self.ext(values['expected'], critical=True)
            self.assertEqual(ext_critical, ext_critical)
            ext_not_critical = self.ext(values['expected'], critical=False)
            self.assertEqual(ext_not_critical, ext_not_critical)

            for value in values['values']:
                ext_1 = self.ext(value)
                self.assertEqual(ext, ext_1)
                ext_2 = self.ext(value, critical=True)
                self.assertEqual(ext_critical, ext_2)
                ext_3 = self.ext(value, critical=False)
                self.assertEqual(ext_not_critical, ext_3)

    def test_init(self):
        """Test that the constructor behaves equal regardles of input value."""
        for config in self.test_values.values():
            expected = self.ext(config['expected'])

            for value in config['values']:
                self.assertExtensionEqual(self.ext(value), expected)

            if config.get('extension_type'):
                self.assertExtensionEqual(self.ext(config['extension_type']), expected)

            # Now the same with explicit critical values
            for critical in self.critical_values:
                expected = self.ext(config['expected'], critical=critical)

                for value in config['values']:
                    self.assertExtensionEqual(self.ext(value, critical=critical), expected)

                if config.get('extension_type'):
                    self.assertEqual(self.ext(config['extension_type'], critical=critical), expected)

    def test_init_no_bool_critical(self):
        """"Test creating an extension with a non-bool critical value."""
        class_name = 'example_class'

        class _Example:  # pylint: disable=too-few-public-methods
            def __str__(self):
                return class_name

        for config in self.test_values.values():
            for value in config['values']:
                if isinstance(value, x509.extensions.ExtensionType):
                    continue  # self.ext() would construct an x509.Extension and the constructor would fail

                with self.assertRaisesRegex(ValueError, '^%s: Invalid critical value passed$' % class_name):
                    self.ext(value, critical=_Example())

    def test_init_unknown_type(self):
        """Try creating an extension with a value of unknown type."""
        class _Example:  # pylint: disable=too-few-public-methods
            pass

        with self.assertRaisesRegex(ValueError, '^Value is of unsupported type _Example$'):
            self.ext_class(_Example())

    def test_ne(self):
        """Test ``!=`` (not-equal) operator."""
        for config in self.test_values.values():
            if self.force_critical is None:
                self.assertNotEqual(
                    self.ext(config['expected'], critical=True),
                    self.ext(config['expected'], critical=False)
                )

            for other_config in self.test_values.values():
                if self.force_critical is None:
                    self.assertNotEqual(
                        self.ext(config['expected'], critical=True),
                        self.ext(other_config['expected'], critical=False)
                    )
                if self.force_critical is None:
                    self.assertNotEqual(
                        self.ext(config['expected'], critical=False),
                        self.ext(other_config['expected'], critical=True)
                    )

                if config['expected'] != other_config['expected']:
                    self.assertNotEqual(
                        self.ext(config['expected']),
                        self.ext(other_config['expected'])
                    )

    def test_repr(self):
        """Test repr()."""
        for config in self.test_values.values():
            for value in config['values']:
                ext = self.ext(value)
                exp = config['expected_repr']
                expected = self.repr_tmpl.format(name=self.ext_class_name, value=exp,
                                                 critical=ext.default_critical)
                self.assertEqual(repr(ext), expected)

                for critical in self.critical_values:
                    ext = self.ext(value, critical=critical)
                    expected = self.repr_tmpl.format(name=self.ext_class_name, value=exp, critical=critical)
                    self.assertEqual(repr(ext), expected)

    def test_serialize(self):
        """Test serialization of extension."""
        for config in self.test_values.values():
            ext = self.ext(config['expected'])
            self.assertSerialized(ext, config)

            for critical in self.critical_values:
                ext = self.ext(config['expected'], critical=critical)
                self.assertSerialized(ext, config, critical=critical)

    def test_str(self):
        """Test str()."""
        for config in self.test_values.values():
            for value in config['values']:
                ext = self.ext(value)
                exp = config['expected_repr']

                expected = self.repr_tmpl.format(name=self.ext_class_name, value=exp,
                                                 critical=ext.default_critical)
                self.assertEqual(str(ext), expected)

                for critical in self.critical_values:
                    ext = self.ext(value, critical=critical)
                    expected = self.repr_tmpl.format(name=self.ext_class_name, value=exp, critical=critical)
                    self.assertEqual(str(ext), expected)

    def test_value(self):
        """Test that value property can be used for the constructor."""
        for config in self.test_values.values():
            ext = self.ext(value=config['expected'])
            self.assertExtensionEqual(ext, self.ext(ext.value))


class ExtensionTestMixin(AbstractExtensionTestMixin):
    """Override generic implementations to use test_value property."""

    def test_as_extension(self):
        """Test the as_extension property."""
        for config in self.test_values.values():
            if config['extension_type'] is None:
                continue  # test case is not a valid extension

            ext = self.ext(config['expected'])
            cg_ext = x509.extensions.Extension(
                oid=self.ext_class.oid, critical=self.ext_class.default_critical,
                value=config['extension_type'])
            self.assertEqual(ext.as_extension(), cg_ext)

            for critical in self.critical_values:
                ext = self.ext(config['expected'], critical=critical)
                self.assertEqual(ext.as_extension(), x509.extensions.Extension(
                    oid=self.ext_class.oid, critical=critical, value=config['extension_type']))

    def test_config(self):
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

    def test_extension_type(self):
        """Test extension_type property."""
        for config in self.test_values.values():
            if config['extension_type'] is None:
                continue  # test case is not a valid extension

            ext = self.ext(config['expected'])
            self.assertEqual(ext.extension_type, config['extension_type'])

    def test_for_builder(self):
        """Test the for_builder() method."""
        for config in self.test_values.values():
            if config['extension_type'] is None:
                continue  # test case is not a valid extension

            ext = self.ext(config['expected'])
            self.assertEqual(
                ext.for_builder(),
                {'extension': config['extension_type'], 'critical': self.ext_class.default_critical}
            )

            for critical in self.critical_values:
                ext = self.ext(config['expected'], critical=critical)
                self.assertEqual(ext.for_builder(),
                                 {'extension': config['extension_type'], 'critical': critical})


class NullExtensionTestMixin(ExtensionTestMixin):
    """TestCase mixin for tests that all extensions are expected to pass, including abstract base classes."""

    repr_tmpl = '<{name}: critical={critical}>'

    def assertExtensionEqual(self, first, second):
        """Function to test if an extension is really really equal.

        This function should compare extension internals directly not via the __eq__ function.
        """
        self.assertEqual(first.__class__, second.__class__)
        self.assertEqual(first.critical, second.critical)

    def assertSerialized(self, ext, config, critical=None):
        if critical is None:
            critical = self.ext_class.default_critical
        self.assertEqual(ext.serialize(), {'critical': critical})

    def test_dummy_functions(self):
        """NullExtension implements abstract functions for the value which are in reality unused."""
        self.assertIsNone(self.ext_class().serialize_value())
        self.assertEqual(self.ext_class().repr_value(), '')


class IterableExtensionTestMixin:
    """Mixin for testing IterableExtension-based extensions."""

    invalid_values = []

    def assertSameInstance(self, orig_id, orig_value_id, new, expected_value):  # pylint: disable=invalid-name
        """Assert that `new` is still the same instance and has the expected value."""
        self.assertEqual(new.value, expected_value)
        self.assertEqual(id(new), orig_id)  # assert that this is really the same instance
        self.assertEqual(id(new.value), orig_value_id)

    def assertEqualFunction(self, func, init, value, update=True, infix=True,  # pylint: disable=invalid-name
                            set_init=None, set_value=None, raises=None):
        """Assert that the given function f behaves the same way on a set and on the tested extension.

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

        f : func
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
        """
        if set_value is None:
            set_value = value
        if set_init is None:
            set_init = init

        container = self.container_type(set_init)
        ext = self.ext_class({'value': init})

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

    def test_clear(self):
        """Test ext.clear()."""
        for values in self.test_values.values():
            ext = self.ext(values['expected'])
            ext.clear()
            self.assertEqual(len(ext.value), 0)

    def test_in(self):
        """Test the ``in`` operator."""
        for config in self.test_values.values():
            ext = self.ext_class({'value': config['expected']})
            for values in config['values']:
                for value in values:
                    self.assertIn(value, ext)

    def test_len(self):  # len()
        """Test len(ext)."""
        for values in self.test_values.values():
            self.assertEqual(len(self.ext_class({'value': values['expected']})), len(values['expected']))

    def test_not_in(self):
        """Test the ``not in`` operator."""
        for config in self.test_values.values():
            for values in config['values']:
                ext = self.ext_class({'value': set()})

                for value in values:
                    self.assertNotIn(value, ext)
                    self.assertEqual(len(ext), 0)


class ListExtensionTestMixin(IterableExtensionTestMixin):
    """Mixin for testing ListExtension-based extensions."""

    # pylint: disable=unnecessary-lambda; assertion functions require passing lambda functions

    container_type = list

    def test_append(self):
        """Test ext.append()."""
        for config in self.test_values.values():
            if not config['expected']:
                continue  # we don't have values to append

            for values in config['values']:
                expected = self.ext(config['expected'])
                ext = self.ext(values[:-1])  # all but the last item
                ext.append(values[-1])
                self.assertExtensionEqual(ext, expected)

    def test_count(self):
        """Test ext.count()."""
        for config in self.test_values.values():
            ext = self.ext(config['expected'])
            for values in config['values']:
                for expected_elem, other_elem in zip(config['expected'], values):
                    self.assertEqual(config['expected'].count(expected_elem), ext.count(expected_elem))
                    self.assertEqual(config['expected'].count(expected_elem), ext.count(other_elem))

        for value in self.invalid_values:
            for config in self.test_values.values():
                ext = self.ext(config['expected'])
                self.assertEqual(ext.count(value), 0)

    def test_del(self):
        """Test item deletion (e.g. ``del ext[0]``)."""
        for config in self.test_values.values():
            ext = self.ext(config['expected'])
            self.assertEqual(len(ext), len(config['expected']))

            for _val in config['expected']:  # loop so that we subsequently delete all values
                del ext[0]
            self.assertEqual(len(ext), 0)

            with self.assertRaisesRegex(IndexError, r'^list assignment index out of range$'):
                del ext[0]

    def test_del_slices(self):
        """Test deleting slices."""
        for config in self.test_values.values():
            ext = self.ext(config['expected'])
            del ext[0:]
            self.assertEqual(len(ext), 0)

    def test_extend(self):
        """Test ext.extend()."""
        func = lambda c, j: c.extend(j)  # noqa
        for config in self.test_values.values():
            set_value = config['expected']
            if 'expected_djca' in config:
                set_value = config['expected_djca']

            self.assertEqualFunction(func, init=config['expected'], value=config['expected'],
                                     set_init=set_value, set_value=set_value)
            self.assertEqualFunction(func, init=config['expected'], value=config['expected'][0:],
                                     set_init=set_value, set_value=set_value[0:])
            self.assertEqualFunction(func, config['expected'], config['expected'][1:],
                                     set_init=set_value, set_value=set_value[1:])
            self.assertEqualFunction(func, config['expected'], config['expected'][:2],
                                     set_init=set_value, set_value=set_value[:2])

    def test_getitem(self):
        """Test item getter (e.g. ``x = ext[0]``)."""
        func = lambda c, j: operator.getitem(c, j)  # noqa
        for config in self.test_values.values():
            ct_expected = config['expected']
            if 'expected_djca' in config:
                ct_expected = config['expected_djca']

            for values in config['values']:
                for i in range(0, len(values)):
                    self.assertEqualFunction(func, values, i, set_init=ct_expected)

                self.assertEqualFunction(func, config['expected'], len(config['expected']),
                                         set_init=ct_expected,
                                         raises=(IndexError, r'^list index out of range$'))

    def test_getitem_slices(self):
        """Test getting slices (e.g. ``x = ext[0:1]``)."""
        func = lambda c, j: operator.getitem(c, j)  # noqa
        for config in self.test_values.values():
            ct_expected = config['expected']
            if 'expected_djca' in config:
                ct_expected = config['expected_djca']

            for values in config['values']:
                self.assertEqualFunction(func, values, slice(1), set_init=ct_expected)
                self.assertEqualFunction(func, values, slice(0, 1), set_init=ct_expected)
                self.assertEqualFunction(func, values, slice(0, 2), set_init=ct_expected)
                self.assertEqualFunction(func, values, slice(0, 2, 2), set_init=ct_expected)

    def test_insert(self):
        """Test ext.insert()."""
        for config in self.test_values.values():
            ct_expected = config['expected']
            if 'expected_djca' in config:
                ct_expected = config['expected_djca']

            for values in config['values']:
                for expected_value, value in zip(ct_expected, values):
                    kwargs = {'infix': False, 'set_value': expected_value}
                    self.assertEqualFunction(lambda c, e: c.insert(0, e), [], value, **kwargs)
                    self.assertEqualFunction(lambda c, e: c.insert(0, e), config['expected'], value,
                                             set_init=ct_expected, **kwargs)
                    self.assertEqualFunction(lambda c, e: c.insert(1, e), config['expected'], value,
                                             set_init=ct_expected, **kwargs)
                    self.assertEqualFunction(lambda c, e: c.insert(9, e), config['expected'], value,
                                             set_init=ct_expected, **kwargs)

    def test_pop(self):
        """Test ext.pop()."""
        for config in self.test_values.values():
            for values in config['values']:
                ext = self.ext(values)

                if config['expected']:
                    with self.assertRaisesRegex(IndexError, '^pop index out of range$'):
                        ext.pop(len(config['expected']))

                exp = reversed(config['expected'])
                if 'expected_djca' in config:
                    exp = reversed(config['expected_djca'])

                for expected in exp:
                    self.assertEqual(expected, ext.pop())
                self.assertEqual(len(ext), 0)

        with self.assertRaisesRegex(IndexError, '^pop from empty list$'):
            self.ext([]).pop()

    def test_remove(self):
        """Test ext.remove()."""
        for config in self.test_values.values():
            for values in config['values']:
                for expected_value, value in zip(config['expected'], values):
                    kwargs = {'infix': False, 'set_value': expected_value}
                    self.assertEqualFunction(lambda c, e: c.remove(e), config['expected'], value, **kwargs)

    def test_setitem(self):
        """Test setting items (e.g. ``ext[0] = ...``)."""
        func = lambda c, j: operator.setitem(c, j[0], j[1])  # noqa
        for config in self.test_values.values():
            ct_expected = config['expected']
            if 'expected_djca' in config:
                ct_expected = config['expected_djca']

            for values in config['values']:
                for i, val in enumerate(values):
                    self.assertEqualFunction(func, list(config['expected']), (i, val),
                                             set_init=ct_expected, set_value=(i, ct_expected[i]))

    def test_setitem_slices(self):
        """Test setting slices."""
        func = lambda c, j: operator.setitem(c, j[0], j[1])  # noqa
        for config in self.test_values.values():
            ct_expected = config['expected']
            if 'expected_djca' in config:
                ct_expected = config['expected_djca']

            for values in config['values']:
                for _i in range(0, len(values)):  # loop to test all possible slices
                    start_slice = slice(0, 1)
                    self.assertEqualFunction(
                        func, list(config['expected']), (start_slice, values[start_slice], ),
                        set_init=ct_expected, set_value=(start_slice, ct_expected[start_slice]))


class OrderedSetExtensionTestMixin(IterableExtensionTestMixin):
    """Mixin for OrderedSetExtension based extensions."""

    # pylint: disable=unnecessary-lambda; assertion functions require passing lambda functions
    # pylint: disable=too-many-public-methods; b/c we're testing all those set functions

    container_type = set
    ext_class_name = 'OrderedSetExtension'

    def assertIsCopy(self, orig, new, expected_value=None):  # pylint: disable=invalid-name
        """Assert that `new` is a different instance then `other` and has possibly updated values."""
        if expected_value is None:
            expected_value = orig.value.copy()  # copy just to be sure

        self.assertEqual(new.value, expected_value)
        self.assertIsNot(orig, new)  # assert that this is a different instance
        self.assertIsNot(orig.value, new.value)  # value is also different instance

    def assertSingleValueOperator(self, oper, update=True, infix=True):  # pylint: disable=invalid-name
        """Test that an operator taking a single value works the same way with sets and this extension."""
        for config in self.test_values.values():

            # Apply function to an empty extension
            self.assertEqualFunction(oper, set(), config['expected'], update=update, infix=infix)

            # Apply function to an extension with every "expected" value
            for init_config in self.test_values.values():
                self.assertEqualFunction(oper, init_config['expected'], config['expected'], update=update,
                                         infix=infix)

            # Test that equivalent values work exactly the same way:
            for test_value in config['values']:
                # Again, apply function to the empty extension/set
                self.assertEqualFunction(oper, set(), test_value, set_value=config['expected'],
                                         update=update, infix=infix)

                # Again, apply function to an extension with every "expected" value
                for init_config in self.test_values.values():
                    self.assertEqualFunction(oper, init=init_config['expected'], value=test_value,
                                             set_value=config['expected'], update=update, infix=infix)

    def assertMultipleValuesOperator(self, oper, update=True, infix=True):  # pylint: disable=invalid-name
        """Test that an operator taking a multiple values works the same way with sets and this extension."""
        for first_config in self.test_values.values():
            for second_config in self.test_values.values():
                expected = (set(first_config['expected']), set(second_config['expected']))

                # Apply function to an empty extension
                self.assertEqualFunction(oper, set(), expected, update=update, infix=infix)

                for init_config in self.test_values.values():
                    expected = (
                        set(init_config['expected']),
                        set(first_config['expected']), set(second_config['expected']),
                    )
                    self.assertEqualFunction(oper, init_config['expected'], expected, update=update,
                                             infix=infix)

    def assertRelation(self, oper):  # pylint: disable=invalid-name
        """Assert that a extension relation is equal to that of set()."""
        self.assertEqual(oper(set(), set()), oper(self.ext_class({'value': set()}), set()))
        self.assertEqual(oper(set(), set()), oper(self.ext_class({'value': set()}),
                                                  self.ext_class({'value': set()})))

        for config in self.test_values.values():
            self.assertEqual(
                oper(config['expected'], config['expected']),
                oper(self.ext_class({'value': set(config['expected'])}), set(config['expected']))
            )
            self.assertEqual(
                oper(config['expected'], config['expected']),
                oper(self.ext_class({'value': set(config['expected'])}),
                     self.ext_class({'value': set(config['expected'])}))
            )

            for second_config in self.test_values.values():
                intersection_expected = config['expected'] & second_config['expected']
                self.assertEqual(
                    oper(config['expected'], intersection_expected),
                    oper(self.ext_class({'value': set(config['expected'])}), intersection_expected)
                )
                self.assertEqual(
                    oper(config['expected'], intersection_expected),
                    oper(self.ext_class({'value': set(config['expected'])}),
                         self.ext_class({'value': intersection_expected}))
                )
                self.assertEqual(
                    oper(config['expected'], intersection_expected),
                    oper(self.ext_class({'value': config['expected']}),
                         self.ext_class({'value': set(intersection_expected)}))
                )

                union_expected = config['expected'] | second_config['expected']
                self.assertEqual(
                    oper(config['expected'], set(union_expected)),
                    oper(self.ext_class({'value': set(config['expected'])}), union_expected)
                )
                self.assertEqual(
                    oper(config['expected'], set(union_expected)),
                    oper(self.ext_class({'value': set(config['expected'])}),
                         self.ext_class({'value': set(union_expected)}))
                )
                self.assertEqual(
                    oper(config['expected'], set(union_expected)),
                    oper(self.ext_class({'value': config['expected']}), set(union_expected))
                )

                symmetric_diff_expected = config['expected'] ^ second_config['expected']
                self.assertEqual(
                    oper(config['expected'], set(symmetric_diff_expected)),
                    oper(self.ext_class({'value': set(config['expected'])}), set(symmetric_diff_expected))
                )
                self.assertEqual(
                    oper(config['expected'], set(symmetric_diff_expected)),
                    oper(self.ext_class({'value': set(config['expected'])}),
                         self.ext_class({'value': set(symmetric_diff_expected)}))
                )
                self.assertEqual(
                    oper(set(symmetric_diff_expected), config['expected']),
                    oper(self.ext_class({'value': set(symmetric_diff_expected)}),
                         self.ext_class({'value': set(config['expected'])}))
                )

    def test_add(self):
        """Test ext.add()."""
        for config in self.test_values.values():
            for values in config['values']:
                ext = self.ext_class({'value': set()})
                for value in values:
                    ext.add(value)
                    self.assertIn(value, ext)
                    # Note: we cannot assert the length, because values might include alias values

                self.assertEqual(ext, self.ext_class({'value': config['expected']}))

    def test_copy(self):
        """Test ext.copy()."""
        for config in self.test_values.values():
            ext = self.ext_class({'value': config['expected']})
            ext_copy = ext.copy()
            self.assertIsCopy(ext, ext_copy, config['expected'])

    def test_difference(self):
        """Test ext.difference()."""
        self.assertSingleValueOperator(lambda s, o: s.difference(o), infix=False, update=False)
        self.assertMultipleValuesOperator(lambda s, o: s.difference(*o), infix=False, update=False)

    def test_difference_operator(self):
        """Test the ``-`` operator."""
        self.assertSingleValueOperator(lambda s, o: operator.sub(s, o), update=False)
        self.assertMultipleValuesOperator(
            lambda s, o: operator.sub(s, functools.reduce(operator.sub, [t.copy() for t in o])),
            update=False)

    def test_difference_update(self):
        """Test ext.difference_update()."""
        self.assertSingleValueOperator(lambda s, o: s.difference_update(o), infix=False)
        self.assertMultipleValuesOperator(lambda s, o: s.difference_update(*o), infix=False)

    def test_difference_update_operator(self):
        """Test the ``-=`` operator."""
        self.assertSingleValueOperator(lambda s, o: operator.isub(s, o))
        self.assertMultipleValuesOperator(
            lambda s, o: operator.isub(s, functools.reduce(operator.sub, [t.copy() for t in o])))

    def test_discard(self):
        """Test  ext.discard()."""
        for config in self.test_values.values():
            for values in config['values']:
                ext = self.ext_class({'value': config['expected']})
                ext_empty = self.ext_class({'value': set()})

                for i, value in enumerate(values, start=1):
                    self.assertIn(value, ext)
                    ext.discard(value)
                    self.assertNotIn(value, ext)
                    self.assertEqual(len(ext) + i, len(config['expected']))

                    self.assertEqual(len(ext_empty), 0)
                    ext_empty.discard(value)
                    self.assertEqual(len(ext_empty), 0)

    def test_greater_then_operator(self):
        """Test the ``<`` operator."""
        self.assertRelation(lambda s, o: operator.gt(s, o))

    def test_intersection(self):
        """Test ext.intersection()."""
        self.assertSingleValueOperator(lambda s, o: s.intersection(o), infix=False, update=False)
        self.assertMultipleValuesOperator(lambda s, o: s.intersection(*o), infix=False, update=False)

    def test_intersection_operator(self):
        """Test the ``&`` operator."""
        self.assertSingleValueOperator(lambda s, o: operator.and_(s, o), update=False)
        self.assertMultipleValuesOperator(
            lambda s, o: operator.and_(s, functools.reduce(operator.and_, [t.copy() for t in o])),
            update=False)

    def test_intersection_update(self):
        """Test ext.intersection_update()."""
        self.assertSingleValueOperator(lambda s, o: s.intersection_update(o), infix=False)
        self.assertMultipleValuesOperator(lambda s, o: s.intersection_update(*o), infix=False)

    def test_intersection_update_operator(self):
        """Test the ``&=`` operator."""
        self.assertSingleValueOperator(lambda s, o: operator.iand(s, o))
        self.assertMultipleValuesOperator(
            lambda s, o: operator.iand(s, functools.reduce(operator.and_, [t.copy() for t in o])))

    def test_isdisjoint(self):
        """Test ext.isdisjoint()."""
        self.assertRelation(lambda s, o: s.isdisjoint(o))

    def test_issubset(self):
        """Test ext.issubset()."""
        self.assertRelation(lambda s, o: s.issubset(o))

    def test_issubset_operator(self):
        """Test the ``<=`` operator."""
        self.assertRelation(lambda s, o: operator.le(s, o))

    def test_issuperset(self):
        """Test ext.issuperset()."""
        self.assertRelation(lambda s, o: s.issuperset(o))

    def test_issuperset_operator(self):
        """Test the ``>=`` operator."""
        self.assertRelation(lambda s, o: operator.ge(s, o))

    def test_lesser_then_operator(self):
        """Test the ``<`` operator."""
        self.assertRelation(lambda s, o: operator.lt(s, o))

    def test_pop(self):
        """Test ext.pop()."""
        for config in self.test_values.values():
            for _values in config['values']:  # loop so that we pop all values from ext
                ext = self.ext_class({'value': set(config['expected'])})
                self.assertEqual(len(ext), len(config['expected']))

                while len(ext) > 0:
                    # pop an element
                    orig_length = len(ext)
                    value = ext.pop()

                    self.assertNotIn(value, ext)
                    self.assertEqual(len(ext) + 1, orig_length)  # length shrunk by one

        ext = self.ext_class({'value': set()})
        with self.assertRaisesRegex(KeyError, "^'pop from an empty set'$"):
            ext.pop()

    def test_remove(self):
        """Test ext.remove()."""
        for config in self.test_values.values():
            for values in config['values']:
                ext = self.ext_class({'value': set(config['expected'])})

                for i, value in enumerate(values, start=1):
                    self.assertIsNone(ext.remove(value))
                    self.assertNotIn(value, ext)
                    self.assertEqual(len(ext) + i, len(config['expected']))

                    with self.assertRaises(KeyError):
                        # NOTE: We cannot test the message here because it may be a mapped value
                        ext.remove(value)

    def test_smaller_then_operator(self):
        """Test the ``<`` operator."""
        self.assertRelation(lambda s, o: operator.lt(s, o))

    def test_symmetric_difference(self):
        """Test ext.symmetric_difference."""
        self.assertSingleValueOperator(lambda s, o: s.symmetric_difference(o), update=False, infix=False)

    def test_symmetric_difference_operator(self):
        """Test ``^`` operator (symmetric_difference)."""
        self.assertSingleValueOperator(lambda s, o: operator.xor(s, o), update=False)

    def test_symmetric_difference_update(self):
        """Test ext.symmetric_difference_update()."""
        self.assertSingleValueOperator(lambda s, o: s.symmetric_difference_update(o), infix=False)

    def test_symmetric_difference_update_operator(self):
        """Test the ``^=`` operator."""
        self.assertSingleValueOperator(lambda s, o: operator.ixor(s, o))

    def test_union(self):
        """Test ext.union()."""
        self.assertSingleValueOperator(lambda s, o: s.union(o), infix=False, update=False)
        self.assertMultipleValuesOperator(lambda s, o: s.union(*o), infix=False, update=False)

    def test_union_operator(self):
        """Test the ``|`` operator``."""
        self.assertSingleValueOperator(lambda s, o: operator.or_(s, o), update=False)
        self.assertMultipleValuesOperator(
            lambda s, o: operator.or_(s, functools.reduce(operator.or_, [t.copy() for t in o])), update=False)

    def test_update(self):
        """Test ext.update()."""
        self.assertSingleValueOperator(lambda s, o: s.update(o), infix=False)
        self.assertMultipleValuesOperator(lambda s, o: s.update(*o), infix=False)

    def test_update_operator(self):
        """Test the ``|=`` operator."""
        self.assertSingleValueOperator(lambda s, o: operator.ior(s, o))
        self.assertMultipleValuesOperator(
            lambda s, o: operator.ior(s, functools.reduce(operator.ior, [t.copy() for t in o])))


class AuthorityInformationAccessTestCase(ExtensionTestMixin, TestCase):
    """Test AuthorityInformationAccess extension."""

    ext_class = AuthorityInformationAccess
    ext_class_key = 'authority_information_access'
    ext_class_name = 'AuthorityInformationAccess'

    uri1 = 'https://example1.com'
    uri2 = 'https://example2.net'
    uri3 = 'https://example3.org'
    uri4 = 'https://example4.at'

    test_values = {
        'empty': {
            'values': [{}],
            'expected': {'issuers': [], 'ocsp': []},
            'expected_bool': False,
            'expected_repr': 'issuers=[], ocsp=[]',
            'expected_serialized': {},
            'expected_text': '',
            'extension_type': x509.AuthorityInformationAccess(descriptions=[]),
        },
        'issuer': {
            'values': [{'issuers': [uri1]}, {'issuers': [uri(uri1)]}, ],
            'expected': {'issuers': [uri(uri1)], 'ocsp': []},
            'expected_repr': "issuers=['URI:%s'], ocsp=[]" % uri1,
            'expected_serialized': {'issuers': ['URI:%s' % uri1]},
            'expected_text': 'CA Issuers:\n  * URI:%s' % uri1,
            'extension_type': x509.AuthorityInformationAccess(descriptions=[
                x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, uri(uri1))
            ]),
        },
        'ocsp': {
            'values': [{'ocsp': [uri2]}, {'ocsp': [uri(uri2)]}, ],
            'expected': {'ocsp': [uri(uri2)], 'issuers': []},
            'expected_repr': "issuers=[], ocsp=['URI:%s']" % uri2,
            'expected_serialized': {'ocsp': ['URI:%s' % uri2]},
            'expected_text': 'OCSP:\n  * URI:%s' % uri2,
            'extension_type': x509.AuthorityInformationAccess(descriptions=[
                x509.AccessDescription(AuthorityInformationAccessOID.OCSP, uri(uri2))
            ]),
        },
        'both': {
            'values': [{'ocsp': [uri1], 'issuers': [uri2]}, {'ocsp': [uri(uri1)], 'issuers': [uri(uri2)]}, ],
            'expected': {'ocsp': [uri(uri1)], 'issuers': [uri(uri2)]},
            'expected_repr': "issuers=['URI:%s'], ocsp=['URI:%s']" % (uri2, uri1),
            'expected_serialized': {'ocsp': ['URI:%s' % uri1], 'issuers': ['URI:%s' % uri2]},
            'expected_text': 'CA Issuers:\n  * URI:%s\nOCSP:\n  * URI:%s' % (uri2, uri1),
            'extension_type': x509.AuthorityInformationAccess(descriptions=[
                x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, uri(uri2)),
                x509.AccessDescription(AuthorityInformationAccessOID.OCSP, uri(uri1)),
            ]),
        },
        'multiple': {
            'values': [
                {'ocsp': [uri1, uri2], 'issuers': [uri3, uri4]},
                {'ocsp': [uri1, uri(uri2)], 'issuers': [uri3, uri(uri4)]},
                {'ocsp': [uri(uri1), uri(uri2)], 'issuers': [uri(uri3), uri(uri4)]},
            ],
            'expected': {'ocsp': [uri(uri1), uri(uri2)], 'issuers': [uri(uri3), uri(uri4)]},
            'expected_repr': "issuers=['URI:%s', 'URI:%s'], ocsp=['URI:%s', 'URI:%s']" % (
                uri3, uri4, uri1, uri2),
            'expected_serialized': {'ocsp': ['URI:%s' % uri1, 'URI:%s' % uri2],
                                    'issuers': ['URI:%s' % uri3, 'URI:%s' % uri4]},
            'expected_text': 'CA Issuers:\n  * URI:%s\n  * URI:%s\n'
                             'OCSP:\n  * URI:%s\n  * URI:%s' % (uri3, uri4, uri1, uri2),
            'extension_type': x509.AuthorityInformationAccess(descriptions=[
                x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, uri(uri3)),
                x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, uri(uri4)),
                x509.AccessDescription(AuthorityInformationAccessOID.OCSP, uri(uri1)),
                x509.AccessDescription(AuthorityInformationAccessOID.OCSP, uri(uri2)),
            ]),
        },
    }

    def test_bool(self):
        """Test bool(ext)."""
        for config in self.test_values.values():
            ext = self.ext(config['expected'])
            self.assertEqual(bool(ext), config.get('expected_bool', True))

    def test_value(self):
        return

    def test_none_value(self):
        """Test that we can use and pass None as values for GeneralNamesList values."""
        ext = self.ext_class({'value': {'issuers': None, 'ocsp': None}})
        self.assertEqual(ext.issuers, [])
        self.assertEqual(ext.ocsp, [])
        self.assertEqual(ext.extension_type, x509.AuthorityInformationAccess(descriptions=[]))

    def test_properties(self):
        """Test issuers and ocsp properties"""
        expected_issuers = GeneralNameList([self.uri1])
        expected_ocsp = GeneralNameList([self.uri2])
        expected = AuthorityInformationAccess({'value': {"issuers": [self.uri1], "ocsp": [self.uri2]}})

        ext = AuthorityInformationAccess()
        ext.issuers = [self.uri1]
        ext.ocsp = [self.uri2]
        self.assertEqual(ext.issuers, expected_issuers)
        self.assertEqual(ext.ocsp, expected_ocsp)
        self.assertIsInstance(ext.issuers, GeneralNameList)
        self.assertIsInstance(ext.ocsp, GeneralNameList)
        self.assertEqual(ext, expected)

        ext = AuthorityInformationAccess()
        ext.issuers = expected_issuers
        ext.ocsp = expected_ocsp
        self.assertEqual(ext.issuers, expected_issuers)
        self.assertEqual(ext.ocsp, expected_ocsp)
        self.assertIsInstance(ext.issuers, GeneralNameList)
        self.assertIsInstance(ext.ocsp, GeneralNameList)
        self.assertEqual(ext, expected)


class AuthorityKeyIdentifierTestCase(ExtensionTestMixin, TestCase):
    """Test AuthorityKeyIdentifier extension."""

    ext_class = AuthorityKeyIdentifier
    ext_class_key = 'authority_key_identifier'
    ext_class_name = 'AuthorityKeyIdentifier'

    b1 = b'333333'
    b2 = b'DDDDDD'
    b3 = b'UUUUUU'
    hex1 = '33:33:33:33:33:33'
    hex2 = '44:44:44:44:44:44'
    hex3 = '55:55:55:55:55:55'
    uri1 = 'http://ca.example.com/crl'
    dns1 = 'example.org'
    s1 = 0
    s2 = 1

    test_values = {
        'one': {
            'values': [hex1, ],
            'expected': b1,
            'expected_repr': 'keyid: %s' % hex1,
            'expected_serialized': {'key_identifier': hex1},
            'expected_text': '* KeyID: %s' % hex1,
            'extension_type': x509.AuthorityKeyIdentifier(b1, None, None),
        },
        'two': {
            'values': [hex2, ],
            'expected': b2,
            'expected_repr': 'keyid: %s' % hex2,
            'expected_serialized': {'key_identifier': hex2},
            'expected_text': '* KeyID: %s' % hex2,
            'extension_type': x509.AuthorityKeyIdentifier(b2, None, None),
        },
        'three': {
            'values': [hex3, ],
            'expected': b3,
            'expected_repr': 'keyid: %s' % hex3,
            'expected_serialized': {'key_identifier': hex3},
            'expected_text': '* KeyID: %s' % hex3,
            'extension_type': x509.AuthorityKeyIdentifier(b3, None, None),
        },
        'issuer/serial': {
            'expected': {'authority_cert_issuer': [dns1], 'authority_cert_serial_number': s1},
            'values': [{'authority_cert_issuer': [dns1], 'authority_cert_serial_number': s1}],
            'expected_repr': "issuer: ['DNS:%s'], serial: %s" % (dns1, s1),
            'expected_serialized': {'authority_cert_issuer': ['DNS:%s' % dns1],
                                    'authority_cert_serial_number': s1},
            'expected_text': "* Issuer:\n  * DNS:%s\n* Serial: %s" % (dns1, s1),
            'extension_type': x509.AuthorityKeyIdentifier(None, [dns(dns1)], s1),
        }
    }

    def test_from_subject_key_identifier(self):
        """Test creating an extension from a subject key identifier."""
        for config in self.test_values.values():
            if not isinstance(config['expected'], bytes):
                continue

            ski = SubjectKeyIdentifier({'value': config['expected']})
            ext = self.ext_class(ski)
            self.assertExtensionEqual(ext, self.ext_class({'value': config['expected']}))

    def test_none_value(self):
        """Test that we can use and pass None as values for GeneralNamesList values."""
        ext = self.ext_class({'value': {
            'key_identifier': self.b1,
            'authority_cert_issuer': None,
            'authority_cert_serial_number': None,
        }})
        self.assertEqual(ext.extension_type, x509.AuthorityKeyIdentifier(
            key_identifier=self.b1, authority_cert_issuer=None, authority_cert_serial_number=None
        ))

    def test_value(self):
        return


class BasicConstraintsTestCase(ExtensionTestMixin, TestCase):
    """Test BasicConstraints extension."""

    ext_class = BasicConstraints
    ext_class_key = 'basic_constraints'
    ext_class_name = 'BasicConstraints'

    test_values = {
        'no_ca': {
            'values': [
                {'ca': False},
                {'ca': False, 'pathlen': 3},  # ignored b/c ca=False
                {'ca': False, 'pathlen': None},  # ignored b/c ca=False
            ],
            'expected': {'ca': False, 'pathlen': None},
            'expected_text': 'CA:FALSE',
            'expected_repr': "ca=False",
            'expected_serialized': {'ca': False},
            'extension_type': x509.BasicConstraints(ca=False, path_length=None),
        },
        'no_pathlen': {
            'values': [
                {'ca': True},
                {'ca': True, 'pathlen': None},
            ],
            'expected': {'ca': True, 'pathlen': None},
            'expected_text': 'CA:TRUE',
            'expected_repr': "ca=True, pathlen=None",
            'expected_serialized': {'ca': True, 'pathlen': None},
            'extension_type': x509.BasicConstraints(ca=True, path_length=None),
        },
        'pathlen_zero': {
            'values': [
                {'ca': True, 'pathlen': 0},
            ],
            'expected': {'ca': True, 'pathlen': 0},
            'expected_text': 'CA:TRUE, pathlen:0',
            'expected_repr': "ca=True, pathlen=0",
            'expected_serialized': {'ca': True, 'pathlen': 0},
            'extension_type': x509.BasicConstraints(ca=True, path_length=0),
        },
        'pathlen_three': {
            'values': [
                {'ca': True, 'pathlen': 3},
            ],
            'expected': {'ca': True, 'pathlen': 3},
            'expected_text': 'CA:TRUE, pathlen:3',
            'expected_repr': "ca=True, pathlen=3",
            'expected_serialized': {'ca': True, 'pathlen': 3},
            'extension_type': x509.BasicConstraints(ca=True, path_length=3),
        },
    }

    def test_invalid_pathlen(self):
        """Test passing an invalid pathlen."""
        with self.assertRaisesRegex(ValueError, r'^Could not parse pathlen: "foo"$'):
            BasicConstraints({'value': {'ca': True, 'pathlen': 'foo'}})

        with self.assertRaisesRegex(ValueError, r'^Could not parse pathlen: ""$'):
            BasicConstraints({'value': {'ca': True, 'pathlen': ''}})

        with self.assertRaisesRegex(ValueError, r'^Could not parse pathlen: "foobar"$'):
            BasicConstraints({'value': {'ca': True, 'pathlen': 'foobar'}})

    def test_value(self):
        return


class CRLDistributionPointsTestCase(ListExtensionTestMixin, ExtensionTestMixin, TestCase):
    """Test CRLDistributionPoints extension."""

    ext_class = CRLDistributionPoints
    ext_class_key = 'crl_distribution_points'
    ext_class_name = 'CRLDistributionPoints'
    ext_class_type = x509.CRLDistributionPoints

    uri1 = 'http://ca.example.com/crl'
    uri2 = 'http://ca.example.net/crl'
    uri3 = 'http://ca.example.com/'
    dns1 = 'example.org'
    rdn1 = '/CN=example.com'

    s1 = {'full_name': ['URI:%s' % uri1]}
    s2 = {'full_name': ['URI:%s' % uri1, 'DNS:%s' % dns1]}
    s3 = {'relative_name': rdn1}
    s4 = {
        'full_name': ['URI:%s' % uri2],
        'crl_issuer': ['URI:%s' % uri3],
        'reasons': ['ca_compromise', 'key_compromise'],
    }
    dp1 = DistributionPoint(s1)
    dp2 = DistributionPoint(s2)
    dp3 = DistributionPoint(s3)
    dp4 = DistributionPoint(s4)

    cg_rdn1 = rdn([(NameOID.COMMON_NAME, 'example.com')])

    cg_dp1 = x509.DistributionPoint(full_name=[uri(uri1)], relative_name=None, crl_issuer=None, reasons=None)
    cg_dp2 = x509.DistributionPoint(full_name=[uri(uri1), dns(dns1)], relative_name=None, crl_issuer=None,
                                    reasons=None)
    cg_dp3 = x509.DistributionPoint(full_name=None, relative_name=cg_rdn1, crl_issuer=None, reasons=None)
    cg_dp4 = x509.DistributionPoint(full_name=[uri(uri2)], relative_name=None, crl_issuer=[uri(uri3)],
                                    reasons=frozenset([x509.ReasonFlags.key_compromise,
                                                       x509.ReasonFlags.ca_compromise]))

    cg_dps1 = x509.CRLDistributionPoints([cg_dp1])
    cg_dps2 = x509.CRLDistributionPoints([cg_dp2])
    cg_dps3 = x509.CRLDistributionPoints([cg_dp3])
    cg_dps4 = x509.CRLDistributionPoints([cg_dp4])

    invalid_values = [True, None]
    test_values = {
        'one': {
            'values': [[s1], [dp1], [cg_dp1], [{'full_name': [uri1]}], [{'full_name': [uri(uri1)]}]],
            'expected': [s1],
            'expected_djca': [dp1],
            'expected_repr': "[<DistributionPoint: full_name=['URI:%s']>]" % uri1,
            'expected_serialized': [s1],
            'expected_text': '* DistributionPoint:\n  * Full Name:\n    * URI:%s' % uri1,
            'extension_type': cg_dps1,
        },
        'two': {
            'values': [[s2], [dp2], [cg_dp2], [{'full_name': [uri1, dns1]}],
                       [{'full_name': [uri(uri1), dns(dns1)]}]],
            'expected': [s2],
            'expected_djca': [dp2],
            'expected_repr': "[<DistributionPoint: full_name=['URI:%s', 'DNS:%s']>]" % (uri1, dns1),
            'expected_serialized': [s2],
            'expected_text': '* DistributionPoint:\n  * Full Name:\n    * URI:%s\n    '
                             '* DNS:%s' % (uri1, dns1),
            'extension_type': cg_dps2,
        },
        'rdn': {
            'values': [[s3], [dp3], [cg_dp3], [{'relative_name': cg_rdn1}]],
            'expected': [s3],
            'expected_djca': [dp3],
            'expected_repr': "[<DistributionPoint: relative_name='%s'>]" % rdn1,
            'expected_serialized': [s3],
            'expected_text': '* DistributionPoint:\n  * Relative Name: %s' % rdn1,
            'extension_type': cg_dps3,
        },
        'adv': {
            'values': [[s4], [dp4], [cg_dp4]],
            'expected': [s4],
            'expected_djca': [dp4],
            'expected_repr': "[<DistributionPoint: full_name=['URI:%s'], crl_issuer=['URI:%s'], "
                             "reasons=['ca_compromise', 'key_compromise']>]" % (uri2, uri3),
            'expected_serialized': [s4],
            'expected_text': '* DistributionPoint:\n  * Full Name:\n    * URI:%s\n'
                             '  * CRL Issuer:\n    * URI:%s\n'
                             '  * Reasons: ca_compromise, key_compromise' % (uri2, uri3),
            'extension_type': cg_dps4,
        },
    }

    def test_none_value(self):
        """Test that we can pass a None value for GeneralNameList items."""
        ext = self.ext_class()
        self.assertEqual(ext.extension_type, self.ext_class_type(distribution_points=[]))

        ext.append(DistributionPoint({'full_name': None}))
        self.assertEqual(ext.extension_type, self.ext_class_type(distribution_points=[
            x509.DistributionPoint(full_name=None, relative_name=None, reasons=None, crl_issuer=None)
        ]))

        ext[0].full_name = GeneralNameList()
        self.assertEqual(ext.extension_type, self.ext_class_type(distribution_points=[
            x509.DistributionPoint(full_name=None, relative_name=None, reasons=None, crl_issuer=None)
        ]))


class CertificatePoliciesTestCase(ListExtensionTestMixin, ExtensionTestMixin, TestCase):
    """Test CertificatePolicies extension."""

    ext_class = CertificatePolicies
    ext_class_name = 'CertificatePolicies'
    ext_class_key = 'certificate_policies'

    oid = '2.5.29.32.0'

    text1, text2, text3, text4, text5, text6 = ['text%s' % i for i in range(1, 7)]

    un1 = {
        'policy_identifier': oid,
        'policy_qualifiers': [text1],
    }
    un2 = {
        'policy_identifier': oid,
        'policy_qualifiers': [
            {'explicit_text': text2, }
        ],
    }
    un3 = {
        'policy_identifier': oid,
        'policy_qualifiers': [
            {
                'notice_reference': {
                    'organization': text3,
                    'notice_numbers': [1, ],
                }
            }
        ],
    }
    un4 = {
        'policy_identifier': oid,
        'policy_qualifiers': [
            text4,
            {
                'explicit_text': text5,
                'notice_reference': {
                    'organization': text6,
                    'notice_numbers': [1, 2, 3],
                }
            }
        ],
    }
    p1 = PolicyInformation(un1)
    p2 = PolicyInformation(un2)
    p3 = PolicyInformation(un3)
    p4 = PolicyInformation(un4)

    xun1 = text1
    xun2 = x509.UserNotice(explicit_text=text2, notice_reference=None)
    xun3 = x509.UserNotice(
        explicit_text=None, notice_reference=x509.NoticeReference(organization=text3, notice_numbers=[1]))
    xun4_1 = text4
    xun4_2 = x509.UserNotice(
        explicit_text=text5,
        notice_reference=x509.NoticeReference(organization=text6, notice_numbers=[1, 2, 3])
    )
    xpi1 = x509.PolicyInformation(policy_identifier=ObjectIdentifier(oid), policy_qualifiers=[xun1])
    xpi2 = x509.PolicyInformation(policy_identifier=ObjectIdentifier(oid), policy_qualifiers=[xun2])
    xpi3 = x509.PolicyInformation(policy_identifier=ObjectIdentifier(oid), policy_qualifiers=[xun3])
    xpi4 = x509.PolicyInformation(policy_identifier=ObjectIdentifier(oid), policy_qualifiers=[xun4_1, xun4_2])

    xcp1 = x509.CertificatePolicies(policies=[xpi1])
    xcp2 = x509.CertificatePolicies(policies=[xpi2])
    xcp3 = x509.CertificatePolicies(policies=[xpi3])
    xcp4 = x509.CertificatePolicies(policies=[xpi4])
    xcp5 = x509.CertificatePolicies(policies=[xpi1, xpi2, xpi4])

    test_values = {
        'one': {
            'values': [[un1], [xpi1]],
            'expected': [p1],
            'expected_djca': [p1],
            'expected_repr': "1 policy",
            'expected_serialized': [un1],
            'expected_text': '* Policy Identifier: %s\n  Policy Qualifiers:\n  * %s' % (oid, text1),
            'extension_type': xcp1,
        },
        'two': {
            'values': [[un2], [xpi2]],
            'expected': [p2],
            'expected_djca': [p2],
            'expected_repr': "1 policy",
            'expected_serialized': [un2],
            'expected_text': '* Policy Identifier: %s\n  Policy Qualifiers:\n  * UserNotice:\n'
                             '    * Explicit text: %s' % (oid, text2),
            'extension_type': xcp2,
        },
        'three': {
            'values': [[un3], [xpi3]],
            'expected': [p3],
            'expected_djca': [p3],
            'expected_repr': "1 policy",
            'expected_serialized': [un3],
            'expected_text': '* Policy Identifier: %s\n  Policy Qualifiers:\n  * UserNotice:\n'
                             '    * Reference:\n      * Organiziation: %s\n'
                             '      * Notice Numbers: [1]' % (oid, text3),
            'extension_type': xcp3,
        },
        'four': {
            'values': [[un4], [xpi4]],
            'expected': [p4],
            'expected_djca': [p4],
            'expected_repr': "1 policy",
            'expected_serialized': [un4],
            'expected_text': '* Policy Identifier: %s\n  Policy Qualifiers:\n  * %s\n  * UserNotice:\n'
                             '    * Explicit text: %s\n    * Reference:\n      * Organiziation: %s\n'
                             '      * Notice Numbers: [1, 2, 3]' % (oid, text4, text5, text6),
            'extension_type': xcp4,
        },
        'five': {
            'values': [[un1, un2, un4], [xpi1, xpi2, xpi4], [un1, xpi2, un4]],
            'expected': [p1, p2, p4],
            'expected_djca': [p1, p2, p4],
            'expected_repr': "3 policies",
            'expected_serialized': [un1, un2, un4],
            'expected_text': '* Policy Identifier: %s\n  Policy Qualifiers:\n  * %s\n'
                             '* Policy Identifier: %s\n  Policy Qualifiers:\n  * UserNotice:\n'
                             '    * Explicit text: %s\n'
                             '* Policy Identifier: %s\n  Policy Qualifiers:\n  * %s\n  * UserNotice:\n'
                             '    * Explicit text: %s\n    * Reference:\n      * Organiziation: %s\n'
                             '      * Notice Numbers: [1, 2, 3]' % (oid, text1, oid, text2, oid, text4,
                                                                    text5, text6),
            'extension_type': xcp5,
        },
    }


class FreshestCRLTestCase(CRLDistributionPointsTestCase):
    """Test FreshestCRL extension."""

    ext_class = FreshestCRL
    ext_class_key = 'freshest_crl'
    ext_class_name = 'FreshestCRL'
    ext_class_type = x509.FreshestCRL

    cg_dps1 = x509.FreshestCRL([CRLDistributionPointsTestCase.cg_dp1])
    cg_dps2 = x509.FreshestCRL([CRLDistributionPointsTestCase.cg_dp2])
    cg_dps3 = x509.FreshestCRL([CRLDistributionPointsTestCase.cg_dp3])
    cg_dps4 = x509.FreshestCRL([CRLDistributionPointsTestCase.cg_dp4])

    def setUp(self):
        self.test_values['one']['extension_type'] = self.cg_dps1
        self.test_values['two']['extension_type'] = self.cg_dps2
        self.test_values['rdn']['extension_type'] = self.cg_dps3
        self.test_values['adv']['extension_type'] = self.cg_dps4


class InhibitAnyPolicyTestCase(ExtensionTestMixin, TestCase):
    """Test InhibitAnyPolicy extension."""

    ext_class = InhibitAnyPolicy
    ext_class_key = 'inhibit_any_policy'
    ext_class_name = 'InhibitAnyPolicy'

    test_values = {
        'zero': {
            'values': [
                0,
            ],
            'expected': 0,
            'expected_repr': '0',
            'expected_serialized': 0,
            'expected_text': '0',
            'extension_type': x509.InhibitAnyPolicy(0),
        },
        'one': {
            'values': [
                1,
            ],
            'expected': 1,
            'expected_repr': '1',
            'expected_serialized': 1,
            'expected_text': '1',
            'extension_type': x509.InhibitAnyPolicy(1),
        },
    }

    def test_int(self):
        """Test passing various int values."""
        ext = InhibitAnyPolicy(0)
        self.assertEqual(ext.skip_certs, 0)
        ext = InhibitAnyPolicy(1)
        self.assertEqual(ext.skip_certs, 1)

        with self.assertRaisesRegex(ValueError, r'-1: must be a positive int$'):
            InhibitAnyPolicy(-1)
        with self.assertRaisesRegex(ValueError, r'-1: must be a positive int$'):
            InhibitAnyPolicy({'value': -1})

    def test_default(self):
        """Test the default value for the constructor."""
        self.assertEqual(InhibitAnyPolicy().skip_certs, 0)

    def test_no_int(self):
        """Test passing invalid values."""
        with self.assertRaisesRegex(ValueError, r'^abc: must be an int$'):
            InhibitAnyPolicy({'value': 'abc'})
        with self.assertRaisesRegex(ValueError, r'^Value is of unsupported type str$'):
            InhibitAnyPolicy('abc')

    def test_value(self):
        return


class IssuerAlternativeNameTestCase(ListExtensionTestMixin, ExtensionTestMixin, TestCase):
    """Test IssuerAlternativeName extension."""

    ext_class = IssuerAlternativeName
    ext_class_key = 'issuer_alternative_name'
    ext_class_name = 'IssuerAlternativeName'
    ext_class_type = x509.IssuerAlternativeName

    uri1 = value1 = 'https://example.com'
    uri2 = value2 = 'https://example.net'
    dns1 = value3 = 'example.com'
    dns2 = value4 = 'example.net'
    et1 = x509.IssuerAlternativeName([uri(value1)])

    invalid_values = ['DNS:https://example.com', True, None]
    test_values = {
        'empty': {
            'values': [[]],
            'expected': [],
            'expected_repr': '[]',
            'expected_serialized': [],
            'expected_text': '',
            'extension_type': ext_class_type([]),
        },
        'uri': {
            'values': [[uri1], [uri(uri1)]],
            'expected': [uri(uri1)],
            'expected_repr': "['URI:%s']" % uri1,
            'expected_serialized': ['URI:%s' % uri1],
            'expected_text': '* URI:%s' % uri1,
            'extension_type': ext_class_type([uri(uri1)]),
        },
        'dns': {
            'values': [[dns1], [dns(dns1)]],
            'expected': [dns(dns1)],
            'expected_repr': "['DNS:%s']" % dns1,
            'expected_serialized': ['DNS:%s' % dns1],
            'expected_text': '* DNS:%s' % dns1,
            'extension_type': ext_class_type([dns(dns1)]),
        },
        'both': {
            'values': [[uri1, dns1], [uri(uri1), dns(dns1)], [uri1, dns(dns1)], [uri(uri1), dns1]],
            'expected': [uri(uri1), dns(dns1)],
            'expected_repr': "['URI:%s', 'DNS:%s']" % (uri1, dns1),
            'expected_serialized': ['URI:%s' % uri1, 'DNS:%s' % dns1],
            'expected_text': '* URI:%s\n* DNS:%s' % (uri1, dns1),
            'extension_type': ext_class_type([uri(uri1), dns(dns1)]),
        },
        'all': {
            'values': [
                [uri1, uri2, dns1, dns2],
                [uri(uri1), uri(uri2), dns1, dns2],
                [uri1, uri2, dns(dns1), dns(dns2)],
                [uri(uri1), uri(uri2), dns(dns1), dns(dns2)],
            ],
            'expected': [uri(uri1), uri(uri2), dns(dns1), dns(dns2)],
            'expected_repr': "['URI:%s', 'URI:%s', 'DNS:%s', 'DNS:%s']" % (uri1, uri2, dns1, dns2),
            'expected_serialized': ['URI:%s' % uri1, 'URI:%s' % uri2, 'DNS:%s' % dns1, 'DNS:%s' % dns2],
            'expected_text': '* URI:%s\n* URI:%s\n* DNS:%s\n* DNS:%s' % (uri1, uri2, dns1, dns2),
            'extension_type': ext_class_type([uri(uri1), uri(uri2), dns(dns1), dns(dns2)]),
        },
        'order': {  # same as "all" above but other order
            'values': [
                [dns2, dns1, uri2, uri1],
                [dns(dns2), dns(dns1), uri2, uri1],
                [dns2, dns1, uri(uri2), uri(uri1)],
                [dns(dns2), dns(dns1), uri(uri2), uri(uri1)],
            ],
            'expected': [dns(dns2), dns(dns1), uri(uri2), uri(uri1)],
            'expected_repr': "['DNS:%s', 'DNS:%s', 'URI:%s', 'URI:%s']" % (dns2, dns1, uri2, uri1),
            'expected_serialized': ['DNS:%s' % dns2, 'DNS:%s' % dns1, 'URI:%s' % uri2, 'URI:%s' % uri1],
            'expected_text': '* DNS:%s\n* DNS:%s\n* URI:%s\n* URI:%s' % (dns2, dns1, uri2, uri1),
            'extension_type': ext_class_type([dns(dns2), dns(dns1), uri(uri2), uri(uri1)]),
        },
    }

    def test_none_value(self):
        """Test that we can pass a None value for GeneralNameList items."""
        empty = self.ext_class({'value': None})
        self.assertEqual(empty.extension_type, self.ext_class_type([]))
        self.assertEqual(empty, self.ext_class({'value': []}))
        empty.insert(0, self.value1)
        self.assertEqual(empty.extension_type, self.et1)


class PolicyConstraintsTestCase(ExtensionTestMixin, TestCase):
    """Test PolicyConstraints extension."""

    ext_class = PolicyConstraints
    ext_class_key = 'policy_constraints'
    ext_class_name = 'PolicyConstraints'

    test_values = {
        'rep_zero': {
            'values': [
                {'require_explicit_policy': 0},
            ],
            'expected': {'require_explicit_policy': 0},
            'expected_repr': 'require_explicit_policy=0',
            'expected_serialized': {'require_explicit_policy': 0},
            'expected_text': '* RequireExplicitPolicy: 0',
            'extension_type': x509.PolicyConstraints(require_explicit_policy=0, inhibit_policy_mapping=None),
        },
        'rep_one': {
            'values': [
                {'require_explicit_policy': 1},
            ],
            'expected': {'require_explicit_policy': 1},
            'expected_repr': 'require_explicit_policy=1',
            'expected_serialized': {'require_explicit_policy': 1},
            'expected_text': '* RequireExplicitPolicy: 1',
            'extension_type': x509.PolicyConstraints(require_explicit_policy=1, inhibit_policy_mapping=None),
        },
        'rep_none': {
            'values': [
                {'require_explicit_policy': None},
            ],
            'expected': {},
            'expected_repr': '-',
            'expected_serialized': {},
            'expected_text': '',
            'extension_type': None,
        },
        'iap_zero': {
            'values': [
                {'inhibit_policy_mapping': 0},
            ],
            'expected': {'inhibit_policy_mapping': 0},
            'expected_repr': 'inhibit_policy_mapping=0',
            'expected_serialized': {'inhibit_policy_mapping': 0},
            'expected_text': '* InhibitPolicyMapping: 0',
            'extension_type': x509.PolicyConstraints(require_explicit_policy=None, inhibit_policy_mapping=0),
        },
        'iap_one': {
            'values': [
                {'inhibit_policy_mapping': 1},
            ],
            'expected': {'inhibit_policy_mapping': 1},
            'expected_repr': 'inhibit_policy_mapping=1',
            'expected_serialized': {'inhibit_policy_mapping': 1},
            'expected_text': '* InhibitPolicyMapping: 1',
            'extension_type': x509.PolicyConstraints(require_explicit_policy=None, inhibit_policy_mapping=1),
        },
        'iap_none': {
            'values': [
                {'inhibit_policy_mapping': None},
            ],
            'expected': {},
            'expected_repr': '-',
            'expected_serialized': {},
            'expected_text': '',
            'extension_type': None,
        },
        'both': {
            'values': [
                {'inhibit_policy_mapping': 2, 'require_explicit_policy': 3},
            ],
            'expected': {'inhibit_policy_mapping': 2, 'require_explicit_policy': 3},
            'expected_repr': 'inhibit_policy_mapping=2, require_explicit_policy=3',
            'expected_serialized': {'inhibit_policy_mapping': 2, 'require_explicit_policy': 3},
            'expected_text': '* InhibitPolicyMapping: 2\n* RequireExplicitPolicy: 3',
            'extension_type': x509.PolicyConstraints(require_explicit_policy=3, inhibit_policy_mapping=2),
        },
    }

    def test_init_error(self):
        """Test constructor errors."""
        with self.assertRaisesRegex(ValueError, r'^abc: inhibit_policy_mapping must be int or None$'):
            PolicyConstraints({'value': {'inhibit_policy_mapping': 'abc'}})
        with self.assertRaisesRegex(ValueError, r'^-1: inhibit_policy_mapping must be a positive int$'):
            PolicyConstraints({'value': {'inhibit_policy_mapping': -1}})
        with self.assertRaisesRegex(ValueError, r'^abc: require_explicit_policy must be int or None$'):
            PolicyConstraints({'value': {'require_explicit_policy': 'abc'}})
        with self.assertRaisesRegex(ValueError, r'^-1: require_explicit_policy must be a positive int$'):
            PolicyConstraints({'value': {'require_explicit_policy': -1}})

    def test_properties(self):
        """Test properties"""
        pconst = PolicyConstraints()
        self.assertIsNone(pconst.inhibit_policy_mapping)
        self.assertIsNone(pconst.require_explicit_policy)

        pconst = PolicyConstraints({'value': {'inhibit_policy_mapping': 1, 'require_explicit_policy': 2}})
        self.assertEqual(pconst.inhibit_policy_mapping, 1)
        self.assertEqual(pconst.require_explicit_policy, 2)

        pconst.inhibit_policy_mapping = 3
        pconst.require_explicit_policy = 4
        self.assertEqual(pconst.inhibit_policy_mapping, 3)
        self.assertEqual(pconst.require_explicit_policy, 4)

        pconst.inhibit_policy_mapping = None
        pconst.require_explicit_policy = None
        self.assertIsNone(pconst.inhibit_policy_mapping)
        self.assertIsNone(pconst.require_explicit_policy)

    def test_value(self):
        return


class KeyUsageTestCase(OrderedSetExtensionTestMixin, ExtensionTestMixin, TestCase):
    """Test KeyUsage extension."""

    ext_class = KeyUsage
    ext_class_key = 'key_usage'
    ext_class_name = 'KeyUsage'

    test_values = {
        'one': {
            'values': [
                {'key_agreement', },
                ['keyAgreement', ],
            ],
            'expected': frozenset(['key_agreement']),
            'expected_repr': "['keyAgreement']",
            'expected_text': '* keyAgreement',
            'expected_serialized': ['keyAgreement'],
            'extension_type': x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=True, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False),
        },
        'two': {
            'values': [
                {'key_agreement', 'key_encipherment', },
                ['keyAgreement', 'keyEncipherment'],
                ['keyEncipherment', 'keyAgreement'],
                ['keyEncipherment', 'key_agreement'],
            ],
            'expected': frozenset(['key_agreement', 'key_encipherment']),
            'expected_repr': "['keyAgreement', 'keyEncipherment']",
            'expected_text': '* keyAgreement\n* keyEncipherment',
            'expected_serialized': ['keyAgreement', 'keyEncipherment'],
            'extension_type': x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=True,
                data_encipherment=False, key_agreement=True, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False),
        },
        'three': {
            'values': [
                {'key_agreement', 'key_encipherment', 'content_commitment', },
                ['keyAgreement', 'keyEncipherment', 'nonRepudiation', ],
                ['nonRepudiation', 'keyAgreement', 'keyEncipherment', ],
                ['nonRepudiation', 'keyAgreement', 'keyEncipherment', ],
                ['content_commitment', 'key_agreement', 'key_encipherment', ],
            ],
            'expected': frozenset(['key_agreement', 'key_encipherment', 'content_commitment', ]),
            'expected_repr': "['keyAgreement', 'keyEncipherment', 'nonRepudiation']",
            'expected_text': '* keyAgreement\n* keyEncipherment\n* nonRepudiation',
            'expected_serialized': ['keyAgreement', 'keyEncipherment', 'nonRepudiation'],
            'extension_type': x509.KeyUsage(
                digital_signature=False, content_commitment=True, key_encipherment=True,
                data_encipherment=False, key_agreement=True, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False),
        },
    }

    def test_completeness(self):
        """Test that we support all key usages."""
        self.assertEqual(set(KeyUsage.CRYPTOGRAPHY_MAPPING.keys()), {e[0] for e in KeyUsage.CHOICES})

    def test_auto_add(self):
        """Test that ``decipher_only`` and ``encipher_only`` automatically add ``key_agreement``."""
        self.assertEqual(KeyUsage({'value': ['decipher_only']}),
                         KeyUsage({'value': ['decipher_only', 'key_agreement']}))
        self.assertEqual(KeyUsage({'value': ['encipher_only']}),
                         KeyUsage({'value': ['encipher_only', 'key_agreement']}))

    def test_unknown_values(self):
        """Test passing unknown values."""
        with self.assertRaisesRegex(ValueError, r'^Unknown value: foo$'):
            KeyUsage({'value': ['foo']})

        with self.assertRaisesRegex(ValueError, r'^Unknown value: True$'):
            KeyUsage({'value': [True]})


class ExtendedKeyUsageTestCase(OrderedSetExtensionTestMixin, ExtensionTestMixin, TestCase):
    """Test ExtendedKeyUsage extension."""

    ext_class = ExtendedKeyUsage
    ext_class_key = 'extended_key_usage'
    ext_class_name = 'ExtendedKeyUsage'

    test_values = {
        'one': {
            'values': [
                {'serverAuth'},
                {ExtendedKeyUsageOID.SERVER_AUTH},
                [ExtendedKeyUsageOID.SERVER_AUTH],
            ],
            'extension_type': x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            'expected': frozenset([ExtendedKeyUsageOID.SERVER_AUTH]),
            'expected_repr': "['serverAuth']",
            'expected_serialized': ['serverAuth'],
            'expected_text': '* serverAuth',
        },
        'two': {
            'values': [
                {'serverAuth', 'clientAuth', },
                {ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH},
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH],
                [ExtendedKeyUsageOID.SERVER_AUTH, 'clientAuth'],
            ],
            'extension_type': x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH,
                                                     ExtendedKeyUsageOID.SERVER_AUTH]),
            'expected': frozenset([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
            'expected_repr': "['clientAuth', 'serverAuth']",
            'expected_serialized': ['clientAuth', 'serverAuth'],
            'expected_text': '* clientAuth\n* serverAuth',
        },
        'three': {
            'values': [
                {'serverAuth', 'clientAuth', 'timeStamping', },
                {ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH,
                 ExtendedKeyUsageOID.TIME_STAMPING, },
                {ExtendedKeyUsageOID.CLIENT_AUTH, 'serverAuth',
                 ExtendedKeyUsageOID.TIME_STAMPING, },
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH,
                 ExtendedKeyUsageOID.TIME_STAMPING],
                [ExtendedKeyUsageOID.TIME_STAMPING, ExtendedKeyUsageOID.SERVER_AUTH,
                 ExtendedKeyUsageOID.CLIENT_AUTH],
            ],
            'extension_type': x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH,
                                                     ExtendedKeyUsageOID.SERVER_AUTH,
                                                     ExtendedKeyUsageOID.TIME_STAMPING]),
            'expected': frozenset([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH,
                                   ExtendedKeyUsageOID.TIME_STAMPING]),
            'expected_repr': "['clientAuth', 'serverAuth', 'timeStamping']",
            'expected_serialized': ['clientAuth', 'serverAuth', 'timeStamping'],
            'expected_text': '* clientAuth\n* serverAuth\n* timeStamping',
        },
    }

    def test_unknown_values(self):
        """Test passing unknown values."""
        with self.assertRaisesRegex(ValueError, r'^Unknown value: foo$'):
            ExtendedKeyUsage({'value': ['foo']})

        with self.assertRaisesRegex(ValueError, r'^Unknown value: True$'):
            ExtendedKeyUsage({'value': [True]})

    def test_completeness(self):
        """Test that we support all ExtendedKeyUsageOIDs."""
        for attr in [getattr(ExtendedKeyUsageOID, a) for a in dir(ExtendedKeyUsageOID) if a[0] != '_']:
            if isinstance(attr, ObjectIdentifier):
                # pylint: disable=protected-access; ok for a test case
                self.assertIn(attr, ExtendedKeyUsage._CRYPTOGRAPHY_MAPPING_REVERSED)

        # make sure we haven't forgotton any keys in the form selection
        self.assertEqual(set(ExtendedKeyUsage.CRYPTOGRAPHY_MAPPING.keys()),
                         {e[0] for e in ExtendedKeyUsage.CHOICES})


class NameConstraintsTestCase(ExtensionTestMixin, TestCase):
    """Test NameConstraints extension."""

    ext_class = NameConstraints
    ext_class_key = 'name_constraints'
    ext_class_name = 'NameConstraints'

    d1 = 'example.com'
    d2 = 'example.net'

    test_values = {
        'empty': {
            'values': [
                {'excluded': [], 'permitted': []},
                {'excluded': None, 'permitted': None},
            ],
            'expected': x509.NameConstraints(permitted_subtrees=[], excluded_subtrees=[]),
            'expected_repr': 'permitted=[], excluded=[]',
            'expected_serialized': {'excluded': [], 'permitted': []},
            'expected_text': "",
            'extension_type': x509.NameConstraints(permitted_subtrees=[], excluded_subtrees=[]),
        },
        'permitted': {
            'values': [
                {'permitted': [d1]},
                {'permitted': ['DNS:%s' % d1]},
                {'permitted': [dns(d1)]},
                {'permitted': [dns(d1)], 'excluded': []},
            ],
            'expected': x509.NameConstraints(permitted_subtrees=[dns(d1)], excluded_subtrees=[]),
            'expected_repr': "permitted=['DNS:%s'], excluded=[]" % d1,
            'expected_serialized': {'excluded': [], 'permitted': ['DNS:%s' % d1]},
            'expected_text': "Permitted:\n  * DNS:%s\n" % d1,
            'extension_type': x509.NameConstraints(permitted_subtrees=[dns(d1)],
                                                   excluded_subtrees=[]),
        },
        'excluded': {
            'values': [
                {'excluded': [d1]},
                {'excluded': ['DNS:%s' % d1]},
                {'excluded': [dns(d1)]},
                {'excluded': [dns(d1)], 'permitted': []},
            ],
            'expected': x509.NameConstraints(permitted_subtrees=[], excluded_subtrees=[dns(d1)]),
            'expected_repr': "permitted=[], excluded=['DNS:%s']" % d1,
            'expected_serialized': {'excluded': ['DNS:%s' % d1], 'permitted': []},
            'expected_text': "Excluded:\n  * DNS:%s\n" % d1,
            'extension_type': x509.NameConstraints(permitted_subtrees=[],
                                                   excluded_subtrees=[dns(d1)]),
        },
        'both': {
            'values': [
                {'permitted': [d1], 'excluded': [d2]},
                {'permitted': ['DNS:%s' % d1], 'excluded': ['DNS:%s' % d2]},
                {'permitted': [dns(d1)], 'excluded': [dns(d2)]},
                {'permitted': [dns(d1)], 'excluded': [d2]},
            ],
            'expected': x509.NameConstraints(permitted_subtrees=[dns(d1)], excluded_subtrees=[dns(d2)]),
            'expected_repr': "permitted=['DNS:%s'], excluded=['DNS:%s']" % (d1, d2),
            'expected_serialized': {'excluded': ['DNS:%s' % d2], 'permitted': ['DNS:%s' % d1]},
            'expected_text': "Permitted:\n  * DNS:%s\nExcluded:\n  * DNS:%s\n" % (d1, d2),
            'extension_type': x509.NameConstraints(permitted_subtrees=[dns(d1)], excluded_subtrees=[dns(d2)]),
        },
    }

    def test_bool(self):
        """Test bool(ext)."""
        self.assertFalse(bool(NameConstraints()))
        self.assertTrue(bool(NameConstraints({'value': {'permitted': ['example.com']}})))
        self.assertTrue(bool(NameConstraints({'value': {'excluded': ['example.com']}})))

    def test_setters(self):
        """Test items etters."""
        expected = NameConstraints({'value': {
            'permitted': ['example.com'],
            'excluded': ['example.net'],
        }})
        ext = NameConstraints()
        ext.permitted = ['example.com']
        ext.excluded = ['example.net']
        self.assertEqual(ext, expected)

        ext = NameConstraints()
        ext.permitted = GeneralNameList(['example.com'])
        ext.excluded = GeneralNameList(['example.net'])
        self.assertEqual(ext, expected)

        ext = NameConstraints()
        ext.permitted += ['example.com']
        ext.excluded += ['example.net']
        self.assertExtensionEqual(ext, expected)

    def test_none_value(self):
        """Test that we can use and pass None as values for GeneralNamesList values."""
        ext = self.ext_class({'value': {}})
        self.assertEqual(ext.extension_type,
                         x509.NameConstraints(permitted_subtrees=[], excluded_subtrees=[]))
        self.assertEqual(ext.excluded, [])
        self.assertEqual(ext.permitted, [])

        ext = self.ext_class({'value': {'permitted': None, 'excluded': None}})
        self.assertEqual(ext.extension_type,
                         x509.NameConstraints(permitted_subtrees=[], excluded_subtrees=[]))
        self.assertEqual(ext.excluded, [])
        self.assertEqual(ext.permitted, [])

    def test_value(self):
        return


class OCSPNoCheckTestCase(NullExtensionTestMixin, TestCase):
    """Test OCSPNoCheck extension."""

    ext_class = OCSPNoCheck
    ext_class_key = 'ocsp_no_check'
    ext_class_name = 'OCSPNoCheck'

    test_values = {
        'empty': {
            'values': [{}, None],
            'expected': None,
            'expected_repr': '',
            'expected_serialized': None,
            'expected_text': "OCSPNoCheck",
            'extension_type': x509.OCSPNoCheck(),
        },
    }


class PrecertPoisonTestCase(NullExtensionTestMixin, TestCase):
    """Test PrecertPoison extension."""

    ext_class = PrecertPoison
    ext_class_key = 'precert_poison'
    ext_class_name = 'PrecertPoison'
    force_critical = True
    test_values = {
        'empty': {
            'values': [{}, None],
            'expected': None,
            'expected_repr': '',
            'expected_serialized': None,
            'expected_text': "PrecertPoison",
            'extension_type': x509.PrecertPoison(),
        },
    }

    def test_eq(self):
        for values in self.test_values.values():
            ext = self.ext(values['expected'])
            self.assertEqual(ext, ext)
            ext_critical = self.ext(values['expected'], critical=True)
            self.assertEqual(ext_critical, ext_critical)

            for value in values['values']:
                ext_1 = self.ext(value)
                self.assertEqual(ext, ext_1)
                ext_2 = self.ext(value, critical=True)
                self.assertEqual(ext_critical, ext_2)

    def test_hash(self):
        """Test hash()."""
        for config in self.test_values.values():
            ext = self.ext(config['expected'])
            ext_critical = self.ext(config['expected'], critical=True)
            self.assertEqual(hash(ext), hash(ext_critical))

            for other_config in self.test_values.values():
                other_ext = self.ext(other_config['expected'])
                other_ext_critical = self.ext(other_config['expected'], critical=True)

                if config['expected'] == other_config['expected']:
                    self.assertEqual(hash(ext), hash(other_ext))
                    self.assertEqual(hash(ext_critical), hash(other_ext_critical))
                else:
                    self.assertNotEqual(hash(ext), hash(other_ext))
                    self.assertNotEqual(hash(ext_critical), hash(other_ext_critical))

    def test_critical(self):
        """Test the critical property."""
        with self.assertRaisesRegex(ValueError, r'^PrecertPoison must always be marked as critical$'):
            PrecertPoison({'critical': False})


class PrecertificateSignedCertificateTimestampsTestCase(DjangoCAWithCertTestCase):
    """Test PrecertificateSignedCertificateTimestamps extension."""

    # pylint: disable=too-many-public-methods; RO-extension requires implementing everything again
    # pylint: disable=too-many-instance-attributes; RO-extension requires implementing everything again

    ext_class = PrecertificateSignedCertificateTimestamps
    ext_class_key = 'precertificate_signed_certificate_timestamps'
    ext_class_name = 'PrecertificateSignedCertificateTimestamps'

    def setUp(self):
        super().setUp()
        self.name1 = 'letsencrypt_x3-cert'
        self.name2 = 'comodo_ev-cert'
        cert1 = self.certs[self.name1]
        cert2 = self.certs[self.name2]

        self.cgx1 = cert1.x509.extensions.get_extension_for_oid(
            ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
        self.cgx2 = cert2.x509.extensions.get_extension_for_oid(
            ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
        self.ext1 = PrecertificateSignedCertificateTimestamps(self.cgx1)
        self.ext2 = PrecertificateSignedCertificateTimestamps(self.cgx2)
        self.exts = [self.ext1, self.ext2]
        self.data1 = certs[self.name1]['precertificate_signed_certificate_timestamps_serialized']
        self.data2 = certs[self.name2]['precertificate_signed_certificate_timestamps_serialized']

    def test_config(self):
        """Test basic configuration."""
        self.assertTrue(issubclass(self.ext_class, Extension))
        self.assertEqual(self.ext_class.key, self.ext_class_key)
        self.assertEqual(self.ext_class.name, self.ext_class_name)

        # Test mapping dicts
        self.assertEqual(KEY_TO_EXTENSION[self.ext_class.key], self.ext_class)
        self.assertEqual(OID_TO_EXTENSION[self.ext_class.oid], self.ext_class)

        # test that the model matches
        self.assertTrue(hasattr(X509CertMixin, self.ext_class.key))
        self.assertIsInstance(getattr(X509CertMixin, self.ext_class.key), cached_property)

    def test_as_text(self):
        """Test as_text()."""
        self.assertEqual(self.ext1.as_text(), '''* Precertificate ({v[0][version]}):
    Timestamp: {v[0][timestamp]}
    Log ID: {v[0][log_id]}
* Precertificate ({v[1][version]}):
    Timestamp: {v[1][timestamp]}
    Log ID: {v[1][log_id]}'''.format(v=self.data1['value']))

        self.assertEqual(self.ext2.as_text(), '''* Precertificate ({v[0][version]}):
    Timestamp: {v[0][timestamp]}
    Log ID: {v[0][log_id]}
* Precertificate ({v[1][version]}):
    Timestamp: {v[1][timestamp]}
    Log ID: {v[1][log_id]}
* Precertificate ({v[2][version]}):
    Timestamp: {v[2][timestamp]}
    Log ID: {v[2][log_id]}'''.format(v=self.data2['value']))

    def test_count(self):
        """Test ext.count()."""
        self.assertEqual(self.ext1.count(self.data1['value'][0]), 1)
        self.assertEqual(self.ext1.count(self.data2['value'][0]), 0)
        self.assertEqual(self.ext1.count(self.cgx1.value[0]), 1)
        self.assertEqual(self.ext1.count(self.cgx2.value[0]), 0)

        self.assertEqual(self.ext2.count(self.data1['value'][0]), 0)
        self.assertEqual(self.ext2.count(self.data2['value'][0]), 1)
        self.assertEqual(self.ext2.count(self.cgx1.value[0]), 0)
        self.assertEqual(self.ext2.count(self.cgx2.value[0]), 1)

    def test_del(self):
        """Test item deletion (e.g. ``del ext[0]``, not supported here)."""
        with self.assertRaises(NotImplementedError):
            del self.ext1[0]
        with self.assertRaises(NotImplementedError):
            del self.ext2[0]

    def test_extend(self):
        """Test ext.extend() (not supported here)."""
        with self.assertRaises(NotImplementedError):
            self.ext1.extend([])
        with self.assertRaises(NotImplementedError):
            self.ext2.extend([])

    def test_extension_type(self):
        """Test extension_type property."""
        self.assertEqual(self.ext1.extension_type, self.cgx1.value)
        self.assertEqual(self.ext2.extension_type, self.cgx2.value)

    def test_getitem(self):
        """Test item getter (e.g. ``x = ext[0]``)."""
        self.assertEqual(self.ext1[0], self.data1['value'][0])
        self.assertEqual(self.ext1[1], self.data1['value'][1])
        with self.assertRaises(IndexError):
            self.ext1[2]  # pylint: disable=pointless-statement

        self.assertEqual(self.ext2[0], self.data2['value'][0])
        self.assertEqual(self.ext2[1], self.data2['value'][1])
        self.assertEqual(self.ext2[2], self.data2['value'][2])
        with self.assertRaises(IndexError):
            self.ext2[3]  # pylint: disable=pointless-statement

    def test_getitem_slices(self):
        """Test getting slices (e.g. ``x = ext[0:1]``)."""
        self.assertEqual(self.ext1[:1], self.data1['value'][:1])
        self.assertEqual(self.ext2[:2], self.data2['value'][:2])
        self.assertEqual(self.ext2[:], self.data2['value'][:])

    def test_hash(self):
        """Test hash()."""
        self.assertEqual(hash(self.ext1), hash(self.ext1))
        self.assertEqual(hash(self.ext2), hash(self.ext2))
        self.assertNotEqual(hash(self.ext1), hash(self.ext2))

    def test_in(self):
        """Test the ``in`` operator."""
        for val in self.data1['value']:
            self.assertIn(val, self.ext1)
        for val in self.cgx1.value:
            self.assertIn(val, self.ext1)
        for val in self.data2['value']:
            self.assertIn(val, self.ext2)
        for val in self.cgx2.value:
            self.assertIn(val, self.ext2)

    def test_insert(self):
        """Test ext.insert() (Not supported here)."""
        with self.assertRaises(NotImplementedError):
            self.ext1.insert(0, self.data1['value'][0])
        with self.assertRaises(NotImplementedError):
            self.ext2.insert(0, self.data2['value'][0])

    def test_len(self):
        """Test len(ext) (Not supported here)."""
        self.assertEqual(len(self.ext1), 2)
        self.assertEqual(len(self.ext2), 3)

    def test_ne(self):
        """Test ``!=`` (not-equal) operator."""
        self.assertNotEqual(self.ext1, self.ext2)

    def test_not_in(self):
        """Test the ``not in`` operator."""
        self.assertNotIn(self.data1['value'][0], self.ext2)
        self.assertNotIn(self.data2['value'][0], self.ext1)

        self.assertNotIn(self.cgx1.value[0], self.ext2)
        self.assertNotIn(self.cgx2.value[0], self.ext1)

    def test_pop(self):
        """Test ext.pop() (Not supported here)."""
        with self.assertRaises(NotImplementedError):
            self.ext1.pop(self.data1['value'][0])
        with self.assertRaises(NotImplementedError):
            self.ext2.pop(self.data2['value'][0])

    def test_remove(self):
        """Test ext.remove() (Not supported here)."""
        with self.assertRaises(NotImplementedError):
            self.ext1.remove(self.data1['value'][0])
        with self.assertRaises(NotImplementedError):
            self.ext2.remove(self.data2['value'][0])

    def test_repr(self):
        """Test repr()."""
        self.assertEqual(repr(self.ext1),
                         '<PrecertificateSignedCertificateTimestamps: 2 timestamps, critical=False>')
        self.assertEqual(repr(self.ext2),
                         '<PrecertificateSignedCertificateTimestamps: 3 timestamps, critical=False>')

        with self.patch_object(self.ext2, 'critical', True):
            self.assertEqual(repr(self.ext2),
                             '<PrecertificateSignedCertificateTimestamps: 3 timestamps, critical=True>')

    def test_serialize(self):
        """Test serialization of extension."""
        self.assertEqual(self.ext1.serialize(), self.data1)
        self.assertEqual(self.ext2.serialize(), self.data2)

    def test_setitem(self):
        """Test setting items (e.g. ``ext[0] = ...``)."""
        with self.assertRaises(NotImplementedError):
            self.ext1[0] = self.data2['value'][0]
        with self.assertRaises(NotImplementedError):
            self.ext2[0] = self.data1['value'][0]

    def test_setitem_slices(self):
        """Test setting slices (not supported here)."""
        with self.assertRaises(NotImplementedError):
            self.ext1[:] = self.data2
        with self.assertRaises(NotImplementedError):
            self.ext2[:] = self.data1

    def test_str(self):
        """Test str()."""
        self.assertEqual(str(self.ext1),
                         '<PrecertificateSignedCertificateTimestamps: 2 timestamps, critical=False>')
        self.assertEqual(str(self.ext2),
                         '<PrecertificateSignedCertificateTimestamps: 3 timestamps, critical=False>')

        with self.patch_object(self.ext2, 'critical', True):
            self.assertEqual(str(self.ext2),
                             '<PrecertificateSignedCertificateTimestamps: 3 timestamps, critical=True>')


class UnknownExtensionTestCase(TestCase):
    """Test UnrecognizedExtension extension."""

    def test_basic(self):
        """Only test basic functionality."""
        oid = x509.ObjectIdentifier('1.2.1')
        cgext = x509.Extension(oid=oid, value=x509.UnrecognizedExtension(oid=oid, value=b'unrecognized'),
                               critical=True)
        ext = UnrecognizedExtension(cgext)

        self.assertEqual(ext.name, 'Unsupported extension (OID %s)' % oid.dotted_string)
        self.assertEqual(ext.as_text(), 'Could not parse extension')
        self.assertEqual(ext.as_extension(), cgext)
        self.assertEqual(str(ext), '<Unsupported extension (OID %s): <unprintable>, critical=True>' %
                         oid.dotted_string)

        with self.assertRaisesRegex(ValueError, r"^Cannot serialize an unrecognized extension$"):
            ext.serialize_value()

        name = 'my name'
        error = 'my error'
        ext = UnrecognizedExtension(cgext, name=name, error=error)
        self.assertEqual(ext.name, name)
        self.assertEqual(ext.as_text(), 'Could not parse extension (%s)' % error)

    def test_invalid_extension(self):
        """Test creating from an actually recognized extension."""
        value = x509.Extension(oid=SubjectAlternativeName.oid, critical=True,
                               value=x509.SubjectAlternativeName([uri("example.com")]))
        with self.assertRaisesRegex(TypeError, r"^Extension value must be a x509\.UnrecognizedExtension$"):
            UnrecognizedExtension(value)

    def test_from_dict(self):
        """Test that you cannot instantiate this extension from a dict."""
        with self.assertRaisesRegex(TypeError, r"Value must be a x509\.Extension instance$"):
            UnrecognizedExtension({"value": "foo"})


class SubjectAlternativeNameTestCase(IssuerAlternativeNameTestCase):
    """Test SubjectAlternativeName extension."""

    ext_class = SubjectAlternativeName
    ext_class_key = 'subject_alternative_name'
    ext_class_name = 'SubjectAlternativeName'
    ext_class_type = x509.SubjectAlternativeName

    uri1 = value1 = 'https://example.com'
    uri2 = 'https://example.net'
    dns1 = 'example.com'
    dns2 = 'example.net'
    et1 = x509.SubjectAlternativeName([uri(value1)])

    test_values = {
        'empty': {
            'values': [[]],
            'expected': [],
            'expected_repr': '[]',
            'expected_serialized': [],
            'expected_text': '',
            'extension_type': ext_class_type([]),
        },
        'uri': {
            'values': [[uri1], [uri(uri1)]],
            'expected': [uri(uri1)],
            'expected_repr': "['URI:%s']" % uri1,
            'expected_serialized': ['URI:%s' % uri1],
            'expected_text': '* URI:%s' % uri1,
            'extension_type': ext_class_type([uri(uri1)]),
        },
        'dns': {
            'values': [[dns1], [dns(dns1)]],
            'expected': [dns(dns1)],
            'expected_repr': "['DNS:%s']" % dns1,
            'expected_serialized': ['DNS:%s' % dns1],
            'expected_text': '* DNS:%s' % dns1,
            'extension_type': ext_class_type([dns(dns1)]),
        },
        'both': {
            'values': [[uri1, dns1], [uri(uri1), dns(dns1)], [uri1, dns(dns1)], [uri(uri1), dns1]],
            'expected': [uri(uri1), dns(dns1)],
            'expected_repr': "['URI:%s', 'DNS:%s']" % (uri1, dns1),
            'expected_serialized': ['URI:%s' % uri1, 'DNS:%s' % dns1],
            'expected_text': '* URI:%s\n* DNS:%s' % (uri1, dns1),
            'extension_type': ext_class_type([uri(uri1), dns(dns1)]),
        },
        'all': {
            'values': [
                [uri1, uri2, dns1, dns2],
                [uri(uri1), uri(uri2), dns1, dns2],
                [uri1, uri2, dns(dns1), dns(dns2)],
                [uri(uri1), uri(uri2), dns(dns1), dns(dns2)],
            ],
            'expected': [uri(uri1), uri(uri2), dns(dns1), dns(dns2)],
            'expected_repr': "['URI:%s', 'URI:%s', 'DNS:%s', 'DNS:%s']" % (uri1, uri2, dns1, dns2),
            'expected_serialized': ['URI:%s' % uri1, 'URI:%s' % uri2, 'DNS:%s' % dns1, 'DNS:%s' % dns2],
            'expected_text': '* URI:%s\n* URI:%s\n* DNS:%s\n* DNS:%s' % (uri1, uri2, dns1, dns2),
            'extension_type': ext_class_type([uri(uri1), uri(uri2), dns(dns1), dns(dns2)]),
        },
        'order': {  # same as "all" above but other order
            'values': [
                [dns2, dns1, uri2, uri1],
                [dns(dns2), dns(dns1), uri2, uri1],
                [dns2, dns1, uri(uri2), uri(uri1)],
                [dns(dns2), dns(dns1), uri(uri2), uri(uri1)],
            ],
            'expected': [dns(dns2), dns(dns1), uri(uri2), uri(uri1)],
            'expected_repr': "['DNS:%s', 'DNS:%s', 'URI:%s', 'URI:%s']" % (dns2, dns1, uri2, uri1),
            'expected_serialized': ['DNS:%s' % dns2, 'DNS:%s' % dns1, 'URI:%s' % uri2, 'URI:%s' % uri1],
            'expected_text': '* DNS:%s\n* DNS:%s\n* URI:%s\n* URI:%s' % (dns2, dns1, uri2, uri1),
            'extension_type': ext_class_type([dns(dns2), dns(dns1), uri(uri2), uri(uri1)]),
        },
    }

    def test_get_common_name(self):
        """Test the get_common_name() function."""
        common_name = 'example.com'
        dirname = 'dirname:/CN=example.net'

        san = SubjectAlternativeName({'value': [common_name]})
        self.assertEqual(san.get_common_name(), common_name)

        san = SubjectAlternativeName({'value': [common_name, dirname]})
        self.assertEqual(san.get_common_name(), common_name)

        san = SubjectAlternativeName({'value': [dirname, common_name]})
        self.assertEqual(san.get_common_name(), 'example.com')

        san = SubjectAlternativeName({'value': [dirname]})
        self.assertIsNone(san.get_common_name())


class SubjectKeyIdentifierTestCase(ExtensionTestMixin, TestCase):
    """Test SubjectKeyIdentifier extension."""

    ext_class = SubjectKeyIdentifier
    ext_class_key = 'subject_key_identifier'
    ext_class_name = 'SubjectKeyIdentifier'

    hex1 = '33:33:33:33:33:33'
    hex2 = '44:44:44:44:44:44'
    hex3 = '55:55:55:55:55:55'
    b1 = b'333333'
    b2 = b'DDDDDD'
    b3 = b'UUUUUU'

    test_values = {
        'one': {
            'values': [hex1, ],
            'expected': b1,
            'expected_repr': hex1,
            'expected_serialized': hex1,
            'expected_text': hex1,
            'extension_type': x509.SubjectKeyIdentifier(b1),
        },
        'two': {
            'values': [hex2, ],
            'expected': b2,
            'expected_repr': hex2,
            'expected_serialized': hex2,
            'expected_text': hex2,
            'extension_type': x509.SubjectKeyIdentifier(b2),
        },
        'three': {
            'values': [hex3, ],
            'expected': b3,
            'expected_repr': hex3,
            'expected_serialized': hex3,
            'expected_text': hex3,
            'extension_type': x509.SubjectKeyIdentifier(b3),
        },
    }


class TLSFeatureTestCase(OrderedSetExtensionTestMixin, ExtensionTestMixin, TestCase):
    """Test TLSFeature extension."""

    ext_class = TLSFeature
    ext_class_key = 'tls_feature'
    ext_class_name = 'TLSFeature'

    test_values = {
        'one': {
            'values': [
                {TLSFeatureType.status_request, },
                {'OCSPMustStaple', },
            ],
            'extension_type': x509.TLSFeature(features=[TLSFeatureType.status_request]),
            'expected': frozenset([TLSFeatureType.status_request]),
            'expected_repr': "['OCSPMustStaple']",
            'expected_serialized': ['OCSPMustStaple'],
            'expected_text': '* OCSPMustStaple',
        },
        'two': {
            'values': [
                {TLSFeatureType.status_request, TLSFeatureType.status_request_v2},
                {'OCSPMustStaple', 'MultipleCertStatusRequest'},
                [TLSFeatureType.status_request, TLSFeatureType.status_request_v2],
                [TLSFeatureType.status_request_v2, TLSFeatureType.status_request],
                ['OCSPMustStaple', 'MultipleCertStatusRequest'],
                ['MultipleCertStatusRequest', 'OCSPMustStaple'],
            ],
            'extension_type': x509.TLSFeature(features=[
                TLSFeatureType.status_request_v2,
                TLSFeatureType.status_request,
            ]),
            'expected': frozenset([TLSFeatureType.status_request, TLSFeatureType.status_request_v2]),
            'expected_repr': "['MultipleCertStatusRequest', 'OCSPMustStaple']",
            'expected_serialized': ['MultipleCertStatusRequest', 'OCSPMustStaple'],
            'expected_text': '* MultipleCertStatusRequest\n* OCSPMustStaple',
        },
        'three': {
            'values': [
                {TLSFeatureType.status_request_v2},
                {'MultipleCertStatusRequest'},
            ],
            'extension_type': x509.TLSFeature(features=[TLSFeatureType.status_request_v2]),
            'expected': frozenset([TLSFeatureType.status_request_v2]),
            'expected_repr': "['MultipleCertStatusRequest']",
            'expected_serialized': ['MultipleCertStatusRequest'],
            'expected_text': '* MultipleCertStatusRequest',
        },
    }

    def test_unknown_values(self):
        """Test passing unknown values."""
        with self.assertRaisesRegex(ValueError, r'^Unknown value: foo$'):
            TLSFeature({'value': ['foo']})

        with self.assertRaisesRegex(ValueError, r'^Unknown value: True$'):
            TLSFeature({'value': [True]})

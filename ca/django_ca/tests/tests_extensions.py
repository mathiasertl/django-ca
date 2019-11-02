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

import doctest
import functools
import operator
import os
import unittest

import six

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

from .. import ca_settings
from ..extensions import KEY_TO_EXTENSION
from ..extensions import OID_TO_EXTENSION
from ..extensions import AuthorityInformationAccess
from ..extensions import AuthorityKeyIdentifier
from ..extensions import BasicConstraints
from ..extensions import CertificatePolicies
from ..extensions import CRLDistributionPoints
from ..extensions import DistributionPoint
from ..extensions import ExtendedKeyUsage
from ..extensions import Extension
from ..extensions import IssuerAlternativeName
from ..extensions import KeyUsage
from ..extensions import ListExtension
from ..extensions import NameConstraints
from ..extensions import OCSPNoCheck
from ..extensions import OrderedSetExtension
from ..extensions import PolicyInformation
from ..extensions import PrecertificateSignedCertificateTimestamps
from ..extensions import PrecertPoison
from ..extensions import SubjectAlternativeName
from ..extensions import SubjectKeyIdentifier
from ..extensions import TLSFeature
from ..extensions import UnrecognizedExtension
from ..models import X509CertMixin
from .base import DjangoCATestCase
from .base import DjangoCAWithCertTestCase
from .base import certs


def dns(d):  # just a shortcut
    return x509.DNSName(d)


def uri(u):  # just a shortcut
    return x509.UniformResourceIdentifier(u)


def rdn(r):  # just a shortcut
    return x509.RelativeDistinguishedName([x509.NameAttribute(*t) for t in r])


def load_tests(loader, tests, ignore):
    docs_path = os.path.join(settings.DOC_DIR, 'python', 'extensions.rst')
    if six.PY3:  # pragma: only py3
        # unicode strings make this very hard to test doctests in both py2 and py3
        tests.addTests(doctest.DocTestSuite('django_ca.extensions'))
        tests.addTests(doctest.DocFileSuite(docs_path, module_relative=False))
    return tests


class AbstractExtensionTestMixin:
    """TestCase mixin for tests that all extensions are expected to pass, including abstract base classes."""

    force_critical = None
    repr_tmpl = '<{name}: {value}, critical={critical}>'

    def assertExtensionEqual(self, first, second):
        """Function to test if an extension is really really equal.

        This function should compare extension internals directly not via the __eq__ function.
        """
        self.assertEqual(first.__class__, second.__class__)
        self.assertEqual(first.critical, second.critical)
        self.assertEqual(first.value, second.value)

    def assertSerialized(self, ext, config, critical=None):
        if critical is None:
            critical = self.ext_class.default_critical

        self.assertEqual(ext.serialize(), {
            'value': config['expected_serialized'],
            'critical': critical,
        })

    @property
    def critical_values(self):
        if self.force_critical is not False:
            yield True
        if self.force_critical is not True:
            yield False

    def ext(self, value=None, critical=None):
        if value is None:
            value = {}

        if isinstance(value, x509.extensions.ExtensionType):
            if critical is None:
                critical = self.ext_class.default_critical
            ext = x509.extensions.Extension(oid=self.ext_class.oid, critical=critical, value=value)
            return self.ext_class(ext)
        else:
            d = {'value': value}
            if critical is not None:
                d['critical'] = critical
            return self.ext_class(d)

    def test_as_extension(self):
        for config in self.test_values.values():
            with self.assertRaises(NotImplementedError):
                Extension({'value': config['expected']}).as_extension()

    def test_as_text(self):
        for key, config in self.test_values.items():
            ext = self.ext(config['expected'])
            self.assertEqual(ext.as_text(), config['expected_text'])

    def test_extension_type(self):
        for config in self.test_values.values():
            with self.assertRaises(NotImplementedError):
                Extension({'value': config['expected']}).extension_type

    def test_for_builder(self):
        for config in self.test_values.values():
            with self.assertRaises(NotImplementedError):
                Extension({'value': config['expected']}).for_builder()

    def test_config(self):
        self.assertIsNone(self.ext_class.key)
        self.assertIsNone(self.ext_class.oid)

    def test_hash(self):
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
        self.maxDiff = None
        # Test that the constructor behaves equal regardles of input value
        for key, config in self.test_values.items():
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
        class_name = 'example_class'

        class example:
            def __str__(self):
                return class_name

        for key, config in self.test_values.items():
            for value in config['values']:
                if isinstance(value, x509.extensions.ExtensionType):
                    continue  # self.ext() would construct an x509.Extension and the constructor would fail

                with self.assertRaisesRegex(ValueError, '^%s: Invalid critical value passed$' % class_name):
                    self.ext(value, critical=example())

    def test_init_unknown_type(self):
        if six.PY2:
            class_name = 'instance'
        else:
            class_name = 'example'

        class example:
            pass

        with self.assertRaisesRegex(ValueError, '^Value is of unsupported type %s$' % class_name):
            self.ext_class(example())

    def test_ne(self):
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
        for config in self.test_values.values():
            for value in config['values']:
                ext = self.ext(value)
                exp = config['expected_repr']
                if six.PY2 and 'expected_repr_py2' in config:
                    exp = config['expected_repr_py2']

                expected = self.repr_tmpl.format(name=self.ext_class_name, value=exp,
                                                 critical=ext.default_critical)
                self.assertEqual(repr(ext), expected)

                for critical in self.critical_values:
                    ext = self.ext(value, critical=critical)
                    expected = self.repr_tmpl.format(name=self.ext_class_name, value=exp, critical=critical)
                    self.assertEqual(repr(ext), expected)

    def test_serialize(self):
        for key, config in self.test_values.items():
            ext = self.ext(config['expected'])
            self.assertSerialized(ext, config)

            for critical in self.critical_values:
                ext = self.ext(config['expected'], critical=critical)
                self.assertSerialized(ext, config, critical=critical)

    def test_str(self):
        for config in self.test_values.values():
            for value in config['values']:
                ext = self.ext(value)
                exp = config['expected_repr']
                if six.PY2 and 'expected_repr_py2' in config:
                    exp = config['expected_repr_py2']

                expected = self.repr_tmpl.format(name=self.ext_class_name, value=exp,
                                                 critical=ext.default_critical)
                self.assertEqual(str(ext), expected)

                for critical in self.critical_values:
                    ext = self.ext(value, critical=critical)
                    expected = self.repr_tmpl.format(name=self.ext_class_name, value=exp, critical=critical)
                    self.assertEqual(str(ext), expected)

    def test_value(self):
        # test that value property can be used for the constructor
        for config in self.test_values.values():
            ext = self.ext(value=config['expected'])
            self.assertExtensionEqual(ext, self.ext(ext.value))


class ExtensionTestMixin(AbstractExtensionTestMixin):
    """Override generic implementations to use test_value property."""

    def test_as_extension(self):
        for key, config in self.test_values.items():
            ext = self.ext(config['expected'])
            cg = x509.extensions.Extension(
                oid=self.ext_class.oid, critical=self.ext_class.default_critical,
                value=config['extension_type'])
            self.assertEqual(ext.as_extension(), cg)

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
        self.assertIsInstance(self.ext_class.key, six.string_types)
        self.assertGreater(len(self.ext_class.key), 0)
        self.assertIsInstance(self.ext_class.name, six.string_types)
        self.assertGreater(len(self.ext_class.name), 0)

        # Test mapping dicts
        self.assertEqual(KEY_TO_EXTENSION[self.ext_class.key], self.ext_class)
        self.assertEqual(OID_TO_EXTENSION[self.ext_class.oid], self.ext_class)

        # test that the model matches
        self.assertEqual(X509CertMixin.OID_MAPPING[self.ext_class.oid], self.ext_class.key)
        self.assertTrue(hasattr(X509CertMixin, self.ext_class.key))
        self.assertIsInstance(getattr(X509CertMixin, self.ext_class.key), cached_property)

    def test_extension_type(self):
        for key, config in self.test_values.items():
            ext = self.ext(config['expected'])
            self.assertEqual(ext.extension_type, config['extension_type'])

    def test_for_builder(self):
        for key, config in self.test_values.items():
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


class IterableExtensionTestMixin:
    container_type = None  # extension emulates a given container type
    invalid_values = []

    def assertSameInstance(self, orig_id, orig_value_id, new, expected_value):
        """Assert that `new` is still the same instance and has the expected value."""
        self.assertEqual(new.value, expected_value)
        self.assertEqual(id(new), orig_id)  # assert that this is really the same instance
        self.assertEqual(id(new.value), orig_value_id)

    def assertEqualFunction(self, f, init, value, update=True, infix=True, set_init=None, set_value=None,
                            raises=None):
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

        s, ext = self.container_type(set_init), self.ext_class({'value': init})
        if update is True:
            orig_id, orig_value_id = id(ext), id(ext.value)

            if raises:
                with self.assertRaisesRegex(*raises):
                    f(s, set_value)
                with self.assertRaisesRegex(*raises):
                    f(ext, value)
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
                f(s, set_value)
                f(ext, value)
            else:
                self.assertIsNone(f(s, set_value))  # apply to set
                self.assertIsNone(f(ext, value))

            # Note: Also checked when exception is raised, to make sure that it hasn't changed
            self.assertSameInstance(orig_id, orig_value_id, ext, expected_value=s)
        else:
            ext_updated = f(ext, value)
            s_updated = f(s, set_value)  # apply to set
            self.assertIsCopy(ext, ext_updated, s_updated)

    def test_clear(self):
        for values in self.test_values.values():
            ext = self.ext(values['expected'])
            ext.clear()
            self.assertEqual(len(ext.value), 0)

    def test_in(self):
        for values in self.test_values.values():
            ext = self.ext_class({'value': values['expected']})
            for values in values['values']:
                for value in values:
                    self.assertIn(value, ext)

    def test_len(self):  # len()
        for values in self.test_values.values():
            self.assertEqual(len(self.ext_class({'value': values['expected']})), len(values['expected']))

    def test_not_in(self):
        for config in self.test_values.values():
            for values in config['values']:
                ext = self.ext_class({'value': set()})

                for value in values:
                    self.assertNotIn(value, ext)
                    self.assertEqual(len(ext), 0)


class ListExtensionTestMixin(IterableExtensionTestMixin):
    container_type = list

    def test_append(self):
        for key, config in self.test_values.items():
            if not config['expected']:
                continue  # we don't have values to append

            for values in config['values']:
                expected = self.ext(config['expected'])
                ext = self.ext(config['expected'][:-1])  # all but the last item
                ext.append(config['expected'][-1])
                self.assertExtensionEqual(ext, expected)

    def test_count(self):
        for key, config in self.test_values.items():
            ext = self.ext(config['expected'])
            for values in config['values']:
                for expected_elem, other_elem in zip(config['expected'], values):
                    self.assertEqual(config['expected'].count(expected_elem), ext.count(expected_elem))
                    self.assertEqual(config['expected'].count(expected_elem), ext.count(other_elem))

        for value in self.invalid_values:
            for key, config in self.test_values.items():
                ext = self.ext(config['expected'])
                self.assertEqual(ext.count(value), 0)

    def test_del(self):
        for key, config in self.test_values.items():
            ext = self.ext(config['expected'])
            self.assertEqual(len(ext), len(config['expected']))

            for i, val in enumerate(config['expected']):
                del ext[0]
            self.assertEqual(len(ext), 0)

            with self.assertRaisesRegex(IndexError, r'^list assignment index out of range$'):
                del ext[0]

    def test_del_slices(self):
        for key, config in self.test_values.items():
            ext = self.ext(config['expected'])
            del ext[0:]
            self.assertEqual(len(ext), 0)

    def test_extend(self):
        func = lambda c, j: c.extend(j)  # noqa
        for key, config in self.test_values.items():
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
        func = lambda c, j: operator.getitem(c, j)  # noqa
        for key, config in self.test_values.items():
            ct_expected = config['expected']
            if 'expected_djca' in config:
                ct_expected = config['expected_djca']

            for values in config['values']:
                for value in values:
                    for i in range(0, len(values)):
                        self.assertEqualFunction(func, config['expected'], i, set_init=ct_expected)

                self.assertEqualFunction(func, config['expected'], len(config['expected']),
                                         set_init=ct_expected,
                                         raises=(IndexError, r'^list index out of range$'))

    def test_getitem_slices(self):
        func = lambda c, j: operator.getitem(c, j)  # noqa
        for key, config in self.test_values.items():
            ct_expected = config['expected']
            if 'expected_djca' in config:
                ct_expected = config['expected_djca']

            for values in config['values']:
                self.assertEqualFunction(func, config['expected'], slice(1), set_init=ct_expected)
                self.assertEqualFunction(func, config['expected'], slice(0, 1), set_init=ct_expected)
                self.assertEqualFunction(func, config['expected'], slice(0, 2), set_init=ct_expected)
                self.assertEqualFunction(func, config['expected'], slice(0, 2, 2), set_init=ct_expected)

    def test_insert(self):
        for key, config in self.test_values.items():
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
        for key, config in self.test_values.items():
            for values in config['values']:
                ext = self.ext(config['expected'])

                if config['expected']:
                    with self.assertRaisesRegex(IndexError, '^pop index out of range$'):
                        ext.pop(len(config['expected']))

                exp = reversed(config['expected_serialized'])
                if 'expected_djca' in config:
                    exp = reversed(config['expected_djca'])

                for expected, value in zip(exp, config['values']):
                    self.assertEqual(expected, ext.pop())
                self.assertEqual(len(ext), 0)

        with self.assertRaisesRegex(IndexError, '^pop from empty list$'):
            self.ext([]).pop()

    def test_remove(self):
        for key, config in self.test_values.items():
            for values in config['values']:
                for expected_value, value in zip(config['expected'], values):
                    kwargs = {'infix': False, 'set_value': expected_value}
                    self.assertEqualFunction(lambda c, e: c.remove(e), config['expected'], value, **kwargs)

    def test_setitem(self):
        func = lambda c, j: operator.setitem(c, j[0], j[1])  # noqa
        for key, config in self.test_values.items():
            ct_expected = config['expected']
            if 'expected_djca' in config:
                ct_expected = config['expected_djca']

            for values in config['values']:
                for i in range(0, len(values)):
                    self.assertEqualFunction(func, list(config['expected']), (i, values[i], ),
                                             set_init=ct_expected, set_value=(i, ct_expected[i]))

    def test_setitem_slices(self):
        func = lambda c, j: operator.setitem(c, j[0], j[1])  # noqa
        for key, config in self.test_values.items():
            ct_expected = config['expected']
            if 'expected_djca' in config:
                ct_expected = config['expected_djca']

            for values in config['values']:
                for i in range(0, len(values)):
                    s = slice(0, 1)
                    self.assertEqualFunction(func, list(config['expected']), (s, values[s], ),
                                             set_init=ct_expected, set_value=(s, ct_expected[s]))


class OrderedSetExtensionTestMixin(IterableExtensionTestMixin):
    container_type = set
    ext_class_name = 'OrderedSetExtension'

    def assertIsCopy(self, orig, new, expected_value=None):
        """Assert that `new` is a different instance then `other` and has possibly updated values."""
        if expected_value is None:
            expected_value = orig.value.copy()  # copy just to be sure

        self.assertEqual(new.value, expected_value)
        self.assertIsNot(orig, new)  # assert that this is a different instance
        self.assertIsNot(orig.value, new.value)  # value is also different instance

    def assertSingleValueOperator(self, f, update=True, infix=True):
        """Test that an operator taking a single value works the same way with sets and this extension."""
        for key, config in self.test_values.items():

            # Apply function to an empty extension
            self.assertEqualFunction(f, set(), config['expected'], update=update, infix=infix)

            # Apply function to an extension with every "expected" value
            for init_config in self.test_values.values():
                self.assertEqualFunction(f, init_config['expected'], config['expected'], update=update,
                                         infix=infix)

            # Test that equivalent values work exactly the same way:
            for test_value in config['values']:
                # Again, apply function to the empty extension/set
                self.assertEqualFunction(f, set(), test_value, set_value=config['expected'],
                                         update=update, infix=infix)

                # Again, apply function to an extension with every "expected" value
                for init_key, init_config in self.test_values.items():
                    self.assertEqualFunction(f, init=init_config['expected'], value=test_value,
                                             set_value=config['expected'], update=update, infix=infix)

    def assertMultipleValuesOperator(self, f, update=True, infix=True):
        """Test that an operator taking a multiple values works the same way with sets and this extension."""
        for first_config in self.test_values.values():
            for second_config in self.test_values.values():
                expected = (set(first_config['expected']), set(second_config['expected']))

                # Apply function to an empty extension
                self.assertEqualFunction(f, set(), expected, update=update, infix=infix)

                for init_config in self.test_values.values():
                    expected = (
                        set(init_config['expected']),
                        set(first_config['expected']), set(second_config['expected']),
                    )
                    self.assertEqualFunction(f, init_config['expected'], expected, update=update, infix=infix)

    def assertRelation(self, f):
        self.assertEqual(f(set(), set()), f(self.ext_class({'value': set()}), set()))
        self.assertEqual(f(set(), set()), f(self.ext_class({'value': set()}),
                                            self.ext_class({'value': set()})))

        for key, config in self.test_values.items():
            self.assertEqual(
                f(config['expected'], config['expected']),
                f(self.ext_class({'value': set(config['expected'])}), set(config['expected']))
            )
            self.assertEqual(
                f(config['expected'], config['expected']),
                f(self.ext_class({'value': set(config['expected'])}),
                  self.ext_class({'value': set(config['expected'])}))
            )

            for second_key, second_config in self.test_values.items():
                intersection_expected = config['expected'] & second_config['expected']
                self.assertEqual(
                    f(config['expected'], intersection_expected),
                    f(self.ext_class({'value': set(config['expected'])}), intersection_expected)
                )
                self.assertEqual(
                    f(config['expected'], intersection_expected),
                    f(self.ext_class({'value': set(config['expected'])}),
                      self.ext_class({'value': intersection_expected}))
                )
                self.assertEqual(
                    f(config['expected'], intersection_expected),
                    f(self.ext_class({'value': config['expected']}),
                      self.ext_class({'value': set(intersection_expected)}))
                )

                union_expected = config['expected'] | second_config['expected']
                self.assertEqual(
                    f(config['expected'], set(union_expected)),
                    f(self.ext_class({'value': set(config['expected'])}), union_expected)
                )
                self.assertEqual(
                    f(config['expected'], set(union_expected)),
                    f(self.ext_class({'value': set(config['expected'])}),
                      self.ext_class({'value': set(union_expected)}))
                )
                self.assertEqual(
                    f(config['expected'], set(union_expected)),
                    f(self.ext_class({'value': config['expected']}), set(union_expected))
                )

                symmetric_diff_expected = config['expected'] ^ second_config['expected']
                self.assertEqual(
                    f(config['expected'], set(symmetric_diff_expected)),
                    f(self.ext_class({'value': set(config['expected'])}), set(symmetric_diff_expected))
                )
                self.assertEqual(
                    f(config['expected'], set(symmetric_diff_expected)),
                    f(self.ext_class({'value': set(config['expected'])}),
                      self.ext_class({'value': set(symmetric_diff_expected)}))
                )
                self.assertEqual(
                    f(set(symmetric_diff_expected), config['expected']),
                    f(self.ext_class({'value': set(symmetric_diff_expected)}),
                      self.ext_class({'value': set(config['expected'])}))
                )

    def test_add(self):
        for key, config in self.test_values.items():
            for values in config['values']:
                ext = self.ext_class({'value': set()})
                for value in values:
                    ext.add(value)
                    self.assertIn(value, ext)
                    # Note: we cannot assert the length, because values might include alias values

                self.assertEqual(ext, self.ext_class({'value': config['expected']}))

    def test_copy(self):
        for config in self.test_values.values():
            ext = self.ext_class({'value': config['expected']})
            ext_copy = ext.copy()
            self.assertIsCopy(ext, ext_copy, config['expected'])

    def test_difference(self):
        self.assertSingleValueOperator(lambda s, o: s.difference(o), infix=False, update=False)
        self.assertMultipleValuesOperator(lambda s, o: s.difference(*o), infix=False, update=False)

    def test_difference_operator(self):  # test - operator
        self.assertSingleValueOperator(lambda s, o: operator.sub(s, o), update=False)
        self.assertMultipleValuesOperator(
            lambda s, o: operator.sub(s, functools.reduce(operator.sub, [t.copy() for t in o])),
            update=False)

    def test_difference_update(self):
        self.assertSingleValueOperator(lambda s, o: s.difference_update(o), infix=False)
        self.assertMultipleValuesOperator(lambda s, o: s.difference_update(*o), infix=False)

    def test_difference_update_operator(self):  # test -= operator
        self.assertSingleValueOperator(lambda s, o: operator.isub(s, o))
        self.assertMultipleValuesOperator(
            lambda s, o: operator.isub(s, functools.reduce(operator.sub, [t.copy() for t in o])))

    def test_discard(self):
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

    def test_greater_then_operator(self):  # test < relation
        self.assertRelation(lambda s, o: operator.gt(s, o))

    def test_intersection(self):
        self.assertSingleValueOperator(lambda s, o: s.intersection(o), infix=False, update=False)
        self.assertMultipleValuesOperator(lambda s, o: s.intersection(*o), infix=False, update=False)

    def test_intersection_operator(self):  # test & operator
        self.assertSingleValueOperator(lambda s, o: operator.and_(s, o), update=False)
        self.assertMultipleValuesOperator(
            lambda s, o: operator.and_(s, functools.reduce(operator.and_, [t.copy() for t in o])),
            update=False)

    def test_intersection_update(self):
        self.assertSingleValueOperator(lambda s, o: s.intersection_update(o), infix=False)
        self.assertMultipleValuesOperator(lambda s, o: s.intersection_update(*o), infix=False)

    def test_intersection_update_operator(self):  # test &= operator
        self.assertSingleValueOperator(lambda s, o: operator.iand(s, o))
        self.assertMultipleValuesOperator(
            lambda s, o: operator.iand(s, functools.reduce(operator.and_, [t.copy() for t in o])))

    def test_isdisjoint(self):
        self.assertRelation(lambda s, o: s.isdisjoint(o))

    def test_issubset(self):
        self.assertRelation(lambda s, o: s.issubset(o))

    def test_issubset_operator(self):  # test <= operator
        self.assertRelation(lambda s, o: operator.le(s, o))

    def test_issuperset(self):
        self.assertRelation(lambda s, o: s.issuperset(o))

    def test_issuperset_operator(self):  # test >= operator
        self.assertRelation(lambda s, o: operator.ge(s, o))

    def test_lesser_then_operator(self):  # test < operator
        self.assertRelation(lambda s, o: operator.lt(s, o))

    def test_pop(self):
        for config in self.test_values.values():
            for values in config['values']:
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

        ext = self.ext_class({'value': set(config['expected'])})

    def test_smaller_then_operator(self):  # test < operator
        self.assertRelation(lambda s, o: operator.lt(s, o))

    def test_symmetric_difference(self):  # equivalent to ^ operator
        self.assertSingleValueOperator(lambda s, o: s.symmetric_difference(o), update=False, infix=False)

    def test_symmetric_difference_operator(self):  # test ^ operator == symmetric_difference
        self.assertSingleValueOperator(lambda s, o: operator.xor(s, o), update=False)

    def _test_symmetric_difference_update(self, f, infix=True):
        self.assertSingleValueOperator(f, update=True, infix=infix)

    def test_symmetric_difference_update(self):
        self.assertSingleValueOperator(lambda s, o: s.symmetric_difference_update(o), infix=False)

    def test_symmetric_difference_update_operator(self):  # test ^= operator
        self.assertSingleValueOperator(lambda s, o: operator.ixor(s, o))

    def test_union(self):
        self.assertSingleValueOperator(lambda s, o: s.union(o), infix=False, update=False)
        self.assertMultipleValuesOperator(lambda s, o: s.union(*o), infix=False, update=False)

    def test_union_operator(self):  # test | operator
        self.assertSingleValueOperator(lambda s, o: operator.or_(s, o), update=False)
        self.assertMultipleValuesOperator(
            lambda s, o: operator.or_(s, functools.reduce(operator.or_, [t.copy() for t in o])), update=False)

    def test_update(self):
        self.assertSingleValueOperator(lambda s, o: s.update(o), infix=False)
        self.assertMultipleValuesOperator(lambda s, o: s.update(*o), infix=False)

    def test_update_operator(self):  # test |= operator
        self.assertSingleValueOperator(lambda s, o: operator.ior(s, o))
        self.assertMultipleValuesOperator(
            lambda s, o: operator.ior(s, functools.reduce(operator.ior, [t.copy() for t in o])))


class ExtensionTestCase(AbstractExtensionTestMixin, TestCase):
    ext_class = Extension
    ext_class_name = 'Extension'
    test_values = {
        'one': {
            'values': ['foobar', ],
            'expected': 'foobar',
            'expected_repr': "foobar",
            'expected_serialized': 'foobar',
            'expected_text': 'foobar',
        },
    }

    def test_from_extension(self):
        ext = x509.Extension(oid=x509.ExtensionOID.BASIC_CONSTRAINTS, critical=True,
                             value=x509.BasicConstraints(ca=True, path_length=3))
        with self.assertRaises(NotImplementedError):
            Extension(ext)


class ListExtensionTestCase(TestCase):
    def test_hash(self):
        self.assertEqual(hash(ListExtension({'value': ['foo']})),
                         hash(ListExtension({'value': ['foo']})))
        self.assertNotEqual(hash(ListExtension({'value': 'foo', 'critical': False})),
                            hash(ListExtension({'value': 'bar', 'critical': False})))
        self.assertNotEqual(hash(ListExtension({'value': 'foo', 'critical': False})),
                            hash(ListExtension({'value': 'foo', 'critical': True})))

    def test_operators(self):
        ext = ListExtension({'value': ['foo']})
        self.assertIn('foo', ext)
        self.assertNotIn('bar', ext)

    def test_list_funcs(self):
        ext = ListExtension({'value': ['foo']})
        ext.append('bar')
        self.assertEqual(ext.value, ['foo', 'bar'])
        self.assertEqual(ext.count('foo'), 1)
        self.assertEqual(ext.count('bar'), 1)
        self.assertEqual(ext.count('bla'), 0)

        ext.clear()
        self.assertEqual(ext.value, [])
        self.assertEqual(ext.count('foo'), 0)

        ext.extend(['bar', 'bla'])
        self.assertEqual(ext.value, ['bar', 'bla'])
        ext.extend(['foo'])
        self.assertEqual(ext.value, ['bar', 'bla', 'foo'])

        self.assertEqual(ext.pop(), 'foo')
        self.assertEqual(ext.value, ['bar', 'bla'])

        self.assertIsNone(ext.remove('bar'))
        self.assertEqual(ext.value, ['bla'])

        ext.insert(0, 'foo')
        self.assertEqual(ext.value, ['foo', 'bla'])

    def test_slices(self):
        val = ['foo', 'bar', 'bla']
        ext = ListExtension({'value': val})
        self.assertEqual(ext[0], val[0])
        self.assertEqual(ext[1], val[1])
        self.assertEqual(ext[0:], val[0:])
        self.assertEqual(ext[1:], val[1:])
        self.assertEqual(ext[:1], val[:1])
        self.assertEqual(ext[1:2], val[1:2])

        ext[0] = 'test'
        val[0] = 'test'
        self.assertEqual(ext.value, val)
        ext[1:2] = ['x', 'y']
        val[1:2] = ['x', 'y']
        self.assertEqual(ext.value, val)
        ext[1:] = ['a', 'b']
        val[1:] = ['a', 'b']
        self.assertEqual(ext.value, val)

        del ext[0]
        del val[0]
        self.assertEqual(ext.value, val)

    def test_serialize(self):
        val = ['foo', 'bar', 'bla']
        ext = ListExtension({'value': val, 'critical': False})
        self.assertEqual(ext, ListExtension(ext.serialize()))
        ext = ListExtension({'value': val, 'critical': True})
        self.assertEqual(ext, ListExtension(ext.serialize()))


class OrderedSetExtensionTestCase(OrderedSetExtensionTestMixin, AbstractExtensionTestMixin, TestCase):
    ext_class = OrderedSetExtension
    test_values = {
        'one': {
            'values': [
                {'one_value', },
                ['one_value', ],
            ],
            'expected': frozenset(['one_value']),
            'expected_repr': "['one_value']",
            'expected_serialized': ['one_value'],
            'expected_text': '* one_value',
        },
        'two': {
            'values': [
                {'one_value', 'two_value', },
                ['one_value', 'two_value', ],
                ['two_value', 'one_value', ],
            ],
            'expected': frozenset(['one_value', 'two_value', ]),
            'expected_repr': "['one_value', 'two_value']",
            'expected_serialized': ['one_value', 'two_value'],
            'expected_text': '* one_value\n* two_value',
        },
        'three': {
            'values': [
                {'three_value', },
            ],
            'expected': frozenset(['three_value']),
            'expected_repr': "['three_value']",
            'expected_serialized': ['three_value'],
            'expected_text': '* three_value',
        },
    }


class AuthorityInformationAccessTestCase(ExtensionTestMixin, TestCase):
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
        for key, config in self.test_values.items():
            ext = self.ext(config['expected'])
            self.assertEqual(bool(ext), config.get('expected_bool', True))

    def test_shortcuts(self):
        ext = self.ext()
        self.assertEqual(ext.issuers, [])
        self.assertEqual(ext.ocsp, [])
        ext.ocsp = [self.uri1]
        ext.issuers = [self.uri2]
        self.assertEqual(ext.issuers, [uri(self.uri2)])
        self.assertEqual(ext.ocsp, [uri(self.uri1)])


class AuthorityKeyIdentifierTestCase(ExtensionTestMixin, TestCase):
    ext_class = AuthorityKeyIdentifier
    ext_class_key = 'authority_key_identifier'
    ext_class_name = 'AuthorityKeyIdentifier'

    b1 = b'333333'
    b2 = b'DDDDDD'
    b3 = b'UUUUUU'
    hex1 = '33:33:33:33:33:33'
    hex2 = '44:44:44:44:44:44'
    hex3 = '55:55:55:55:55:55'

    test_values = {
        'one': {
            'values': [hex1, ],
            'expected': b1,
            'expected_repr': b1,
            'expected_serialized': hex1,
            'expected_text': 'keyid:%s' % hex1,
            'extension_type': x509.AuthorityKeyIdentifier(b1, None, None),
        },
        'two': {
            'values': [hex2, ],
            'expected': b2,
            'expected_repr': b2,
            'expected_serialized': hex2,
            'expected_text': 'keyid:%s' % hex2,
            'extension_type': x509.AuthorityKeyIdentifier(b2, None, None),
        },
        'three': {
            'values': [hex3, ],
            'expected': b3,
            'expected_repr': b3,
            'expected_serialized': hex3,
            'expected_text': 'keyid:%s' % hex3,
            'extension_type': x509.AuthorityKeyIdentifier(b3, None, None),
        },
    }

    def test_from_subject_key_identifier(self):
        for key, config in self.test_values.items():
            ski = SubjectKeyIdentifier({'value': config['expected']})
            ext = self.ext_class(ski)
            self.assertExtensionEqual(ext, self.ext_class({'value': config['expected']}))


class BasicConstraintsTestCase(ExtensionTestMixin, TestCase):
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

    def test_setters(self):
        ext = BasicConstraints({'value': {'ca': False, 'pathlen': None}})
        self.assertFalse(ext.ca)
        self.assertIsNone(ext.pathlen)

        ext.ca = True
        ext.pathlen = 3
        self.assertTrue(ext.ca)
        self.assertEqual(ext.pathlen, 3)

    def test_invalid_pathlen(self):
        with self.assertRaisesRegex(ValueError, r'^Could not parse pathlen: "foo"$'):
            BasicConstraints({'value': {'ca': True, 'pathlen': 'foo'}})

        with self.assertRaisesRegex(ValueError, r'^Could not parse pathlen: ""$'):
            BasicConstraints({'value': {'ca': True, 'pathlen': ''}})

        with self.assertRaisesRegex(ValueError, r'^Could not parse pathlen: "foobar"$'):
            BasicConstraints({'value': {'ca': True, 'pathlen': 'foobar'}})


class DistributionPointTestCase(TestCase):
    def test_init_basic(self):
        dp = DistributionPoint()
        self.assertIsNone(dp.full_name)
        self.assertIsNone(dp.relative_name)
        self.assertIsNone(dp.crl_issuer)
        self.assertIsNone(dp.reasons)

        dp = DistributionPoint({
            'full_name': ['http://example.com'],
            'crl_issuer': ['http://example.net'],
        })
        self.assertEqual(dp.full_name, [uri('http://example.com')])
        self.assertIsNone(dp.relative_name)
        self.assertEqual(dp.crl_issuer, [uri('http://example.net')])
        self.assertIsNone(dp.reasons)

        dp = DistributionPoint({
            'full_name': 'http://example.com',
            'crl_issuer': 'http://example.net',
        })
        self.assertEqual(dp.full_name, [uri('http://example.com')])
        self.assertIsNone(dp.relative_name)
        self.assertEqual(dp.crl_issuer, [uri('http://example.net')])
        self.assertIsNone(dp.reasons)

    def test_init_errors(self):
        with self.assertRaisesRegex(ValueError, r'^data must be x509.DistributionPoint or dict$'):
            DistributionPoint('foobar')

        with self.assertRaisesRegex(ValueError, r'^full_name and relative_name cannot both have a value$'):
            DistributionPoint({
                'full_name': ['http://example.com'],
                'relative_name': '/CN=example.com',
            })

    def test_str(self):
        dp = DistributionPoint({'full_name': 'http://example.com'})
        if six.PY2:
            self.assertEqual(str(dp), "<DistributionPoint: full_name=[u'URI:http://example.com']>")
        else:
            self.assertEqual(str(dp), "<DistributionPoint: full_name=['URI:http://example.com']>")


class CRLDistributionPointsTestCase(ListExtensionTestMixin, ExtensionTestMixin, TestCase):
    ext_class = CRLDistributionPoints
    ext_class_key = 'crl_distribution_points'
    ext_class_name = 'CRLDistributionPoints'

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

    cg_rdn1 = rdn([(NameOID.COMMON_NAME, u'example.com')])

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
            'expected_repr_py2': "[<DistributionPoint: full_name=[u'URI:%s']>]" % uri1,
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
            'expected_repr_py2': "[<DistributionPoint: full_name=[u'URI:%s', u'DNS:%s']>]" % (uri1, dns1),
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
            'expected_repr_py2': "[<DistributionPoint: full_name=[u'URI:%s'], crl_issuer=[u'URI:%s'], "
                                 "reasons=['ca_compromise', 'key_compromise']>]" % (uri2, uri3),
            'expected_serialized': [s4],
            'expected_text': '* DistributionPoint:\n  * Full Name:\n    * URI:%s\n'
                             '  * CRL Issuer:\n    * URI:%s\n'
                             '  * Reasons: ca_compromise, key_compromise' % (uri2, uri3),
            'extension_type': cg_dps4,
        },
    }


class PolicyInformationTestCase(DjangoCATestCase):
    oid = '2.5.29.32.0'

    # various qualifiers
    q1 = 'text1'
    q2 = x509.UserNotice(explicit_text='text2', notice_reference=None)
    q3 = x509.UserNotice(
        explicit_text=None,
        notice_reference=x509.NoticeReference(organization='text3', notice_numbers=[1])
    )
    q4 = 'text4'
    q5 = x509.UserNotice(
        explicit_text='text5',
        notice_reference=x509.NoticeReference(organization='text6', notice_numbers=[1, 2, 3])
    )

    x1 = x509.PolicyInformation(policy_identifier=ObjectIdentifier(oid),
                                policy_qualifiers=[q1])
    x2 = x509.PolicyInformation(
        policy_identifier=ObjectIdentifier(oid),
        policy_qualifiers=[q2],
    )
    x3 = x509.PolicyInformation(
        policy_identifier=ObjectIdentifier(oid),
        policy_qualifiers=[q3],
    )
    x4 = x509.PolicyInformation(
        policy_identifier=ObjectIdentifier(oid),
        policy_qualifiers=[q4, q5],
    )
    s1 = {
        'policy_identifier': oid,
        'policy_qualifiers': ['text1'],
    }
    s2 = {
        'policy_identifier': oid,
        'policy_qualifiers': [
            {'explicit_text': 'text2', }
        ],
    }
    s3 = {
        'policy_identifier': oid,
        'policy_qualifiers': [
            {
                'notice_reference': {
                    'organization': 'text3',
                    'notice_numbers': [1, ],
                }
            }
        ],
    }
    s4 = {
        'policy_identifier': oid,
        'policy_qualifiers': [
            'text4',
            {
                'explicit_text': 'text5',
                'notice_reference': {
                    'organization': 'text6',
                    'notice_numbers': [1, 2, 3],
                }
            }
        ],
    }

    def setUp(self):
        super(PolicyInformationTestCase, self).setUp()

        self.pi1 = PolicyInformation(self.s1)
        self.pi2 = PolicyInformation(self.s2)
        self.pi3 = PolicyInformation(self.s3)
        self.pi4 = PolicyInformation(self.s4)
        self.pi_empty = PolicyInformation()

    def test_append(self):
        self.pi1.append(self.q2)
        self.pi1.append(self.s3['policy_qualifiers'][0])
        self.assertEqual(self.pi1, PolicyInformation({
            'policy_identifier': self.oid,
            'policy_qualifiers': [self.q1, self.q2, self.q3],
        }))

        self.pi_empty.policy_identifier = self.oid
        self.pi_empty.append(self.q3)
        self.assertEqual(self.pi3, self.pi_empty)

    def test_as_text(self):
        self.assertEqual(self.pi1.as_text(), 'Policy Identifier: 2.5.29.32.0\n'
                                             'Policy Qualifiers:\n* text1')
        self.assertEqual(self.pi2.as_text(), 'Policy Identifier: 2.5.29.32.0\n'
                                             'Policy Qualifiers:\n'
                                             '* UserNotice:\n'
                                             '  * Explicit text: text2')
        self.assertEqual(self.pi3.as_text(),
                         'Policy Identifier: 2.5.29.32.0\n'
                         'Policy Qualifiers:\n'
                         '* UserNotice:\n'
                         '  * Reference:\n'
                         '    * Organiziation: text3\n'
                         '    * Notice Numbers: [1]')
        self.assertEqual(self.pi4.as_text(),
                         'Policy Identifier: 2.5.29.32.0\n'
                         'Policy Qualifiers:\n'
                         '* text4\n'
                         '* UserNotice:\n'
                         '  * Explicit text: text5\n'
                         '  * Reference:\n'
                         '    * Organiziation: text6\n'
                         '    * Notice Numbers: [1, 2, 3]')
        self.assertEqual(self.pi_empty.as_text(), 'Policy Identifier: None\nNo Policy Qualifiers')

        self.load_all_cas()
        self.load_all_certs()
        for name, cert in list(self.cas.items()) + list(self.certs.items()):
            try:
                ext = cert.x509.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value
            except x509.ExtensionNotFound:
                continue

            for index, policy in enumerate(ext):
                pi = PolicyInformation(policy)
                self.assertEqual(pi.as_text(), certs[name]['policy_texts'][index])

    def test_certs(self):
        self.load_all_cas()
        self.load_all_certs()
        for name, cert in list(self.cas.items()) + list(self.certs.items()):
            try:
                val = cert.x509.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value
            except x509.ExtensionNotFound:
                continue

            for policy in val:
                pi = PolicyInformation(policy)
                self.assertEqual(pi.for_extension_type, policy)

                # pass the serialized value to the constructor and see if it's still the same
                pi2 = PolicyInformation(pi.serialize())
                self.assertEqual(pi, pi2)
                self.assertEqual(pi.serialize(), pi2.serialize())
                self.assertEqual(pi2.for_extension_type, policy)

    def test_clear(self):
        self.pi1.clear()
        self.assertIsNone(self.pi1.policy_qualifiers)

    def test_constructor(self):
        # just some constructors that are otherwise not called
        pi = PolicyInformation()
        self.assertIsNone(pi.policy_identifier)
        self.assertIsNone(pi.policy_qualifiers)

        pi = PolicyInformation({
            'policy_identifier': '1.2.3',
            'policy_qualifiers': [
                x509.UserNotice(notice_reference=None, explicit_text='foobar'),
            ],
        })
        # todo: test pi

        pi = PolicyInformation({
            'policy_identifier': '1.2.3',
            'policy_qualifiers': [{
                'notice_reference': x509.NoticeReference(organization='foobar', notice_numbers=[1]),
            }],
        })
        # todo: test pi

    def test_constructor_errors(self):
        with self.assertRaisesRegex(
                ValueError, r'^PolicyInformation data must be either x509.PolicyInformation or dict$'):
            PolicyInformation(True)

        with self.assertRaisesRegex(ValueError, r'^PolicyQualifier must be string, dict or x509.UserNotice$'):
            PolicyInformation({'policy_identifier': '1.2.3', 'policy_qualifiers': [True]})

        with self.assertRaisesRegex(
                ValueError, r'^NoticeReference must be either None, a dict or an x509.NoticeReference$'):
            PolicyInformation({'policy_identifier': '1.2.3', 'policy_qualifiers': [{
                'notice_reference': True,
            }]})

    def test_contains(self):
        self.assertIn(self.q1, self.pi1)
        self.assertIn(self.q2, self.pi2)
        self.assertIn(self.q3, self.pi3)
        self.assertIn(self.q4, self.pi4)
        self.assertIn(self.q5, self.pi4)
        self.assertIn(self.s1['policy_qualifiers'][0], self.pi1)
        self.assertIn(self.s2['policy_qualifiers'][0], self.pi2)
        self.assertIn(self.s3['policy_qualifiers'][0], self.pi3)
        self.assertIn(self.s4['policy_qualifiers'][0], self.pi4)
        self.assertIn(self.s4['policy_qualifiers'][1], self.pi4)

        self.assertNotIn(self.q2, self.pi1)
        self.assertNotIn(self.q1, self.pi_empty)
        self.assertNotIn(self.s1['policy_qualifiers'][0], self.pi2)
        self.assertNotIn(self.s2['policy_qualifiers'][0], self.pi1)
        self.assertNotIn(self.s2['policy_qualifiers'][0], self.pi_empty)

    def test_count(self):
        self.assertEqual(self.pi1.count(self.s1['policy_qualifiers'][0]), 1)
        self.assertEqual(self.pi1.count(self.q1), 1)
        self.assertEqual(self.pi1.count(self.s2), 0)
        self.assertEqual(self.pi1.count(self.q2), 0)
        self.assertEqual(self.pi_empty.count(self.q2), 0)

    def test_delitem(self):
        del self.pi1[0]
        self.pi_empty.policy_identifier = self.oid
        self.assertEqual(self.pi1, self.pi_empty)

        self.assertEqual(len(self.pi4), 2)
        del self.pi4[0]
        self.assertEqual(len(self.pi4), 1)

        with self.assertRaisesRegex(IndexError, r'^list assignment index out of range$'):
            del self.pi1[0]

    def test_extend(self):
        self.pi1.extend([self.q2, self.q4])
        self.assertEqual(self.pi1, PolicyInformation({
            'policy_identifier': self.oid,
            'policy_qualifiers': [self.q1, self.q2, self.q4],
        }))

        self.pi2.extend([self.s1['policy_qualifiers'][0]])
        self.assertEqual(self.pi2, PolicyInformation({
            'policy_identifier': self.oid,
            'policy_qualifiers': [self.q2, self.q1],
        }))

    def test_getitem(self):
        self.assertEqual(self.pi1[0], self.s1['policy_qualifiers'][0])
        self.assertEqual(self.pi4[0], self.s4['policy_qualifiers'][0])
        self.assertEqual(self.pi4[1], self.s4['policy_qualifiers'][1])
        self.assertEqual(self.pi4[1:], [self.s4['policy_qualifiers'][1]])

        with self.assertRaisesRegex(IndexError, r'^list index out of range$'):
            self.pi_empty[0]
        with self.assertRaisesRegex(IndexError, r'^list index out of range$'):
            self.pi_empty[2:]

    def test_hash(self):
        self.assertEqual(hash(self.pi1), hash(self.pi1))
        self.assertEqual(hash(self.pi2), hash(self.pi2))
        self.assertEqual(hash(self.pi3), hash(self.pi3))
        self.assertEqual(hash(self.pi4), hash(self.pi4))
        self.assertEqual(hash(self.pi_empty), hash(self.pi_empty))

        self.assertEqual(hash(self.pi1), hash(PolicyInformation(self.s1)))
        self.assertEqual(hash(self.pi2), hash(PolicyInformation(self.s2)))
        self.assertEqual(hash(self.pi3), hash(PolicyInformation(self.s3)))
        self.assertEqual(hash(self.pi4), hash(PolicyInformation(self.s4)))
        self.assertEqual(hash(self.pi_empty), hash(PolicyInformation()))

        self.assertNotEqual(hash(self.pi1), hash(self.pi2))
        self.assertNotEqual(hash(self.pi1), hash(self.pi3))
        self.assertNotEqual(hash(self.pi1), hash(self.pi4))
        self.assertNotEqual(hash(self.pi2), hash(self.pi3))
        self.assertNotEqual(hash(self.pi2), hash(self.pi4))
        self.assertNotEqual(hash(self.pi3), hash(self.pi4))

    def test_insert(self):
        self.pi1.insert(0, self.q2)
        self.assertEqual(self.pi1, PolicyInformation({
            'policy_identifier': self.oid,
            'policy_qualifiers': [self.q2, self.q1],
        }))
        self.pi1.insert(1, self.s3['policy_qualifiers'][0])
        self.assertEqual(self.pi1, PolicyInformation({
            'policy_identifier': self.oid,
            'policy_qualifiers': [self.q2, self.q3, self.q1],
        }))

        self.pi_empty.insert(1, self.q2)
        self.pi_empty.policy_identifier = self.oid
        self.assertEqual(self.pi2, self.pi_empty)

    def test_len(self):
        self.assertEqual(len(self.pi1), 1)
        self.assertEqual(len(self.pi2), 1)
        self.assertEqual(len(self.pi3), 1)
        self.assertEqual(len(self.pi4), 2)
        self.assertEqual(len(self.pi_empty), 0)

    def test_policy_identifier_setter(self):
        value = '1.2.3'
        expected = ObjectIdentifier(value)
        pi = PolicyInformation({'policy_identifier': value})
        pi.policy_identifier = value
        self.assertEqual(pi.policy_identifier, expected)

        pi = PolicyInformation({'policy_identifier': expected})
        self.assertEqual(pi.policy_identifier, expected)

        new_value = '2.3.4'
        new_expected = ObjectIdentifier(new_value)
        pi.policy_identifier = new_value
        self.assertEqual(pi.policy_identifier, new_expected)

    def test_pop(self):
        self.pi_empty.policy_identifier = self.oid
        self.assertEqual(self.pi1.pop(), self.s1['policy_qualifiers'][0])
        self.assertEqual(self.pi1, self.pi_empty)

        self.assertEqual(self.pi4.pop(1), self.s4['policy_qualifiers'][1])
        self.assertEqual(self.pi4, PolicyInformation({
            'policy_identifier': self.oid,
            'policy_qualifiers': [self.q4],
        }))

        self.assertEqual(self.pi4.pop(), self.s4['policy_qualifiers'][0])
        self.assertEqual(self.pi4, self.pi_empty)

        with self.assertRaisesRegex(IndexError, r'^pop from empty list$'):
            self.pi_empty.pop()

    def test_remove(self):
        self.pi_empty.policy_identifier = self.oid
        self.pi1.remove(self.q1)
        self.assertEqual(self.pi1, self.pi_empty)

        self.pi2.remove(self.s2['policy_qualifiers'][0])
        self.assertEqual(self.pi1, self.pi_empty)

        self.pi4.remove(self.q4)
        self.assertEqual(self.pi4, PolicyInformation({
            'policy_identifier': self.oid,
            'policy_qualifiers': [self.q5],
        }))

        with self.assertRaisesRegex(ValueError, r'^list\.remove\(x\): x not in list$'):
            self.pi_empty.remove(self.s3['policy_qualifiers'][0])

    def _test_repr(self, func):

        if six.PY2:  # pragma: only py2
            self.assertEqual(func(self.pi1), "<PolicyInformation(oid=2.5.29.32.0, qualifiers=[u'text1'])>")
            self.assertEqual(
                func(self.pi2),
                "<PolicyInformation(oid=2.5.29.32.0, qualifiers=[{u'explicit_text': u'text2'}])>")
            self.assertEqual(func(self.pi_empty), "<PolicyInformation(oid=None, qualifiers=None)>")
        else:
            self.assertEqual(func(self.pi1), "<PolicyInformation(oid=2.5.29.32.0, qualifiers=['text1'])>")
            self.assertEqual(func(self.pi2),
                             "<PolicyInformation(oid=2.5.29.32.0, qualifiers=[{'explicit_text': 'text2'}])>")
            self.assertEqual(func(self.pi_empty), "<PolicyInformation(oid=None, qualifiers=None)>")

        # NOTE: order of dict is different here, so we do not test output, just make sure there's no exception
        func(self.pi3)
        func(self.pi4)

    def test_repr(self):
        self._test_repr(repr)

    def test_str(self):
        self._test_repr(str)


class CertificatePoliciesTestCase(ListExtensionTestMixin, ExtensionTestMixin, TestCase):
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


class IssuerAlternativeNameTestCase(ListExtensionTestMixin, ExtensionTestMixin, TestCase):
    ext_class = IssuerAlternativeName
    ext_class_key = 'issuer_alternative_name'
    ext_class_name = 'IssuerAlternativeName'
    ext_class_type = x509.IssuerAlternativeName

    uri1 = 'https://example.com'
    uri2 = 'https://example.net'
    dns1 = 'example.com'
    dns2 = 'example.net'

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
            'expected_repr_py2': "[u'URI:%s']" % uri1,
            'expected_serialized': ['URI:%s' % uri1],
            'expected_text': '* URI:%s' % uri1,
            'extension_type': ext_class_type([uri(uri1)]),
        },
        'dns': {
            'values': [[dns1], [dns(dns1)]],
            'expected': [dns(dns1)],
            'expected_repr': "['DNS:%s']" % dns1,
            'expected_repr_py2': "[u'DNS:%s']" % dns1,
            'expected_serialized': ['DNS:%s' % dns1],
            'expected_text': '* DNS:%s' % dns1,
            'extension_type': ext_class_type([dns(dns1)]),
        },
        'both': {
            'values': [[uri1, dns1], [uri(uri1), dns(dns1)], [uri1, dns(dns1)], [uri(uri1), dns1]],
            'expected': [uri(uri1), dns(dns1)],
            'expected_repr': "['URI:%s', 'DNS:%s']" % (uri1, dns1),
            'expected_repr_py2': "[u'URI:%s', u'DNS:%s']" % (uri1, dns1),
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
            'expected_repr_py2': "[u'URI:%s', u'URI:%s', u'DNS:%s', u'DNS:%s']" % (uri1, uri2, dns1, dns2),
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
            'expected_repr_py2': "[u'DNS:%s', u'DNS:%s', u'URI:%s', u'URI:%s']" % (dns2, dns1, uri2, uri1),
            'expected_serialized': ['DNS:%s' % dns2, 'DNS:%s' % dns1, 'URI:%s' % uri2, 'URI:%s' % uri1],
            'expected_text': '* DNS:%s\n* DNS:%s\n* URI:%s\n* URI:%s' % (dns2, dns1, uri2, uri1),
            'extension_type': ext_class_type([dns(dns2), dns(dns1), uri(uri2), uri(uri1)]),
        },
    }


class KeyUsageTestCase(OrderedSetExtensionTestMixin, ExtensionTestMixin, TestCase):
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
        # make sure whe haven't forgotton any keys anywhere
        self.assertEqual(set(KeyUsage.CRYPTOGRAPHY_MAPPING.keys()),
                         set([e[0] for e in KeyUsage.CHOICES]))

    def test_auto_add(self):
        # decipher/encipher_only automatically add key_agreement
        self.assertEqual(KeyUsage({'value': ['decipher_only']}),
                         KeyUsage({'value': ['decipher_only', 'key_agreement']}))
        self.assertEqual(KeyUsage({'value': ['encipher_only']}),
                         KeyUsage({'value': ['encipher_only', 'key_agreement']}))

    def test_unknown_values(self):
        with self.assertRaisesRegex(ValueError, r'^Unknown value: foo$'):
            KeyUsage({'value': ['foo']})

        with self.assertRaisesRegex(ValueError, r'^Unknown value: True$'):
            KeyUsage({'value': [True]})


class ExtendedKeyUsageTestCase(OrderedSetExtensionTestMixin, ExtensionTestMixin, TestCase):
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
        with self.assertRaisesRegex(ValueError, r'^Unknown value: foo$'):
            ExtendedKeyUsage({'value': ['foo']})

        with self.assertRaisesRegex(ValueError, r'^Unknown value: True$'):
            ExtendedKeyUsage({'value': [True]})

    def test_completeness(self):
        # make sure we support all ExtendedKeyUsageOIDs
        for attr in [getattr(ExtendedKeyUsageOID, a) for a in dir(ExtendedKeyUsageOID) if a[0] != '_']:
            if isinstance(attr, ObjectIdentifier):
                self.assertIn(attr, ExtendedKeyUsage._CRYPTOGRAPHY_MAPPING_REVERSED)

        # make sure we haven't forgotton any keys in the form selection
        self.assertEqual(set(ExtendedKeyUsage.CRYPTOGRAPHY_MAPPING.keys()),
                         set([e[0] for e in ExtendedKeyUsage.CHOICES]))


class NameConstraintsTestCase(ExtensionTestMixin, TestCase):
    ext_class = NameConstraints
    ext_class_key = 'name_constraints'
    ext_class_name = 'NameConstraints'

    d1 = 'example.com'
    d2 = 'example.net'

    test_values = {
        'empty': {
            'values': [
                {'excluded': [], 'permitted': []},
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
        self.assertFalse(bool(NameConstraints()))
        self.assertTrue(bool(NameConstraints({'value': {'permitted': ['example.com']}})))
        self.assertTrue(bool(NameConstraints({'value': {'excluded': ['example.com']}})))

    def test_setters(self):
        ext = NameConstraints()
        ext.permitted += ['example.com']
        ext.excluded += ['example.net']

        self.assertExtensionEqual(ext, NameConstraints({'value': {
            'permitted': ['example.com'],
            'excluded': ['example.net']
        }}))


class OCSPNoCheckTestCase(NullExtensionTestMixin, TestCase):
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

    @unittest.skipIf(settings.SKIP_OCSP_NOCHECK, "OCSPNoCheck not supported with cryptography<2.7")
    def test_as_extension(self):
        super(OCSPNoCheckTestCase, self).test_as_extension()

    @unittest.skipIf(settings.SKIP_OCSP_NOCHECK, "OCSPNoCheck not supported with cryptography<2.7")
    def test_extension_type(self):
        super(OCSPNoCheckTestCase, self).test_extension_type()

    @unittest.skipIf(settings.SKIP_OCSP_NOCHECK, "OCSPNoCheck not supported with cryptography<2.7")
    def test_for_builder(self):
        super(OCSPNoCheckTestCase, self).test_for_builder()


class PrecertPoisonTestCase(NullExtensionTestMixin, TestCase):
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

    @unittest.skipIf(settings.SKIP_PRECERT_POISON, "PrecertPoison not supported with cryptography<2.7")
    def test_as_extension(self):
        super(PrecertPoisonTestCase, self).test_as_extension()

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

    @unittest.skipIf(settings.SKIP_PRECERT_POISON, "PrecertPoison not supported with cryptography<2.7")
    def test_extension_type(self):
        super(PrecertPoisonTestCase, self).test_extension_type()

    @unittest.skipIf(settings.SKIP_PRECERT_POISON, "PrecertPoison not supported with cryptography<2.7")
    def test_for_builder(self):
        super(PrecertPoisonTestCase, self).test_for_builder()

    def test_hash(self):
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
        with self.assertRaisesRegex(ValueError, r'^PrecertPoison must always be marked as critical$'):
            PrecertPoison({'critical': False})


@unittest.skipUnless(ca_settings.OPENSSL_SUPPORTS_SCT,
                     'This version of OpenSSL does not support SCTs')
class PrecertificateSignedCertificateTimestampsTestCase(DjangoCAWithCertTestCase):
    ext_class = PrecertificateSignedCertificateTimestamps
    ext_class_key = 'precertificate_signed_certificate_timestamps'
    ext_class_name = 'PrecertificateSignedCertificateTimestamps'

    def setUp(self):
        super(PrecertificateSignedCertificateTimestampsTestCase, self).setUp()
        self.name1 = 'letsencrypt_x3-cert'
        self.name2 = 'comodo_ev-cert'
        cert1 = self.certs[self.name1]
        cert2 = self.certs[self.name2]

        self.x1 = cert1.x509.extensions.get_extension_for_oid(
            ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
        self.x2 = cert2.x509.extensions.get_extension_for_oid(
            ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
        self.ext1 = PrecertificateSignedCertificateTimestamps(self.x1)
        self.ext2 = PrecertificateSignedCertificateTimestamps(self.x2)
        self.exts = [self.ext1, self.ext2]
        self.xs = [self.x1, self.x2]
        self.data1 = certs[self.name1]['precertificate_signed_certificate_timestamps']
        self.data2 = certs[self.name2]['precertificate_signed_certificate_timestamps']

    def test_config(self):
        self.assertTrue(issubclass(self.ext_class, Extension))
        self.assertEqual(self.ext_class.key, self.ext_class_key)
        self.assertEqual(self.ext_class.name, self.ext_class_name)

        # Test mapping dicts
        self.assertEqual(KEY_TO_EXTENSION[self.ext_class.key], self.ext_class)
        self.assertEqual(OID_TO_EXTENSION[self.ext_class.oid], self.ext_class)

        # test that the model matches
        self.assertEqual(X509CertMixin.OID_MAPPING[self.ext_class.oid], self.ext_class.key)
        self.assertTrue(hasattr(X509CertMixin, self.ext_class.key))
        self.assertIsInstance(getattr(X509CertMixin, self.ext_class.key), cached_property)

    def test_as_text(self):
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
        self.assertEqual(self.ext1.count(self.data1['value'][0]), 1)
        self.assertEqual(self.ext1.count(self.data2['value'][0]), 0)
        self.assertEqual(self.ext1.count(self.x1.value[0]), 1)
        self.assertEqual(self.ext1.count(self.x2.value[0]), 0)

        self.assertEqual(self.ext2.count(self.data1['value'][0]), 0)
        self.assertEqual(self.ext2.count(self.data2['value'][0]), 1)
        self.assertEqual(self.ext2.count(self.x1.value[0]), 0)
        self.assertEqual(self.ext2.count(self.x2.value[0]), 1)

    def test_del(self):
        with self.assertRaises(NotImplementedError):
            del self.ext1[0]
        with self.assertRaises(NotImplementedError):
            del self.ext2[0]

    def test_extend(self):
        with self.assertRaises(NotImplementedError):
            self.ext1.extend([])
        with self.assertRaises(NotImplementedError):
            self.ext2.extend([])

    def test_extension_type(self):
        self.assertEqual(self.ext1.extension_type, self.x1.value)
        self.assertEqual(self.ext2.extension_type, self.x2.value)

    def test_getitem(self):
        self.assertEqual(self.ext1[0], self.data1['value'][0])
        self.assertEqual(self.ext1[1], self.data1['value'][1])
        with self.assertRaises(IndexError):
            self.ext1[2]

        self.assertEqual(self.ext2[0], self.data2['value'][0])
        self.assertEqual(self.ext2[1], self.data2['value'][1])
        self.assertEqual(self.ext2[2], self.data2['value'][2])
        with self.assertRaises(IndexError):
            self.ext2[3]

    def test_getitem_slices(self):
        self.assertEqual(self.ext1[:1], self.data1['value'][:1])
        self.assertEqual(self.ext2[:2], self.data2['value'][:2])
        self.assertEqual(self.ext2[:], self.data2['value'][:])

    def test_hash(self):
        self.assertEqual(hash(self.ext1), hash(self.ext1))
        self.assertEqual(hash(self.ext2), hash(self.ext2))
        self.assertNotEqual(hash(self.ext1), hash(self.ext2))

    def test_in(self):
        for val in self.data1['value']:
            self.assertIn(val, self.ext1)
        for val in self.x1.value:
            self.assertIn(val, self.ext1)
        for val in self.data2['value']:
            self.assertIn(val, self.ext2)
        for val in self.x2.value:
            self.assertIn(val, self.ext2)

    def test_insert(self):
        with self.assertRaises(NotImplementedError):
            self.ext1.insert(0, self.data1['value'][0])
        with self.assertRaises(NotImplementedError):
            self.ext2.insert(0, self.data2['value'][0])

    def test_len(self):
        self.assertEqual(len(self.ext1), 2)
        self.assertEqual(len(self.ext2), 3)

    def test_ne(self):
        self.assertNotEqual(self.ext1, self.ext2)

    def test_not_in(self):
        self.assertNotIn(self.data1['value'][0], self.ext2)
        self.assertNotIn(self.data2['value'][0], self.ext1)

        self.assertNotIn(self.x1.value[0], self.ext2)
        self.assertNotIn(self.x2.value[0], self.ext1)

    def test_pop(self):
        with self.assertRaises(NotImplementedError):
            self.ext1.pop(self.data1['value'][0])
        with self.assertRaises(NotImplementedError):
            self.ext2.pop(self.data2['value'][0])

    def test_remove(self):
        with self.assertRaises(NotImplementedError):
            self.ext1.remove(self.data1['value'][0])
        with self.assertRaises(NotImplementedError):
            self.ext2.remove(self.data2['value'][0])

    def test_repr(self):
        self.assertEqual(repr(self.ext1),
                         '<PrecertificateSignedCertificateTimestamps: 2 timestamps, critical=False>')
        self.assertEqual(repr(self.ext2),
                         '<PrecertificateSignedCertificateTimestamps: 3 timestamps, critical=False>')

        with self.patch_object(self.ext2, 'critical', True):
            self.assertEqual(repr(self.ext2),
                             '<PrecertificateSignedCertificateTimestamps: 3 timestamps, critical=True>')

    def test_serialize(self):
        self.assertEqual(self.ext1.serialize(), self.data1)
        self.assertEqual(self.ext2.serialize(), self.data2)

    def test_setitem(self):
        with self.assertRaises(NotImplementedError):
            self.ext1[0] = self.data2['value'][0]
        with self.assertRaises(NotImplementedError):
            self.ext2[0] = self.data1['value'][0]

    def test_setitem_slices(self):
        with self.assertRaises(NotImplementedError):
            self.ext1[:] = self.data2
        with self.assertRaises(NotImplementedError):
            self.ext2[:] = self.data1

    def test_str(self):
        self.assertEqual(str(self.ext1),
                         '<PrecertificateSignedCertificateTimestamps: 2 timestamps, critical=False>')
        self.assertEqual(str(self.ext2),
                         '<PrecertificateSignedCertificateTimestamps: 3 timestamps, critical=False>')

        with self.patch_object(self.ext2, 'critical', True):
            self.assertEqual(str(self.ext2),
                             '<PrecertificateSignedCertificateTimestamps: 3 timestamps, critical=True>')


class UnknownExtensionTestCase(TestCase):
    def test_basic(self):
        unk = SubjectAlternativeName({'value': ['https://example.com']}).as_extension()
        ext = UnrecognizedExtension(unk)
        self.assertEqual(ext.name, 'Unsupported extension (OID %s)' % unk.oid.dotted_string)
        self.assertEqual(ext.as_text(), 'Could not parse extension')

        name = 'my name'
        error = 'my error'
        ext = UnrecognizedExtension(unk, name=name, error=error)
        self.assertEqual(ext.name, name)
        self.assertEqual(ext.as_text(), 'Could not parse extension (%s)' % error)


class SubjectAlternativeNameTestCase(IssuerAlternativeNameTestCase):
    ext_class = SubjectAlternativeName
    ext_class_key = 'subject_alternative_name'
    ext_class_name = 'SubjectAlternativeName'
    ext_class_type = x509.SubjectAlternativeName

    uri1 = 'https://example.com'
    uri2 = 'https://example.net'
    dns1 = 'example.com'
    dns2 = 'example.net'

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
            'expected_repr_py2': "[u'URI:%s']" % uri1,
            'expected_serialized': ['URI:%s' % uri1],
            'expected_text': '* URI:%s' % uri1,
            'extension_type': ext_class_type([uri(uri1)]),
        },
        'dns': {
            'values': [[dns1], [dns(dns1)]],
            'expected': [dns(dns1)],
            'expected_repr': "['DNS:%s']" % dns1,
            'expected_repr_py2': "[u'DNS:%s']" % dns1,
            'expected_serialized': ['DNS:%s' % dns1],
            'expected_text': '* DNS:%s' % dns1,
            'extension_type': ext_class_type([dns(dns1)]),
        },
        'both': {
            'values': [[uri1, dns1], [uri(uri1), dns(dns1)], [uri1, dns(dns1)], [uri(uri1), dns1]],
            'expected': [uri(uri1), dns(dns1)],
            'expected_repr': "['URI:%s', 'DNS:%s']" % (uri1, dns1),
            'expected_repr_py2': "[u'URI:%s', u'DNS:%s']" % (uri1, dns1),
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
            'expected_repr_py2': "[u'URI:%s', u'URI:%s', u'DNS:%s', u'DNS:%s']" % (uri1, uri2, dns1, dns2),
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
            'expected_repr_py2': "[u'DNS:%s', u'DNS:%s', u'URI:%s', u'URI:%s']" % (dns2, dns1, uri2, uri1),
            'expected_serialized': ['DNS:%s' % dns2, 'DNS:%s' % dns1, 'URI:%s' % uri2, 'URI:%s' % uri1],
            'expected_text': '* DNS:%s\n* DNS:%s\n* URI:%s\n* URI:%s' % (dns2, dns1, uri2, uri1),
            'extension_type': ext_class_type([dns(dns2), dns(dns1), uri(uri2), uri(uri1)]),
        },
    }

    def test_get_common_name(self):
        cn = 'example.com'
        dn = 'dirname:/CN=example.net'

        san = SubjectAlternativeName({'value': [cn]})
        self.assertEqual(san.get_common_name(), cn)

        san = SubjectAlternativeName({'value': [cn, dn]})
        self.assertEqual(san.get_common_name(), cn)

        san = SubjectAlternativeName({'value': [dn, cn]})
        self.assertEqual(san.get_common_name(), 'example.com')

        san = SubjectAlternativeName({'value': [dn]})
        self.assertIsNone(san.get_common_name())


class SubjectKeyIdentifierTestCase(ExtensionTestMixin, TestCase):
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
            'expected_repr': b1,
            'expected_serialized': hex1,
            'expected_text': hex1,
            'extension_type': x509.SubjectKeyIdentifier(b1),
        },
        'two': {
            'values': [hex2, ],
            'expected': b2,
            'expected_repr': b2,
            'expected_serialized': hex2,
            'expected_text': hex2,
            'extension_type': x509.SubjectKeyIdentifier(b2),
        },
        'three': {
            'values': [hex3, ],
            'expected': b3,
            'expected_repr': b3,
            'expected_serialized': hex3,
            'expected_text': hex3,
            'extension_type': x509.SubjectKeyIdentifier(b3),
        },
    }


class TLSFeatureTestCase(OrderedSetExtensionTestMixin, ExtensionTestMixin, TestCase):
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
        with self.assertRaisesRegex(ValueError, r'^Unknown value: foo$'):
            TLSFeature({'value': ['foo']})

        with self.assertRaisesRegex(ValueError, r'^Unknown value: True$'):
            TLSFeature({'value': [True]})

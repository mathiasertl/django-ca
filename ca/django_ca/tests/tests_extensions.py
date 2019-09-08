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
import unittest

import six

from cryptography import x509
from cryptography.x509 import TLSFeatureType
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import ObjectIdentifier

from django.test import TestCase
from django.utils.functional import cached_property

from .. import ca_settings
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


def load_tests(loader, tests, ignore):
    if six.PY3:  # pragma: only py3
        # unicode strings make this very hard to test doctests in both py2 and py3
        tests.addTests(doctest.DocTestSuite('django_ca.extensions'))
    return tests


class AbstractExtensionTestMixin:
    """TestCase mixin for tests that all extensions are expected to pass, including abstract base classes."""

    def test_hash(self):
        raise NotImplementedError

    def test_eq(self):
        for e in self.exts:
            self.assertEqual(e, e)

    def test_ne(self):
        raise NotImplementedError

    def test_repr(self):
        raise NotImplementedError

    def test_str(self):
        raise NotImplementedError


class ExtensionTestMixin(AbstractExtensionTestMixin):
    """TestCase mixin for tests that only concrete extension classes are expected to pass."""

    def test_as_text(self):
        raise NotImplementedError

    def test_as_extension(self):
        for e, x in zip(self.exts, self.xs):
            self.assertEqual(e.as_extension(), x)

    def test_config(self):
        self.assertTrue(issubclass(self.ext_class, Extension))
        self.assertIsInstance(self.ext_class.key, six.string_types)
        self.assertGreater(len(self.ext_class.key), 1)

        # test that the model matches
        self.assertEqual(X509CertMixin.OID_MAPPING[self.ext_class.oid], self.ext_class.key)
        self.assertTrue(hasattr(X509CertMixin, self.ext_class.key))
        self.assertIsInstance(getattr(X509CertMixin, self.ext_class.key), cached_property)

    def test_extension_type(self):
        for e, x in zip(self.exts, self.xs):
            self.assertEqual(e.extension_type, x.value)

    def test_for_builder(self):
        for e, x in zip(self.exts, self.xs):
            self.assertEqual(e.for_builder(), {'critical': x.critical, 'extension': x.value})

    def test_from_extension(self):
        for e, x in zip(self.exts, self.xs):
            self.assertEqual(e, self.ext_class(x))

    def test_serialize(self):
        raise NotImplementedError


class NewAbstractExtensionTestMixin:
    """TestCase mixin for tests that all extensions are expected to pass, including abstract base classes."""

    def ext(self, value, critical=None):
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

    def test_ne(self):
        for config in self.test_values.values():
            self.assertNotEqual(
                self.ext(config['expected'], critical=True),
                self.ext(config['expected'], critical=False)
            )

            for other_config in self.test_values.values():
                self.assertNotEqual(
                    self.ext(config['expected'], critical=True),
                    self.ext(other_config['expected'], critical=False)
                )
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
                self.assertEqual(repr(ext), config['expected_repr'] % ext.default_critical)

                ext = self.ext(value, critical=True)
                self.assertEqual(repr(ext), config['expected_repr'] % True)

                ext = self.ext(value, critical=False)
                self.assertEqual(repr(ext), config['expected_repr'] % False)

    def test_str(self):
        for config in self.test_values.values():
            for value in config['values']:
                ext = self.ext(value)
                if ext.default_critical:
                    self.assertEqual(str(ext), config['expected_str'] + '/critical')
                else:
                    self.assertEqual(str(ext), config['expected_str'])

                ext = self.ext(value, critical=True)
                self.assertEqual(str(ext), config['expected_str'] + '/critical')

                ext = self.ext(value, critical=False)
                self.assertEqual(str(ext), config['expected_str'])


class NewExtensionTestMixin(NewAbstractExtensionTestMixin):
    """Override generic implementations to use test_value property."""

    def test_as_extension(self):
        for test_key, test_config in self.test_values.items():
            ext = self.ext(test_config['expected'])
            cg = x509.extensions.Extension(
                oid=self.ext_class.oid, critical=self.ext_class.default_critical,
                value=test_config['extension_type']
            )
            self.assertEqual(ext.as_extension(), cg)

            for critical in [True, False]:
                ext = self.ext(test_config['expected'], critical=critical)
                self.assertEqual(ext.as_extension(), x509.extensions.Extension(
                    oid=self.ext_class.oid, critical=critical, value=test_config['extension_type']
                ))

    def test_as_text(self):
        for test_key, test_config in self.test_values.items():
            ext = self.ext(test_config['expected'])
            self.assertEqual(ext.as_text(), test_config['expected_text'])

    def test_extension_type(self):
        for test_key, test_config in self.test_values.items():
            ext = self.ext(test_config['expected'])
            self.assertEqual(ext.extension_type, test_config['extension_type'])

    def test_for_builder(self):
        for test_key, test_config in self.test_values.items():
            ext = self.ext(test_config['expected'])
            self.assertEqual(
                ext.for_builder(),
                {'extension': test_config['extension_type'], 'critical': self.ext_class.default_critical}
            )

            for critical in [True, False]:
                ext = self.ext(test_config['expected'], critical=critical)
                self.assertEqual(
                    ext.for_builder(),
                    {'extension': test_config['extension_type'], 'critical': critical}
                )

    def test_serialize(self):
        for test_key, test_config in self.test_values.items():
            ext = self.ext(test_config['expected'])
            self.assertEqual(ext.serialize(), {
                'value': test_config['expected_serialized'],
                'critical': self.ext_class.default_critical,
            })

            for critical in [True, False]:
                ext = self.ext(test_config['expected'], critical=critical)
                self.assertEqual(ext.serialize(), {
                    'value': test_config['expected_serialized'],
                    'critical': critical,
                })


class IterableExtensionTestMixin:
    def test_in(self):
        raise NotImplementedError

    def test_len(self):
        raise NotImplementedError

    def test_not_in(self):
        raise NotImplementedError


class ListExtensionTestMixin(IterableExtensionTestMixin):
    def test_count(self):
        raise NotImplementedError

    def test_del(self):
        raise NotImplementedError

    def test_extend(self):
        raise NotImplementedError

    def test_getitem(self):
        raise NotImplementedError

    def test_getitem_slices(self):
        raise NotImplementedError

    def test_insert(self):
        raise NotImplementedError

    def test_pop(self):
        raise NotImplementedError

    def test_remove(self):
        raise NotImplementedError

    def test_setitem(self):
        raise NotImplementedError

    def test_setitem_slices(self):
        raise NotImplementedError


class OrderedSetExtensionTestMixin(IterableExtensionTestMixin):
    def assertIsCopy(self, orig, new, expected_value=None):
        """Assert that `new` is a different instance then `other` and has possibly updated values."""
        if expected_value is None:
            expected_value = orig.value.copy()  # copy just to be sure

        self.assertEqual(new.value, expected_value)
        self.assertIsNot(orig, new)  # assert that this is a different instance
        self.assertIsNot(orig.value, new.value)  # value is also different instance

    def assertSameInstance(self, orig_id, orig_value_id, new, expected_value):
        """Assert that `new` is still the same instance and has the expected value."""
        self.assertEqual(new.value, expected_value)
        self.assertEqual(id(new), orig_id)  # assert that this is really the same instance
        self.assertEqual(id(new.value), orig_value_id)

    def assertExtensionEqual(self, first, second):
        self.assertEqual(first.critical, second.critical)
        self.assertEqual(first.value, second.value)

    def assertEqualFunction(self, f, init, value, update=True, infix=True, set_value=None):
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

        s, ext = set(init), self.ext_class({'value': init})
        if update is True:
            orig_id, orig_value_id = id(ext), id(ext.value)

            # infix functions from the operator module (e.g. operator.ixor) return the updated value,
            # while the function equivalent returns None. For example:
            #   >>> s.symmetric_difference_update({'foo'}) is None
            #
            # which is equivalent to:
            #   >>> s ^= {'foo'}
            #
            # but:
            #   >>> operator.ixor(s, {'foo'}) == {'foo'}  # and not None, like above
            if infix is True:
                f(s, set_value)
                f(ext, value)
            else:
                self.assertIsNone(f(s, set_value))  # apply to set
                self.assertIsNone(f(ext, value))
            self.assertSameInstance(orig_id, orig_value_id, ext, s)
        else:
            ext_updated = f(ext, value)
            s_updated = f(s, set_value)  # apply to set
            self.assertIsCopy(ext, ext_updated, s_updated)

    def assertSingleValueOperator(self, f, update=True, infix=True):
        """Test that an operator taking a single value works the same way with sets and this extension."""
        for test_key, test_config in self.test_values.items():

            # Apply function to an empty extension
            self.assertEqualFunction(f, set(), test_config['expected'], update=update, infix=infix)

            # Apply function to an extension with every "expected" value
            for init_test_config in self.test_values.values():
                self.assertEqualFunction(f, init_test_config['expected'], test_config['expected'],
                                         update=update, infix=infix)

            # Test that equivalent values work exactly the same way:
            for test_value in test_config['values']:
                # Again, apply function to the empty extension/set
                self.assertEqualFunction(f, set(), test_value, set_value=test_config['expected'],
                                         update=update, infix=infix)

                # Again, apply function to an extension with every "expected" value
                for init_key, init_test_config in self.test_values.items():
                    self.assertEqualFunction(f, init=init_test_config['expected'],
                                             value=test_value,
                                             set_value=test_config['expected'],
                                             update=update, infix=infix)

    def assertMultipleValuesOperator(self, f, update=True, infix=True):
        """Test that an operator taking a multiple values works the same way with sets and this extension."""
        for first_test_config in self.test_values.values():
            for second_test_config in self.test_values.values():
                expected = (set(first_test_config['expected']), set(second_test_config['expected']))

                # Apply function to an empty extension
                self.assertEqualFunction(f, set(), expected, update=update, infix=infix)

                for init_test_config in self.test_values.values():
                    expected = (
                        set(init_test_config['expected']),
                        set(first_test_config['expected']), set(second_test_config['expected']),
                    )
                    self.assertEqualFunction(f, init_test_config['expected'], expected,
                                             update=update, infix=infix)

    def assertRelation(self, f):
        self.assertEqual(f(set(), set()), f(self.ext_class({'value': set()}), set()))
        self.assertEqual(f(set(), set()), f(self.ext_class({'value': set()}),
                                            self.ext_class({'value': set()})))

        for test_config in self.test_values.values():
            self.assertEqual(
                f(test_config['expected'], test_config['expected']),
                f(self.ext_class({'value': set(test_config['expected'])}), set(test_config['expected']))
            )
            self.assertEqual(
                f(test_config['expected'], test_config['expected']),
                f(self.ext_class({'value': set(test_config['expected'])}),
                  self.ext_class({'value': set(test_config['expected'])}))
            )

            for second_test_config in self.test_values.values():
                intersection_expected = test_config['expected'] & second_test_config['expected']
                self.assertEqual(
                    f(test_config['expected'], intersection_expected),
                    f(self.ext_class({'value': set(test_config['expected'])}), intersection_expected)
                )
                self.assertEqual(
                    f(test_config['expected'], intersection_expected),
                    f(self.ext_class({'value': set(test_config['expected'])}),
                      self.ext_class({'value': intersection_expected}))
                )
                self.assertEqual(
                    f(test_config['expected'], intersection_expected),
                    f(self.ext_class({'value': test_config['expected']}),
                      self.ext_class({'value': set(intersection_expected)}))
                )

                union_expected = test_config['expected'] | second_test_config['expected']
                self.assertEqual(
                    f(test_config['expected'], set(union_expected)),
                    f(self.ext_class({'value': set(test_config['expected'])}), union_expected)
                )
                self.assertEqual(
                    f(test_config['expected'], set(union_expected)),
                    f(self.ext_class({'value': set(test_config['expected'])}),
                      self.ext_class({'value': set(union_expected)}))
                )
                self.assertEqual(
                    f(test_config['expected'], set(union_expected)),
                    f(self.ext_class({'value': test_config['expected']}), set(union_expected))
                )

                symmetric_diff_expected = test_config['expected'] ^ second_test_config['expected']
                self.assertEqual(
                    f(test_config['expected'], set(symmetric_diff_expected)),
                    f(self.ext_class({'value': set(test_config['expected'])}), set(symmetric_diff_expected))
                )
                self.assertEqual(
                    f(test_config['expected'], set(symmetric_diff_expected)),
                    f(self.ext_class({'value': set(test_config['expected'])}),
                      self.ext_class({'value': set(symmetric_diff_expected)}))
                )
                self.assertEqual(
                    f(set(symmetric_diff_expected), test_config['expected']),
                    f(self.ext_class({'value': set(symmetric_diff_expected)}),
                      self.ext_class({'value': set(test_config['expected'])}))
                )

    def test_add(self):
        for test_key, test_config in self.test_values.items():
            for values in test_config['values']:
                ext = self.ext_class({'value': set()})
                for value in values:
                    ext.add(value)
                    self.assertIn(value, ext)
                    # Note: we cannot assert the length, because values might include alias values

                self.assertEqual(ext, self.ext_class({'value': test_config['expected']}))

    def test_clear(self):
        for values in self.test_values.values():
            ext = self.ext_class({'value': values['expected']})
            ext.clear()
            self.assertEqual(ext.value, set())
            self.assertEqual(len(ext.value), 0)

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

    def test_in(self):
        for values in self.test_values.values():
            ext = self.ext_class({'value': values['expected']})
            for values in values['values']:
                for value in values:
                    self.assertIn(value, ext)

    def test_init(self):
        # Test that the constructor behaves equal regardles of input value
        for test_key, test_config in self.test_values.items():
            expected = self.ext_class({'value': test_config['expected']})

            for value in test_config['values']:
                self.assertExtensionEqual(self.ext_class({'value': value}), expected)

            if test_config.get('extension_type'):
                cg = x509.extensions.Extension(
                    oid=self.ext_class.oid, critical=self.ext_class.default_critical,
                    value=test_config['extension_type']
                )
                self.assertEqual(expected, self.ext_class(cg))

            # Now the same with explicit critical values
            for critical in [True, False]:
                expected = self.ext_class({'value': test_config['expected'], 'critical': critical})

                for value in test_config['values']:
                    self.assertExtensionEqual(
                        self.ext_class({'value': value, 'critical': critical}), expected)

                if test_config.get('extension_type'):
                    cg = x509.extensions.Extension(
                        oid=self.ext_class.oid, critical=critical,
                        value=test_config['extension_type']
                    )
                    self.assertEqual(expected, self.ext_class(cg))

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

    def test_len(self):  # len()
        for values in self.test_values.values():
            self.assertEqual(len(self.ext_class({'value': values['expected']})), len(values['expected']))

    def test_lesser_then_operator(self):  # test < operator
        self.assertRelation(lambda s, o: operator.lt(s, o))

    def test_not_in(self):
        for config in self.test_values.values():
            for values in config['values']:
                ext = self.ext_class({'value': set()})

                for value in values:
                    self.assertNotIn(value, ext)
                    self.assertEqual(len(ext), 0)

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


class ExtensionTestCase(ExtensionTestMixin, TestCase):
    value = 'foobar'

    def test_config(self):
        return  # not useful here

    def assertExtension(self, ext, critical=True):
        self.assertEqual(ext.value, self.value)
        self.assertEqual(ext.critical, critical)

    def test_as_extension(self):
        with self.assertRaises(NotImplementedError):
            Extension({'value': self.value}).as_extension()

    def test_extension_type(self):
        with self.assertRaises(NotImplementedError):
            Extension({'value': self.value}).extension_type

    def test_eq(self):
        ext = Extension({'value': self.value, 'critical': True})
        self.assertEqual(ext, Extension({'critical': True, 'value': self.value}))

    def test_for_builder(self):
        with self.assertRaises(NotImplementedError):
            Extension({'value': self.value}).for_builder()

    def test_from_extension(self):
        with self.assertRaises(NotImplementedError):
            Extension({'value': self.value}).from_extension(None)

    def test_hash(self):
        self.assertEqual(hash(Extension({'value': self.value})),
                         hash(Extension({'value': self.value})))
        self.assertEqual(hash(Extension({'critical': False, 'value': self.value})),
                         hash(Extension({'critical': False, 'value': self.value})))

        self.assertNotEqual(hash(Extension({'critical': True, 'value': self.value})),
                            hash(Extension({'critical': False, 'value': self.value})))
        self.assertNotEqual(hash(Extension({'critical': False, 'value': self.value[::-1]})),
                            hash(Extension({'critical': False, 'value': self.value})))

    def test_ne(self):
        ext = Extension({'value': self.value, 'critical': True})
        self.assertNotEqual(ext, Extension({'value': self.value}))
        self.assertNotEqual(ext, Extension({'critical': True, 'value': 'other'}))
        self.assertNotEqual(ext, Extension({'value': 'other'}))

    def test_repr(self):
        self.assertEqual(repr(Extension({'critical': True, 'value': self.value})),
                         '<Extension: %s, critical=True>' % self.value)
        self.assertEqual(repr(Extension({'value': self.value})),
                         '<Extension: %s, critical=False>' % self.value)

    def test_serialize(self):
        ext = Extension({'value': self.value})
        self.assertEqual(ext.serialize(), {'critical': False, 'value': self.value})
        self.assertEqual(ext, Extension(ext.serialize()))

        ext = Extension({'critical': True, 'value': self.value})
        self.assertEqual(ext.serialize(), {'value': self.value, 'critical': True})
        self.assertEqual(ext, Extension(ext.serialize()))

    def test_str(self):
        self.assertEqual(str(Extension({'critical': True, 'value': self.value})), '%s/critical' % self.value)
        self.assertEqual(str(Extension({'value': self.value})), self.value)

    def test_basic(self):
        self.assertExtension(Extension({'critical': True, 'value': self.value}))

        self.assertExtension(Extension({'value': self.value}), critical=False)
        self.assertExtension(Extension({'critical': False, 'value': self.value}), critical=False)
        self.assertExtension(Extension({'value': self.value}), critical=False)

    def test_as_text(self):
        self.assertEqual(Extension({'critical': True, 'value': self.value}).as_text(), self.value)

    def test_error(self):
        with self.assertRaisesRegex(ValueError, r'^None: Invalid critical value passed$'):
            Extension({'critical': None, 'value': ['cRLSign']})

        with self.assertRaisesRegex(ValueError, r'^Value is of unsupported type object$'):
            Extension(object())

        with self.assertRaises(NotImplementedError):
            Extension(x509.extensions.Extension(ExtensionOID.BASIC_CONSTRAINTS, True, b''))

        # Test that methods that should be implemented by sub-classes raise NotImplementedError
        ext = Extension({'critical': True, 'value': self.value})
        with self.assertRaises(NotImplementedError):
            ext.extension_type

        with self.assertRaises(NotImplementedError):
            ext.for_builder()

        # These do not work because base class does not define an OID
        with self.assertRaises(AttributeError):
            ext.name


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


class OrderedSetExtensionTestCase(OrderedSetExtensionTestMixin, NewAbstractExtensionTestMixin, TestCase):
    ext_class = OrderedSetExtension
    test_values = {
        'one': {
            'values': [
                {'one_value', },
                ['one_value', ],
            ],
            'expected': frozenset(['one_value']),
            'expected_repr': "<OrderedSetExtension: ['one_value'], critical=%s>",
            'expected_serialized': ['one_value'],
            'expected_str': 'one_value'
        },
        'two': {
            'values': [
                {'one_value', 'two_value', },
                ['one_value', 'two_value', ],
                ['two_value', 'one_value', ],
            ],
            'expected': frozenset(['one_value', 'two_value', ]),
            'expected_repr': "<OrderedSetExtension: ['one_value', 'two_value'], critical=%s>",
            'expected_serialized': ['one_value', 'two_value'],
            'expected_str': 'one_value,two_value',
        },
        'three': {
            'values': [
                {'three_value', },
            ],
            'expected': frozenset(['three_value']),
            'expected_repr': "<OrderedSetExtension: ['three_value'], critical=%s>",
            'expected_serialized': ['three_value'],
            'expected_str': 'three_value',
        },
    }


class AuthorityInformationAccessTestCase(ExtensionTestMixin, TestCase):
    ext_class = AuthorityInformationAccess

    x1 = x509.extensions.Extension(
        oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS, critical=False,
        value=x509.AuthorityInformationAccess(descriptions=[])
    )
    x2 = x509.extensions.Extension(
        oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS, critical=False,
        value=x509.AuthorityInformationAccess(descriptions=[
            x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS,
                                   uri('https://example.com')),
        ])
    )
    x3 = x509.extensions.Extension(
        oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS, critical=False,
        value=x509.AuthorityInformationAccess(descriptions=[
            x509.AccessDescription(AuthorityInformationAccessOID.OCSP,
                                   uri('https://example.com')),
        ])
    )
    x4 = x509.extensions.Extension(
        oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS, critical=False,
        value=x509.AuthorityInformationAccess(descriptions=[
            x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS,
                                   uri('https://example.com')),
            x509.AccessDescription(AuthorityInformationAccessOID.OCSP,
                                   uri('https://example.net')),
            x509.AccessDescription(AuthorityInformationAccessOID.OCSP,
                                   uri('https://example.org')),
        ])
    )
    x5 = x509.extensions.Extension(
        oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS, critical=True,
        value=x509.AuthorityInformationAccess(descriptions=[
            x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS,
                                   uri('https://example.com')),
            x509.AccessDescription(AuthorityInformationAccessOID.OCSP,
                                   uri('https://example.net')),
            x509.AccessDescription(AuthorityInformationAccessOID.OCSP,
                                   uri('https://example.org')),
        ])
    )
    xs = [x1, x2, x3, x4, x5]

    def setUp(self):
        super(AuthorityInformationAccessTestCase, self).setUp()
        self.ext1 = AuthorityInformationAccess(self.x1)
        self.ext2 = AuthorityInformationAccess(self.x2)
        self.ext3 = AuthorityInformationAccess(self.x3)
        self.ext4 = AuthorityInformationAccess(self.x4)
        self.ext5 = AuthorityInformationAccess(self.x5)
        self.exts = [self.ext1, self.ext2, self.ext3, self.ext4, self.ext5]

    def test_as_text(self):
        self.assertEqual(self.ext1.as_text(),
                         '')
        self.assertEqual(self.ext2.as_text(),
                         'CA Issuers:\n  * URI:https://example.com\n')
        self.assertEqual(self.ext3.as_text(),
                         'OCSP:\n  * URI:https://example.com\n')
        self.assertEqual(self.ext4.as_text(),
                         'CA Issuers:\n'
                         '  * URI:https://example.com\n'
                         'OCSP:\n'
                         '  * URI:https://example.net\n'
                         '  * URI:https://example.org\n')
        self.assertEqual(self.ext5.as_text(),
                         'CA Issuers:\n'
                         '  * URI:https://example.com\n'
                         'OCSP:\n'
                         '  * URI:https://example.net\n'
                         '  * URI:https://example.org\n')

    def test_hash(self):
        self.assertEqual(hash(self.ext1), hash(self.ext1))
        self.assertEqual(hash(self.ext2), hash(self.ext2))
        self.assertEqual(hash(self.ext3), hash(self.ext3))
        self.assertEqual(hash(self.ext4), hash(self.ext4))
        self.assertEqual(hash(self.ext5), hash(self.ext5))

        self.assertNotEqual(hash(self.ext1), hash(self.ext2))
        self.assertNotEqual(hash(self.ext1), hash(self.ext3))
        self.assertNotEqual(hash(self.ext1), hash(self.ext4))
        self.assertNotEqual(hash(self.ext1), hash(self.ext5))
        self.assertNotEqual(hash(self.ext2), hash(self.ext3))
        self.assertNotEqual(hash(self.ext2), hash(self.ext4))
        self.assertNotEqual(hash(self.ext2), hash(self.ext5))
        self.assertNotEqual(hash(self.ext3), hash(self.ext4))
        self.assertNotEqual(hash(self.ext3), hash(self.ext5))
        self.assertNotEqual(hash(self.ext4), hash(self.ext5))

    def test_ne(self):
        self.assertNotEqual(self.ext1, self.ext2)
        self.assertNotEqual(self.ext1, self.ext3)
        self.assertNotEqual(self.ext1, self.ext4)
        self.assertNotEqual(self.ext1, self.ext5)
        self.assertNotEqual(self.ext2, self.ext3)
        self.assertNotEqual(self.ext2, self.ext4)
        self.assertNotEqual(self.ext2, self.ext5)
        self.assertNotEqual(self.ext3, self.ext4)
        self.assertNotEqual(self.ext3, self.ext5)
        self.assertNotEqual(self.ext4, self.ext5)

    def test_repr(self):
        self.assertEqual(
            repr(self.ext1),
            '<AuthorityInformationAccess: issuers=[], ocsp=[], critical=False>')
        self.assertEqual(
            repr(self.ext2),
            '<AuthorityInformationAccess: issuers=[\'URI:https://example.com\'], ocsp=[], critical=False>')
        self.assertEqual(
            repr(self.ext3),
            "<AuthorityInformationAccess: issuers=[], ocsp=['URI:https://example.com'], critical=False>")
        self.assertEqual(
            repr(self.ext4),
            "<AuthorityInformationAccess: issuers=['URI:https://example.com'], "
            "ocsp=['URI:https://example.net', 'URI:https://example.org'], critical=False>")
        self.assertEqual(
            repr(self.ext5),
            "<AuthorityInformationAccess: issuers=['URI:https://example.com'], "
            "ocsp=['URI:https://example.net', 'URI:https://example.org'], critical=True>")

    def test_serialize(self):
        extensions = [
            AuthorityInformationAccess(self.x1),
            AuthorityInformationAccess(self.x2),
            AuthorityInformationAccess(self.x3),
            AuthorityInformationAccess(self.x4),
            AuthorityInformationAccess(self.x5),
        ]
        for ext in extensions:
            self.assertEqual(AuthorityInformationAccess(ext.serialize()), ext)

    #################
    # Old functions #
    #################

    def test_from_dict(self):
        ext = AuthorityInformationAccess({'value': {'issuers': ['https://example.com']}})
        self.assertEqual(ext.issuers, [uri('https://example.com')])
        self.assertEqual(ext.ocsp, [])
        self.assertFalse(ext.critical)
        self.assertEqual(ext.as_extension(), self.x2)

        ext = AuthorityInformationAccess({'value': {'ocsp': ['https://example.com']}})
        self.assertEqual(ext.issuers, [])
        self.assertEqual(ext.ocsp, [uri('https://example.com')])
        self.assertFalse(ext.critical)
        self.assertEqual(ext.as_extension(), self.x3)

        ext = AuthorityInformationAccess({'value': {'issuers': [uri('https://example.com')]}})
        self.assertEqual(ext.issuers, [uri('https://example.com')])
        self.assertEqual(ext.ocsp, [])
        self.assertFalse(ext.critical)
        self.assertEqual(ext.as_extension(), self.x2)

        ext = AuthorityInformationAccess({'value': {'ocsp': [uri('https://example.com')]}})
        self.assertEqual(ext.ocsp, [uri('https://example.com')])
        self.assertEqual(ext.issuers, [])
        self.assertFalse(ext.critical)
        self.assertEqual(ext.as_extension(), self.x3)

        ext = AuthorityInformationAccess({'value': {
            'issuers': ['https://example.com'],
            'ocsp': ['https://example.net', 'https://example.org']
        }})
        self.assertEqual(ext.issuers, [uri('https://example.com')])
        self.assertEqual(ext.ocsp, [uri('https://example.net'), uri('https://example.org')])
        self.assertFalse(ext.critical)
        self.assertEqual(ext.as_extension(), self.x4)

    def test_from_extension(self):
        ext = AuthorityInformationAccess(self.x2)
        self.assertEqual(ext.issuers, [uri('https://example.com')])
        self.assertEqual(ext.ocsp, [])
        self.assertFalse(ext.critical)
        self.assertEqual(ext.as_extension(), self.x2)

        ext = AuthorityInformationAccess(self.x3)
        self.assertEqual(ext.issuers, [])
        self.assertEqual(ext.ocsp, [uri('https://example.com')])
        self.assertFalse(ext.critical)
        self.assertEqual(ext.as_extension(), self.x3)

        ext = AuthorityInformationAccess(self.x4)
        self.assertEqual(ext.issuers, [uri('https://example.com')])
        self.assertEqual(ext.ocsp, [uri('https://example.net'), uri('https://example.org')])
        self.assertFalse(ext.critical)
        self.assertEqual(ext.as_extension(), self.x4)

    def test_empty_value(self):
        for val in [self.x1, {}, {'issuers': [], 'ocsp': []}]:
            ext = AuthorityInformationAccess(val)
            self.assertEqual(ext.ocsp, [], val)
            self.assertEqual(ext.issuers, [], val)
            self.assertFalse(ext.critical)
            self.assertEqual(ext.as_extension(), self.x1)

    def test_unsupported(self):
        with self.assertRaisesRegex(ValueError, r'^Value is of unsupported type NoneType$'):
            AuthorityInformationAccess(None)
        with self.assertRaisesRegex(ValueError, r'^Value is of unsupported type bool$'):
            AuthorityInformationAccess(False)

    def test_bool(self):
        self.assertEqual(bool(AuthorityInformationAccess(self.x1)), False)
        self.assertEqual(bool(AuthorityInformationAccess({})), False)
        self.assertEqual(bool(AuthorityInformationAccess(self.x1)), False)

        self.assertEqual(bool(AuthorityInformationAccess(self.x2)), True)
        self.assertEqual(bool(AuthorityInformationAccess(self.x3)), True)
        self.assertEqual(bool(AuthorityInformationAccess(self.x4)), True)

    def test_str(self):  # various methods converting to str
        self.assertEqual(repr(AuthorityInformationAccess(self.x1)),
                         '<AuthorityInformationAccess: issuers=[], ocsp=[], critical=False>')
        self.assertEqual(str(AuthorityInformationAccess(self.x1)),
                         'AuthorityInformationAccess(issuers=[], ocsp=[], critical=False)')
        self.assertEqual(
            str(AuthorityInformationAccess(self.x2)),
            "AuthorityInformationAccess(issuers=['URI:https://example.com'], ocsp=[], critical=False)")
        self.assertEqual(
            str(AuthorityInformationAccess(self.x3)),
            "AuthorityInformationAccess(issuers=[], ocsp=['URI:https://example.com'], critical=False)")
        self.assertEqual(
            str(AuthorityInformationAccess(self.x4)),
            "AuthorityInformationAccess(issuers=['URI:https://example.com'], ocsp=['URI:https://example.net', 'URI:https://example.org'], critical=False)") # NOQA

        self.assertEqual(AuthorityInformationAccess(self.x1).as_text(), "")
        self.assertEqual(
            AuthorityInformationAccess(self.x2).as_text(),
            "CA Issuers:\n  * URI:https://example.com\n")
        self.assertEqual(
            AuthorityInformationAccess(self.x3).as_text(),
            "OCSP:\n  * URI:https://example.com\n")
        self.assertEqual(
            AuthorityInformationAccess(self.x4).as_text(),
            "CA Issuers:\n  * URI:https://example.com\nOCSP:\n  * URI:https://example.net\n  * URI:https://example.org\n")  # NOQA


class AuthorityKeyIdentifierTestCase(ExtensionTestMixin, TestCase):
    ext_class = AuthorityKeyIdentifier

    hex1 = '33:33:33:33:33:33'
    hex2 = '44:44:44:44:44:44'
    hex3 = '55:55:55:55:55:55'

    b1 = b'333333'
    b2 = b'DDDDDD'
    b3 = b'UUUUUU'

    x1 = x509.Extension(
        oid=x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER, critical=False,
        value=x509.AuthorityKeyIdentifier(b1, None, None))
    x2 = x509.Extension(
        oid=x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER, critical=False,
        value=x509.AuthorityKeyIdentifier(b2, None, None))
    x3 = x509.Extension(
        oid=x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER, critical=True,
        value=x509.AuthorityKeyIdentifier(b3, None, None)
    )
    xs = [x1, x2, x3]

    def setUp(self):
        super(AuthorityKeyIdentifierTestCase, self).setUp()
        self.ext1 = AuthorityKeyIdentifier(self.x1)
        self.ext2 = AuthorityKeyIdentifier(self.x2)
        self.ext3 = AuthorityKeyIdentifier(self.x3)
        self.exts = [self.ext1, self.ext2, self.ext3]

    def test_as_text(self):
        self.assertEqual(self.ext1.as_text(), 'keyid:%s' % self.hex1)
        self.assertEqual(self.ext2.as_text(), 'keyid:%s' % self.hex2)
        self.assertEqual(self.ext3.as_text(), 'keyid:%s' % self.hex3)

    def test_hash(self):
        self.assertEqual(hash(self.ext1), hash(self.ext1))
        self.assertEqual(hash(self.ext2), hash(self.ext2))
        self.assertEqual(hash(self.ext3), hash(self.ext3))
        self.assertNotEqual(hash(self.ext1), hash(self.ext2))
        self.assertNotEqual(hash(self.ext1), hash(self.ext3))
        self.assertNotEqual(hash(self.ext2), hash(self.ext3))

    def test_ne(self):
        self.assertNotEqual(self.ext1, self.ext2)
        self.assertNotEqual(self.ext1, self.ext3)
        self.assertNotEqual(self.ext2, self.ext3)
        self.assertNotEqual(self.ext3, AuthorityKeyIdentifier({'value': self.hex3}))  # ext3 is critical

    def test_repr(self):
        if six.PY2:  # pragma: only py2
            self.assertEqual(repr(self.ext1), '<AuthorityKeyIdentifier: 333333, critical=False>')
            self.assertEqual(repr(self.ext2), '<AuthorityKeyIdentifier: DDDDDD, critical=False>')
            self.assertEqual(repr(self.ext3), '<AuthorityKeyIdentifier: UUUUUU, critical=True>')
        else:
            self.assertEqual(repr(self.ext1), '<AuthorityKeyIdentifier: b\'333333\', critical=False>')
            self.assertEqual(repr(self.ext2), '<AuthorityKeyIdentifier: b\'DDDDDD\', critical=False>')
            self.assertEqual(repr(self.ext3), '<AuthorityKeyIdentifier: b\'UUUUUU\', critical=True>')

    def test_serialize(self):
        self.assertEqual(self.ext1.serialize(), {'critical': False, 'value': self.hex1})
        self.assertEqual(self.ext2.serialize(), {'critical': False, 'value': self.hex2})
        self.assertEqual(self.ext3.serialize(), {'critical': True, 'value': self.hex3})
        self.assertEqual(self.ext1.serialize(), AuthorityKeyIdentifier({'value': self.hex1}).serialize())
        self.assertNotEqual(self.ext1.serialize(), self.ext2.serialize())

    def test_str(self):
        ext = AuthorityKeyIdentifier({'value': self.hex1})
        self.assertEqual(str(ext), 'keyid:%s' % self.hex1)

    def test_subject_key_identifier(self):
        ski = SubjectKeyIdentifier({'value': self.hex1})
        ext = AuthorityKeyIdentifier(ski)
        self.assertEqual(ext.as_text(), 'keyid:%s' % self.hex1)
        self.assertEqual(ext.extension_type.key_identifier, self.x1.value.key_identifier)

    def test_error(self):
        with self.assertRaisesRegex(ValueError, r'^Value is of unsupported type NoneType$'):
            AuthorityKeyIdentifier(None)
        with self.assertRaisesRegex(ValueError, r'^Value is of unsupported type bool$'):
            AuthorityKeyIdentifier(False)


class BasicConstraintsTestCase(ExtensionTestMixin, TestCase):
    ext_class = BasicConstraints

    x1 = x509.Extension(
        oid=x509.ExtensionOID.BASIC_CONSTRAINTS, critical=True,
        value=x509.BasicConstraints(ca=False, path_length=None)
    )
    x2 = x509.Extension(
        oid=x509.ExtensionOID.BASIC_CONSTRAINTS, critical=True,
        value=x509.BasicConstraints(ca=True, path_length=None)
    )
    x3 = x509.Extension(
        oid=x509.ExtensionOID.BASIC_CONSTRAINTS, critical=True,
        value=x509.BasicConstraints(ca=True, path_length=0)
    )
    x4 = x509.Extension(
        oid=x509.ExtensionOID.BASIC_CONSTRAINTS, critical=True,
        value=x509.BasicConstraints(ca=True, path_length=3)
    )
    # NOTE: Very unusual, BC is normally marked as critical
    x5 = x509.Extension(
        oid=x509.ExtensionOID.BASIC_CONSTRAINTS, critical=False,
        value=x509.BasicConstraints(ca=False, path_length=None)
    )
    xs = [x1, x2, x3, x4, x5]

    def setUp(self):
        super(BasicConstraintsTestCase, self).setUp()
        self.ext1 = BasicConstraints({'value': {'ca': False}})
        self.ext2 = BasicConstraints({'value': {'ca': True}})
        self.ext3 = BasicConstraints({'value': {'ca': True, 'pathlen': 0}})
        self.ext4 = BasicConstraints({'value': {'ca': True, 'pathlen': 3}})
        self.ext5 = BasicConstraints({'value': {'ca': False}, 'critical': False})
        self.exts = [self.ext1, self.ext2, self.ext3, self.ext4, self.ext5]

    def assertBC(self, bc, ca, pathlen, critical=True):
        self.assertEqual(bc.ca, ca)
        self.assertEqual(bc.pathlen, pathlen)
        self.assertEqual(bc.critical, critical)
        self.assertEqual(bc.value, (ca, pathlen))

    def test_as_text(self):
        self.assertEqual(BasicConstraints({'value': {'ca': True}}).as_text(), 'CA:TRUE')
        self.assertEqual(BasicConstraints({'value': {'ca': True, 'pathlen': 3}}).as_text(),
                         'CA:TRUE, pathlen:3')
        self.assertEqual(BasicConstraints({'value': {'ca': False}}).as_text(), 'CA:FALSE')

    def test_hash(self):
        self.assertEqual(hash(self.ext1), hash(self.ext1))
        self.assertEqual(hash(self.ext2), hash(self.ext2))
        self.assertEqual(hash(self.ext3), hash(self.ext3))
        self.assertEqual(hash(self.ext4), hash(self.ext4))
        self.assertEqual(hash(self.ext5), hash(self.ext5))

        self.assertNotEqual(hash(self.ext1), hash(self.ext2))
        self.assertNotEqual(hash(self.ext1), hash(self.ext3))
        self.assertNotEqual(hash(self.ext2), hash(self.ext3))

    def test_ne(self):
        self.assertNotEqual(self.ext1, self.ext2)
        self.assertNotEqual(self.ext1, self.ext3)
        self.assertNotEqual(self.ext1, self.ext4)
        self.assertNotEqual(self.ext1, self.ext5)
        self.assertNotEqual(self.ext2, self.ext3)
        self.assertNotEqual(self.ext2, self.ext4)
        self.assertNotEqual(self.ext2, self.ext5)
        self.assertNotEqual(self.ext3, self.ext4)
        self.assertNotEqual(self.ext3, self.ext5)
        self.assertNotEqual(self.ext4, self.ext5)

    def test_repr(self):
        self.assertEqual(repr(self.ext1), "<BasicConstraints: 'CA:FALSE', critical=True>")
        self.assertEqual(repr(self.ext2), "<BasicConstraints: 'CA:TRUE', critical=True>")
        self.assertEqual(repr(self.ext3), "<BasicConstraints: 'CA:TRUE, pathlen:0', critical=True>")
        self.assertEqual(repr(self.ext4), "<BasicConstraints: 'CA:TRUE, pathlen:3', critical=True>")
        self.assertEqual(repr(self.ext5), "<BasicConstraints: 'CA:FALSE', critical=False>")

    def test_str(self):
        self.assertEqual(str(self.ext1), "CA:FALSE/critical")
        self.assertEqual(str(self.ext2), "CA:TRUE/critical")
        self.assertEqual(str(self.ext3), "CA:TRUE, pathlen:0/critical")
        self.assertEqual(str(self.ext4), "CA:TRUE, pathlen:3/critical")
        self.assertEqual(str(self.ext5), "CA:FALSE")

    # Old functions

    def test_from_extension(self):
        self.assertBC(BasicConstraints(x509.Extension(
            oid=x509.ExtensionOID.BASIC_CONSTRAINTS, critical=True,
            value=x509.BasicConstraints(ca=True, path_length=3))), True, 3, True)

    def test_dict(self):
        self.assertBC(BasicConstraints({'value': {'ca': True}}), True, None, True)
        self.assertBC(BasicConstraints({'value': {'ca': False}}), False, None, True)
        self.assertBC(BasicConstraints({'value': {'ca': True, 'pathlen': 3}}), True, 3, True)
        self.assertBC(BasicConstraints({'value': {'ca': True, 'pathlen': None}}), True, None, True)
        self.assertBC(BasicConstraints({'value': {'ca': True}, 'critical': False}), True, None, False)

    def test_other(self):
        # test without pathlen
        self.assertBC(BasicConstraints({'value': {'ca': False}}), False, None, True)
        self.assertBC(BasicConstraints({'value': {'ca': True}}), True, None, True)
        self.assertBC(BasicConstraints({'value': {'ca': True}}), True, None, True)

        # test adding a pathlen
        self.assertBC(BasicConstraints({'value': {'ca': True, 'pathlen': 0}}), True, 0, True)
        self.assertBC(BasicConstraints({'value': {'ca': True, 'pathlen': 1}}), True, 1, True)
        self.assertBC(BasicConstraints({'value': {'ca': True, 'pathlen': 2}}), True, 2, True)

        with self.assertRaisesRegex(ValueError, r'^Could not parse pathlen: "foo"$'):
            BasicConstraints({'value': {'ca': True, 'pathlen': 'foo'}})

        with self.assertRaisesRegex(ValueError, r'^Could not parse pathlen: ""$'):
            BasicConstraints({'value': {'ca': True, 'pathlen': ''}})

        with self.assertRaisesRegex(ValueError, r'^Could not parse pathlen: "foobar"$'):
            BasicConstraints({'value': {'ca': True, 'pathlen': 'foobar'}})

    def test_serialize(self):
        exts = [
            BasicConstraints({'value': {'ca': True}}),
            BasicConstraints({'value': {'ca': False}}),
            BasicConstraints({'value': {'ca': True, 'pathlen': 3}}),
            BasicConstraints({'value': {'ca': True, 'pathlen': None}}),
            BasicConstraints({'value': {'ca': True}, 'critical': False}),
        ]
        for ext in exts:
            self.assertEqual(BasicConstraints(ext.serialize()), ext)


class DistributionPointTestCase(TestCase):
    def test_init_basic(self):
        dp = DistributionPoint({})
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


class CRLDistributionPointsTestCase(ListExtensionTestMixin, ExtensionTestMixin, TestCase):
    ext_class = CRLDistributionPoints

    dp1 = x509.DistributionPoint(
        full_name=[
            x509.UniformResourceIdentifier('http://ca.example.com/crl'),
        ],
        relative_name=None,
        crl_issuer=None,
        reasons=None
    )
    dp2 = x509.DistributionPoint(
        full_name=[
            x509.UniformResourceIdentifier('http://ca.example.com/crl'),
            x509.DirectoryName(x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u"AT")])),
        ],
        relative_name=None,
        crl_issuer=None,
        reasons=None
    )
    dp3 = x509.DistributionPoint(
        full_name=None,
        relative_name=x509.RelativeDistinguishedName([
            x509.NameAttribute(NameOID.COMMON_NAME, u'example.com'),
        ]),
        crl_issuer=None,
        reasons=None
    )
    dp4 = x509.DistributionPoint(
        full_name=[
            x509.UniformResourceIdentifier('http://ca.example.com/crl'),
        ],
        relative_name=None,
        crl_issuer=[
            x509.UniformResourceIdentifier('http://ca.example.com/'),
        ],
        reasons=frozenset([x509.ReasonFlags.key_compromise, x509.ReasonFlags.ca_compromise])
    )

    # serialized versions of dps above
    s1 = {'full_name': ['URI:http://ca.example.com/crl']}
    s2 = {'full_name': ['URI:http://ca.example.com/crl', 'dirname:/C=AT']}
    s3 = {'relative_name': '/CN=example.com'}
    s4 = {
        'full_name': ['URI:http://ca.example.com/crl'],
        'crl_issuer': ['URI:http://ca.example.com/'],
        'reasons': ['ca_compromise', 'key_compromise'],
    }

    # cryptography extensions
    x1 = x509.Extension(oid=ExtensionOID.CRL_DISTRIBUTION_POINTS, critical=False,
                        value=x509.CRLDistributionPoints([dp1]))
    x2 = x509.Extension(oid=ExtensionOID.CRL_DISTRIBUTION_POINTS, critical=False,
                        value=x509.CRLDistributionPoints([dp2]))
    x3 = x509.Extension(oid=ExtensionOID.CRL_DISTRIBUTION_POINTS, critical=False,
                        value=x509.CRLDistributionPoints([dp3]))
    x4 = x509.Extension(oid=ExtensionOID.CRL_DISTRIBUTION_POINTS, critical=False,
                        value=x509.CRLDistributionPoints([dp4]))
    x5 = x509.Extension(oid=ExtensionOID.CRL_DISTRIBUTION_POINTS, critical=True,
                        value=x509.CRLDistributionPoints([dp2, dp4]))
    xs = [x1, x2, x3, x4, x5]

    def setUp(self):
        super(CRLDistributionPointsTestCase, self).setUp()
        # django_ca extensions
        self.ext1 = CRLDistributionPoints(self.x1)
        self.ext2 = CRLDistributionPoints(self.x2)
        self.ext3 = CRLDistributionPoints(self.x3)
        self.ext4 = CRLDistributionPoints(self.x4)
        self.ext5 = CRLDistributionPoints(self.x5)
        self.exts = [self.ext1, self.ext2, self.ext3, self.ext4, self.ext5]

    def test_as_text(self):
        self.assertEqual(self.ext1.as_text(), """* DistributionPoint:
  * Full Name:
    * URI:http://ca.example.com/crl""")
        self.assertEqual(self.ext2.as_text(), """* DistributionPoint:
  * Full Name:
    * URI:http://ca.example.com/crl
    * dirname:/C=AT""")
        self.assertEqual(self.ext3.as_text(), """* DistributionPoint:
  * Relative Name: /CN=example.com""")
        self.assertEqual(self.ext4.as_text(), """* DistributionPoint:
  * Full Name:
    * URI:http://ca.example.com/crl
  * CRL Issuer:
    * URI:http://ca.example.com/
  * Reasons: ca_compromise, key_compromise""")
        self.assertEqual(self.ext5.as_text(), """* DistributionPoint:
  * Full Name:
    * URI:http://ca.example.com/crl
    * dirname:/C=AT
* DistributionPoint:
  * Full Name:
    * URI:http://ca.example.com/crl
  * CRL Issuer:
    * URI:http://ca.example.com/
  * Reasons: ca_compromise, key_compromise""")

    def test_count(self):
        self.assertEqual(self.ext1.count(self.s1), 1)
        self.assertEqual(self.ext1.count(self.dp1), 1)
        self.assertEqual(self.ext1.count(DistributionPoint(self.s1)), 1)
        self.assertEqual(self.ext1.count(self.s2), 0)
        self.assertEqual(self.ext1.count(self.dp2), 0)
        self.assertEqual(self.ext1.count(DistributionPoint(self.s2)), 0)
        self.assertEqual(self.ext5.count(self.s2), 1)
        self.assertEqual(self.ext5.count(self.dp2), 1)
        self.assertEqual(self.ext5.count(DistributionPoint(self.s2)), 1)
        self.assertEqual(self.ext5.count(self.s4), 1)
        self.assertEqual(self.ext5.count(self.dp4), 1)
        self.assertEqual(self.ext5.count(DistributionPoint(self.s4)), 1)
        self.assertEqual(self.ext5.count(self.s3), 0)
        self.assertEqual(self.ext5.count(self.dp3), 0)
        self.assertEqual(self.ext5.count(DistributionPoint(self.s3)), 0)
        self.assertEqual(self.ext5.count(None), 0)

    def test_del(self):
        self.assertIn(self.dp1, self.ext1)
        del self.ext1[0]
        self.assertNotIn(self.dp1, self.ext1)
        self.assertEqual(len(self.ext1), 0)

        self.assertIn(self.dp2, self.ext5)
        self.assertIn(self.dp4, self.ext5)
        del self.ext5[1]
        self.assertIn(self.dp2, self.ext5)
        self.assertNotIn(self.dp4, self.ext5)
        self.assertEqual(len(self.ext5), 1)

        self.assertEqual(len(self.ext4), 1)
        with self.assertRaisesRegex(IndexError, '^list assignment index out of range$'):
            del self.ext4[1]
        self.assertEqual(len(self.ext4), 1)

    def test_extend(self):
        self.ext1.extend([self.s2])
        self.assertEqual(self.ext1, CRLDistributionPoints({'value': [
            DistributionPoint(self.dp1), DistributionPoint(self.dp2)]}))
        self.ext1.extend([self.dp3])
        self.assertEqual(self.ext1, CRLDistributionPoints({'value': [
            DistributionPoint(self.dp1), DistributionPoint(self.dp2), DistributionPoint(self.dp3),
        ]}))
        self.ext1.extend([DistributionPoint(self.dp4)])
        self.assertEqual(self.ext1, CRLDistributionPoints({'value': [
            DistributionPoint(self.dp1), DistributionPoint(self.dp2), DistributionPoint(self.dp3),
            DistributionPoint(self.dp4),
        ]}))

    def test_getitem(self):
        self.assertEqual(self.ext1[0], DistributionPoint(self.dp1))
        self.assertEqual(self.ext2[0], DistributionPoint(self.dp2))
        self.assertEqual(self.ext5[0], DistributionPoint(self.dp2))
        self.assertEqual(self.ext5[1], DistributionPoint(self.dp4))

        with self.assertRaisesRegex(IndexError, '^list index out of range$'):
            self.ext5[2]

    def test_getitem_slices(self):
        self.assertEqual(self.ext1[0:], [DistributionPoint(self.dp1)])
        self.assertEqual(self.ext1[1:], [])
        self.assertEqual(self.ext1[2:], [])
        self.assertEqual(self.ext5[0:], [DistributionPoint(self.dp2), DistributionPoint(self.dp4)])

    def test_hash(self):
        self.assertEqual(hash(self.ext1), hash(self.ext1))
        self.assertEqual(hash(self.ext2), hash(self.ext2))
        self.assertEqual(hash(self.ext3), hash(self.ext3))
        self.assertEqual(hash(self.ext4), hash(self.ext4))
        self.assertEqual(hash(self.ext5), hash(self.ext5))

        self.assertEqual(hash(self.ext1), hash(CRLDistributionPoints(self.x1)))
        self.assertEqual(hash(self.ext2), hash(CRLDistributionPoints(self.x2)))
        self.assertEqual(hash(self.ext3), hash(CRLDistributionPoints(self.x3)))
        self.assertEqual(hash(self.ext4), hash(CRLDistributionPoints(self.x4)))
        self.assertEqual(hash(self.ext5), hash(CRLDistributionPoints(self.x5)))

        self.assertNotEqual(hash(self.ext1), hash(self.ext2))
        self.assertNotEqual(hash(self.ext1), hash(self.ext3))
        self.assertNotEqual(hash(self.ext1), hash(self.ext4))
        self.assertNotEqual(hash(self.ext1), hash(self.ext5))
        self.assertNotEqual(hash(self.ext2), hash(self.ext3))
        self.assertNotEqual(hash(self.ext2), hash(self.ext4))
        self.assertNotEqual(hash(self.ext2), hash(self.ext5))
        self.assertNotEqual(hash(self.ext3), hash(self.ext4))
        self.assertNotEqual(hash(self.ext3), hash(self.ext5))

    def test_in(self):
        self.assertIn(self.s1, self.ext1)
        self.assertIn(self.s2, self.ext2)
        self.assertIn(self.s3, self.ext3)
        self.assertIn(self.s4, self.ext4)
        self.assertIn(self.s2, self.ext5)
        self.assertIn(self.s4, self.ext5)

        self.assertIn(self.dp1, self.ext1)
        self.assertIn(self.dp2, self.ext2)
        self.assertIn(self.dp3, self.ext3)
        self.assertIn(self.dp4, self.ext4)
        self.assertIn(self.dp2, self.ext5)
        self.assertIn(self.dp4, self.ext5)

    def test_insert(self):
        self.ext1.insert(0, self.dp2)
        self.assertEqual(self.ext1.serialize(), {'critical': False, 'value': [self.s2, self.s1]})
        self.ext1.insert(1, self.s3)
        self.assertEqual(self.ext1.serialize(), {'critical': False, 'value': [self.s2, self.s3, self.s1]})

    def test_len(self):
        self.assertEqual(len(self.ext1), 1)
        self.assertEqual(len(self.ext2), 1)
        self.assertEqual(len(self.ext3), 1)
        self.assertEqual(len(self.ext4), 1)
        self.assertEqual(len(self.ext5), 2)

    def test_ne(self):
        self.assertNotEqual(self.ext1, self.ext2)
        self.assertNotEqual(self.ext2, self.ext3)
        self.assertNotEqual(self.ext3, self.ext4)
        self.assertNotEqual(self.ext4, self.ext5)
        self.assertNotEqual(self.ext1, self.ext5)

    def test_not_in(self):
        self.assertNotIn(self.s2, self.ext1)
        self.assertNotIn(self.s3, self.ext2)
        self.assertNotIn(self.dp2, self.ext1)
        self.assertNotIn(self.dp3, self.ext4)

    def test_pop(self):
        ext = CRLDistributionPoints({'value': [self.dp1, self.dp2, self.dp3]})
        self.assertEqual(ext.pop(), DistributionPoint(self.dp3))
        self.assertEqual(ext.serialize(), {'critical': False, 'value': [self.s1, self.s2]})

        self.assertEqual(ext.pop(0), DistributionPoint(self.dp1))
        self.assertEqual(ext.serialize(), {'critical': False, 'value': [self.s2]})

        with self.assertRaisesRegex(IndexError, '^pop index out of range'):
            ext.pop(3)

    def test_remove(self):
        ext = CRLDistributionPoints({'value': [self.dp1, self.dp2, self.dp3]})
        self.assertEqual(ext.serialize(), {'critical': False, 'value': [self.s1, self.s2, self.s3]})

        ext.remove(self.dp2)
        self.assertEqual(ext.serialize(), {'critical': False, 'value': [self.s1, self.s3]})

        ext.remove(self.s3)
        self.assertEqual(ext.serialize(), {'critical': False, 'value': [self.s1]})

    def test_repr(self):
        if six.PY3:
            self.assertEqual(
                repr(self.ext1),
                "<CRLDistributionPoints: [<DistributionPoint: full_name=['URI:http://ca.example.com/crl']>], "
                "critical=False>"
            )
            self.assertEqual(
                repr(self.ext2),
                "<CRLDistributionPoints: [<DistributionPoint: full_name=['URI:http://ca.example.com/crl', "
                "'dirname:/C=AT']>], critical=False>"
            )
            self.assertEqual(
                repr(self.ext3),
                "<CRLDistributionPoints: [<DistributionPoint: relative_name='/CN=example.com'>], "
                "critical=False>"
            )
            self.assertEqual(
                repr(self.ext4),
                "<CRLDistributionPoints: [<DistributionPoint: full_name=['URI:http://ca.example.com/crl'], "
                "crl_issuer=['URI:http://ca.example.com/'], reasons=['ca_compromise', 'key_compromise']>], "
                "critical=False>"
            )
            self.assertEqual(
                repr(self.ext5),
                "<CRLDistributionPoints: ["
                "<DistributionPoint: full_name=['URI:http://ca.example.com/crl', 'dirname:/C=AT']>, "
                "<DistributionPoint: full_name=['URI:http://ca.example.com/crl'], "
                "crl_issuer=['URI:http://ca.example.com/'], reasons=['ca_compromise', 'key_compromise']>], "
                "critical=True>"
            )
        else:  # pragma: only py2
            self.assertEqual(
                repr(self.ext1),
                "<CRLDistributionPoints: [<DistributionPoint: full_name=[u'URI:http://ca.example.com/crl']>],"
                " critical=False>"
            )
            self.assertEqual(
                repr(self.ext2),
                "<CRLDistributionPoints: [<DistributionPoint: full_name=[u'URI:http://ca.example.com/crl', "
                "u'dirname:/C=AT']>], critical=False>"
            )
            self.assertEqual(
                repr(self.ext3),
                "<CRLDistributionPoints: [<DistributionPoint: relative_name='/CN=example.com'>], "
                "critical=False>"
            )
            self.assertEqual(
                repr(self.ext4),
                "<CRLDistributionPoints: [<DistributionPoint: full_name=[u'URI:http://ca.example.com/crl'], "
                "crl_issuer=[u'URI:http://ca.example.com/'], "
                "reasons=['ca_compromise', 'key_compromise']>], critical=False>"
            )
            self.assertEqual(
                repr(self.ext5),
                "<CRLDistributionPoints: [<DistributionPoint: "
                "full_name=[u'URI:http://ca.example.com/crl', u'dirname:/C=AT']>, "
                "<DistributionPoint: full_name=[u'URI:http://ca.example.com/crl'], "
                "crl_issuer=[u'URI:http://ca.example.com/'], reasons=['ca_compromise', 'key_compromise']>], "
                "critical=True>"
            )

    def test_serialize(self):
        self.assertEqual(self.ext1.serialize(), {'critical': False, 'value': [self.s1]})
        self.assertEqual(self.ext2.serialize(), {'critical': False, 'value': [self.s2]})
        self.assertEqual(self.ext3.serialize(), {'critical': False, 'value': [self.s3]})
        self.assertEqual(self.ext4.serialize(), {'critical': False, 'value': [self.s4]})
        self.assertEqual(self.ext5.serialize(), {'critical': True, 'value': [self.s2, self.s4]})

    def test_setitem(self):
        self.ext1[0] = self.s2
        self.assertEqual(self.ext1, self.ext2)
        self.ext1[0] = self.s3
        self.assertEqual(self.ext1, self.ext3)
        self.ext1[0] = self.dp4
        self.assertEqual(self.ext1, self.ext4)

        with self.assertRaisesRegex(IndexError, r'^list assignment index out of range$'):
            self.ext1[1] = self.dp4

    def test_setitem_slices(self):
        expected = CRLDistributionPoints({'value': [self.dp1, self.dp2, self.dp3]})
        self.ext1[1:] = [self.dp2, self.dp3]
        self.assertEqual(self.ext1, expected)
        self.ext1[1:] = [self.s2, self.s3]
        self.assertEqual(self.ext1, expected)

    def test_str(self):
        if six.PY3:
            self.assertEqual(
                str(self.ext1),
                "CRLDistributionPoints([DistributionPoint(full_name=['URI:http://ca.example.com/crl'])], "
                "critical=False)"
            )
            self.assertEqual(
                str(self.ext2),
                "CRLDistributionPoints([DistributionPoint("
                "full_name=['URI:http://ca.example.com/crl', 'dirname:/C=AT'])], critical=False)"
            )
            self.assertEqual(
                str(self.ext3),
                "CRLDistributionPoints([DistributionPoint(relative_name='/CN=example.com')], critical=False)"
            )
            self.assertEqual(
                str(self.ext4),
                "CRLDistributionPoints([DistributionPoint(full_name=['URI:http://ca.example.com/crl'], "
                "crl_issuer=['URI:http://ca.example.com/'], reasons=['ca_compromise', 'key_compromise'])], "
                "critical=False)"
            )
            self.assertEqual(
                str(self.ext5),
                "CRLDistributionPoints([DistributionPoint("
                "full_name=['URI:http://ca.example.com/crl', 'dirname:/C=AT']), "
                "DistributionPoint(full_name=['URI:http://ca.example.com/crl'], "
                "crl_issuer=['URI:http://ca.example.com/'], "
                "reasons=['ca_compromise', 'key_compromise'])], critical=True)"
            )
        else:  # pragma: only py2
            self.assertEqual(
                str(self.ext1),
                "CRLDistributionPoints([DistributionPoint(full_name=[u'URI:http://ca.example.com/crl'])], "
                "critical=False)"
            )
            self.assertEqual(
                str(self.ext2),
                "CRLDistributionPoints([DistributionPoint("
                "full_name=[u'URI:http://ca.example.com/crl', u'dirname:/C=AT'])], critical=False)"
            )
            self.assertEqual(
                str(self.ext3),
                "CRLDistributionPoints([DistributionPoint(relative_name='/CN=example.com')], critical=False)"
            )
            self.assertEqual(
                str(self.ext4),
                "CRLDistributionPoints([DistributionPoint(full_name=[u'URI:http://ca.example.com/crl'], "
                "crl_issuer=[u'URI:http://ca.example.com/'], "
                "reasons=['ca_compromise', 'key_compromise'])], critical=False)"
            )
            self.assertEqual(
                str(self.ext5),
                "CRLDistributionPoints([DistributionPoint("
                "full_name=[u'URI:http://ca.example.com/crl', u'dirname:/C=AT']), "
                "DistributionPoint(full_name=[u'URI:http://ca.example.com/crl'], "
                "crl_issuer=[u'URI:http://ca.example.com/'], "
                "reasons=['ca_compromise', 'key_compromise'])], critical=True)"
            )


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

    def test_repr(self):
        if six.PY2:  # pragma: only py2
            self.assertEqual(repr(self.pi1), "<PolicyInformation(oid=2.5.29.32.0, qualifiers=[u'text1'])>")
            self.assertEqual(
                repr(self.pi2),
                "<PolicyInformation(oid=2.5.29.32.0, qualifiers=[{u'explicit_text': u'text2'}])>")
            self.assertEqual(repr(self.pi_empty), "<PolicyInformation(oid=None, qualifiers=None)>")
        else:
            self.assertEqual(repr(self.pi1), "<PolicyInformation(oid=2.5.29.32.0, qualifiers=['text1'])>")
            self.assertEqual(repr(self.pi2),
                             "<PolicyInformation(oid=2.5.29.32.0, qualifiers=[{'explicit_text': 'text2'}])>")
            self.assertEqual(repr(self.pi_empty), "<PolicyInformation(oid=None, qualifiers=None)>")

        # NOTE: order of dict is different here, so we do not test output, just make sure there's no exception
        repr(self.pi3)
        repr(self.pi4)

    def test_str(self):
        self.assertEqual(str(self.pi1), 'PolicyInformation(oid=2.5.29.32.0, 1 qualifier)')
        self.assertEqual(str(self.pi2), 'PolicyInformation(oid=2.5.29.32.0, 1 qualifier)')
        self.assertEqual(str(self.pi3), 'PolicyInformation(oid=2.5.29.32.0, 1 qualifier)')
        self.assertEqual(str(self.pi4), 'PolicyInformation(oid=2.5.29.32.0, 2 qualifiers)')
        self.assertEqual(str(self.pi_empty), 'PolicyInformation(oid=None, 0 qualifiers)')


class CertificatePoliciesTestCase(ListExtensionTestMixin, ExtensionTestMixin, TestCase):
    ext_class = CertificatePolicies
    oid = '2.5.29.32.0'

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

    xpi1 = x509.PolicyInformation(policy_identifier=ObjectIdentifier(oid),
                                  policy_qualifiers=[q1])
    xpi2 = x509.PolicyInformation(
        policy_identifier=ObjectIdentifier(oid),
        policy_qualifiers=[q2],
    )
    xpi3 = x509.PolicyInformation(
        policy_identifier=ObjectIdentifier(oid),
        policy_qualifiers=[q3],
    )
    xpi4 = x509.PolicyInformation(
        policy_identifier=ObjectIdentifier(oid),
        policy_qualifiers=[q4, q5],
    )
    spi1 = {
        'policy_identifier': oid,
        'policy_qualifiers': ['text1'],
    }
    spi2 = {
        'policy_identifier': oid,
        'policy_qualifiers': [
            {'explicit_text': 'text2', }
        ],
    }
    spi3 = {
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
    spi4 = {
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
    x1 = x509.Extension(
        oid=ExtensionOID.CERTIFICATE_POLICIES, critical=False,
        value=x509.CertificatePolicies(policies=[xpi1])
    )
    x2 = x509.Extension(
        oid=ExtensionOID.CERTIFICATE_POLICIES, critical=False,
        value=x509.CertificatePolicies(policies=[xpi2])
    )
    x3 = x509.Extension(
        oid=ExtensionOID.CERTIFICATE_POLICIES, critical=False,
        value=x509.CertificatePolicies(policies=[xpi3])
    )
    x4 = x509.Extension(
        oid=ExtensionOID.CERTIFICATE_POLICIES, critical=False,
        value=x509.CertificatePolicies(policies=[xpi4])
    )
    x5 = x509.Extension(
        oid=ExtensionOID.CERTIFICATE_POLICIES, critical=False,
        value=x509.CertificatePolicies(policies=[xpi1, xpi2, xpi4])
    )
    x6 = x509.Extension(
        oid=ExtensionOID.CERTIFICATE_POLICIES, critical=True,
        value=x509.CertificatePolicies(policies=[])
    )
    xs = [x1, x2, x3, x4, x5, x6]

    def setUp(self):
        super(CertificatePoliciesTestCase, self).setUp()
        self.pi1 = PolicyInformation(self.xpi1)
        self.pi2 = PolicyInformation(self.xpi2)
        self.pi3 = PolicyInformation(self.xpi3)
        self.pi4 = PolicyInformation(self.xpi4)
        self.ext1 = CertificatePolicies({'value': [self.xpi1]})
        self.ext2 = CertificatePolicies({'value': [self.xpi2]})
        self.ext3 = CertificatePolicies({'value': [self.xpi3]})
        self.ext4 = CertificatePolicies({'value': [self.xpi4]})
        self.ext5 = CertificatePolicies({'value': [self.xpi1, self.xpi2, self.xpi4]})
        self.ext6 = CertificatePolicies({'critical': True})
        self.exts = [self.ext1, self.ext2, self.ext3, self.ext4, self.ext5, self.ext6]

    def test_as_text(self):
        self.assertEqual(
            self.ext1.as_text(),
            '* Policy Identifier: 2.5.29.32.0\n'
            '  Policy Qualifiers:\n'
            '  * text1'
        )
        self.assertEqual(
            self.ext2.as_text(),
            '* Policy Identifier: 2.5.29.32.0\n'
            '  Policy Qualifiers:\n'
            '  * UserNotice:\n'
            '    * Explicit text: text2'
        )
        self.assertEqual(
            self.ext3.as_text(),
            '* Policy Identifier: 2.5.29.32.0\n'
            '  Policy Qualifiers:\n'
            '  * UserNotice:\n'
            '    * Reference:\n'
            '      * Organiziation: text3\n'
            '      * Notice Numbers: [1]'
        )
        self.assertEqual(
            self.ext4.as_text(),
            '* Policy Identifier: 2.5.29.32.0\n'
            '  Policy Qualifiers:\n'
            '  * text4\n'
            '  * UserNotice:\n'
            '    * Explicit text: text5\n'
            '    * Reference:\n'
            '      * Organiziation: text6\n'
            '      * Notice Numbers: [1, 2, 3]'
        )
        self.assertEqual(
            self.ext5.as_text(),
            '* Policy Identifier: 2.5.29.32.0\n'
            '  Policy Qualifiers:\n'
            '  * text1\n'
            '* Policy Identifier: 2.5.29.32.0\n'
            '  Policy Qualifiers:\n'
            '  * UserNotice:\n'
            '    * Explicit text: text2\n'
            '* Policy Identifier: 2.5.29.32.0\n'
            '  Policy Qualifiers:\n'
            '  * text4\n'
            '  * UserNotice:\n'
            '    * Explicit text: text5\n'
            '    * Reference:\n'
            '      * Organiziation: text6\n'
            '      * Notice Numbers: [1, 2, 3]'
        )
        self.assertEqual(self.ext6.as_text(), '')

    def test_count(self):
        self.assertEqual(self.ext1.count(self.xpi1), 1)
        self.assertEqual(self.ext1.count(self.spi1), 1)
        self.assertEqual(self.ext1.count(self.pi1), 1)
        self.assertEqual(self.ext1.count(self.xpi2), 0)
        self.assertEqual(self.ext1.count(self.spi2), 0)
        self.assertEqual(self.ext1.count(self.pi2), 0)

    def test_del(self):
        del self.ext1[0]
        self.assertEqual(len(self.ext1), 0)

    def test_extend(self):
        self.ext1.extend([self.xpi2, self.pi4])
        self.assertEqual(self.ext1, self.ext5)

    def test_getitem(self):
        self.assertEqual(self.ext1[0], self.pi1)
        self.assertEqual(self.ext2[0], self.pi2)
        self.assertEqual(self.ext3[0], self.pi3)
        self.assertEqual(self.ext5[0], self.pi1)
        self.assertEqual(self.ext5[1], self.pi2)
        self.assertEqual(self.ext5[2], self.pi4)

    def test_getitem_slices(self):
        self.assertEqual(self.ext5[0:], [self.pi1, self.pi2, self.pi4])
        self.assertEqual(self.ext5[1:], [self.pi2, self.pi4])
        self.assertEqual(self.ext5[2:], [self.pi4])

    def test_hash(self):
        self.assertEqual(hash(self.ext1), hash(self.ext1))
        self.assertEqual(hash(self.ext2), hash(self.ext2))
        self.assertEqual(hash(self.ext3), hash(self.ext3))
        self.assertEqual(hash(self.ext4), hash(self.ext4))
        self.assertEqual(hash(self.ext5), hash(self.ext5))
        self.assertEqual(hash(self.ext6), hash(self.ext6))

        self.assertEqual(hash(self.ext1), hash(CertificatePolicies({'value': [self.xpi1]})))
        self.assertEqual(hash(self.ext2), hash(CertificatePolicies({'value': [self.xpi2]})))
        self.assertEqual(hash(self.ext3), hash(CertificatePolicies({'value': [self.xpi3]})))
        self.assertEqual(hash(self.ext4), hash(CertificatePolicies({'value': [self.xpi4]})))
        self.assertEqual(hash(self.ext5), hash(CertificatePolicies(
            {'value': [self.xpi1, self.xpi2, self.xpi4]})))

        self.assertEqual(hash(self.ext1), hash(CertificatePolicies({'value': [self.spi1]})))
        self.assertEqual(hash(self.ext2), hash(CertificatePolicies({'value': [self.spi2]})))
        self.assertEqual(hash(self.ext3), hash(CertificatePolicies({'value': [self.spi3]})))
        self.assertEqual(hash(self.ext4), hash(CertificatePolicies({'value': [self.spi4]})))
        self.assertEqual(hash(self.ext5), hash(CertificatePolicies(
            {'value': [self.spi1, self.spi2, self.spi4]})))

        self.assertNotEqual(hash(self.ext1), hash(self.ext2))
        self.assertNotEqual(hash(self.ext1), hash(self.ext3))
        self.assertNotEqual(hash(self.ext1), hash(self.ext4))
        self.assertNotEqual(hash(self.ext1), hash(self.ext5))
        self.assertNotEqual(hash(self.ext1), hash(self.ext6))
        self.assertNotEqual(hash(self.ext2), hash(self.ext3))
        self.assertNotEqual(hash(self.ext2), hash(self.ext4))
        self.assertNotEqual(hash(self.ext2), hash(self.ext5))
        self.assertNotEqual(hash(self.ext2), hash(self.ext6))
        self.assertNotEqual(hash(self.ext3), hash(self.ext4))
        self.assertNotEqual(hash(self.ext3), hash(self.ext5))
        self.assertNotEqual(hash(self.ext3), hash(self.ext6))

        self.assertNotEqual(hash(self.ext3), hash(self.ext6))
        self.assertNotEqual(hash(self.ext4), hash(CertificatePolicies({'critical': False})))

    def test_in(self):
        self.assertIn(self.xpi1, self.ext1)
        self.assertIn(self.spi1, self.ext1)
        self.assertIn(self.pi1, self.ext1)

        self.assertIn(self.xpi2, self.ext2)
        self.assertIn(self.spi2, self.ext2)
        self.assertIn(self.pi2, self.ext2)

        self.assertIn(self.xpi1, self.ext5)
        self.assertIn(self.xpi2, self.ext5)
        self.assertIn(self.xpi4, self.ext5)

    def test_insert(self):
        self.assertEqual(self.ext1.serialize(), {'critical': False, 'value': [self.spi1]})
        self.ext1.insert(0, self.xpi2)
        self.assertEqual(self.ext1.serialize(), {'critical': False, 'value': [self.spi2, self.spi1]})
        self.ext1.insert(1, self.spi3)
        self.assertEqual(self.ext1.serialize(),
                         {'critical': False, 'value': [self.spi2, self.spi3, self.spi1]})
        self.ext1.insert(0, self.pi4)
        self.assertEqual(self.ext1.serialize(),
                         {'critical': False, 'value': [self.spi4, self.spi2, self.spi3, self.spi1]})

    def test_len(self):
        self.assertEqual(len(self.ext1), 1)
        self.assertEqual(len(self.ext2), 1)
        self.assertEqual(len(self.ext3), 1)
        self.assertEqual(len(self.ext4), 1)
        self.assertEqual(len(self.ext5), 3)
        self.assertEqual(len(self.ext6), 0)

    def test_ne(self):
        self.assertNotEqual(self.ext1, self.ext2)
        self.assertNotEqual(self.ext1, self.ext3)
        self.assertNotEqual(self.ext1, self.ext4)
        self.assertNotEqual(self.ext1, self.ext5)
        self.assertNotEqual(self.ext1, self.ext6)

        self.assertNotEqual(self.ext2, self.ext3)
        self.assertNotEqual(self.ext2, self.ext4)
        self.assertNotEqual(self.ext2, self.ext5)
        self.assertNotEqual(self.ext2, self.ext6)

        self.assertNotEqual(self.ext3, self.ext4)
        self.assertNotEqual(self.ext3, self.ext5)
        self.assertNotEqual(self.ext3, self.ext6)

        self.assertNotEqual(self.ext6, CertificatePolicies({'critical': False}))

    def test_not_in(self):
        self.assertNotIn(self.xpi2, self.ext1)
        self.assertNotIn(self.spi2, self.ext1)
        self.assertNotIn(self.pi2, self.ext1)

        self.assertNotIn(self.xpi2, self.ext6)
        self.assertNotIn(self.spi2, self.ext6)
        self.assertNotIn(self.pi2, self.ext6)

    def test_pop(self):
        self.assertEqual(self.ext1.pop(), self.pi1)
        self.assertEqual(len(self.ext1), 0)
        self.assertEqual(self.ext5.pop(1), self.pi2)
        self.assertEqual(len(self.ext5), 2)

    def test_remove(self):
        self.ext1.remove(self.xpi1)
        self.assertEqual(len(self.ext1), 0)
        self.ext2.remove(self.spi2)
        self.assertEqual(len(self.ext2), 0)
        self.ext3.remove(self.pi3)
        self.assertEqual(len(self.ext3), 0)

    def test_repr(self):
        self.assertEqual(
            repr(self.ext1),
            '<CertificatePolicies: [PolicyInformation(oid=2.5.29.32.0, 1 qualifier)], critical=False>')
        self.assertEqual(
            repr(self.ext2),
            '<CertificatePolicies: [PolicyInformation(oid=2.5.29.32.0, 1 qualifier)], critical=False>')
        self.assertEqual(
            repr(self.ext3),
            '<CertificatePolicies: [PolicyInformation(oid=2.5.29.32.0, 1 qualifier)], critical=False>')
        self.assertEqual(
            repr(self.ext4),
            '<CertificatePolicies: [PolicyInformation(oid=2.5.29.32.0, 2 qualifiers)], critical=False>')
        self.assertEqual(
            repr(self.ext5),
            '<CertificatePolicies: [PolicyInformation(oid=2.5.29.32.0, 1 qualifier), '
            'PolicyInformation(oid=2.5.29.32.0, 1 qualifier), PolicyInformation(oid=2.5.29.32.0, 2 '
            'qualifiers)], critical=False>'
        )
        self.assertEqual(
            repr(self.ext6),
            '<CertificatePolicies: [], critical=True>'
        )

    def test_serialize(self):
        self.assertEqual(self.ext1.serialize(), {'critical': False, 'value': [self.spi1]})
        self.assertEqual(self.ext2.serialize(), {'critical': False, 'value': [self.spi2]})
        self.assertEqual(self.ext3.serialize(), {'critical': False, 'value': [self.spi3]})
        self.assertEqual(self.ext4.serialize(), {'critical': False, 'value': [self.spi4]})
        self.assertEqual(self.ext5.serialize(),
                         {'critical': False, 'value': [self.spi1, self.spi2, self.spi4]})
        self.assertEqual(self.ext6.serialize(), {'critical': True, 'value': []})

        self.assertEqual(self.ext1, CertificatePolicies(self.ext1.serialize()))
        self.assertEqual(self.ext2, CertificatePolicies(self.ext2.serialize()))
        self.assertEqual(self.ext3, CertificatePolicies(self.ext3.serialize()))
        self.assertEqual(self.ext4, CertificatePolicies(self.ext4.serialize()))
        self.assertEqual(self.ext5, CertificatePolicies(self.ext5.serialize()))
        self.assertEqual(self.ext6, CertificatePolicies(self.ext6.serialize()))

    def test_setitem(self):
        self.ext1[0] = self.xpi2
        self.assertEqual(self.ext1, self.ext2)
        self.ext1[0] = self.spi3
        self.assertEqual(self.ext1, self.ext3)
        self.ext1[0] = self.pi4
        self.assertEqual(self.ext1, self.ext4)

    def test_setitem_slices(self):
        self.ext1[0:] = [self.xpi2]
        self.assertEqual(self.ext1, self.ext2)

    def test_str(self):
        self.assertEqual(str(self.ext1), 'CertificatePolicies(1 Policy, critical=False)')
        self.assertEqual(str(self.ext2), 'CertificatePolicies(1 Policy, critical=False)')
        self.assertEqual(str(self.ext3), 'CertificatePolicies(1 Policy, critical=False)')
        self.assertEqual(str(self.ext4), 'CertificatePolicies(1 Policy, critical=False)')
        self.assertEqual(str(self.ext5), 'CertificatePolicies(3 Policies, critical=False)')
        self.assertEqual(str(self.ext6), 'CertificatePolicies(0 Policies, critical=True)')


class IssuerAlternativeNameTestCase(ListExtensionTestMixin, ExtensionTestMixin, TestCase):
    ext_class = IssuerAlternativeName
    ext_class_name = 'IssuerAlternativeName'
    uri1 = 'https://example.com'
    uri2 = 'https://example.net'
    dns1 = 'example.com'
    dns2 = 'example.net'

    x1 = x509.extensions.Extension(
        oid=ExtensionOID.ISSUER_ALTERNATIVE_NAME, critical=False,
        value=x509.IssuerAlternativeName([])
    )
    x2 = x509.extensions.Extension(
        oid=ExtensionOID.ISSUER_ALTERNATIVE_NAME, critical=False,
        value=x509.IssuerAlternativeName([uri(uri1)])
    )
    x3 = x509.extensions.Extension(
        oid=ExtensionOID.ISSUER_ALTERNATIVE_NAME, critical=False,
        value=x509.IssuerAlternativeName([uri(uri1), dns(dns1)])
    )
    x4 = x509.extensions.Extension(
        oid=ExtensionOID.ISSUER_ALTERNATIVE_NAME, critical=True,
        value=x509.IssuerAlternativeName([])
    )
    x5 = x509.extensions.Extension(
        oid=ExtensionOID.ISSUER_ALTERNATIVE_NAME, critical=True,
        value=x509.IssuerAlternativeName([uri(uri2), dns(dns2)])
    )
    xs = [x1, x2, x3, x4, x5]

    def setUp(self):
        super(IssuerAlternativeNameTestCase, self).setUp()

        self.ext1 = self.ext_class({'critical': False})
        self.ext2 = self.ext_class({'critical': False, 'value': [self.uri1]})
        self.ext3 = self.ext_class({'critical': False, 'value': [self.uri1, self.dns1]})
        self.ext4 = self.ext_class({'critical': True})
        self.ext5 = self.ext_class({'critical': True, 'value': [self.uri2, self.dns2]})

        self.exts = [self.ext1, self.ext2, self.ext3, self.ext4, self.ext5]

    def test_as_text(self):
        self.assertEqual(self.ext1.as_text(), "")
        self.assertEqual(self.ext2.as_text(), "* URI:https://example.com")
        self.assertEqual(self.ext3.as_text(), "* URI:https://example.com\n* DNS:example.com")
        self.assertEqual(self.ext4.as_text(), "")
        self.assertEqual(self.ext5.as_text(), "* URI:https://example.net\n* DNS:example.net")

    def test_count(self):
        self.assertEqual(self.ext1.count(self.uri1), 0)
        self.assertEqual(self.ext1.count(uri(self.uri1)), 0)
        self.assertEqual(self.ext2.count(self.uri1), 1)
        self.assertEqual(self.ext2.count(uri(self.uri1)), 1)

    def test_del(self):
        del self.ext3[1]
        self.assertEqual(self.ext3, self.ext2)
        del self.ext3[0]
        self.assertEqual(self.ext3, self.ext1)

    def test_extend(self):
        self.ext1.extend([self.uri1, dns(self.dns1)])
        self.assertEqual(self.ext1, self.ext3)

    def test_getitem(self):
        self.assertEqual(self.ext3[0], 'URI:%s' % self.uri1)
        self.assertEqual(self.ext3[1], 'DNS:%s' % self.dns1)
        self.assertEqual(self.ext5[0], 'URI:%s' % self.uri2)
        self.assertEqual(self.ext5[1], 'DNS:%s' % self.dns2)

    def test_getitem_slices(self):
        self.assertEqual(self.ext3[0:], ['URI:%s' % self.uri1, 'DNS:%s' % self.dns1])
        self.assertEqual(self.ext3[1:], ['DNS:%s' % self.dns1])
        self.assertEqual(self.ext5[0:], ['URI:%s' % self.uri2, 'DNS:%s' % self.dns2])
        self.assertEqual(self.ext5[1:], ['DNS:%s' % self.dns2])

    def test_hash(self):
        self.assertNotEqual(hash(self.ext1), hash(self.ext2))
        self.assertNotEqual(hash(self.ext1), hash(self.ext3))
        self.assertNotEqual(hash(self.ext1), hash(self.ext4))
        self.assertNotEqual(hash(self.ext1), hash(self.ext5))
        self.assertNotEqual(hash(self.ext2), hash(self.ext3))
        self.assertNotEqual(hash(self.ext2), hash(self.ext4))
        self.assertNotEqual(hash(self.ext2), hash(self.ext5))
        self.assertNotEqual(hash(self.ext3), hash(self.ext4))
        self.assertNotEqual(hash(self.ext3), hash(self.ext5))
        self.assertNotEqual(hash(self.ext4), hash(self.ext5))

    def test_in(self):
        self.assertIn(self.uri1, self.ext2)
        self.assertIn(self.uri1, self.ext3)
        self.assertIn(uri(self.uri1), self.ext3)
        self.assertIn(self.uri2, self.ext5)
        self.assertIn(self.dns2, self.ext5)
        self.assertIn(uri(self.uri2), self.ext5)
        self.assertIn(dns(self.dns2), self.ext5)

    def test_insert(self):
        self.ext1.insert(0, self.uri1)
        self.assertEqual(self.ext1, self.ext2)
        self.ext1.insert(1, dns(self.dns1))
        self.assertEqual(self.ext1, self.ext3)

        self.ext1.insert(5, dns(self.dns2))
        self.assertEqual(self.ext1, self.ext_class({
            'critical': False,
            'value': [self.uri1, self.dns1, self.dns2],
        }))

    def test_len(self):
        self.assertEqual(len(self.ext1), 0)
        self.assertEqual(len(self.ext2), 1)
        self.assertEqual(len(self.ext3), 2)
        self.assertEqual(len(self.ext4), 0)
        self.assertEqual(len(self.ext5), 2)

    def test_ne(self):
        self.assertNotEqual(self.ext1, self.ext2)
        self.assertNotEqual(self.ext1, self.ext3)
        self.assertNotEqual(self.ext1, self.ext4)
        self.assertNotEqual(self.ext1, self.ext5)
        self.assertNotEqual(self.ext2, self.ext3)
        self.assertNotEqual(self.ext2, self.ext4)
        self.assertNotEqual(self.ext2, self.ext5)
        self.assertNotEqual(self.ext3, self.ext4)
        self.assertNotEqual(self.ext3, self.ext5)
        self.assertNotEqual(self.ext4, self.ext5)

    def test_not_in(self):
        self.assertNotIn(self.dns2, self.ext2)
        self.assertNotIn(self.dns2, self.ext3)
        self.assertNotIn(dns(self.dns1), self.ext1)

    def test_pop(self):
        self.assertEqual(self.ext3.pop(1), 'DNS:%s' % self.dns1)
        self.assertEqual(self.ext3, self.ext2)

        with self.assertRaisesRegex(IndexError, '^pop index out of range$'):
            self.ext3.pop(1)

    def test_remove(self):
        self.ext3.remove(self.dns1)
        self.assertEqual(self.ext3, self.ext2)

        self.ext3.remove(uri(self.uri1))
        self.assertEqual(self.ext3, self.ext1)

        with self.assertRaisesRegex(ValueError, r'^list\.remove\(x\): x not in list$'):
            self.ext3.remove(uri(self.uri1))

    def test_repr(self):
        self.assertEqual(repr(self.ext1), "<%s: [], critical=False>" % self.ext_class_name)
        self.assertEqual(repr(self.ext2),
                         "<%s: ['URI:https://example.com'], critical=False>" % self.ext_class_name)
        self.assertEqual(
            repr(self.ext3),
            "<%s: ['URI:https://example.com', 'DNS:example.com'], critical=False>" % self.ext_class_name)
        self.assertEqual(repr(self.ext4), "<%s: [], critical=True>" % self.ext_class_name)
        self.assertEqual(
            repr(self.ext5),
            "<%s: ['URI:https://example.net', 'DNS:example.net'], critical=True>" % self.ext_class_name)

    def test_serialize(self):
        self.assertEqual(self.ext1.serialize(), {'critical': False, 'value': []})
        self.assertEqual(self.ext2.serialize(), {'critical': False, 'value': ['URI:https://example.com']})
        self.assertEqual(self.ext3.serialize(),
                         {'critical': False, 'value': ['URI:https://example.com', 'DNS:example.com']})
        self.assertEqual(self.ext4.serialize(), {'critical': True, 'value': []})
        self.assertEqual(self.ext5.serialize(),
                         {'critical': True, 'value': ['URI:https://example.net', 'DNS:example.net']})

    def test_setitem(self):
        self.ext3[0] = self.uri2
        self.ext3[1] = dns(self.dns2)
        self.ext3.critical = True
        self.assertEqual(self.ext3, self.ext5)

        with self.assertRaisesRegex(IndexError, '^list assignment index out of range$'):
            self.ext1[0] = self.uri1

    def test_setitem_slices(self):
        self.ext2[1:] = [self.dns1]
        self.assertEqual(self.ext2, self.ext3)
        self.ext4[0:] = [uri(self.uri2), dns(self.dns2)]
        self.assertEqual(self.ext4, self.ext5)

    def test_str(self):
        self.assertEqual(str(self.ext1), "")
        self.assertEqual(str(self.ext2), "URI:https://example.com")
        self.assertEqual(str(self.ext3), "URI:https://example.com,DNS:example.com")
        self.assertEqual(str(self.ext4), "/critical")
        self.assertEqual(str(self.ext5), "URI:https://example.net,DNS:example.net/critical")


class KeyUsageTestCase(OrderedSetExtensionTestMixin, NewExtensionTestMixin, TestCase):
    ext_class = KeyUsage
    test_values = {
        'one': {
            'values': [
                {'key_agreement', },
                ['keyAgreement', ],
            ],
            'expected': frozenset(['key_agreement']),
            'expected_str': 'keyAgreement',
            'expected_repr': "<KeyUsage: ['keyAgreement'], critical=%s>",
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
            'expected_str': 'keyAgreement,keyEncipherment',
            'expected_repr': "<KeyUsage: ['keyAgreement', 'keyEncipherment'], critical=%s>",
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
            'expected_str': 'keyAgreement,keyEncipherment,nonRepudiation',
            'expected_repr': "<KeyUsage: ['keyAgreement', 'keyEncipherment', 'nonRepudiation'], "
                             "critical=%s>",
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

    def test_unknown_values(self):
        with self.assertRaisesRegex(ValueError, r'^Unknown value: foo$'):
            KeyUsage({'value': ['foo']})

        with self.assertRaisesRegex(ValueError, r'^Unknown value: True$'):
            KeyUsage({'value': [True]})


class ExtendedKeyUsageTestCase(OrderedSetExtensionTestMixin, NewExtensionTestMixin, TestCase):
    ext_class = ExtendedKeyUsage
    test_values = {
        'one': {
            'values': [
                {'serverAuth'},
                {ExtendedKeyUsageOID.SERVER_AUTH},
                [ExtendedKeyUsageOID.SERVER_AUTH],
            ],
            'extension_type': x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            'expected': frozenset([ExtendedKeyUsageOID.SERVER_AUTH]),
            'expected_repr': "<ExtendedKeyUsage: ['serverAuth'], critical=%s>",
            'expected_serialized': ['serverAuth'],
            'expected_str': 'serverAuth',
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
            'expected_repr': "<ExtendedKeyUsage: ['clientAuth', 'serverAuth'], critical=%s>",
            'expected_serialized': ['clientAuth', 'serverAuth'],
            'expected_str': 'clientAuth,serverAuth',
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
            'expected_repr': "<ExtendedKeyUsage: ['clientAuth', 'serverAuth', 'timeStamping'], critical=%s>",
            'expected_serialized': ['clientAuth', 'serverAuth', 'timeStamping'],
            'expected_str': 'clientAuth,serverAuth,timeStamping',
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


class NameConstraintsTestCase(NewExtensionTestMixin, TestCase):
    d1 = 'example.com'
    d2 = 'example.net'

    ext_class = NameConstraints
    test_values = {
        'empty': {
            'values': {
                x509.NameConstraints(permitted_subtrees=[], excluded_subtrees=[]),
            },
            'expected': x509.NameConstraints(permitted_subtrees=[], excluded_subtrees=[]),
            'expected_repr': '<NameConstraints: permitted=[], excluded=[], critical=%s>',
            'expected_serialized': {'excluded': [], 'permitted': []},
            'expected_str': 'NameConstraints(permitted=[], excluded=[], critical={critical})',
            'expected_text': "",
            'extension_type': x509.NameConstraints(permitted_subtrees=[], excluded_subtrees=[]),
        },
        'permitted': {
            'values': {
                x509.NameConstraints(permitted_subtrees=[dns(d1)], excluded_subtrees=[]),
            },
            'expected': x509.NameConstraints(permitted_subtrees=[dns(d1)], excluded_subtrees=[]),
            'expected_repr': "<NameConstraints: permitted=['DNS:%s'], excluded=[], critical=%%s>" % d1,
            'expected_serialized': {'excluded': [], 'permitted': ['DNS:%s' % d1]},
            'expected_str': "NameConstraints(permitted=['DNS:%s'], excluded=[], "
                            "critical={critical})" % d1,
            'expected_text': "Permitted:\n  * DNS:%s\n" % d1,
            'extension_type': x509.NameConstraints(permitted_subtrees=[dns(d1)],
                                                   excluded_subtrees=[]),
        },
        'excluded': {
            'values': {
                x509.NameConstraints(permitted_subtrees=[], excluded_subtrees=[dns(d1)]),
            },
            'expected': x509.NameConstraints(permitted_subtrees=[], excluded_subtrees=[dns(d1)]),
            'expected_repr': "<NameConstraints: permitted=[], excluded=['DNS:%s'], critical=%%s>" % d1,
            'expected_serialized': {'excluded': ['DNS:%s' % d1], 'permitted': []},
            'expected_str': "NameConstraints(permitted=[], excluded=['DNS:%s'], critical={critical})" % d1,
            'expected_text': "Excluded:\n  * DNS:%s\n" % d1,
            'extension_type': x509.NameConstraints(permitted_subtrees=[],
                                                   excluded_subtrees=[dns(d1)]),
        },
        'both': {
            'values': {
                x509.NameConstraints(permitted_subtrees=[dns(d1)], excluded_subtrees=[dns(d2)])
            },
            'expected': x509.NameConstraints(permitted_subtrees=[dns(d1)], excluded_subtrees=[dns(d2)]),
            'expected_repr': "<NameConstraints: permitted=['DNS:%s'], excluded=['DNS:%s'], "
                             "critical=%%s>" % (d1, d2),
            'expected_serialized': {'excluded': ['DNS:%s' % d2], 'permitted': ['DNS:%s' % d1]},
            'expected_str': "NameConstraints(permitted=['DNS:%s'], excluded=['DNS:%s'], "
                            "critical={critical})" % (d1, d2),
            'expected_text': "Permitted:\n  * DNS:%s\nExcluded:\n  * DNS:%s\n" % (d1, d2),
            'extension_type': x509.NameConstraints(permitted_subtrees=[dns(d1)], excluded_subtrees=[dns(d2)]),
        },
    }

    def test_bool(self):
        self.assertFalse(bool(NameConstraints({})))
        self.assertTrue(bool(NameConstraints({'value': {'permitted': ['example.com']}})))
        self.assertTrue(bool(NameConstraints({'value': {'excluded': ['example.com']}})))

    def test_str(self):
        # overwritten for now because str() does not append "/critical".
        for config in self.test_values.values():
            for value in config['values']:
                ext = self.ext(value)
                self.assertEqual(str(ext), config['expected_str'].format(critical=ext.default_critical))

                ext = self.ext(value, critical=True)
                self.assertEqual(str(ext), config['expected_str'].format(critical=True))

                ext = self.ext(value, critical=False)
                self.assertEqual(str(ext), config['expected_str'].format(critical=False))


class OCSPNoCheckTestCase(ExtensionTestMixin, TestCase):
    ext_class = OCSPNoCheck

    x1 = x509.extensions.Extension(oid=ExtensionOID.OCSP_NO_CHECK, critical=True,
                                   value=x509.OCSPNoCheck())
    x2 = x509.extensions.Extension(oid=ExtensionOID.OCSP_NO_CHECK, critical=False,
                                   value=x509.OCSPNoCheck())
    xs = [x1, x2]

    def setUp(self):
        super(OCSPNoCheckTestCase, self).setUp()
        self.ext1 = OCSPNoCheck({'critical': True})
        self.ext2 = OCSPNoCheck({'critical': False})
        self.exts = [self.ext1, self.ext2]

    # OCSPNoCheck does not compare as equal until cryptography 2.7:
    #   https://github.com/pyca/cryptography/issues/4818
    @unittest.skipUnless(x509.OCSPNoCheck() == x509.OCSPNoCheck(),
                         'Extensions compare as equal.')  # pragma: cryptography<2.7
    def test_as_extension(self):
        super(OCSPNoCheckTestCase, self).test_as_extension()

    def test_as_text(self):
        ext1 = OCSPNoCheck()
        ext2 = OCSPNoCheck({'critical': True})
        self.assertEqual(ext1.as_text(), "OCSPNoCheck")
        self.assertEqual(ext2.as_text(), "OCSPNoCheck")

    def test_ne(self):
        ext1 = x509.extensions.Extension(oid=ExtensionOID.OCSP_NO_CHECK, critical=True, value=None)
        ext2 = x509.extensions.Extension(oid=ExtensionOID.OCSP_NO_CHECK, critical=False, value=None)

        self.assertNotEqual(OCSPNoCheck(ext1), OCSPNoCheck(ext2))
        self.assertNotEqual(OCSPNoCheck({'critical': True}), OCSPNoCheck({'critical': False}))

    def test_hash(self):
        ext1 = OCSPNoCheck()
        ext2 = OCSPNoCheck({'critical': True})

        self.assertEqual(hash(ext1), hash(ext1))
        self.assertEqual(hash(ext2), hash(ext2))
        self.assertNotEqual(hash(ext1), hash(ext2))

    # OCSPNoCheck does not compare as equal until cryptography 2.7:
    #   https://github.com/pyca/cryptography/issues/4818
    @unittest.skipUnless(x509.OCSPNoCheck() == x509.OCSPNoCheck(),
                         'Extensions compare as equal.')  # pragma: cryptography<2.7
    def test_extension_type(self):
        super(OCSPNoCheckTestCase, self).test_extension_type()

    # OCSPNoCheck does not compare as equal until cryptography 2.7:
    #   https://github.com/pyca/cryptography/issues/4818
    @unittest.skipUnless(x509.OCSPNoCheck() == x509.OCSPNoCheck(),
                         'Extensions compare as equal.')  # pragma: cryptography<2.7
    def test_for_builder(self):
        super(OCSPNoCheckTestCase, self).test_for_builder()

    def test_from_extension(self):
        ext = OCSPNoCheck(x509.extensions.Extension(
            oid=ExtensionOID.OCSP_NO_CHECK, critical=True, value=None))
        self.assertTrue(ext.critical)

        ext = OCSPNoCheck(x509.extensions.Extension(
            oid=ExtensionOID.OCSP_NO_CHECK, critical=False, value=None))
        self.assertFalse(ext.critical)

    def test_from_dict(self):
        self.assertFalse(OCSPNoCheck({}).critical)
        self.assertTrue(OCSPNoCheck({'critical': True}).critical)
        self.assertTrue(OCSPNoCheck({'critical': True, 'foo': 'bar'}).critical)
        self.assertFalse(OCSPNoCheck({'critical': False}).critical)
        self.assertFalse(OCSPNoCheck({'critical': False, 'foo': 'bar'}).critical)

    def test_str(self):
        ext1 = OCSPNoCheck({'critical': True})
        ext2 = OCSPNoCheck({'critical': False})

        self.assertEqual(str(ext1), 'OCSPNoCheck/critical')
        self.assertEqual(str(ext2), 'OCSPNoCheck')

    def test_repr(self):
        ext1 = OCSPNoCheck({'critical': True})
        ext2 = OCSPNoCheck({'critical': False})

        self.assertEqual(repr(ext1), '<OCSPNoCheck: critical=True>')
        self.assertEqual(repr(ext2), '<OCSPNoCheck: critical=False>')

    def test_serialize(self):
        ext1 = OCSPNoCheck({'critical': True})
        ext2 = OCSPNoCheck({'critical': False})

        self.assertEqual(ext1.serialize(), ext1.serialize())
        self.assertNotEqual(ext1.serialize(), ext2.serialize())
        self.assertEqual(ext1, OCSPNoCheck(ext1.serialize()))
        self.assertEqual(ext2, OCSPNoCheck(ext2.serialize()))


class PrecertPoisonTestCase(ExtensionTestMixin, TestCase):
    # NOTE: this extension is always critical and has no value, that's why there are fewer test instances here
    ext_class = PrecertPoison

    x1 = x509.extensions.Extension(oid=ExtensionOID.PRECERT_POISON, critical=True, value=x509.PrecertPoison())
    xs = [x1]

    def setUp(self):
        super(PrecertPoisonTestCase, self).setUp()
        self.ext1 = PrecertPoison({})
        self.exts = [self.ext1]

    # PrecertPoison does not compare as equal until cryptography 2.7:
    #   https://github.com/pyca/cryptography/issues/4818
    @unittest.skipUnless(hasattr(x509, 'PrecertPoison') and x509.PrecertPoison() == x509.PrecertPoison(),
                         'Extensions compare as equal.')  # pragma: only cryptography<2.7
    def test_as_extension(self):
        super(PrecertPoisonTestCase, self).test_as_extension()

    def test_as_text(self):
        self.assertEqual(PrecertPoison().as_text(), "PrecertPoison")

    # PrecertPoison does not compare as equal until cryptography 2.7:
    #   https://github.com/pyca/cryptography/issues/4818
    @unittest.skipUnless(hasattr(x509, 'PrecertPoison') and x509.PrecertPoison() == x509.PrecertPoison(),
                         'Extensions compare as equal.')  # pragma: only cryptography<2.7
    def test_extension_type(self):
        super(PrecertPoisonTestCase, self).test_extension_type()

    # PrecertPoison does not compare as equal until cryptography 2.7:
    #   https://github.com/pyca/cryptography/issues/4818
    @unittest.skipUnless(hasattr(x509, 'PrecertPoison') and x509.PrecertPoison() == x509.PrecertPoison(),
                         'Extensions compare as equal.')  # pragma: only cryptography<2.7
    def test_for_builder(self):
        super(PrecertPoisonTestCase, self).test_for_builder()

    def test_hash(self):
        ext1 = PrecertPoison()
        ext2 = PrecertPoison({'critical': True})

        self.assertEqual(hash(ext1), hash(ext1))
        self.assertEqual(hash(ext2), hash(ext2))
        self.assertEqual(hash(ext1), hash(ext2))

    def test_ne(self):
        # PrecertPoison is always critical and has no value, thus all instances compare as equal (and there
        # is nothing we could test)
        pass

    def test_from_extension(self):
        ext = PrecertPoison(x509.extensions.Extension(
            oid=ExtensionOID.PRECERT_POISON, critical=True, value=None))
        self.assertTrue(ext.critical)

    def test_from_dict(self):
        self.assertTrue(PrecertPoison({}).critical)
        self.assertTrue(PrecertPoison({'critical': True}).critical)
        self.assertTrue(PrecertPoison({'critical': True, 'foo': 'bar'}).critical)

    def test_str(self):
        self.assertEqual(str(PrecertPoison({'critical': True})), 'PrecertPoison/critical')

    def test_repr(self):
        self.assertEqual(repr(PrecertPoison({'critical': True})), '<PrecertPoison: critical=True>')

    def test_serialize(self):
        ext1 = PrecertPoison()
        ext2 = PrecertPoison({'critical': True})

        self.assertEqual(ext1.serialize(), ext1.serialize())
        self.assertEqual(ext1.serialize(), ext2.serialize())
        self.assertEqual(ext1, PrecertPoison(ext1.serialize()))
        self.assertEqual(ext2, PrecertPoison(ext2.serialize()))

    def test_non_critical(self):
        ext = x509.extensions.Extension(oid=ExtensionOID.PRECERT_POISON, critical=False, value=None)

        with self.assertRaisesRegex(ValueError, '^PrecertPoison must always be marked as critical$'):
            PrecertPoison(ext)
        with self.assertRaisesRegex(ValueError, '^PrecertPoison must always be marked as critical$'):
            PrecertPoison({'critical': False})


@unittest.skipUnless(ca_settings.OPENSSL_SUPPORTS_SCT,
                     'This version of OpenSSL does not support SCTs')
class PrecertificateSignedCertificateTimestampsTestCase(DjangoCAWithCertTestCase):

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
        if six.PY2:  # pragma: only py2
            exp1 = [{str(k): str(v) for k, v in e.items()} for e in self.data1['value']]
            exp2 = [{str(k): str(v) for k, v in e.items()} for e in self.data2['value']]
        else:
            exp1 = self.data1['value']
            exp2 = self.data2['value']

        self.assertEqual(
            repr(self.ext1),
            '<PrecertificateSignedCertificateTimestamps: %s, critical=False>' % repr(exp1))
        self.assertEqual(
            repr(self.ext2),
            '<PrecertificateSignedCertificateTimestamps: %s, critical=False>' % repr(exp2))

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
        self.assertEqual(str(self.ext1), '<2 entry(s)>')
        self.assertEqual(str(self.ext2), '<3 entry(s)>')

        with self.patch_object(self.ext2, 'critical', True):
            self.assertEqual(str(self.ext2), '<3 entry(s)>/critical')


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
    ext_class_name = 'SubjectAlternativeName'
    x1 = x509.extensions.Extension(
        oid=ExtensionOID.SUBJECT_ALTERNATIVE_NAME, critical=False,
        value=x509.SubjectAlternativeName([])
    )
    x2 = x509.extensions.Extension(
        oid=ExtensionOID.SUBJECT_ALTERNATIVE_NAME, critical=False,
        value=x509.SubjectAlternativeName([uri(IssuerAlternativeNameTestCase.uri1)])
    )
    x3 = x509.extensions.Extension(
        oid=ExtensionOID.SUBJECT_ALTERNATIVE_NAME, critical=False,
        value=x509.SubjectAlternativeName([uri(IssuerAlternativeNameTestCase.uri1),
                                           dns(IssuerAlternativeNameTestCase.dns1)])
    )
    x4 = x509.extensions.Extension(
        oid=ExtensionOID.SUBJECT_ALTERNATIVE_NAME, critical=True,
        value=x509.SubjectAlternativeName([])
    )
    x5 = x509.extensions.Extension(
        oid=ExtensionOID.SUBJECT_ALTERNATIVE_NAME, critical=True,
        value=x509.SubjectAlternativeName([uri(IssuerAlternativeNameTestCase.uri2),
                                           dns(IssuerAlternativeNameTestCase.dns2)])
    )
    xs = [x1, x2, x3, x4, x5]


class SubjectKeyIdentifierTestCase(ExtensionTestMixin, TestCase):
    ext_class = SubjectKeyIdentifier

    hex1 = '33:33:33:33:33:33'
    hex2 = '44:44:44:44:44:44'
    hex3 = '55:55:55:55:55:55'
    b1 = b'333333'
    b2 = b'DDDDDD'
    b3 = b'UUUUUU'  # really unknown right now
    x1 = x509.Extension(
        oid=x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER, critical=False,
        value=x509.SubjectKeyIdentifier(b1)
    )
    x2 = x509.Extension(
        oid=x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER, critical=False,
        value=x509.SubjectKeyIdentifier(b2)
    )
    x3 = x509.Extension(
        oid=x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER, critical=True,
        value=x509.SubjectKeyIdentifier(b3)
    )
    xs = [x1, x2, x3]

    def setUp(self):
        super(SubjectKeyIdentifierTestCase, self).setUp()
        self.ext1 = SubjectKeyIdentifier({'value': self.hex1})
        self.ext2 = SubjectKeyIdentifier({'value': self.hex2})
        self.ext3 = SubjectKeyIdentifier({'value': self.hex3, 'critical': True})
        self.exts = [self.ext1, self.ext2, self.ext3]

    def test_basic(self):
        ext = SubjectKeyIdentifier(self.x1)
        self.assertEqual(ext.as_text(), '33:33:33:33:33:33')
        self.assertEqual(ext.as_extension(), self.x1)

    def test_as_text(self):
        self.assertEqual(SubjectKeyIdentifier({'value': self.hex1}).as_text(), self.hex1)
        self.assertEqual(SubjectKeyIdentifier({'value': self.hex2}).as_text(), self.hex2)
        self.assertEqual(SubjectKeyIdentifier(self.x1).as_text(), self.hex1)

    def test_hash(self):
        ext1 = SubjectKeyIdentifier({'value': self.hex1})
        ext2 = SubjectKeyIdentifier({'value': self.hex2})
        ext3 = SubjectKeyIdentifier(self.x1)

        self.assertEqual(hash(ext1), hash(ext1))
        self.assertEqual(hash(ext1), hash(ext3))
        self.assertEqual(hash(ext2), hash(ext2))
        self.assertNotEqual(hash(ext1), hash(ext2))

    def test_ne(self):
        ext1 = SubjectKeyIdentifier({'value': self.hex1})
        ext2 = SubjectKeyIdentifier({'value': self.hex2})
        ext3 = SubjectKeyIdentifier(self.x1)

        self.assertNotEqual(ext1, ext2)
        self.assertNotEqual(ext2, ext3)

    def test_repr(self):
        ext1 = SubjectKeyIdentifier({'value': self.hex1})
        ext2 = SubjectKeyIdentifier({'value': self.hex2})
        ext3 = SubjectKeyIdentifier(self.x1)

        if six.PY2:  # pragma: only py2
            self.assertEqual(repr(ext1), '<SubjectKeyIdentifier: 333333, critical=False>')
            self.assertEqual(repr(ext2), '<SubjectKeyIdentifier: DDDDDD, critical=False>')
            self.assertEqual(repr(ext3), '<SubjectKeyIdentifier: 333333, critical=False>')
        else:
            self.assertEqual(repr(ext1), '<SubjectKeyIdentifier: b\'333333\', critical=False>')
            self.assertEqual(repr(ext2), '<SubjectKeyIdentifier: b\'DDDDDD\', critical=False>')
            self.assertEqual(repr(ext3), '<SubjectKeyIdentifier: b\'333333\', critical=False>')

    def test_serialize(self):
        ext1 = SubjectKeyIdentifier({'value': self.hex1})
        ext2 = SubjectKeyIdentifier({'value': self.hex2})
        ext3 = SubjectKeyIdentifier(self.x1)

        self.assertEqual(ext1.serialize(), {'critical': False, 'value': self.hex1})
        self.assertEqual(ext2.serialize(), {'critical': False, 'value': self.hex2})
        self.assertEqual(ext3.serialize(), {'critical': False, 'value': self.hex1})
        self.assertEqual(ext1.serialize(), SubjectKeyIdentifier({'value': self.hex1}).serialize())
        self.assertNotEqual(ext1.serialize(), ext2.serialize())

    def test_str(self):
        ext = SubjectKeyIdentifier({'value': self.hex1})
        self.assertEqual(str(ext), self.hex1)


class TLSFeatureTestCase(OrderedSetExtensionTestMixin, NewExtensionTestMixin, TestCase):
    ext_class = TLSFeature
    test_values = {
        'one': {
            'values': [
                {TLSFeatureType.status_request, },
                {'OCSPMustStaple', },
            ],
            'extension_type': x509.TLSFeature(features=[TLSFeatureType.status_request]),
            'expected': frozenset([TLSFeatureType.status_request]),
            'expected_repr': "<TLSFeature: ['OCSPMustStaple'], critical=%s>",
            'expected_serialized': ['OCSPMustStaple'],
            'expected_str': 'OCSPMustStaple',
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
            'expected_repr': "<TLSFeature: ['MultipleCertStatusRequest', 'OCSPMustStaple'], critical=%s>",
            'expected_serialized': ['MultipleCertStatusRequest', 'OCSPMustStaple'],
            'expected_str': 'MultipleCertStatusRequest,OCSPMustStaple',
            'expected_text': '* MultipleCertStatusRequest\n* OCSPMustStaple',
        },
        'three': {
            'values': [
                {TLSFeatureType.status_request_v2},
                {'MultipleCertStatusRequest'},
            ],
            'extension_type': x509.TLSFeature(features=[TLSFeatureType.status_request_v2]),
            'expected': frozenset([TLSFeatureType.status_request_v2]),
            'expected_repr': "<TLSFeature: ['MultipleCertStatusRequest'], critical=%s>",
            'expected_serialized': ['MultipleCertStatusRequest'],
            'expected_str': 'MultipleCertStatusRequest',
            'expected_text': '* MultipleCertStatusRequest',
        },
    }

    def test_unknown_values(self):
        with self.assertRaisesRegex(ValueError, r'^Unknown value: foo$'):
            TLSFeature({'value': ['foo']})

        with self.assertRaisesRegex(ValueError, r'^Unknown value: True$'):
            TLSFeature({'value': [True]})

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

"""Test specialized member classes in :py:mod:`django_ca.extensions`."""

from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.oid import ObjectIdentifier

from django.test import TestCase

from ..extensions import DistributionPoint
from ..extensions import PolicyInformation
from .base import DjangoCATestCase
from .base import certs
from .base import uri


class DistributionPointTestCase(TestCase):
    """Test DistributionPoint class."""

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
        """Test str()."""
        dp = DistributionPoint({'full_name': 'http://example.com'})
        self.assertEqual(str(dp), "<DistributionPoint: full_name=['URI:http://example.com']>")


class PolicyInformationTestCase(DjangoCATestCase):
    """Test PolicyInformation class."""

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
        super().setUp()

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
        """Test as_text()."""
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
        """Test ext.count()."""
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
        """Test ext.extend()."""
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
        """Test item getter (e.g. ``x = ext[0]``)."""
        self.assertEqual(self.pi1[0], self.s1['policy_qualifiers'][0])
        self.assertEqual(self.pi4[0], self.s4['policy_qualifiers'][0])
        self.assertEqual(self.pi4[1], self.s4['policy_qualifiers'][1])
        self.assertEqual(self.pi4[1:], [self.s4['policy_qualifiers'][1]])

        with self.assertRaisesRegex(IndexError, r'^list index out of range$'):
            self.pi_empty[0]
        with self.assertRaisesRegex(IndexError, r'^list index out of range$'):
            self.pi_empty[2:]

    def test_hash(self):
        """Test hash()."""
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
        """Test ext.insert()."""
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
        """Test len(ext)."""
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
        """Test ext.pop()."""
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
        """Test ext.remove()."""
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
        self.assertEqual(func(self.pi1), "<PolicyInformation(oid=2.5.29.32.0, qualifiers=['text1'])>")
        self.assertEqual(func(self.pi2),
                         "<PolicyInformation(oid=2.5.29.32.0, qualifiers=[{'explicit_text': 'text2'}])>")
        self.assertEqual(func(self.pi_empty), "<PolicyInformation(oid=None, qualifiers=None)>")

        # NOTE: order of dict is different here, so we do not test output, just make sure there's no exception
        func(self.pi3)
        func(self.pi4)

    def test_repr(self):
        """Test repr()."""
        self._test_repr(repr)

    def test_str(self):
        """Test str()."""
        self._test_repr(str)

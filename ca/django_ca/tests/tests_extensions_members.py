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

"""Tests for extension utility clases in :py:mod:`django_ca.extensions.utils`."""

import typing

from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier

from django.test import TestCase

from django_ca.extensions.utils import DistributionPoint, PolicyInformation
from django_ca.tests.base import uri
from django_ca.tests.base.mixins import TestCaseMixin
from django_ca.typehints import ParsablePolicyInformation


class DistributionPointTestCase(TestCase):
    """Test DistributionPoint class."""

    def test_init_basic(self) -> None:
        """Test basic initialization."""
        dpoint = DistributionPoint()
        self.assertIsNone(dpoint.full_name)
        self.assertIsNone(dpoint.relative_name)
        self.assertIsNone(dpoint.crl_issuer)
        self.assertIsNone(dpoint.reasons)

        dpoint = DistributionPoint(
            {
                "full_name": ["http://example.com"],
                "crl_issuer": ["http://example.net"],
            }
        )
        self.assertEqual(dpoint.full_name, [uri("http://example.com")])
        self.assertIsNone(dpoint.relative_name)
        self.assertEqual(dpoint.crl_issuer, [uri("http://example.net")])
        self.assertIsNone(dpoint.reasons)

        dpoint = DistributionPoint(
            {
                "full_name": ["http://example.com"],
                "crl_issuer": ["http://example.net"],
            }
        )
        self.assertEqual(dpoint.full_name, [uri("http://example.com")])
        self.assertIsNone(dpoint.relative_name)
        self.assertEqual(dpoint.crl_issuer, [uri("http://example.net")])
        self.assertIsNone(dpoint.reasons)

    def test_init_errors(self) -> None:
        """Test various invalid input values."""
        with self.assertRaisesRegex(ValueError, r"^data must be x509.DistributionPoint or dict$"):
            DistributionPoint("foobar")  # type: ignore[arg-type]

        with self.assertRaisesRegex(ValueError, r"^full_name and relative_name cannot both have a value$"):
            DistributionPoint(
                {
                    "full_name": ["http://example.com"],
                    "relative_name": "/CN=example.com",
                }
            )

    def test_str(self) -> None:
        """Test str()."""
        dpoint = DistributionPoint({"full_name": ["http://example.com"]})
        self.assertEqual(str(dpoint), "<DistributionPoint: full_name=['URI:http://example.com']>")

    def test_reasons(self) -> None:
        """Test DPs with different reason types."""

        dpoint = DistributionPoint(
            {
                "full_name": ["http://example.com"],
                "crl_issuer": ["http://example.net"],
                "reasons": ["unspecified"],
            }
        )
        self.assertEqual(
            dpoint.reasons,
            {
                x509.ReasonFlags.unspecified,
            },
        )

        dpoint = DistributionPoint(
            {
                "full_name": ["http://example.com"],
                "crl_issuer": ["http://example.net"],
                "reasons": [x509.ReasonFlags.unspecified],
            }
        )
        self.assertEqual(
            dpoint.reasons,
            {
                x509.ReasonFlags.unspecified,
            },
        )


class PolicyInformationTestCase(TestCaseMixin, TestCase):
    """Test PolicyInformation class."""

    oid = "2.5.29.32.0"

    # various qualifiers
    q1 = "text1"
    q2 = x509.UserNotice(explicit_text="text2", notice_reference=None)
    q3 = x509.UserNotice(
        explicit_text=None, notice_reference=x509.NoticeReference(organization="text3", notice_numbers=[1])
    )
    q4 = "text4"
    q5 = x509.UserNotice(
        explicit_text="text5",
        notice_reference=x509.NoticeReference(organization="text6", notice_numbers=[1, 2, 3]),
    )

    x1 = x509.PolicyInformation(policy_identifier=ObjectIdentifier(oid), policy_qualifiers=[q1])
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
    s1: ParsablePolicyInformation = {
        "policy_identifier": oid,
        "policy_qualifiers": ["text1"],
    }
    s2: ParsablePolicyInformation = {
        "policy_identifier": oid,
        "policy_qualifiers": [
            {
                "explicit_text": "text2",
            }
        ],
    }
    s3: ParsablePolicyInformation = {
        "policy_identifier": oid,
        "policy_qualifiers": [
            {
                "notice_reference": {
                    "organization": "text3",
                    "notice_numbers": [
                        1,
                    ],
                }
            }
        ],
    }
    s4: ParsablePolicyInformation = {
        "policy_identifier": oid,
        "policy_qualifiers": [
            "text4",
            {
                "explicit_text": "text5",
                "notice_reference": {
                    "organization": "text6",
                    "notice_numbers": [1, 2, 3],
                },
            },
        ],
    }
    s5: ParsablePolicyInformation = {
        "policy_identifier": oid,
        "policy_qualifiers": [
            {
                "explicit_text": "text5",
                "notice_reference": {
                    "notice_numbers": [1, 2, 3],
                },
            }
        ],
    }

    def setUp(self) -> None:
        super().setUp()

        self.pi1 = PolicyInformation(self.s1)
        self.pi2 = PolicyInformation(self.s2)
        self.pi3 = PolicyInformation(self.s3)
        self.pi4 = PolicyInformation(self.s4)
        self.pi5 = PolicyInformation(self.s5)
        self.pi_empty = PolicyInformation()

    def test_append(self) -> None:
        """Test PolicyInformation.append()."""
        self.pi1.append(self.q2)
        self.pi1.append(self.s3["policy_qualifiers"][0])  # type: ignore[index]
        self.assertEqual(
            self.pi1,
            PolicyInformation(
                {
                    "policy_identifier": self.oid,
                    "policy_qualifiers": [self.q1, self.q2, self.q3],
                }
            ),
        )

        self.pi_empty.policy_identifier = self.oid
        self.pi_empty.append(self.q3)
        self.assertEqual(self.pi3, self.pi_empty)

    def test_certs(self) -> None:
        """Test for all known certs."""
        self.load_named_cas("__all__")
        self.load_named_certs("__all__")
        for cert in list(self.cas.values()) + list(self.certs.values()):
            try:
                val = cert.pub.loaded.extensions.get_extension_for_class(x509.CertificatePolicies).value
            except x509.ExtensionNotFound:
                continue

            for policy in val:
                pi1 = PolicyInformation(policy)
                self.assertEqual(pi1.for_extension_type, policy)

                # pass the serialized value to the constructor and see if it's still the same
                pi2 = PolicyInformation(typing.cast(ParsablePolicyInformation, pi1.serialize()))
                self.assertEqual(pi1, pi2)
                self.assertEqual(pi1.serialize(), pi2.serialize())
                self.assertEqual(pi2.for_extension_type, policy)

    def test_clear(self) -> None:
        """Test PolicyInformation.clear()."""
        self.pi1.clear()
        self.assertIsNone(self.pi1.policy_qualifiers)

    def test_constructor(self) -> None:
        """Test some constructors that are otherwise not called."""
        pinfo = PolicyInformation()
        self.assertIsNone(pinfo.policy_identifier)
        self.assertIsNone(pinfo.policy_qualifiers)

        pinfo = PolicyInformation(
            {
                "policy_identifier": "1.2.3",
                "policy_qualifiers": [
                    x509.UserNotice(notice_reference=None, explicit_text="foobar"),
                ],
            }
        )
        self.assertEqual(len(pinfo), 1)

        pinfo = PolicyInformation(
            {
                "policy_identifier": "1.2.3",
                "policy_qualifiers": [
                    {
                        "notice_reference": x509.NoticeReference(organization="foobar", notice_numbers=[1]),
                    }
                ],
            }
        )
        self.assertEqual(len(pinfo), 1)

    def test_constructor_errors(self) -> None:
        """Test various invalid values for the constructor."""
        # type ignores are because we're testing exactly that here
        with self.assertRaisesRegex(
            ValueError, r"^PolicyInformation data must be either x509.PolicyInformation or dict$"
        ):
            PolicyInformation(True)  # type: ignore[arg-type]

        with self.assertRaisesRegex(ValueError, r"^PolicyQualifier must be string, dict or x509.UserNotice$"):
            PolicyInformation(
                {"policy_identifier": "1.2.3", "policy_qualifiers": [True]}  # type: ignore[list-item]
            )

        with self.assertRaisesRegex(
            ValueError, r"^NoticeReference must be either None, a dict or an x509.NoticeReference$"
        ):
            PolicyInformation(
                {
                    "policy_identifier": "1.2.3",
                    "policy_qualifiers": [
                        {
                            "notice_reference": True,  # type: ignore[typeddict-item]
                        }
                    ],
                }
            )

    def test_contains(self) -> None:
        """Test PolicyInformation.contains()."""
        self.assertIn(self.q1, self.pi1)
        self.assertIn(self.q2, self.pi2)
        self.assertIn(self.q3, self.pi3)
        self.assertIn(self.q4, self.pi4)
        self.assertIn(self.q5, self.pi4)
        self.assertIn(self.s1["policy_qualifiers"][0], self.pi1)  # type: ignore[index]
        self.assertIn(self.s2["policy_qualifiers"][0], self.pi2)  # type: ignore[index]
        self.assertIn(self.s3["policy_qualifiers"][0], self.pi3)  # type: ignore[index]
        self.assertIn(self.s4["policy_qualifiers"][0], self.pi4)  # type: ignore[index]
        self.assertIn(self.s4["policy_qualifiers"][1], self.pi4)  # type: ignore[index]

        self.assertNotIn(self.q2, self.pi1)
        self.assertNotIn(self.q1, self.pi_empty)
        self.assertNotIn(self.s1["policy_qualifiers"][0], self.pi2)  # type: ignore[index]
        self.assertNotIn(self.s2["policy_qualifiers"][0], self.pi1)  # type: ignore[index]
        self.assertNotIn(self.s2["policy_qualifiers"][0], self.pi_empty)  # type: ignore[index]

        # Invalid values are always false:
        self.assertNotIn(True, self.pi1)

    def test_count(self) -> None:
        """Test PolicyInformation.count()."""
        self.assertEqual(self.pi1.count(self.s1["policy_qualifiers"][0]), 1)  # type: ignore[index]
        self.assertEqual(self.pi1.count(self.q1), 1)
        self.assertEqual(self.pi1.count(self.s2), 0)  # type: ignore[arg-type] # full pi is wrong
        self.assertEqual(self.pi1.count(self.q2), 0)
        self.assertEqual(self.pi_empty.count(self.q2), 0)
        self.assertEqual(self.pi1.count(True), 0)  # type: ignore[arg-type] # what we're testing here!

    def test_delitem(self) -> None:
        """Test item deletion (e.g. ``del pi[0]``)."""
        del self.pi1[0]
        self.pi_empty.policy_identifier = self.oid
        self.assertEqual(self.pi1, self.pi_empty)

        self.assertEqual(len(self.pi4), 2)
        del self.pi4[0]
        self.assertEqual(len(self.pi4), 1)

        with self.assertRaisesRegex(IndexError, r"^list assignment index out of range$"):
            del self.pi1[0]

    def test_extend(self) -> None:
        """Test PolicyInformation.extend()."""
        self.pi1.extend([self.q2, self.q4])
        self.assertEqual(
            self.pi1,
            PolicyInformation(
                {
                    "policy_identifier": self.oid,
                    "policy_qualifiers": [self.q1, self.q2, self.q4],
                }
            ),
        )

        self.pi2.extend([self.s1["policy_qualifiers"][0]])  # type: ignore[index]
        self.assertEqual(
            self.pi2,
            PolicyInformation(
                {
                    "policy_identifier": self.oid,
                    "policy_qualifiers": [self.q2, self.q1],
                }
            ),
        )

        # extend an empty list
        self.pi_empty.extend([self.s1["policy_qualifiers"][0]])  # type: ignore[index]
        self.assertEqual(
            self.pi_empty,
            PolicyInformation(
                {
                    "policy_identifier": None,  # type: ignore[typeddict-item]
                    "policy_qualifiers": [self.q1],
                }
            ),
        )

    def test_getitem(self) -> None:
        """Test item getter (e.g. ``x = ext[0]``)."""
        self.assertEqual(self.pi1[0], self.s1["policy_qualifiers"][0])  # type: ignore[index]
        self.assertEqual(self.pi4[0], self.s4["policy_qualifiers"][0])  # type: ignore[index]
        self.assertEqual(self.pi4[1], self.s4["policy_qualifiers"][1])  # type: ignore[index]
        self.assertEqual(self.pi4[1:], [self.s4["policy_qualifiers"][1]])  # type: ignore[index]

        with self.assertRaisesRegex(IndexError, r"^list index out of range$"):
            self.pi_empty[0]  # pylint: disable=pointless-statement
        with self.assertRaisesRegex(IndexError, r"^list index out of range$"):
            self.pi_empty[2:]  # pylint: disable=pointless-statement

    def test_hash(self) -> None:
        """Test hash()."""
        self.assertEqual(hash(self.pi1), hash(self.pi1))
        self.assertEqual(hash(self.pi2), hash(self.pi2))
        self.assertEqual(hash(self.pi3), hash(self.pi3))
        self.assertEqual(hash(self.pi4), hash(self.pi4))
        self.assertEqual(hash(self.pi5), hash(self.pi5))
        self.assertEqual(hash(self.pi_empty), hash(self.pi_empty))

        self.assertEqual(hash(self.pi1), hash(PolicyInformation(self.s1)))
        self.assertEqual(hash(self.pi2), hash(PolicyInformation(self.s2)))
        self.assertEqual(hash(self.pi3), hash(PolicyInformation(self.s3)))
        self.assertEqual(hash(self.pi4), hash(PolicyInformation(self.s4)))
        self.assertEqual(hash(self.pi5), hash(PolicyInformation(self.s5)))
        self.assertEqual(hash(self.pi_empty), hash(PolicyInformation()))

        self.assertNotEqual(hash(self.pi1), hash(self.pi2))
        self.assertNotEqual(hash(self.pi1), hash(self.pi3))
        self.assertNotEqual(hash(self.pi1), hash(self.pi4))
        self.assertNotEqual(hash(self.pi2), hash(self.pi3))
        self.assertNotEqual(hash(self.pi2), hash(self.pi4))
        self.assertNotEqual(hash(self.pi3), hash(self.pi4))

    def test_insert(self) -> None:
        """Test PolicyInformation.insert()."""
        self.pi1.insert(0, self.q2)
        self.assertEqual(
            self.pi1,
            PolicyInformation(
                {
                    "policy_identifier": self.oid,
                    "policy_qualifiers": [self.q2, self.q1],
                }
            ),
        )
        self.pi1.insert(1, self.s3["policy_qualifiers"][0])  # type: ignore[index]
        self.assertEqual(
            self.pi1,
            PolicyInformation(
                {
                    "policy_identifier": self.oid,
                    "policy_qualifiers": [self.q2, self.q3, self.q1],
                }
            ),
        )

        self.pi_empty.insert(1, self.q2)
        self.pi_empty.policy_identifier = self.oid
        self.assertEqual(self.pi2, self.pi_empty)

    def test_iter(self) -> None:
        """Test iter(pi)."""
        self.assertEqual(list(self.pi1), [self.q1])
        self.assertEqual(list(self.pi2), [self.q2])
        self.assertEqual(list(self.pi4), [self.q4, self.q5])
        self.assertEqual(list(self.pi_empty), [])

    def test_len(self) -> None:
        """Test len(ext)."""
        self.assertEqual(len(self.pi1), 1)
        self.assertEqual(len(self.pi2), 1)
        self.assertEqual(len(self.pi3), 1)
        self.assertEqual(len(self.pi4), 2)
        self.assertEqual(len(self.pi5), 1)
        self.assertEqual(len(self.pi_empty), 0)

    def test_policy_identifier_setter(self) -> None:
        """Test setting a policy identifier."""
        value = "1.2.3"
        expected = ObjectIdentifier(value)
        pinfo = PolicyInformation({"policy_identifier": value, "policy_qualifiers": []})
        pinfo.policy_identifier = value
        self.assertEqual(pinfo.policy_identifier, expected)

        pinfo = PolicyInformation({"policy_identifier": expected})
        self.assertEqual(pinfo.policy_identifier, expected)

        new_value = "2.3.4"
        new_expected = ObjectIdentifier(new_value)
        pinfo.policy_identifier = new_value
        self.assertEqual(pinfo.policy_identifier, new_expected)

    def test_pop(self) -> None:
        """Test PolicyInformation.pop()."""
        self.pi_empty.policy_identifier = self.oid
        self.assertEqual(self.pi1.pop(), self.s1["policy_qualifiers"][0])  # type: ignore[index]
        self.assertEqual(self.pi1, self.pi_empty)

        self.assertEqual(self.pi4.pop(1), self.s4["policy_qualifiers"][1])  # type: ignore[index]
        self.assertEqual(
            self.pi4,
            PolicyInformation(
                {
                    "policy_identifier": self.oid,
                    "policy_qualifiers": [self.q4],
                }
            ),
        )

        self.assertEqual(self.pi4.pop(), self.s4["policy_qualifiers"][0])  # type: ignore[index]
        self.assertEqual(self.pi4, self.pi_empty)

        with self.assertRaisesRegex(IndexError, r"^pop from empty list$"):
            self.pi_empty.pop()

    def test_remove(self) -> None:
        """Test PolicyInformation.remove()."""
        self.pi_empty.policy_identifier = self.oid
        self.pi1.remove(self.q1)
        self.assertEqual(self.pi1, self.pi_empty)

        self.pi2.remove(self.s2["policy_qualifiers"][0])  # type: ignore[index]
        self.assertEqual(self.pi1, self.pi_empty)

        self.pi4.remove(self.q4)
        self.assertEqual(
            self.pi4,
            PolicyInformation(
                {
                    "policy_identifier": self.oid,
                    "policy_qualifiers": [self.q5],
                }
            ),
        )

        with self.assertRaisesRegex(ValueError, r"^.*: not in list\.$"):
            self.pi_empty.remove(self.s3["policy_qualifiers"][0])  # type: ignore[index]

    def _test_repr(self, func: typing.Callable[[typing.Any], str]) -> None:
        self.assertEqual(func(self.pi1), "<PolicyInformation(oid=2.5.29.32.0, qualifiers=['text1'])>")
        self.assertEqual(
            func(self.pi2), "<PolicyInformation(oid=2.5.29.32.0, qualifiers=[{'explicit_text': 'text2'}])>"
        )
        self.assertEqual(func(self.pi_empty), "<PolicyInformation(oid=None, qualifiers=None)>")

        # NOTE: order of dict is different here, so we do not test output, just make sure there's no exception
        func(self.pi3)
        func(self.pi4)

    def test_repr(self) -> None:
        """Test repr()."""
        self._test_repr(repr)

    def test_serialize(self) -> None:
        """Test serialization."""
        self.assertEqual(
            self.pi1.serialize(), {"policy_identifier": "2.5.29.32.0", "policy_qualifiers": ["text1"]}
        )
        self.assertEqual(
            self.pi2.serialize(),
            {"policy_identifier": "2.5.29.32.0", "policy_qualifiers": [{"explicit_text": "text2"}]},
        )
        self.assertEqual(
            self.pi3.serialize(),
            {
                "policy_identifier": "2.5.29.32.0",
                "policy_qualifiers": [{"notice_reference": {"notice_numbers": [1], "organization": "text3"}}],
            },
        )
        self.assertEqual(
            self.pi4.serialize(),
            {
                "policy_identifier": "2.5.29.32.0",
                "policy_qualifiers": [
                    "text4",
                    {
                        "explicit_text": "text5",
                        "notice_reference": {"notice_numbers": [1, 2, 3], "organization": "text6"},
                    },
                ],
            },
        )
        self.assertEqual(
            self.pi5.serialize(),
            {
                "policy_identifier": "2.5.29.32.0",
                "policy_qualifiers": [
                    {"explicit_text": "text5", "notice_reference": {"notice_numbers": [1, 2, 3]}}
                ],
            },
        )

    def test_setitem(self) -> None:
        """Test __setitem__()."""
        # pylint: disable=invalid-name; let's just use pi here
        pi = PolicyInformation(self.s1)
        self.assertEqual(pi, self.pi1)
        pi[0] = self.q2
        self.assertEqual(pi, self.pi2)

        pi = PolicyInformation(self.s1)
        pi[0:1] = [self.q2]
        self.assertEqual(pi, self.pi2)

        # list()[0:1] = "x" also works
        pi = PolicyInformation({"policy_identifier": "2.5.29.32.0"})
        pi[0:1] = [self.q2]
        self.assertEqual(pi, self.pi2)

        pi = PolicyInformation()
        with self.assertRaisesRegex(ValueError, r"^Index out of range$"):
            pi[0] = self.q1
        self.assertEqual(len(pi), 0)

        pi = PolicyInformation(self.s1)
        with self.assertRaisesRegex(ValueError, r"^PolicyQualifier must be string, dict or x509.UserNotice$"):
            pi[0] = True  # type: ignore[assignment]
        self.assertEqual(pi, self.pi1)

        pi = PolicyInformation(self.s1)
        with self.assertRaisesRegex(TypeError, rf"^bar/{self.q1}: Invalid key/value type$"):
            pi["bar"] = self.q1  # type: ignore[index]
        self.assertEqual(pi, self.pi1)

    def test_str(self) -> None:
        """Test str()."""
        self._test_repr(str)

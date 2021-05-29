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
import os
import sys
import typing
from unittest import TestLoader
from unittest import TestSuite

from cryptography import x509
from cryptography.x509 import TLSFeatureType
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.oid import ExtensionOID
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
from ..extensions.utils import PolicyInformation
from ..models import X509CertMixin
from ..typehints import ParsablePolicyInformation
from ..utils import GeneralNameList
from .base import certs
from .base import dns
from .base import uri
from .base.extensions import CRLDistributionPointsTestCaseBase
from .base.extensions import ExtensionTestMixin
from .base.extensions import ListExtensionTestMixin
from .base.extensions import NullExtensionTestMixin
from .base.extensions import OrderedSetExtensionTestMixin
from .base.extensions import TestValues
from .base.mixins import TestCaseMixin


def load_tests(  # pylint: disable=unused-argument
    loader: TestLoader, tests: TestSuite, ignore: typing.Optional[str] = None
) -> TestSuite:
    """Load doctests."""

    if sys.version_info >= (3, 7):
        # Older python versions return a different str for classes
        docs_path = os.path.join(settings.DOC_DIR, "python", "extensions.rst")
        tests.addTests(
            doctest.DocFileSuite(
                docs_path,
                module_relative=False,
                globs={
                    "KEY_TO_EXTENSION": KEY_TO_EXTENSION,
                    "OID_TO_EXTENSION": OID_TO_EXTENSION,
                },
            )
        )

    tests.addTests(
        doctest.DocTestSuite(
            "django_ca.extensions",
            extraglobs={
                "ExtensionOID": ExtensionOID,
            },
        )
    )
    tests.addTests(
        doctest.DocTestSuite(
            "django_ca.extensions.base",
            extraglobs={
                "ExtendedKeyUsage": ExtendedKeyUsage,
                "ExtendedKeyUsageOID": ExtendedKeyUsageOID,
                "ExtensionOID": ExtensionOID,
                "KeyUsage": KeyUsage,
                "OCSPNoCheck": OCSPNoCheck,
                "SubjectAlternativeName": SubjectAlternativeName,
                "SubjectKeyIdentifier": SubjectKeyIdentifier,
            },
        )
    )
    tests.addTests(doctest.DocTestSuite("django_ca.extensions.utils"))
    return tests


class AuthorityInformationAccessTestCase(ExtensionTestMixin[AuthorityInformationAccess], TestCase):
    """Test AuthorityInformationAccess extension."""

    ext_class = AuthorityInformationAccess
    ext_class_key = "authority_information_access"
    ext_class_name = "AuthorityInformationAccess"

    uri1 = "https://example1.com"
    uri2 = "https://example2.net"
    uri3 = "https://example3.org"
    uri4 = "https://example4.at"

    test_values = {
        "empty": {
            "values": [{}],
            "expected": {"issuers": [], "ocsp": []},
            "expected_bool": False,
            "expected_repr": "issuers=[], ocsp=[]",
            "expected_serialized": {},
            "expected_text": "",
            "extension_type": x509.AuthorityInformationAccess(descriptions=[]),
        },
        "issuer": {
            "values": [
                {"issuers": [uri1]},
                {"issuers": [uri(uri1)]},
            ],
            "expected": {"issuers": [uri(uri1)], "ocsp": []},
            "expected_repr": "issuers=['URI:%s'], ocsp=[]" % uri1,
            "expected_serialized": {"issuers": ["URI:%s" % uri1]},
            "expected_text": "CA Issuers:\n  * URI:%s" % uri1,
            "extension_type": x509.AuthorityInformationAccess(
                descriptions=[x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, uri(uri1))]
            ),
        },
        "ocsp": {
            "values": [
                {"ocsp": [uri2]},
                {"ocsp": [uri(uri2)]},
            ],
            "expected": {"ocsp": [uri(uri2)], "issuers": []},
            "expected_repr": "issuers=[], ocsp=['URI:%s']" % uri2,
            "expected_serialized": {"ocsp": ["URI:%s" % uri2]},
            "expected_text": "OCSP:\n  * URI:%s" % uri2,
            "extension_type": x509.AuthorityInformationAccess(
                descriptions=[x509.AccessDescription(AuthorityInformationAccessOID.OCSP, uri(uri2))]
            ),
        },
        "both": {
            "values": [
                {"ocsp": [uri1], "issuers": [uri2]},
                {"ocsp": [uri(uri1)], "issuers": [uri(uri2)]},
            ],
            "expected": {"ocsp": [uri(uri1)], "issuers": [uri(uri2)]},
            "expected_repr": "issuers=['URI:%s'], ocsp=['URI:%s']" % (uri2, uri1),
            "expected_serialized": {"ocsp": ["URI:%s" % uri1], "issuers": ["URI:%s" % uri2]},
            "expected_text": "CA Issuers:\n  * URI:%s\nOCSP:\n  * URI:%s" % (uri2, uri1),
            "extension_type": x509.AuthorityInformationAccess(
                descriptions=[
                    x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, uri(uri2)),
                    x509.AccessDescription(AuthorityInformationAccessOID.OCSP, uri(uri1)),
                ]
            ),
        },
        "multiple": {
            "values": [
                {"ocsp": [uri1, uri2], "issuers": [uri3, uri4]},
                {"ocsp": [uri1, uri(uri2)], "issuers": [uri3, uri(uri4)]},
                {"ocsp": [uri(uri1), uri(uri2)], "issuers": [uri(uri3), uri(uri4)]},
            ],
            "expected": {"ocsp": [uri(uri1), uri(uri2)], "issuers": [uri(uri3), uri(uri4)]},
            "expected_repr": "issuers=['URI:%s', 'URI:%s'], ocsp=['URI:%s', 'URI:%s']"
            % (uri3, uri4, uri1, uri2),
            "expected_serialized": {
                "ocsp": ["URI:%s" % uri1, "URI:%s" % uri2],
                "issuers": ["URI:%s" % uri3, "URI:%s" % uri4],
            },
            "expected_text": "CA Issuers:\n  * URI:%s\n  * URI:%s\n"
            "OCSP:\n  * URI:%s\n  * URI:%s" % (uri3, uri4, uri1, uri2),
            "extension_type": x509.AuthorityInformationAccess(
                descriptions=[
                    x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, uri(uri3)),
                    x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, uri(uri4)),
                    x509.AccessDescription(AuthorityInformationAccessOID.OCSP, uri(uri1)),
                    x509.AccessDescription(AuthorityInformationAccessOID.OCSP, uri(uri2)),
                ]
            ),
        },
    }

    def test_bool(self) -> None:
        """Test bool(ext)."""
        for config in self.test_values.values():
            ext = self.ext(config["expected"])
            self.assertEqual(bool(ext), config.get("expected_bool", True))

    def test_value(self) -> None:
        """Overwritten because extension has no value."""
        return

    def test_none_value(self) -> None:
        """Test that we can use and pass None as values for GeneralNamesList values."""
        ext = self.ext_class({"value": {"issuers": None, "ocsp": None}})
        self.assertEqual(ext.issuers, [])
        self.assertEqual(ext.ocsp, [])
        self.assertEqual(ext.extension_type, x509.AuthorityInformationAccess(descriptions=[]))

    def test_properties(self) -> None:
        """Test issuers and ocsp properties"""
        expected_issuers = GeneralNameList([self.uri1])
        expected_ocsp = GeneralNameList([self.uri2])
        expected = AuthorityInformationAccess({"value": {"issuers": [self.uri1], "ocsp": [self.uri2]}})

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


class AuthorityKeyIdentifierTestCase(ExtensionTestMixin[AuthorityKeyIdentifier], TestCase):
    """Test AuthorityKeyIdentifier extension."""

    ext_class = AuthorityKeyIdentifier
    ext_class_key = "authority_key_identifier"
    ext_class_name = "AuthorityKeyIdentifier"

    b1 = b"333333"
    b2 = b"DDDDDD"
    b3 = b"UUUUUU"
    hex1 = "33:33:33:33:33:33"
    hex2 = "44:44:44:44:44:44"
    hex3 = "55:55:55:55:55:55"
    uri1 = "http://ca.example.com/crl"
    dns1 = "example.org"
    s1 = 0
    s2 = 1

    test_values = {
        "one": {
            "values": [
                hex1,
            ],
            "expected": b1,
            "expected_repr": "keyid: %s" % hex1,
            "expected_serialized": {"key_identifier": hex1},
            "expected_text": "* KeyID: %s" % hex1,
            "extension_type": x509.AuthorityKeyIdentifier(b1, None, None),
        },
        "two": {
            "values": [
                hex2,
            ],
            "expected": b2,
            "expected_repr": "keyid: %s" % hex2,
            "expected_serialized": {"key_identifier": hex2},
            "expected_text": "* KeyID: %s" % hex2,
            "extension_type": x509.AuthorityKeyIdentifier(b2, None, None),
        },
        "three": {
            "values": [
                hex3,
            ],
            "expected": b3,
            "expected_repr": "keyid: %s" % hex3,
            "expected_serialized": {"key_identifier": hex3},
            "expected_text": "* KeyID: %s" % hex3,
            "extension_type": x509.AuthorityKeyIdentifier(b3, None, None),
        },
        "issuer/serial": {
            "expected": {"authority_cert_issuer": [dns1], "authority_cert_serial_number": s1},
            "values": [{"authority_cert_issuer": [dns1], "authority_cert_serial_number": s1}],
            "expected_repr": "issuer: ['DNS:%s'], serial: %s" % (dns1, s1),
            "expected_serialized": {
                "authority_cert_issuer": ["DNS:%s" % dns1],
                "authority_cert_serial_number": s1,
            },
            "expected_text": "* Issuer:\n  * DNS:%s\n* Serial: %s" % (dns1, s1),
            "extension_type": x509.AuthorityKeyIdentifier(None, [dns(dns1)], s1),
        },
    }

    def test_from_subject_key_identifier(self) -> None:
        """Test creating an extension from a subject key identifier."""
        for config in self.test_values.values():
            if not isinstance(config["expected"], bytes):
                continue

            ski = SubjectKeyIdentifier({"value": config["expected"]})
            ext = self.ext_class(ski)
            self.assertExtensionEqual(ext, self.ext_class({"value": config["expected"]}))

    def test_none_value(self) -> None:
        """Test that we can use and pass None as values for GeneralNamesList values."""
        ext = self.ext_class(
            {
                "value": {
                    "key_identifier": self.b1,
                    "authority_cert_issuer": None,
                    "authority_cert_serial_number": None,
                }
            }
        )
        self.assertEqual(
            ext.extension_type,
            x509.AuthorityKeyIdentifier(
                key_identifier=self.b1, authority_cert_issuer=None, authority_cert_serial_number=None
            ),
        )

    def test_value(self) -> None:
        """Overwritten because extension has no value."""
        return


class BasicConstraintsTestCase(ExtensionTestMixin[BasicConstraints], TestCase):
    """Test BasicConstraints extension."""

    ext_class = BasicConstraints
    ext_class_key = "basic_constraints"
    ext_class_name = "BasicConstraints"

    test_values = {
        "no_ca": {
            "values": [
                {"ca": False},
                {"ca": False, "pathlen": 3},  # ignored b/c ca=False
                {"ca": False, "pathlen": None},  # ignored b/c ca=False
            ],
            "expected": {"ca": False, "pathlen": None},
            "expected_text": "CA:FALSE",
            "expected_repr": "ca=False",
            "expected_serialized": {"ca": False},
            "extension_type": x509.BasicConstraints(ca=False, path_length=None),
        },
        "no_pathlen": {
            "values": [
                {"ca": True},
                {"ca": True, "pathlen": None},
            ],
            "expected": {"ca": True, "pathlen": None},
            "expected_text": "CA:TRUE",
            "expected_repr": "ca=True, pathlen=None",
            "expected_serialized": {"ca": True, "pathlen": None},
            "extension_type": x509.BasicConstraints(ca=True, path_length=None),
        },
        "pathlen_zero": {
            "values": [
                {"ca": True, "pathlen": 0},
            ],
            "expected": {"ca": True, "pathlen": 0},
            "expected_text": "CA:TRUE, pathlen:0",
            "expected_repr": "ca=True, pathlen=0",
            "expected_serialized": {"ca": True, "pathlen": 0},
            "extension_type": x509.BasicConstraints(ca=True, path_length=0),
        },
        "pathlen_three": {
            "values": [
                {"ca": True, "pathlen": 3},
            ],
            "expected": {"ca": True, "pathlen": 3},
            "expected_text": "CA:TRUE, pathlen:3",
            "expected_repr": "ca=True, pathlen=3",
            "expected_serialized": {"ca": True, "pathlen": 3},
            "extension_type": x509.BasicConstraints(ca=True, path_length=3),
        },
    }

    def test_invalid_pathlen(self) -> None:
        """Test passing an invalid pathlen."""
        with self.assertRaisesRegex(ValueError, r'^Could not parse pathlen: "foo"$'):
            BasicConstraints({"value": {"ca": True, "pathlen": "foo"}})

        with self.assertRaisesRegex(ValueError, r'^Could not parse pathlen: ""$'):
            BasicConstraints({"value": {"ca": True, "pathlen": ""}})

        with self.assertRaisesRegex(ValueError, r'^Could not parse pathlen: "foobar"$'):
            BasicConstraints({"value": {"ca": True, "pathlen": "foobar"}})

    def test_value(self) -> None:
        """Overwritten because extension has no value."""
        return


class CRLDistributionPointsTestCase(
    CRLDistributionPointsTestCaseBase[CRLDistributionPoints, x509.CRLDistributionPoints], TestCase
):
    """Test CRLDistributionPoints extension."""

    ext_class = CRLDistributionPoints
    ext_class_key = "crl_distribution_points"
    ext_class_name = "CRLDistributionPoints"
    ext_class_type = x509.CRLDistributionPoints

    cg_dps1 = x509.CRLDistributionPoints([CRLDistributionPointsTestCaseBase.cg_dp1])
    cg_dps2 = x509.CRLDistributionPoints([CRLDistributionPointsTestCaseBase.cg_dp2])
    cg_dps3 = x509.CRLDistributionPoints([CRLDistributionPointsTestCaseBase.cg_dp3])
    cg_dps4 = x509.CRLDistributionPoints([CRLDistributionPointsTestCaseBase.cg_dp4])


class CertificatePoliciesTestCase(
    ListExtensionTestMixin[CertificatePolicies], ExtensionTestMixin[CertificatePolicies], TestCase
):
    """Test CertificatePolicies extension."""

    ext_class = CertificatePolicies
    ext_class_name = "CertificatePolicies"
    ext_class_key = "certificate_policies"

    oid = "2.5.29.32.0"

    text1, text2, text3, text4, text5, text6 = ["text%s" % i for i in range(1, 7)]

    un1: ParsablePolicyInformation = {
        "policy_identifier": oid,
        "policy_qualifiers": [text1],
    }
    un2: ParsablePolicyInformation = {
        "policy_identifier": oid,
        "policy_qualifiers": [
            {
                "explicit_text": text2,
            }
        ],
    }
    un3: ParsablePolicyInformation = {
        "policy_identifier": oid,
        "policy_qualifiers": [
            {
                "notice_reference": {
                    "organization": text3,
                    "notice_numbers": [
                        1,
                    ],
                }
            }
        ],
    }
    un4: ParsablePolicyInformation = {
        "policy_identifier": oid,
        "policy_qualifiers": [
            text4,
            {
                "explicit_text": text5,
                "notice_reference": {
                    "organization": text6,
                    "notice_numbers": [1, 2, 3],
                },
            },
        ],
    }
    p1 = PolicyInformation(un1)
    p2 = PolicyInformation(un2)
    p3 = PolicyInformation(un3)
    p4 = PolicyInformation(un4)

    xun1 = text1
    xun2 = x509.UserNotice(explicit_text=text2, notice_reference=None)
    xun3 = x509.UserNotice(
        explicit_text=None, notice_reference=x509.NoticeReference(organization=text3, notice_numbers=[1])
    )
    xun4_1 = text4
    xun4_2 = x509.UserNotice(
        explicit_text=text5,
        notice_reference=x509.NoticeReference(organization=text6, notice_numbers=[1, 2, 3]),
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
        "one": {
            "values": [[un1], [xpi1]],
            "expected": [p1],
            "expected_djca": [p1],
            "expected_repr": "1 policy",
            "expected_serialized": [un1],
            "expected_text": "* Policy Identifier: %s\n  Policy Qualifiers:\n  * %s" % (oid, text1),
            "extension_type": xcp1,
        },
        "two": {
            "values": [[un2], [xpi2]],
            "expected": [p2],
            "expected_djca": [p2],
            "expected_repr": "1 policy",
            "expected_serialized": [un2],
            "expected_text": "* Policy Identifier: %s\n  Policy Qualifiers:\n  * UserNotice:\n"
            "    * Explicit text: %s" % (oid, text2),
            "extension_type": xcp2,
        },
        "three": {
            "values": [[un3], [xpi3]],
            "expected": [p3],
            "expected_djca": [p3],
            "expected_repr": "1 policy",
            "expected_serialized": [un3],
            "expected_text": "* Policy Identifier: %s\n  Policy Qualifiers:\n  * UserNotice:\n"
            "    * Reference:\n      * Organiziation: %s\n"
            "      * Notice Numbers: [1]" % (oid, text3),
            "extension_type": xcp3,
        },
        "four": {
            "values": [[un4], [xpi4]],
            "expected": [p4],
            "expected_djca": [p4],
            "expected_repr": "1 policy",
            "expected_serialized": [un4],
            "expected_text": "* Policy Identifier: %s\n  Policy Qualifiers:\n  * %s\n  * UserNotice:\n"
            "    * Explicit text: %s\n    * Reference:\n      * Organiziation: %s\n"
            "      * Notice Numbers: [1, 2, 3]" % (oid, text4, text5, text6),
            "extension_type": xcp4,
        },
        "five": {
            "values": [[un1, un2, un4], [xpi1, xpi2, xpi4], [un1, xpi2, un4]],
            "expected": [p1, p2, p4],
            "expected_djca": [p1, p2, p4],
            "expected_repr": "3 policies",
            "expected_serialized": [un1, un2, un4],
            "expected_text": "* Policy Identifier: %s\n  Policy Qualifiers:\n  * %s\n"
            "* Policy Identifier: %s\n  Policy Qualifiers:\n  * UserNotice:\n"
            "    * Explicit text: %s\n"
            "* Policy Identifier: %s\n  Policy Qualifiers:\n  * %s\n  * UserNotice:\n"
            "    * Explicit text: %s\n    * Reference:\n      * Organiziation: %s\n"
            "      * Notice Numbers: [1, 2, 3]" % (oid, text1, oid, text2, oid, text4, text5, text6),
            "extension_type": xcp5,
        },
    }


class FreshestCRLTestCase(CRLDistributionPointsTestCaseBase[FreshestCRL, x509.FreshestCRL], TestCase):
    """Test FreshestCRL extension."""

    ext_class = FreshestCRL
    ext_class_key = "freshest_crl"
    ext_class_name = "FreshestCRL"
    ext_class_type = x509.FreshestCRL

    cg_dps1 = x509.FreshestCRL([CRLDistributionPointsTestCaseBase.cg_dp1])
    cg_dps2 = x509.FreshestCRL([CRLDistributionPointsTestCaseBase.cg_dp2])
    cg_dps3 = x509.FreshestCRL([CRLDistributionPointsTestCaseBase.cg_dp3])
    cg_dps4 = x509.FreshestCRL([CRLDistributionPointsTestCaseBase.cg_dp4])


class InhibitAnyPolicyTestCase(ExtensionTestMixin[InhibitAnyPolicy], TestCase):
    """Test InhibitAnyPolicy extension."""

    ext_class = InhibitAnyPolicy
    ext_class_key = "inhibit_any_policy"
    ext_class_name = "InhibitAnyPolicy"

    test_values = {
        "zero": {
            "values": [
                0,
            ],
            "expected": 0,
            "expected_repr": "0",
            "expected_serialized": 0,
            "expected_text": "0",
            "extension_type": x509.InhibitAnyPolicy(0),
        },
        "one": {
            "values": [
                1,
            ],
            "expected": 1,
            "expected_repr": "1",
            "expected_serialized": 1,
            "expected_text": "1",
            "extension_type": x509.InhibitAnyPolicy(1),
        },
    }

    def test_int(self) -> None:
        """Test passing various int values."""
        ext = InhibitAnyPolicy(0)
        self.assertEqual(ext.skip_certs, 0)
        ext = InhibitAnyPolicy(1)
        self.assertEqual(ext.skip_certs, 1)

        with self.assertRaisesRegex(ValueError, r"-1: must be a positive int$"):
            InhibitAnyPolicy(-1)
        with self.assertRaisesRegex(ValueError, r"-1: must be a positive int$"):
            InhibitAnyPolicy({"value": -1})

    def test_default(self) -> None:
        """Test the default value for the constructor."""
        self.assertEqual(InhibitAnyPolicy().skip_certs, 0)

    def test_no_int(self) -> None:
        """Test passing invalid values."""
        with self.assertRaisesRegex(ValueError, r"^abc: must be an int$"):
            InhibitAnyPolicy({"value": "abc"})
        with self.assertRaisesRegex(ValueError, r"^Value is of unsupported type str$"):
            InhibitAnyPolicy("abc")  # type: ignore[arg-type]

    def test_value(self) -> None:
        """Overwritten because extension has no value."""
        return


class IssuerAlternativeNameTestCase(
    ListExtensionTestMixin[IssuerAlternativeName], ExtensionTestMixin[IssuerAlternativeName], TestCase
):
    """Test IssuerAlternativeName extension."""

    ext_class = IssuerAlternativeName
    ext_class_key = "issuer_alternative_name"
    ext_class_name = "IssuerAlternativeName"
    ext_class_type = x509.IssuerAlternativeName

    uri1 = value1 = "https://example.com"
    uri2 = value2 = "https://example.net"
    dns1 = value3 = "example.com"
    dns2 = value4 = "example.net"
    et1 = x509.IssuerAlternativeName([uri(value1)])

    invalid_values = ["DNS:https://example.com", True, None]
    test_values = {
        "empty": {
            "values": [[]],
            "expected": [],
            "expected_repr": "[]",
            "expected_serialized": [],
            "expected_text": "",
            "extension_type": ext_class_type([]),
        },
        "uri": {
            "values": [[uri1], [uri(uri1)]],
            "expected": [uri(uri1)],
            "expected_repr": "['URI:%s']" % uri1,
            "expected_serialized": ["URI:%s" % uri1],
            "expected_text": "* URI:%s" % uri1,
            "extension_type": ext_class_type([uri(uri1)]),
        },
        "dns": {
            "values": [[dns1], [dns(dns1)]],
            "expected": [dns(dns1)],
            "expected_repr": "['DNS:%s']" % dns1,
            "expected_serialized": ["DNS:%s" % dns1],
            "expected_text": "* DNS:%s" % dns1,
            "extension_type": ext_class_type([dns(dns1)]),
        },
        "both": {
            "values": [[uri1, dns1], [uri(uri1), dns(dns1)], [uri1, dns(dns1)], [uri(uri1), dns1]],
            "expected": [uri(uri1), dns(dns1)],
            "expected_repr": "['URI:%s', 'DNS:%s']" % (uri1, dns1),
            "expected_serialized": ["URI:%s" % uri1, "DNS:%s" % dns1],
            "expected_text": "* URI:%s\n* DNS:%s" % (uri1, dns1),
            "extension_type": ext_class_type([uri(uri1), dns(dns1)]),
        },
        "all": {
            "values": [
                [uri1, uri2, dns1, dns2],
                [uri(uri1), uri(uri2), dns1, dns2],
                [uri1, uri2, dns(dns1), dns(dns2)],
                [uri(uri1), uri(uri2), dns(dns1), dns(dns2)],
            ],
            "expected": [uri(uri1), uri(uri2), dns(dns1), dns(dns2)],
            "expected_repr": "['URI:%s', 'URI:%s', 'DNS:%s', 'DNS:%s']" % (uri1, uri2, dns1, dns2),
            "expected_serialized": ["URI:%s" % uri1, "URI:%s" % uri2, "DNS:%s" % dns1, "DNS:%s" % dns2],
            "expected_text": "* URI:%s\n* URI:%s\n* DNS:%s\n* DNS:%s" % (uri1, uri2, dns1, dns2),
            "extension_type": ext_class_type([uri(uri1), uri(uri2), dns(dns1), dns(dns2)]),
        },
        "order": {  # same as "all" above but other order
            "values": [
                [dns2, dns1, uri2, uri1],
                [dns(dns2), dns(dns1), uri2, uri1],
                [dns2, dns1, uri(uri2), uri(uri1)],
                [dns(dns2), dns(dns1), uri(uri2), uri(uri1)],
            ],
            "expected": [dns(dns2), dns(dns1), uri(uri2), uri(uri1)],
            "expected_repr": "['DNS:%s', 'DNS:%s', 'URI:%s', 'URI:%s']" % (dns2, dns1, uri2, uri1),
            "expected_serialized": ["DNS:%s" % dns2, "DNS:%s" % dns1, "URI:%s" % uri2, "URI:%s" % uri1],
            "expected_text": "* DNS:%s\n* DNS:%s\n* URI:%s\n* URI:%s" % (dns2, dns1, uri2, uri1),
            "extension_type": ext_class_type([dns(dns2), dns(dns1), uri(uri2), uri(uri1)]),
        },
    }

    def test_none_value(self) -> None:
        """Test that we can pass a None value for GeneralNameList items."""
        empty = self.ext_class({"value": None})
        self.assertEqual(empty.extension_type, self.ext_class_type([]))
        self.assertEqual(empty, self.ext_class({"value": []}))
        empty.insert(0, self.value1)
        self.assertEqual(empty.extension_type, self.et1)


class PolicyConstraintsTestCase(ExtensionTestMixin[PolicyConstraints], TestCase):
    """Test PolicyConstraints extension."""

    ext_class = PolicyConstraints
    ext_class_key = "policy_constraints"
    ext_class_name = "PolicyConstraints"

    test_values = {
        "rep_zero": {
            "values": [
                {"require_explicit_policy": 0},
            ],
            "expected": {"require_explicit_policy": 0},
            "expected_repr": "require_explicit_policy=0",
            "expected_serialized": {"require_explicit_policy": 0},
            "expected_text": "* RequireExplicitPolicy: 0",
            "extension_type": x509.PolicyConstraints(require_explicit_policy=0, inhibit_policy_mapping=None),
        },
        "rep_one": {
            "values": [
                {"require_explicit_policy": 1},
            ],
            "expected": {"require_explicit_policy": 1},
            "expected_repr": "require_explicit_policy=1",
            "expected_serialized": {"require_explicit_policy": 1},
            "expected_text": "* RequireExplicitPolicy: 1",
            "extension_type": x509.PolicyConstraints(require_explicit_policy=1, inhibit_policy_mapping=None),
        },
        "rep_none": {
            "values": [
                {"require_explicit_policy": None},
            ],
            "expected": {},
            "expected_repr": "-",
            "expected_serialized": {},
            "expected_text": "",
            "extension_type": None,
        },
        "iap_zero": {
            "values": [
                {"inhibit_policy_mapping": 0},
            ],
            "expected": {"inhibit_policy_mapping": 0},
            "expected_repr": "inhibit_policy_mapping=0",
            "expected_serialized": {"inhibit_policy_mapping": 0},
            "expected_text": "* InhibitPolicyMapping: 0",
            "extension_type": x509.PolicyConstraints(require_explicit_policy=None, inhibit_policy_mapping=0),
        },
        "iap_one": {
            "values": [
                {"inhibit_policy_mapping": 1},
            ],
            "expected": {"inhibit_policy_mapping": 1},
            "expected_repr": "inhibit_policy_mapping=1",
            "expected_serialized": {"inhibit_policy_mapping": 1},
            "expected_text": "* InhibitPolicyMapping: 1",
            "extension_type": x509.PolicyConstraints(require_explicit_policy=None, inhibit_policy_mapping=1),
        },
        "iap_none": {
            "values": [
                {"inhibit_policy_mapping": None},
            ],
            "expected": {},
            "expected_repr": "-",
            "expected_serialized": {},
            "expected_text": "",
            "extension_type": None,
        },
        "both": {
            "values": [
                {"inhibit_policy_mapping": 2, "require_explicit_policy": 3},
            ],
            "expected": {"inhibit_policy_mapping": 2, "require_explicit_policy": 3},
            "expected_repr": "inhibit_policy_mapping=2, require_explicit_policy=3",
            "expected_serialized": {"inhibit_policy_mapping": 2, "require_explicit_policy": 3},
            "expected_text": "* InhibitPolicyMapping: 2\n* RequireExplicitPolicy: 3",
            "extension_type": x509.PolicyConstraints(require_explicit_policy=3, inhibit_policy_mapping=2),
        },
    }

    def test_init_error(self) -> None:
        """Test constructor errors."""
        with self.assertRaisesRegex(ValueError, r"^abc: inhibit_policy_mapping must be int or None$"):
            PolicyConstraints({"value": {"inhibit_policy_mapping": "abc"}})
        with self.assertRaisesRegex(ValueError, r"^-1: inhibit_policy_mapping must be a positive int$"):
            PolicyConstraints({"value": {"inhibit_policy_mapping": -1}})
        with self.assertRaisesRegex(ValueError, r"^abc: require_explicit_policy must be int or None$"):
            PolicyConstraints({"value": {"require_explicit_policy": "abc"}})
        with self.assertRaisesRegex(ValueError, r"^-1: require_explicit_policy must be a positive int$"):
            PolicyConstraints({"value": {"require_explicit_policy": -1}})

    def test_properties(self) -> None:
        """Test properties"""
        pconst = PolicyConstraints()
        self.assertIsNone(pconst.inhibit_policy_mapping)
        self.assertIsNone(pconst.require_explicit_policy)

        pconst = PolicyConstraints({"value": {"inhibit_policy_mapping": 1, "require_explicit_policy": 2}})
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

    def test_value(self) -> None:
        """Overwritten because extension has no value."""
        return


class KeyUsageTestCase(OrderedSetExtensionTestMixin[KeyUsage], ExtensionTestMixin[KeyUsage], TestCase):
    """Test KeyUsage extension."""

    ext_class = KeyUsage
    ext_class_key = "key_usage"
    ext_class_name = "KeyUsage"

    test_values = {
        "one": {
            "values": [
                {
                    "key_agreement",
                },
                [
                    "keyAgreement",
                ],
            ],
            "expected": frozenset(["key_agreement"]),
            "expected_repr": "['keyAgreement']",
            "expected_text": "* keyAgreement",
            "expected_serialized": ["keyAgreement"],
            "extension_type": x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
        },
        "two": {
            "values": [
                {
                    "key_agreement",
                    "key_encipherment",
                },
                ["keyAgreement", "keyEncipherment"],
                ["keyEncipherment", "keyAgreement"],
                ["keyEncipherment", "key_agreement"],
            ],
            "expected": frozenset(["key_agreement", "key_encipherment"]),
            "expected_repr": "['keyAgreement', 'keyEncipherment']",
            "expected_text": "* keyAgreement\n* keyEncipherment",
            "expected_serialized": ["keyAgreement", "keyEncipherment"],
            "extension_type": x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
        },
        "three": {
            "values": [
                {
                    "key_agreement",
                    "key_encipherment",
                    "content_commitment",
                },
                [
                    "keyAgreement",
                    "keyEncipherment",
                    "nonRepudiation",
                ],
                [
                    "nonRepudiation",
                    "keyAgreement",
                    "keyEncipherment",
                ],
                [
                    "nonRepudiation",
                    "keyAgreement",
                    "keyEncipherment",
                ],
                [
                    "content_commitment",
                    "key_agreement",
                    "key_encipherment",
                ],
            ],
            "expected": frozenset(
                [
                    "key_agreement",
                    "key_encipherment",
                    "content_commitment",
                ]
            ),
            "expected_repr": "['keyAgreement', 'keyEncipherment', 'nonRepudiation']",
            "expected_text": "* keyAgreement\n* keyEncipherment\n* nonRepudiation",
            "expected_serialized": ["keyAgreement", "keyEncipherment", "nonRepudiation"],
            "extension_type": x509.KeyUsage(
                digital_signature=False,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
        },
    }

    def test_completeness(self) -> None:
        """Test that we support all key usages."""
        self.assertEqual(set(KeyUsage.CRYPTOGRAPHY_MAPPING.keys()), {e[0] for e in KeyUsage.CHOICES})

    def test_auto_add(self) -> None:
        """Test that ``decipher_only`` and ``encipher_only`` automatically add ``key_agreement``."""
        self.assertEqual(
            KeyUsage({"value": ["decipher_only"]}), KeyUsage({"value": ["decipher_only", "key_agreement"]})
        )
        self.assertEqual(
            KeyUsage({"value": ["encipher_only"]}), KeyUsage({"value": ["encipher_only", "key_agreement"]})
        )

    def test_unknown_values(self) -> None:
        """Test passing unknown values."""
        with self.assertRaisesRegex(ValueError, r"^Unknown value: foo$"):
            KeyUsage({"value": ["foo"]})

        with self.assertRaisesRegex(ValueError, r"^Unknown value: True$"):
            KeyUsage({"value": [True]})


class ExtendedKeyUsageTestCase(
    OrderedSetExtensionTestMixin[ExtendedKeyUsage], ExtensionTestMixin[ExtendedKeyUsage], TestCase
):
    """Test ExtendedKeyUsage extension."""

    ext_class = ExtendedKeyUsage
    ext_class_key = "extended_key_usage"
    ext_class_name = "ExtendedKeyUsage"

    test_values = {
        "one": {
            "values": [
                {"serverAuth"},
                {ExtendedKeyUsageOID.SERVER_AUTH},
                [ExtendedKeyUsageOID.SERVER_AUTH],
            ],
            "extension_type": x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            "expected": frozenset([ExtendedKeyUsageOID.SERVER_AUTH]),
            "expected_repr": "['serverAuth']",
            "expected_serialized": ["serverAuth"],
            "expected_text": "* serverAuth",
        },
        "two": {
            "values": [
                {
                    "serverAuth",
                    "clientAuth",
                },
                {ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH},
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH],
                [ExtendedKeyUsageOID.SERVER_AUTH, "clientAuth"],
            ],
            "extension_type": x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]
            ),
            "expected": frozenset([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
            "expected_repr": "['clientAuth', 'serverAuth']",
            "expected_serialized": ["clientAuth", "serverAuth"],
            "expected_text": "* clientAuth\n* serverAuth",
        },
        "three": {
            "values": [
                {
                    "serverAuth",
                    "clientAuth",
                    "timeStamping",
                },
                {
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                    ExtendedKeyUsageOID.SERVER_AUTH,
                    ExtendedKeyUsageOID.TIME_STAMPING,
                },
                {
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                    "serverAuth",
                    ExtendedKeyUsageOID.TIME_STAMPING,
                },
                [
                    ExtendedKeyUsageOID.SERVER_AUTH,
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                    ExtendedKeyUsageOID.TIME_STAMPING,
                ],
                [
                    ExtendedKeyUsageOID.TIME_STAMPING,
                    ExtendedKeyUsageOID.SERVER_AUTH,
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                ],
            ],
            "extension_type": x509.ExtendedKeyUsage(
                [
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                    ExtendedKeyUsageOID.SERVER_AUTH,
                    ExtendedKeyUsageOID.TIME_STAMPING,
                ]
            ),
            "expected": frozenset(
                [
                    ExtendedKeyUsageOID.SERVER_AUTH,
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                    ExtendedKeyUsageOID.TIME_STAMPING,
                ]
            ),
            "expected_repr": "['clientAuth', 'serverAuth', 'timeStamping']",
            "expected_serialized": ["clientAuth", "serverAuth", "timeStamping"],
            "expected_text": "* clientAuth\n* serverAuth\n* timeStamping",
        },
    }

    def test_unknown_values(self) -> None:
        """Test passing unknown values."""
        with self.assertRaisesRegex(ValueError, r"^Unknown value: foo$"):
            ExtendedKeyUsage({"value": ["foo"]})

        with self.assertRaisesRegex(ValueError, r"^Unknown value: True$"):
            ExtendedKeyUsage({"value": [True]})

    def test_completeness(self) -> None:
        """Test that we support all ExtendedKeyUsageOIDs."""
        for attr in [getattr(ExtendedKeyUsageOID, a) for a in dir(ExtendedKeyUsageOID) if a[0] != "_"]:
            if isinstance(attr, ObjectIdentifier):
                # pylint: disable=protected-access; ok for a test case
                self.assertIn(attr, ExtendedKeyUsage._CRYPTOGRAPHY_MAPPING_REVERSED)

        # make sure we haven't forgotton any keys in the form selection
        self.assertEqual(
            set(ExtendedKeyUsage.CRYPTOGRAPHY_MAPPING.keys()), {e[0] for e in ExtendedKeyUsage.CHOICES}
        )


class NameConstraintsTestCase(ExtensionTestMixin[NameConstraints], TestCase):
    """Test NameConstraints extension."""

    ext_class = NameConstraints
    ext_class_key = "name_constraints"
    ext_class_name = "NameConstraints"

    d1 = "example.com"
    d2 = "example.net"

    test_values = {
        "empty": {
            "values": [
                {"excluded": [], "permitted": []},
                {"excluded": None, "permitted": None},
            ],
            "expected": x509.NameConstraints(permitted_subtrees=[], excluded_subtrees=[]),
            "expected_repr": "permitted=[], excluded=[]",
            "expected_serialized": {"excluded": [], "permitted": []},
            "expected_text": "",
            "extension_type": x509.NameConstraints(permitted_subtrees=[], excluded_subtrees=[]),
        },
        "permitted": {
            "values": [
                {"permitted": [d1]},
                {"permitted": ["DNS:%s" % d1]},
                {"permitted": [dns(d1)]},
                {"permitted": [dns(d1)], "excluded": []},
            ],
            "expected": x509.NameConstraints(permitted_subtrees=[dns(d1)], excluded_subtrees=[]),
            "expected_repr": "permitted=['DNS:%s'], excluded=[]" % d1,
            "expected_serialized": {"excluded": [], "permitted": ["DNS:%s" % d1]},
            "expected_text": "Permitted:\n  * DNS:%s" % d1,
            "extension_type": x509.NameConstraints(permitted_subtrees=[dns(d1)], excluded_subtrees=[]),
        },
        "excluded": {
            "values": [
                {"excluded": [d1]},
                {"excluded": ["DNS:%s" % d1]},
                {"excluded": [dns(d1)]},
                {"excluded": [dns(d1)], "permitted": []},
            ],
            "expected": x509.NameConstraints(permitted_subtrees=[], excluded_subtrees=[dns(d1)]),
            "expected_repr": "permitted=[], excluded=['DNS:%s']" % d1,
            "expected_serialized": {"excluded": ["DNS:%s" % d1], "permitted": []},
            "expected_text": "Excluded:\n  * DNS:%s" % d1,
            "extension_type": x509.NameConstraints(permitted_subtrees=[], excluded_subtrees=[dns(d1)]),
        },
        "both": {
            "values": [
                {"permitted": [d1], "excluded": [d2]},
                {"permitted": ["DNS:%s" % d1], "excluded": ["DNS:%s" % d2]},
                {"permitted": [dns(d1)], "excluded": [dns(d2)]},
                {"permitted": [dns(d1)], "excluded": [d2]},
            ],
            "expected": x509.NameConstraints(permitted_subtrees=[dns(d1)], excluded_subtrees=[dns(d2)]),
            "expected_repr": "permitted=['DNS:%s'], excluded=['DNS:%s']" % (d1, d2),
            "expected_serialized": {"excluded": ["DNS:%s" % d2], "permitted": ["DNS:%s" % d1]},
            "expected_text": "Permitted:\n  * DNS:%s\nExcluded:\n  * DNS:%s" % (d1, d2),
            "extension_type": x509.NameConstraints(permitted_subtrees=[dns(d1)], excluded_subtrees=[dns(d2)]),
        },
    }

    def test_bool(self) -> None:
        """Test bool(ext)."""
        self.assertFalse(bool(NameConstraints()))
        self.assertTrue(bool(NameConstraints({"value": {"permitted": ["example.com"]}})))
        self.assertTrue(bool(NameConstraints({"value": {"excluded": ["example.com"]}})))

    def test_setters(self) -> None:
        """Test items etters."""
        expected = NameConstraints(
            {
                "value": {
                    "permitted": ["example.com"],
                    "excluded": ["example.net"],
                }
            }
        )
        ext = NameConstraints()
        ext.permitted = ["example.com"]
        ext.excluded = ["example.net"]
        self.assertEqual(ext, expected)

        ext = NameConstraints()
        ext.permitted = GeneralNameList(["example.com"])
        ext.excluded = GeneralNameList(["example.net"])
        self.assertEqual(ext, expected)

        ext = NameConstraints()
        ext.permitted += ["example.com"]
        ext.excluded += ["example.net"]
        self.assertExtensionEqual(ext, expected)

    def test_none_value(self) -> None:
        """Test that we can use and pass None as values for GeneralNamesList values."""
        ext = self.ext_class({"value": {}})
        self.assertEqual(
            ext.extension_type, x509.NameConstraints(permitted_subtrees=[], excluded_subtrees=[])
        )
        self.assertEqual(ext.excluded, [])
        self.assertEqual(ext.permitted, [])

        ext = self.ext_class({"value": {"permitted": None, "excluded": None}})
        self.assertEqual(
            ext.extension_type, x509.NameConstraints(permitted_subtrees=[], excluded_subtrees=[])
        )
        self.assertEqual(ext.excluded, [])
        self.assertEqual(ext.permitted, [])

    def test_value(self) -> None:
        """Overwritten because extension has no value."""
        return


class OCSPNoCheckTestCase(NullExtensionTestMixin[OCSPNoCheck], TestCase):
    """Test OCSPNoCheck extension."""

    ext_class = OCSPNoCheck
    ext_class_key = "ocsp_no_check"
    ext_class_name = "OCSPNoCheck"

    test_values: TestValues = {
        "empty": {
            "values": [{}, None],
            "expected": None,
            "expected_repr": "",
            "expected_serialized": None,
            "expected_text": "OCSPNoCheck",
            "extension_type": x509.OCSPNoCheck(),
        },
    }


class PrecertPoisonTestCase(NullExtensionTestMixin[PrecertPoison], TestCase):
    """Test PrecertPoison extension."""

    ext_class = PrecertPoison
    ext_class_key = "precert_poison"
    ext_class_name = "PrecertPoison"
    force_critical = True
    test_values: TestValues = {
        "empty": {
            "values": [{}, None],
            "expected": None,
            "expected_repr": "",
            "expected_serialized": None,
            "expected_text": "PrecertPoison",
            "extension_type": x509.PrecertPoison(),
        },
    }

    def test_eq(self) -> None:
        """Test for equality."""
        for values in self.test_values.values():
            ext = self.ext(values["expected"])
            self.assertEqual(ext, ext)
            ext_critical = self.ext(values["expected"], critical=True)
            self.assertEqual(ext_critical, ext_critical)

            for value in values["values"]:
                ext_1 = self.ext(value)
                self.assertEqual(ext, ext_1)
                ext_2 = self.ext(value, critical=True)
                self.assertEqual(ext_critical, ext_2)

    def test_hash(self) -> None:
        """Test hash()."""
        for config in self.test_values.values():
            ext = self.ext(config["expected"])
            ext_critical = self.ext(config["expected"], critical=True)
            self.assertEqual(hash(ext), hash(ext_critical))

            for other_config in self.test_values.values():
                other_ext = self.ext(other_config["expected"])
                other_ext_critical = self.ext(other_config["expected"], critical=True)

                if config["expected"] == other_config["expected"]:
                    self.assertEqual(hash(ext), hash(other_ext))
                    self.assertEqual(hash(ext_critical), hash(other_ext_critical))
                else:
                    self.assertNotEqual(hash(ext), hash(other_ext))
                    self.assertNotEqual(hash(ext_critical), hash(other_ext_critical))

    def test_critical(self) -> None:
        """Test the critical property."""
        with self.assertRaisesRegex(ValueError, r"^PrecertPoison must always be marked as critical$"):
            PrecertPoison({"critical": False})  # type: ignore[arg-type]


class PrecertificateSignedCertificateTimestampsTestCase(TestCaseMixin, TestCase):
    """Test PrecertificateSignedCertificateTimestamps extension."""

    # pylint: disable=too-many-public-methods; RO-extension requires implementing everything again
    # pylint: disable=too-many-instance-attributes; RO-extension requires implementing everything again

    default_ca = "letsencrypt_x3"
    default_cert = "letsencrypt_x3-cert"
    load_cas = ("letsencrypt_x3", "comodo_ev")
    load_certs = ("letsencrypt_x3-cert", "comodo_ev-cert")

    ext_class = PrecertificateSignedCertificateTimestamps
    ext_class_key = "precertificate_signed_certificate_timestamps"
    ext_class_name = "PrecertificateSignedCertificateTimestamps"

    def setUp(self) -> None:
        super().setUp()
        self.name1 = "letsencrypt_x3-cert"
        self.name2 = "comodo_ev-cert"
        cert1 = self.certs[self.name1]
        cert2 = self.certs[self.name2]

        self.cgx1 = cert1.pub.loaded.extensions.get_extension_for_class(
            x509.PrecertificateSignedCertificateTimestamps
        )
        self.cgx2 = cert2.pub.loaded.extensions.get_extension_for_class(
            x509.PrecertificateSignedCertificateTimestamps
        )
        self.ext1 = PrecertificateSignedCertificateTimestamps(self.cgx1)
        self.ext2 = PrecertificateSignedCertificateTimestamps(self.cgx2)
        self.exts = [self.ext1, self.ext2]
        self.data1 = certs[self.name1]["precertificate_signed_certificate_timestamps_serialized"]
        self.data2 = certs[self.name2]["precertificate_signed_certificate_timestamps_serialized"]

    def test_config(self) -> None:
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

    def test_as_text(self) -> None:
        """Test as_text()."""
        self.assertEqual(
            self.ext1.as_text(),
            """* Precertificate ({v[0][version]}):
    Timestamp: {v[0][timestamp]}
    Log ID: {v[0][log_id]}
* Precertificate ({v[1][version]}):
    Timestamp: {v[1][timestamp]}
    Log ID: {v[1][log_id]}""".format(
                v=self.data1["value"]
            ),
        )

        self.assertEqual(
            self.ext2.as_text(),
            """* Precertificate ({v[0][version]}):
    Timestamp: {v[0][timestamp]}
    Log ID: {v[0][log_id]}
* Precertificate ({v[1][version]}):
    Timestamp: {v[1][timestamp]}
    Log ID: {v[1][log_id]}
* Precertificate ({v[2][version]}):
    Timestamp: {v[2][timestamp]}
    Log ID: {v[2][log_id]}""".format(
                v=self.data2["value"]
            ),
        )

    def test_count(self) -> None:
        """Test ext.count()."""
        self.assertEqual(self.ext1.count(self.data1["value"][0]), 1)
        self.assertEqual(self.ext1.count(self.data2["value"][0]), 0)
        self.assertEqual(self.ext1.count(self.cgx1.value[0]), 1)
        self.assertEqual(self.ext1.count(self.cgx2.value[0]), 0)

        self.assertEqual(self.ext2.count(self.data1["value"][0]), 0)
        self.assertEqual(self.ext2.count(self.data2["value"][0]), 1)
        self.assertEqual(self.ext2.count(self.cgx1.value[0]), 0)
        self.assertEqual(self.ext2.count(self.cgx2.value[0]), 1)

    def test_del(self) -> None:
        """Test item deletion (e.g. ``del ext[0]``, not supported here)."""
        with self.assertRaises(NotImplementedError):
            del self.ext1[0]  # type: ignore[no-untyped-call]
        with self.assertRaises(NotImplementedError):
            del self.ext2[0]  # type: ignore[no-untyped-call]

    def test_extend(self) -> None:
        """Test ext.extend() (not supported here)."""
        with self.assertRaises(NotImplementedError):
            self.ext1.extend([])  # type: ignore[no-untyped-call]
        with self.assertRaises(NotImplementedError):
            self.ext2.extend([])  # type: ignore[no-untyped-call]

    def test_extension_type(self) -> None:
        """Test extension_type property."""
        self.assertEqual(self.ext1.extension_type, self.cgx1.value)
        self.assertEqual(self.ext2.extension_type, self.cgx2.value)

    def test_getitem(self) -> None:
        """Test item getter (e.g. ``x = ext[0]``)."""
        self.assertEqual(self.ext1[0], self.data1["value"][0])
        self.assertEqual(self.ext1[1], self.data1["value"][1])
        with self.assertRaises(IndexError):
            self.ext1[2]  # pylint: disable=pointless-statement

        self.assertEqual(self.ext2[0], self.data2["value"][0])
        self.assertEqual(self.ext2[1], self.data2["value"][1])
        self.assertEqual(self.ext2[2], self.data2["value"][2])
        with self.assertRaises(IndexError):
            self.ext2[3]  # pylint: disable=pointless-statement

    def test_getitem_slices(self) -> None:
        """Test getting slices (e.g. ``x = ext[0:1]``)."""
        self.assertEqual(self.ext1[:1], self.data1["value"][:1])
        self.assertEqual(self.ext2[:2], self.data2["value"][:2])
        self.assertEqual(self.ext2[:], self.data2["value"][:])

    def test_hash(self) -> None:
        """Test hash()."""
        self.assertEqual(hash(self.ext1), hash(self.ext1))
        self.assertEqual(hash(self.ext2), hash(self.ext2))
        self.assertNotEqual(hash(self.ext1), hash(self.ext2))

    def test_in(self) -> None:
        """Test the ``in`` operator."""
        for val in self.data1["value"]:
            self.assertIn(val, self.ext1)
        for val in self.cgx1.value:
            self.assertIn(val, self.ext1)
        for val in self.data2["value"]:
            self.assertIn(val, self.ext2)
        for val in self.cgx2.value:
            self.assertIn(val, self.ext2)

    def test_insert(self) -> None:
        """Test ext.insert() (Not supported here)."""
        with self.assertRaises(NotImplementedError):
            self.ext1.insert(0, self.data1["value"][0])  # type: ignore[no-untyped-call]
        with self.assertRaises(NotImplementedError):
            self.ext2.insert(0, self.data2["value"][0])  # type: ignore[no-untyped-call]

    def test_len(self) -> None:
        """Test len(ext) (Not supported here)."""
        self.assertEqual(len(self.ext1), 2)
        self.assertEqual(len(self.ext2), 3)

    def test_ne(self) -> None:
        """Test ``!=`` (not-equal) operator."""
        self.assertNotEqual(self.ext1, self.ext2)

    def test_not_in(self) -> None:
        """Test the ``not in`` operator."""
        self.assertNotIn(self.data1["value"][0], self.ext2)
        self.assertNotIn(self.data2["value"][0], self.ext1)

        self.assertNotIn(self.cgx1.value[0], self.ext2)
        self.assertNotIn(self.cgx2.value[0], self.ext1)

    def test_pop(self) -> None:
        """Test ext.pop() (Not supported here)."""
        with self.assertRaises(NotImplementedError):
            self.ext1.pop(self.data1["value"][0])  # type: ignore[no-untyped-call]
        with self.assertRaises(NotImplementedError):
            self.ext2.pop(self.data2["value"][0])  # type: ignore[no-untyped-call]

    def test_remove(self) -> None:
        """Test ext.remove() (Not supported here)."""
        with self.assertRaises(NotImplementedError):
            self.ext1.remove(self.data1["value"][0])  # type: ignore[no-untyped-call]
        with self.assertRaises(NotImplementedError):
            self.ext2.remove(self.data2["value"][0])  # type: ignore[no-untyped-call]

    def test_repr(self) -> None:
        """Test repr()."""
        self.assertEqual(
            repr(self.ext1), "<PrecertificateSignedCertificateTimestamps: 2 timestamps, critical=False>"
        )
        self.assertEqual(
            repr(self.ext2), "<PrecertificateSignedCertificateTimestamps: 3 timestamps, critical=False>"
        )

        with self.patch_object(self.ext2, "critical", True):
            self.assertEqual(
                repr(self.ext2), "<PrecertificateSignedCertificateTimestamps: 3 timestamps, critical=True>"
            )

    def test_serialize(self) -> None:
        """Test serialization of extension."""
        self.assertEqual(self.ext1.serialize(), self.data1)
        self.assertEqual(self.ext2.serialize(), self.data2)

    def test_setitem(self) -> None:
        """Test setting items (e.g. ``ext[0] = ...``)."""
        with self.assertRaises(NotImplementedError):
            self.ext1[0] = self.data2["value"][0]
        with self.assertRaises(NotImplementedError):
            self.ext2[0] = self.data1["value"][0]

    def test_setitem_slices(self) -> None:
        """Test setting slices (not supported here)."""
        with self.assertRaises(NotImplementedError):
            self.ext1[:] = self.data2
        with self.assertRaises(NotImplementedError):
            self.ext2[:] = self.data1

    def test_str(self) -> None:
        """Test str()."""
        self.assertEqual(
            str(self.ext1), "<PrecertificateSignedCertificateTimestamps: 2 timestamps, critical=False>"
        )
        self.assertEqual(
            str(self.ext2), "<PrecertificateSignedCertificateTimestamps: 3 timestamps, critical=False>"
        )

        with self.patch_object(self.ext2, "critical", True):
            self.assertEqual(
                str(self.ext2), "<PrecertificateSignedCertificateTimestamps: 3 timestamps, critical=True>"
            )


class UnknownExtensionTestCase(TestCase):
    """Test UnrecognizedExtension extension."""

    def test_basic(self) -> None:
        """Only test basic functionality."""
        oid = x509.ObjectIdentifier("1.2.1")
        cgext = x509.Extension(
            oid=oid, value=x509.UnrecognizedExtension(oid=oid, value=b"unrecognized"), critical=True
        )
        ext = UnrecognizedExtension(cgext)

        self.assertEqual(ext.name, "Unsupported extension (OID %s)" % oid.dotted_string)
        self.assertEqual(ext.as_text(), "Could not parse extension")
        self.assertEqual(ext.as_extension(), cgext)
        self.assertEqual(
            str(ext), "<Unsupported extension (OID %s): <unprintable>, critical=True>" % oid.dotted_string
        )

        with self.assertRaisesRegex(ValueError, r"^Cannot serialize an unrecognized extension$"):
            ext.serialize_value()

        name = "my name"
        error = "my error"
        ext = UnrecognizedExtension(cgext, name=name, error=error)
        self.assertEqual(ext.name, name)
        self.assertEqual(ext.as_text(), "Could not parse extension (%s)" % error)

    def test_invalid_extension(self) -> None:
        """Test creating from an actually recognized extension."""
        value = x509.Extension(
            oid=SubjectAlternativeName.oid,
            critical=True,
            value=x509.SubjectAlternativeName([uri("example.com")]),
        )
        with self.assertRaisesRegex(TypeError, r"^Extension value must be a x509\.UnrecognizedExtension$"):
            UnrecognizedExtension(value)  # type: ignore[arg-type]

    def test_from_dict(self) -> None:
        """Test that you cannot instantiate this extension from a dict."""
        with self.assertRaisesRegex(TypeError, r"Value must be a x509\.Extension instance$"):
            UnrecognizedExtension({"value": "foo"})  # type: ignore[arg-type]


class SubjectAlternativeNameTestCase(IssuerAlternativeNameTestCase):
    """Test SubjectAlternativeName extension."""

    ext_class = SubjectAlternativeName  # type: ignore[assignment]
    ext_class_key = "subject_alternative_name"
    ext_class_name = "SubjectAlternativeName"
    ext_class_type = x509.SubjectAlternativeName  # type: ignore[assignment]

    uri1 = value1 = "https://example.com"
    uri2 = "https://example.net"
    dns1 = "example.com"
    dns2 = "example.net"
    et1 = x509.SubjectAlternativeName([uri(value1)])  # type: ignore[assignment]

    test_values = {
        "empty": {
            "values": [[]],
            "expected": [],
            "expected_repr": "[]",
            "expected_serialized": [],
            "expected_text": "",
            "extension_type": x509.SubjectAlternativeName([]),
        },
        "uri": {
            "values": [[uri1], [uri(uri1)]],
            "expected": [uri(uri1)],
            "expected_repr": "['URI:%s']" % uri1,
            "expected_serialized": ["URI:%s" % uri1],
            "expected_text": "* URI:%s" % uri1,
            "extension_type": x509.SubjectAlternativeName([uri(uri1)]),
        },
        "dns": {
            "values": [[dns1], [dns(dns1)]],
            "expected": [dns(dns1)],
            "expected_repr": "['DNS:%s']" % dns1,
            "expected_serialized": ["DNS:%s" % dns1],
            "expected_text": "* DNS:%s" % dns1,
            "extension_type": x509.SubjectAlternativeName([dns(dns1)]),
        },
        "both": {
            "values": [[uri1, dns1], [uri(uri1), dns(dns1)], [uri1, dns(dns1)], [uri(uri1), dns1]],
            "expected": [uri(uri1), dns(dns1)],
            "expected_repr": "['URI:%s', 'DNS:%s']" % (uri1, dns1),
            "expected_serialized": ["URI:%s" % uri1, "DNS:%s" % dns1],
            "expected_text": "* URI:%s\n* DNS:%s" % (uri1, dns1),
            "extension_type": x509.SubjectAlternativeName([uri(uri1), dns(dns1)]),
        },
        "all": {
            "values": [
                [uri1, uri2, dns1, dns2],
                [uri(uri1), uri(uri2), dns1, dns2],
                [uri1, uri2, dns(dns1), dns(dns2)],
                [uri(uri1), uri(uri2), dns(dns1), dns(dns2)],
            ],
            "expected": [uri(uri1), uri(uri2), dns(dns1), dns(dns2)],
            "expected_repr": "['URI:%s', 'URI:%s', 'DNS:%s', 'DNS:%s']" % (uri1, uri2, dns1, dns2),
            "expected_serialized": ["URI:%s" % uri1, "URI:%s" % uri2, "DNS:%s" % dns1, "DNS:%s" % dns2],
            "expected_text": "* URI:%s\n* URI:%s\n* DNS:%s\n* DNS:%s" % (uri1, uri2, dns1, dns2),
            "extension_type": x509.SubjectAlternativeName([uri(uri1), uri(uri2), dns(dns1), dns(dns2)]),
        },
        "order": {  # same as "all" above but other order
            "values": [
                [dns2, dns1, uri2, uri1],
                [dns(dns2), dns(dns1), uri2, uri1],
                [dns2, dns1, uri(uri2), uri(uri1)],
                [dns(dns2), dns(dns1), uri(uri2), uri(uri1)],
            ],
            "expected": [dns(dns2), dns(dns1), uri(uri2), uri(uri1)],
            "expected_repr": "['DNS:%s', 'DNS:%s', 'URI:%s', 'URI:%s']" % (dns2, dns1, uri2, uri1),
            "expected_serialized": ["DNS:%s" % dns2, "DNS:%s" % dns1, "URI:%s" % uri2, "URI:%s" % uri1],
            "expected_text": "* DNS:%s\n* DNS:%s\n* URI:%s\n* URI:%s" % (dns2, dns1, uri2, uri1),
            "extension_type": x509.SubjectAlternativeName([dns(dns2), dns(dns1), uri(uri2), uri(uri1)]),
        },
    }

    def test_get_common_name(self) -> None:
        """Test the get_common_name() function."""
        common_name = "example.com"
        dirname = "dirname:/CN=example.net"

        san = SubjectAlternativeName({"value": [common_name]})
        self.assertEqual(san.get_common_name(), common_name)

        san = SubjectAlternativeName({"value": [common_name, dirname]})
        self.assertEqual(san.get_common_name(), common_name)

        san = SubjectAlternativeName({"value": [dirname, common_name]})
        self.assertEqual(san.get_common_name(), "example.com")

        san = SubjectAlternativeName({"value": [dirname]})
        self.assertIsNone(san.get_common_name())


class SubjectKeyIdentifierTestCase(ExtensionTestMixin[SubjectKeyIdentifier], TestCase):
    """Test SubjectKeyIdentifier extension."""

    ext_class = SubjectKeyIdentifier
    ext_class_key = "subject_key_identifier"
    ext_class_name = "SubjectKeyIdentifier"

    hex1 = "33:33:33:33:33:33"
    hex2 = "44:44:44:44:44:44"
    hex3 = "55:55:55:55:55:55"
    b1 = b"333333"
    b2 = b"DDDDDD"
    b3 = b"UUUUUU"

    test_values = {
        "one": {
            "values": [
                x509.SubjectKeyIdentifier(b1),
                hex1,
            ],
            "expected": b1,
            "expected_repr": hex1,
            "expected_serialized": hex1,
            "expected_text": hex1,
            "extension_type": x509.SubjectKeyIdentifier(b1),
        },
        "two": {
            "values": [
                x509.SubjectKeyIdentifier(b2),
                hex2,
            ],
            "expected": b2,
            "expected_repr": hex2,
            "expected_serialized": hex2,
            "expected_text": hex2,
            "extension_type": x509.SubjectKeyIdentifier(b2),
        },
        "three": {
            "values": [
                x509.SubjectKeyIdentifier(b3),
                hex3,
            ],
            "expected": b3,
            "expected_repr": hex3,
            "expected_serialized": hex3,
            "expected_text": hex3,
            "extension_type": x509.SubjectKeyIdentifier(b3),
        },
    }

    def test_ski_constructor(self) -> None:
        """Test passing x509.SubjectKeyIdentifier."""

        self.assertEqual(
            SubjectKeyIdentifier(x509.SubjectKeyIdentifier(self.b1)),
            SubjectKeyIdentifier({"value": self.hex1}),
        )
        self.assertEqual(
            SubjectKeyIdentifier(x509.SubjectKeyIdentifier(self.b2)),
            SubjectKeyIdentifier({"value": self.hex2}),
        )
        self.assertEqual(
            SubjectKeyIdentifier(x509.SubjectKeyIdentifier(self.b3)),
            SubjectKeyIdentifier({"value": self.hex3}),
        )

        # dict also accepts SKI
        self.assertEqual(
            SubjectKeyIdentifier(x509.SubjectKeyIdentifier(self.b1)),
            SubjectKeyIdentifier({"value": x509.SubjectKeyIdentifier(self.b1)}),
        )
        self.assertEqual(
            SubjectKeyIdentifier(x509.SubjectKeyIdentifier(self.b2)),
            SubjectKeyIdentifier({"value": x509.SubjectKeyIdentifier(self.b2)}),
        )
        self.assertEqual(
            SubjectKeyIdentifier(x509.SubjectKeyIdentifier(self.b3)),
            SubjectKeyIdentifier({"value": x509.SubjectKeyIdentifier(self.b3)}),
        )


class TLSFeatureTestCase(OrderedSetExtensionTestMixin[TLSFeature], ExtensionTestMixin[TLSFeature], TestCase):
    """Test TLSFeature extension."""

    ext_class = TLSFeature
    ext_class_key = "tls_feature"
    ext_class_name = "TLSFeature"

    test_values = {
        "one": {
            "values": [
                {
                    TLSFeatureType.status_request,
                },
                {
                    "OCSPMustStaple",
                },
            ],
            "extension_type": x509.TLSFeature(features=[TLSFeatureType.status_request]),
            "expected": frozenset([TLSFeatureType.status_request]),
            "expected_repr": "['OCSPMustStaple']",
            "expected_serialized": ["OCSPMustStaple"],
            "expected_text": "* OCSPMustStaple",
        },
        "two": {
            "values": [
                {TLSFeatureType.status_request, TLSFeatureType.status_request_v2},
                {"OCSPMustStaple", "MultipleCertStatusRequest"},
                [TLSFeatureType.status_request, TLSFeatureType.status_request_v2],
                [TLSFeatureType.status_request_v2, TLSFeatureType.status_request],
                ["OCSPMustStaple", "MultipleCertStatusRequest"],
                ["MultipleCertStatusRequest", "OCSPMustStaple"],
            ],
            "extension_type": x509.TLSFeature(
                features=[
                    TLSFeatureType.status_request_v2,
                    TLSFeatureType.status_request,
                ]
            ),
            "expected": frozenset([TLSFeatureType.status_request, TLSFeatureType.status_request_v2]),
            "expected_repr": "['MultipleCertStatusRequest', 'OCSPMustStaple']",
            "expected_serialized": ["MultipleCertStatusRequest", "OCSPMustStaple"],
            "expected_text": "* MultipleCertStatusRequest\n* OCSPMustStaple",
        },
        "three": {
            "values": [
                {TLSFeatureType.status_request_v2},
                {"MultipleCertStatusRequest"},
            ],
            "extension_type": x509.TLSFeature(features=[TLSFeatureType.status_request_v2]),
            "expected": frozenset([TLSFeatureType.status_request_v2]),
            "expected_repr": "['MultipleCertStatusRequest']",
            "expected_serialized": ["MultipleCertStatusRequest"],
            "expected_text": "* MultipleCertStatusRequest",
        },
    }

    def test_unknown_values(self) -> None:
        """Test passing unknown values."""
        with self.assertRaisesRegex(ValueError, r"^Unknown value: foo$"):
            TLSFeature({"value": ["foo"]})

        with self.assertRaisesRegex(ValueError, r"^Unknown value: True$"):
            TLSFeature({"value": [True]})

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
from unittest import TestLoader, TestSuite

from cryptography import x509
from cryptography.x509 import TLSFeatureType
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtendedKeyUsageOID,
    ExtensionOID,
    ObjectIdentifier,
)

from django.conf import settings
from django.test import TestCase
from django.utils.functional import cached_property
from django.utils.safestring import mark_safe

from ..deprecation import RemovedInDjangoCA124Warning
from ..extensions import (
    KEY_TO_EXTENSION,
    OID_TO_EXTENSION,
    AuthorityInformationAccess,
    AuthorityKeyIdentifier,
    BasicConstraints,
    CertificatePolicies,
    CRLDistributionPoints,
    ExtendedKeyUsage,
    Extension,
    FreshestCRL,
    InhibitAnyPolicy,
    IssuerAlternativeName,
    KeyUsage,
    NameConstraints,
    OCSPNoCheck,
    PolicyConstraints,
    PrecertificateSignedCertificateTimestamps,
    PrecertPoison,
    SubjectAlternativeName,
    SubjectKeyIdentifier,
    TLSFeature,
    parse_extension,
)
from ..extensions.base import UnrecognizedExtension
from ..extensions.utils import (
    PolicyInformation,
    extension_as_admin_html,
    extension_as_text,
    serialize_extension,
)
from ..models import X509CertMixin
from ..typehints import ParsablePolicyInformation
from ..utils import GeneralNameList
from .base import certs, dns, uri
from .base.extensions import (
    CRLDistributionPointsTestCaseBase,
    ExtensionTestMixin,
    ListExtensionTestMixin,
    NullExtensionTestMixin,
    OrderedSetExtensionTestMixin,
    TestValues,
)
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
            "admin_html": "<div class='django-ca-extension-value'></div>",
            "values": [{}],
            "expected": {"issuers": [], "ocsp": []},
            "expected_bool": False,
            "expected_repr": "issuers=[], ocsp=[]",
            "expected_serialized": {},
            "extension_type": x509.AuthorityInformationAccess(descriptions=[]),
            "text": "",
        },
        "issuer": {
            "admin_html": f"CA Issuers:<ul><li>URI:{uri1}</li></ul>",
            "values": [
                {"issuers": [uri1]},
                {"issuers": [uri(uri1)]},
            ],
            "expected": {"issuers": [uri(uri1)], "ocsp": []},
            "expected_repr": f"issuers=['URI:{uri1}'], ocsp=[]",
            "expected_serialized": {"issuers": [f"URI:{uri1}"]},
            "extension_type": x509.AuthorityInformationAccess(
                descriptions=[x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, uri(uri1))]
            ),
            "text": f"CA Issuers:\n  * URI:{uri1}",
        },
        "ocsp": {
            "admin_html": f"OCSP:<ul><li>URI:{uri2}</li></ul>",
            "values": [
                {"ocsp": [uri2]},
                {"ocsp": [uri(uri2)]},
            ],
            "expected": {"ocsp": [uri(uri2)], "issuers": []},
            "expected_repr": f"issuers=[], ocsp=['URI:{uri2}']",
            "expected_serialized": {"ocsp": [f"URI:{uri2}"]},
            "extension_type": x509.AuthorityInformationAccess(
                descriptions=[x509.AccessDescription(AuthorityInformationAccessOID.OCSP, uri(uri2))]
            ),
            "text": f"OCSP:\n  * URI:{uri2}",
        },
        "both": {
            "admin_html": f"CA Issuers:<ul><li>URI:{uri2}</li></ul> OCSP:<ul><li>URI:{uri1}</li></ul>",
            "values": [
                {"ocsp": [uri1], "issuers": [uri2]},
                {"ocsp": [uri(uri1)], "issuers": [uri(uri2)]},
            ],
            "expected": {"ocsp": [uri(uri1)], "issuers": [uri(uri2)]},
            "expected_repr": f"issuers=['URI:{uri2}'], ocsp=['URI:{uri1}']",
            "expected_serialized": {"ocsp": [f"URI:{uri1}"], "issuers": [f"URI:{uri2}"]},
            "extension_type": x509.AuthorityInformationAccess(
                descriptions=[
                    x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, uri(uri2)),
                    x509.AccessDescription(AuthorityInformationAccessOID.OCSP, uri(uri1)),
                ]
            ),
            "text": f"CA Issuers:\n  * URI:{uri2}\nOCSP:\n  * URI:{uri1}",
        },
        "multiple": {
            "admin_html": f"""CA Issuers:
<ul>
  <li>URI:{uri3}</li>
  <li>URI:{uri4}</li>
</ul>
OCSP:
<ul>
  <li>URI:{uri1}</li>
  <li>URI:{uri2}</li>
</ul>""",
            "values": [
                {"ocsp": [uri1, uri2], "issuers": [uri3, uri4]},
                {"ocsp": [uri1, uri(uri2)], "issuers": [uri3, uri(uri4)]},
                {"ocsp": [uri(uri1), uri(uri2)], "issuers": [uri(uri3), uri(uri4)]},
            ],
            "expected": {"ocsp": [uri(uri1), uri(uri2)], "issuers": [uri(uri3), uri(uri4)]},
            "expected_repr": f"issuers=['URI:{uri3}', 'URI:{uri4}'], ocsp=['URI:{uri1}', 'URI:{uri2}']",
            "expected_serialized": {
                "ocsp": [f"URI:{uri1}", f"URI:{uri2}"],
                "issuers": [f"URI:{uri3}", f"URI:{uri4}"],
            },
            "extension_type": x509.AuthorityInformationAccess(
                descriptions=[
                    x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, uri(uri3)),
                    x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, uri(uri4)),
                    x509.AccessDescription(AuthorityInformationAccessOID.OCSP, uri(uri1)),
                    x509.AccessDescription(AuthorityInformationAccessOID.OCSP, uri(uri2)),
                ]
            ),
            "text": f"CA Issuers:\n  * URI:{uri3}\n  * URI:{uri4}\nOCSP:\n  * URI:{uri1}\n  * URI:{uri2}",
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
            "admin_html": f"<ul><li>Key ID: <span class='django-ca-serial'>{hex1}</span></li></ul>",
            "values": [hex1, {"key_identifier": hex1}],
            "expected": b1,
            "expected_repr": f"keyid: {hex1}",
            "expected_serialized": {"key_identifier": hex1},
            "extension_type": x509.AuthorityKeyIdentifier(b1, None, None),
            "text": f"* KeyID: {hex1}",
        },
        "two": {
            "admin_html": f"<ul><li>Key ID: <span class='django-ca-serial'>{hex2}</span></li></ul>",
            "values": [
                hex2,
            ],
            "expected": b2,
            "expected_repr": f"keyid: {hex2}",
            "expected_serialized": {"key_identifier": hex2},
            "extension_type": x509.AuthorityKeyIdentifier(b2, None, None),
            "text": f"* KeyID: {hex2}",
        },
        "three": {
            "admin_html": f"<ul><li>Key ID: <span class='django-ca-serial'>{hex3}</span></li></ul>",
            "values": [
                hex3,
            ],
            "expected": b3,
            "expected_repr": f"keyid: {hex3}",
            "expected_serialized": {"key_identifier": hex3},
            "extension_type": x509.AuthorityKeyIdentifier(b3, None, None),
            "text": f"* KeyID: {hex3}",
        },
        "issuer/serial": {
            "admin_html": f"""<ul>
    <li>Authority certificate issuer:
        <ul><li>DNS:{dns1}</li></ul>
    </li>
</ul>""",
            "expected": {"authority_cert_issuer": [dns1], "authority_cert_serial_number": s1},
            "values": [
                {"authority_cert_issuer": [dns1], "authority_cert_serial_number": s1},
                {"authority_cert_issuer": [dns1], "authority_cert_serial_number": str(s1)},
            ],
            "expected_repr": f"issuer: ['DNS:{dns1}'], serial: {s1}",
            "expected_serialized": {
                "authority_cert_issuer": [f"DNS:{dns1}"],
                "authority_cert_serial_number": s1,
            },
            "extension_type": x509.AuthorityKeyIdentifier(None, [dns(dns1)], s1),
            "text": f"* Issuer:\n  * DNS:{dns1}\n* Serial: {s1}",
        },
    }

    def test_from_subject_key_identifier(self) -> None:
        """Test creating an extension from a subject key identifier."""
        for config in self.test_values.values():
            if not isinstance(config["expected"], bytes):
                continue

            with self.silence_warnings():
                ski = SubjectKeyIdentifier({"value": config["expected"]})
                ext = self.ext_class(ski)
                self.assertExtensionEqual(ext, self.ext_class({"value": config["expected"]}))

    def test_none_value(self) -> None:
        """Test that we can use and pass None as values for GeneralNamesList values."""
        with self.silence_warnings():
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
            "admin_html": "CA: False",
            "values": [
                {"ca": False},
                {"ca": False, "pathlen": 3},  # ignored b/c ca=False
                {"ca": False, "pathlen": None},  # ignored b/c ca=False
            ],
            "expected": {"ca": False, "pathlen": None},
            "expected_repr": "ca=False",
            "expected_serialized": {"ca": False},
            "extension_type": x509.BasicConstraints(ca=False, path_length=None),
            "text": "CA:FALSE",
        },
        "no_pathlen": {
            # include div to make sure that there's no pathlen
            "admin_html": "<div class='django-ca-extension-value'>CA: True</div>",
            "values": [
                {"ca": True},
                {"ca": True, "pathlen": None},
            ],
            "expected": {"ca": True, "pathlen": None},
            "expected_repr": "ca=True, pathlen=None",
            "expected_serialized": {"ca": True, "pathlen": None},
            "extension_type": x509.BasicConstraints(ca=True, path_length=None),
            "text": "CA:TRUE",
        },
        "pathlen_zero": {
            "admin_html": "CA: True, path length: 0",
            "values": [
                {"ca": True, "pathlen": 0},
            ],
            "expected": {"ca": True, "pathlen": 0},
            "expected_repr": "ca=True, pathlen=0",
            "expected_serialized": {"ca": True, "pathlen": 0},
            "extension_type": x509.BasicConstraints(ca=True, path_length=0),
            "text": "CA:TRUE, pathlen:0",
        },
        "pathlen_three": {
            "admin_html": "CA: True, path length: 3",
            "values": [
                {"ca": True, "pathlen": 3},
            ],
            "expected": {"ca": True, "pathlen": 3},
            "expected_repr": "ca=True, pathlen=3",
            "expected_serialized": {"ca": True, "pathlen": 3},
            "extension_type": x509.BasicConstraints(ca=True, path_length=3),
            "text": "CA:TRUE, pathlen:3",
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

    text1, text2, text3, text4, text5, text6 = [f"text{i}" for i in range(1, 7)]

    un1: ParsablePolicyInformation = {
        "policy_identifier": oid,
        "policy_qualifiers": [text1],
    }
    un1_1: ParsablePolicyInformation = {
        "policy_identifier": x509.ObjectIdentifier(oid),
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
    un2_1: ParsablePolicyInformation = {
        "policy_identifier": oid,
        "policy_qualifiers": [x509.UserNotice(explicit_text=text2, notice_reference=None)],
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
    un3_1: ParsablePolicyInformation = {
        "policy_identifier": oid,
        "policy_qualifiers": [
            {"notice_reference": x509.NoticeReference(organization=text3, notice_numbers=[1])}
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
    un6: ParsablePolicyInformation = {"policy_identifier": oid, "policy_qualifiers": None}
    un7: ParsablePolicyInformation = {
        "policy_identifier": oid,
        "policy_qualifiers": [
            {
                "explicit_text": text5,
                "notice_reference": {
                    "notice_numbers": [1],
                },
            },
        ],
    }
    p1 = PolicyInformation(un1)
    p2 = PolicyInformation(un2)
    p3 = PolicyInformation(un3)
    p4 = PolicyInformation(un4)
    p6 = PolicyInformation(un6)
    p7 = PolicyInformation(un7)

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
    xun7 = x509.UserNotice(
        explicit_text=text5,
        notice_reference=x509.NoticeReference(organization=None, notice_numbers=[1]),
    )
    xpi1 = x509.PolicyInformation(policy_identifier=ObjectIdentifier(oid), policy_qualifiers=[xun1])
    xpi2 = x509.PolicyInformation(policy_identifier=ObjectIdentifier(oid), policy_qualifiers=[xun2])
    xpi3 = x509.PolicyInformation(policy_identifier=ObjectIdentifier(oid), policy_qualifiers=[xun3])
    xpi4 = x509.PolicyInformation(policy_identifier=ObjectIdentifier(oid), policy_qualifiers=[xun4_1, xun4_2])
    xpi6 = x509.PolicyInformation(policy_identifier=ObjectIdentifier(oid), policy_qualifiers=None)
    xpi7 = x509.PolicyInformation(policy_identifier=ObjectIdentifier(oid), policy_qualifiers=[xun7])

    xcp1 = x509.CertificatePolicies(policies=[xpi1])
    xcp2 = x509.CertificatePolicies(policies=[xpi2])
    xcp3 = x509.CertificatePolicies(policies=[xpi3])
    xcp4 = x509.CertificatePolicies(policies=[xpi4])
    xcp5 = x509.CertificatePolicies(policies=[xpi1, xpi2, xpi4])
    xcp6 = x509.CertificatePolicies(policies=[xpi6])
    xcp7 = x509.CertificatePolicies(policies=[xpi7])

    test_values = {
        "one": {
            "admin_html": "<ul><li>text1</li></ul>",
            "values": [[un1], [un1_1], [xpi1]],
            "expected": [p1],
            "expected_djca": [p1],
            "expected_repr": "1 policy",
            "expected_serialized": [un1],
            "extension_type": xcp1,
            "text": f"* Policy Identifier: {oid}\n  Policy Qualifiers:\n  * text1",
        },
        "two": {
            "admin_html": f"<ul><li>User Notice:<ul><li>Explicit Text: {text2}</li></ul></li></ul>",
            "values": [[un2], [un2_1], [xpi2]],
            "expected": [p2],
            "expected_djca": [p2],
            "expected_repr": "1 policy",
            "expected_serialized": [un2],
            "extension_type": xcp2,
            "text": f"""* Policy Identifier: {oid}
  Policy Qualifiers:
  * User Notice:
    * Explicit Text: {text2}""",
        },
        "three": {
            "admin_html": f"""<ul>
    <li>User Notice:<ul>
        <li>Notice Reference:<ul>
            <li>Organization: {text3}</li>
            <li>Notice Numbers: [1]</li>
    </ul></li>
</ul></li></ul>""",
            "values": [[un3], [un3_1], [xpi3]],
            "expected": [p3],
            "expected_djca": [p3],
            "expected_repr": "1 policy",
            "expected_serialized": [un3],
            "extension_type": xcp3,
            "text": f"""* Policy Identifier: {oid}
  Policy Qualifiers:
  * User Notice:
    * Notice Reference:
      * Organization: {text3}
      * Notice Numbers: [1]""",
        },
        "four": {
            "admin_html": f"""
    <ul>
        <li>{text4}</li>
        <li>User Notice:
            <ul>
                <li>Explicit Text: text5</li>
                <li>Notice Reference:
                    <ul>
                        <li>Organization: {text6}</li>
                        <li>Notice Numbers: [1, 2, 3]</li>
                    </ul>
                </li>
            </ul>
        </li>
    </ul>""",
            "values": [[un4], [xpi4]],
            "expected": [p4],
            "expected_djca": [p4],
            "expected_repr": "1 policy",
            "expected_serialized": [un4],
            "extension_type": xcp4,
            "text": f"""* Policy Identifier: {oid}
  Policy Qualifiers:
  * {text4}
  * User Notice:
    * Explicit Text: {text5}
    * Notice Reference:
      * Organization: {text6}
      * Notice Numbers: [1, 2, 3]""",
        },
        "five": {
            "admin_html": f"""<ul>
  <li>Unknown OID ({oid}):
    <ul>
      <li>{text1}</li>
    </ul>
  </li>
  <li>Unknown OID ({oid}):
    <ul>
      <li>
          User Notice:
          <ul><li>Explicit Text: {text2}</li></ul>
      </li>
    </ul>
  </li>
  <li>Unknown OID ({oid}):
    <ul>
      <li>{text4}</li>
      <li>
          User Notice:
          <ul>
            <li>Explicit Text: {text5}</li>
            <li>Notice Reference:
              <ul>
                  <li>Organization: {text6}</li>
                  <li>Notice Numbers: [1, 2, 3]</li>
              </ul>
            </li>
          </ul>
      </li>
    </ul>
  </li>
</ul>""",
            "values": [[un1, un2, un4], [xpi1, xpi2, xpi4], [un1, xpi2, un4]],
            "expected": [p1, p2, p4],
            "expected_djca": [p1, p2, p4],
            "expected_repr": "3 policies",
            "expected_serialized": [un1, un2, un4],
            "extension_type": xcp5,
            "text": f"""* Policy Identifier: {oid}
  Policy Qualifiers:
  * {text1}
* Policy Identifier: {oid}
  Policy Qualifiers:
  * User Notice:
    * Explicit Text: {text2}
* Policy Identifier: {oid}
  Policy Qualifiers:
  * {text4}
  * User Notice:
    * Explicit Text: {text5}
    * Notice Reference:
      * Organization: {text6}
      * Notice Numbers: [1, 2, 3]""",
        },
        "six": {
            "expected": [p6],
            "admin_html": """
<ul>
  <li>Unknown OID (2.5.29.32.0)
    <ul>
    <li>No Policy Qualifiers</li>
    </ul>
  </li>
</ul>""",
            "expected_repr": "1 policy",
            "expected_serialized": [un6],
            "extension_type": xcp6,
            "text": f"* Policy Identifier: {oid}\n  No Policy Qualifiers",
            "values": [[un6], [xpi6]],
        },
        "seven": {
            "expected": [p7],
            "admin_html": f"""<ul>
  <li>Unknown OID ({oid}):
    <ul>
      <li>
          User Notice:
          <ul>
            <li>Explicit Text: {text5}</li>
            <li>Notice Reference:
              <ul>
                  <li>Notice Numbers: [1]</li>
              </ul>
            </li>
          </ul>
      </li>
    </ul>
  </li>
</ul>""",
            "expected_repr": "1 policy",
            "expected_serialized": [un7],
            "extension_type": xcp7,
            "text": f"""* Policy Identifier: {oid}
  Policy Qualifiers:
  * User Notice:
    * Explicit Text: {text5}
    * Notice Reference:
      * Notice Numbers: [1]""",
            "values": [[un7], [xpi7]],
        },
    }


class ExtendedKeyUsageTestCase(
    OrderedSetExtensionTestMixin[ExtendedKeyUsage], ExtensionTestMixin[ExtendedKeyUsage], TestCase
):
    """Test ExtendedKeyUsage extension."""

    ext_class = ExtendedKeyUsage
    ext_class_key = "extended_key_usage"
    ext_class_name = "ExtendedKeyUsage"

    test_values = {
        "one": {
            "admin_html": "<ul><li>serverAuth</li></ul>",
            "values": [
                {"serverAuth"},
                {ExtendedKeyUsageOID.SERVER_AUTH},
                [ExtendedKeyUsageOID.SERVER_AUTH],
            ],
            "extension_type": x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            "expected": frozenset([ExtendedKeyUsageOID.SERVER_AUTH]),
            "expected_repr": "['serverAuth']",
            "expected_serialized": ["serverAuth"],
            "text": "* serverAuth",
        },
        "two": {
            "admin_html": "<ul><li>clientAuth</li><li>serverAuth</li></ul>",
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
            "text": "* clientAuth\n* serverAuth",
        },
        "three": {
            "admin_html": "<ul><li>clientAuth</li><li>serverAuth</li><li>timeStamping</li></ul>",
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
            "text": "* clientAuth\n* serverAuth\n* timeStamping",
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
                self.assertIn(attr, ExtendedKeyUsage._CRYPTOGRAPHY_MAPPING_REVERSED, attr)

        # make sure we haven't forgotton any keys in the form selection
        self.assertEqual(
            set(ExtendedKeyUsage.CRYPTOGRAPHY_MAPPING.keys()), {e[0] for e in ExtendedKeyUsage.CHOICES}
        )


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
            "admin_html": "skip certs: 0",
            "values": [
                0,
            ],
            "expected": 0,
            "expected_repr": "0",
            "expected_serialized": 0,
            "extension_type": x509.InhibitAnyPolicy(0),
            "text": "0",
        },
        "one": {
            "admin_html": "skip certs: 1",
            "values": [
                1,
            ],
            "expected": 1,
            "expected_repr": "1",
            "expected_serialized": 1,
            "extension_type": x509.InhibitAnyPolicy(1),
            "text": "1",
        },
    }

    def test_int(self) -> None:
        """Test passing various int values."""
        with self.silence_warnings():
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
        with self.silence_warnings():
            self.assertEqual(InhibitAnyPolicy().skip_certs, 0)

    def test_no_int(self) -> None:
        """Test passing invalid values."""
        with self.silence_warnings():
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
            "admin_html": "<ul></ul>",
            "values": [[]],
            "expected": [],
            "expected_repr": "[]",
            "expected_serialized": [],
            "extension_type": ext_class_type([]),
            "text": "",
        },
        "uri": {
            "admin_html": f"<ul><li>URI:{uri1}</li></ul>",
            "values": [[uri1], [uri(uri1)]],
            "expected": [uri(uri1)],
            "expected_repr": f"['URI:{uri1}']",
            "expected_serialized": [f"URI:{uri1}"],
            "extension_type": ext_class_type([uri(uri1)]),
            "text": f"* URI:{uri1}",
        },
        "dns": {
            "admin_html": f"<ul><li>DNS:{dns1}</li></ul>",
            "values": [[dns1], [dns(dns1)]],
            "expected": [dns(dns1)],
            "expected_repr": f"['DNS:{dns1}']",
            "expected_serialized": [f"DNS:{dns1}"],
            "extension_type": ext_class_type([dns(dns1)]),
            "text": f"* DNS:{dns1}",
        },
        "both": {
            "admin_html": f"<ul><li>URI:{uri1}</li><li>DNS:{dns1}</li></ul>",
            "values": [[uri1, dns1], [uri(uri1), dns(dns1)], [uri1, dns(dns1)], [uri(uri1), dns1]],
            "expected": [uri(uri1), dns(dns1)],
            "expected_repr": f"['URI:{uri1}', 'DNS:{dns1}']",
            "expected_serialized": [f"URI:{uri1}", f"DNS:{dns1}"],
            "extension_type": ext_class_type([uri(uri1), dns(dns1)]),
            "text": f"* URI:{uri1}\n* DNS:{dns1}",
        },
        "all": {
            "admin_html": f"""<ul>
                <li>URI:{uri1}</li><li>URI:{uri2}</li><li>DNS:{dns1}</li><li>DNS:{dns2}</li>
            </ul>""",
            "values": [
                [uri1, uri2, dns1, dns2],
                [uri(uri1), uri(uri2), dns1, dns2],
                [uri1, uri2, dns(dns1), dns(dns2)],
                [uri(uri1), uri(uri2), dns(dns1), dns(dns2)],
            ],
            "expected": [uri(uri1), uri(uri2), dns(dns1), dns(dns2)],
            "expected_repr": f"['URI:{uri1}', 'URI:{uri2}', 'DNS:{dns1}', 'DNS:{dns2}']",
            "expected_serialized": [f"URI:{uri1}", f"URI:{uri2}", f"DNS:{dns1}", f"DNS:{dns2}"],
            "extension_type": ext_class_type([uri(uri1), uri(uri2), dns(dns1), dns(dns2)]),
            "text": f"* URI:{uri1}\n* URI:{uri2}\n* DNS:{dns1}\n* DNS:{dns2}",
        },
        "order": {  # same as "all" above but other order
            "admin_html": f"""<ul>
                  <li>DNS:{dns2}</li><li>DNS:{dns1}</li><li>URI:{uri2}</li><li>URI:{uri1}</li>
            </ul>""",
            "values": [
                [dns2, dns1, uri2, uri1],
                [dns(dns2), dns(dns1), uri2, uri1],
                [dns2, dns1, uri(uri2), uri(uri1)],
                [dns(dns2), dns(dns1), uri(uri2), uri(uri1)],
            ],
            "expected": [dns(dns2), dns(dns1), uri(uri2), uri(uri1)],
            "expected_repr": f"['DNS:{dns2}', 'DNS:{dns1}', 'URI:{uri2}', 'URI:{uri1}']",
            "expected_serialized": [f"DNS:{dns2}", f"DNS:{dns1}", f"URI:{uri2}", f"URI:{uri1}"],
            "extension_type": ext_class_type([dns(dns2), dns(dns1), uri(uri2), uri(uri1)]),
            "text": f"* DNS:{dns2}\n* DNS:{dns1}\n* URI:{uri2}\n* URI:{uri1}",
        },
    }

    def test_none_value(self) -> None:
        """Test that we can pass a None value for GeneralNameList items."""
        empty = self.ext_class({"value": None})
        self.assertEqual(empty.extension_type, self.ext_class_type([]))
        self.assertEqual(empty, self.ext_class({"value": []}))
        empty.insert(0, self.value1)
        self.assertEqual(empty.extension_type, self.et1)


class KeyUsageTestCase(OrderedSetExtensionTestMixin[KeyUsage], ExtensionTestMixin[KeyUsage], TestCase):
    """Test KeyUsage extension."""

    ext_class = KeyUsage
    ext_class_key = "key_usage"
    ext_class_name = "KeyUsage"

    test_values = {
        "one": {
            "admin_html": "<ul><li>keyAgreement</li></ul>",
            "values": [{"key_agreement"}, ["keyAgreement"]],
            "expected": frozenset(["key_agreement"]),
            "expected_repr": "['key_agreement']",
            "expected_serialized": ["key_agreement"],
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
            "text": "* keyAgreement",
        },
        "two": {
            "admin_html": "<ul><li>keyAgreement</li><li>keyEncipherment</li></ul>",
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
            "expected_repr": "['key_agreement', 'key_encipherment']",
            "expected_serialized": ["key_agreement", "key_encipherment"],
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
            "text": "* keyAgreement\n* keyEncipherment",
        },
        "three": {
            "admin_html": "<ul><li>keyAgreement</li><li>keyEncipherment</li><li>nonRepudiation</li></ul>",
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
            "expected_repr": "['content_commitment', 'key_agreement', 'key_encipherment']",
            "expected_serialized": ["content_commitment", "key_agreement", "key_encipherment"],
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
            "text": "* keyAgreement\n* keyEncipherment\n* nonRepudiation",
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


class NameConstraintsTestCase(ExtensionTestMixin[NameConstraints], TestCase):
    """Test NameConstraints extension."""

    ext_class = NameConstraints
    ext_class_key = "name_constraints"
    ext_class_name = "NameConstraints"

    d1 = "example.com"
    d2 = "example.net"

    test_values = {
        "permitted": {
            "admin_html": f"Permitted:<ul><li>DNS:{d1}</li></ul>",
            "values": [
                {"permitted": [d1]},
                {"permitted": [f"DNS:{d1}"]},
                {"permitted": [dns(d1)]},
                {"permitted": [dns(d1)], "excluded": []},
            ],
            "expected": x509.NameConstraints(permitted_subtrees=[dns(d1)], excluded_subtrees=None),
            "expected_repr": f"permitted=['DNS:{d1}'], excluded=[]",
            "expected_serialized": {"permitted": [f"DNS:{d1}"]},
            "extension_type": x509.NameConstraints(permitted_subtrees=[dns(d1)], excluded_subtrees=None),
            "text": f"Permitted:\n  * DNS:{d1}",
        },
        "excluded": {
            "admin_html": f"Excluded:<ul><li>DNS:{d1}</li></ul>",
            "values": [
                {"excluded": [d1]},
                {"excluded": [f"DNS:{d1}"]},
                {"excluded": [dns(d1)]},
                {"excluded": [dns(d1)], "permitted": []},
            ],
            "expected": x509.NameConstraints(permitted_subtrees=None, excluded_subtrees=[dns(d1)]),
            "expected_repr": f"permitted=[], excluded=['DNS:{d1}']",
            "expected_serialized": {"excluded": [f"DNS:{d1}"]},
            "extension_type": x509.NameConstraints(permitted_subtrees=None, excluded_subtrees=[dns(d1)]),
            "text": f"Excluded:\n  * DNS:{d1}",
        },
        "both": {
            "admin_html": f"Permitted:<ul><li>DNS:{d1}</li></ul> Excluded:<ul><li>DNS:{d2}</li></ul>",
            "values": [
                {"permitted": [d1], "excluded": [d2]},
                {"permitted": [f"DNS:{d1}"], "excluded": [f"DNS:{d2}"]},
                {"permitted": [dns(d1)], "excluded": [dns(d2)]},
                {"permitted": [dns(d1)], "excluded": [d2]},
            ],
            "expected": x509.NameConstraints(permitted_subtrees=[dns(d1)], excluded_subtrees=[dns(d2)]),
            "expected_repr": f"permitted=['DNS:{d1}'], excluded=['DNS:{d2}']",
            "expected_serialized": {"excluded": [f"DNS:{d2}"], "permitted": [f"DNS:{d1}"]},
            "extension_type": x509.NameConstraints(permitted_subtrees=[dns(d1)], excluded_subtrees=[dns(d2)]),
            "text": f"Permitted:\n  * DNS:{d1}\nExcluded:\n  * DNS:{d2}",
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
            "admin_html": "Yes",
            "values": [{}, None],
            "expected": None,
            "expected_repr": "",
            "expected_serialized": None,
            "extension_type": x509.OCSPNoCheck(),
            "text": "Yes",
        },
    }


class PolicyConstraintsTestCase(ExtensionTestMixin[PolicyConstraints], TestCase):
    """Test PolicyConstraints extension."""

    ext_class = PolicyConstraints
    ext_class_key = "policy_constraints"
    ext_class_name = "PolicyConstraints"

    test_values = {
        "rep_zero": {
            "admin_html": "<ul><li>RequireExplicitPolicy: 0</li></ul>",
            "values": [
                {"require_explicit_policy": 0},
            ],
            "expected": {"require_explicit_policy": 0},
            "expected_repr": "require_explicit_policy=0",
            "expected_serialized": {"require_explicit_policy": 0},
            "extension_type": x509.PolicyConstraints(require_explicit_policy=0, inhibit_policy_mapping=None),
            "text": "* RequireExplicitPolicy: 0",
        },
        "rep_one": {
            "admin_html": "<ul><li>RequireExplicitPolicy: 1</li></ul>",
            "values": [
                {"require_explicit_policy": 1},
            ],
            "expected": {"require_explicit_policy": 1},
            "expected_repr": "require_explicit_policy=1",
            "expected_serialized": {"require_explicit_policy": 1},
            "extension_type": x509.PolicyConstraints(require_explicit_policy=1, inhibit_policy_mapping=None),
            "text": "* RequireExplicitPolicy: 1",
        },
        "iap_zero": {
            "admin_html": "<ul><li>InhibitPolicyMapping: 0</li></ul>",
            "values": [
                {"inhibit_policy_mapping": 0},
            ],
            "expected": {"inhibit_policy_mapping": 0},
            "expected_repr": "inhibit_policy_mapping=0",
            "expected_serialized": {"inhibit_policy_mapping": 0},
            "extension_type": x509.PolicyConstraints(require_explicit_policy=None, inhibit_policy_mapping=0),
            "text": "* InhibitPolicyMapping: 0",
        },
        "iap_one": {
            "admin_html": "<ul><li>InhibitPolicyMapping: 1</li></ul>",
            "values": [
                {"inhibit_policy_mapping": 1},
            ],
            "expected": {"inhibit_policy_mapping": 1},
            "expected_repr": "inhibit_policy_mapping=1",
            "expected_serialized": {"inhibit_policy_mapping": 1},
            "extension_type": x509.PolicyConstraints(require_explicit_policy=None, inhibit_policy_mapping=1),
            "text": "* InhibitPolicyMapping: 1",
        },
        "both": {
            "admin_html": "<ul><li>InhibitPolicyMapping: 2</li><li>RequireExplicitPolicy: 3</li></ul>",
            "values": [
                {"inhibit_policy_mapping": 2, "require_explicit_policy": 3},
            ],
            "expected": {"inhibit_policy_mapping": 2, "require_explicit_policy": 3},
            "expected_repr": "inhibit_policy_mapping=2, require_explicit_policy=3",
            "expected_serialized": {"inhibit_policy_mapping": 2, "require_explicit_policy": 3},
            "extension_type": x509.PolicyConstraints(require_explicit_policy=3, inhibit_policy_mapping=2),
            "text": "* InhibitPolicyMapping: 2\n* RequireExplicitPolicy: 3",
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


class PrecertPoisonTestCase(NullExtensionTestMixin[PrecertPoison], TestCase):
    """Test PrecertPoison extension."""

    ext_class = PrecertPoison
    ext_class_key = "precert_poison"
    ext_class_name = "PrecertPoison"
    force_critical = True
    test_values: TestValues = {
        "empty": {
            "admin_html": "Yes",
            "values": [{}, None],
            "expected": None,
            "expected_repr": "",
            "expected_serialized": None,
            "extension_type": x509.PrecertPoison(),
            "text": "Yes",
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
        with self.silence_warnings(), self.assertRaisesRegex(
            ValueError, r"^PrecertPoison must always be marked as critical$"
        ):
            PrecertPoison({"critical": False})  # type: ignore[arg-type]


class PrecertificateSignedCertificateTimestampsTestCase(TestCaseMixin, TestCase):
    """Test PrecertificateSignedCertificateTimestamps extension."""

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

    def test_parse_extensino(self) -> None:
        """Test parsing the extension (which fails)."""
        message = rf"^{self.ext_class_key}: Cannot parse extensions of this type\.$"
        with self.assertRaisesRegex(ValueError, message):
            parse_extension(self.ext_class_key, {})

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
    Log ID: 6F:53:76:AC:31:F0:31:19:D8:99:00:A4:51:15:FF:77:15:1C:11:D9:02:C1:00:29:06:8D:B2:08:9A:37:D9:13
* Precertificate ({v[1][version]}):
    Timestamp: {v[1][timestamp]}
    Log ID: 29:3C:51:96:54:C8:39:65:BA:AA:50:FC:58:07:D4:B7:6F:BF:58:7A:29:72:DC:A4:C3:0C:F4:E5:45:47:F4:78""".format(  # NOQA: E501
                v=self.data1["value"]
            ),
        )

        self.assertEqual(
            self.ext2.as_text(),
            """* Precertificate ({v[0][version]}):
    Timestamp: {v[0][timestamp]}
    Log ID: A4:B9:09:90:B4:18:58:14:87:BB:13:A2:CC:67:70:0A:3C:35:98:04:F9:1B:DF:B8:E3:77:CD:0E:C8:0D:DC:10
* Precertificate ({v[1][version]}):
    Timestamp: {v[1][timestamp]}
    Log ID: 56:14:06:9A:2F:D7:C2:EC:D3:F5:E1:BD:44:B2:3E:C7:46:76:B9:BC:99:11:5C:C0:EF:94:98:55:D6:89:D0:DD
* Precertificate ({v[2][version]}):
    Timestamp: {v[2][timestamp]}
    Log ID: EE:4B:BD:B7:75:CE:60:BA:E1:42:69:1F:AB:E1:9E:66:A3:0F:7E:5F:B0:72:D8:83:00:C4:7B:89:7A:A8:FD:CB""".format(  # NOQA: E501
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
        self.assertEqual(serialize_extension(self.cgx1), self.data1)
        self.assertEqual(serialize_extension(self.cgx2), self.data2)

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

    deprecation_msg = r"^django_ca\.extensions\.base\.UnrecognizedExtension is deprecated and will be removed in django-ca 1\.24\.0\.$"  # noqa: E501
    oid = x509.ObjectIdentifier("1.2.1")
    value = x509.UnrecognizedExtension(oid=oid, value=b"unrecognized")
    ext = x509.Extension(
        oid=oid, value=x509.UnrecognizedExtension(oid=oid, value=b"unrecognized"), critical=True
    )
    hex_value = "75:6E:72:65:63:6F:67:6E:69:7A:65:64"

    def test_basic(self) -> None:
        """Only test basic functionality."""
        oid = x509.ObjectIdentifier("1.2.1")
        with self.assertWarnsRegex(RemovedInDjangoCA124Warning, self.deprecation_msg):
            ext = UnrecognizedExtension(self.ext)

        self.assertEqual(ext.name, f"Unsupported extension (OID {oid.dotted_string})")
        self.assertEqual(ext.as_extension(), self.ext)
        self.assertEqual(
            str(ext), f"<Unsupported extension (OID {oid.dotted_string}): <unprintable>, critical=True>"
        )

    def test_as_text(self) -> None:
        """Test rendering an unrecognized extension as text."""
        self.assertEqual(extension_as_text(self.value), self.hex_value)

    def test_invalid_extension(self) -> None:
        """Test creating from an actually recognized extension."""
        value = x509.Extension(
            oid=SubjectAlternativeName.oid,
            critical=True,
            value=x509.SubjectAlternativeName([uri("example.com")]),
        )
        with self.assertRaisesRegex(TypeError, r"^Extension value must be a x509\.UnrecognizedExtension$"):
            with self.assertWarnsRegex(RemovedInDjangoCA124Warning, self.deprecation_msg):
                UnrecognizedExtension(value)  # type: ignore[arg-type]

    def test_from_dict(self) -> None:
        """Test that you cannot instantiate this extension from a dict."""
        with self.assertRaisesRegex(TypeError, r"Value must be a x509\.Extension instance$"):
            with self.assertWarnsRegex(RemovedInDjangoCA124Warning, self.deprecation_msg):
                UnrecognizedExtension({"value": "foo"})  # type: ignore[arg-type]

    def test_serialized(self) -> None:
        """Test serializing an unknown extension."""
        self.assertEqual(
            serialize_extension(self.ext), {"critical": self.ext.critical, "value": self.hex_value}
        )

        # Was not allowed in legacy class based extensions
        with self.assertWarnsRegex(RemovedInDjangoCA124Warning, self.deprecation_msg):
            ext = UnrecognizedExtension(self.ext)
        with self.assertRaisesRegex(ValueError, r"^Cannot serialize an unrecognized extension$"):
            ext.serialize_value()

    def test_abstract_methods(self) -> None:
        """Test overwritten abstract methods that are of no use in this class."""
        oid = x509.ObjectIdentifier("1.2.1")
        cgext = x509.Extension(
            oid=oid, value=x509.UnrecognizedExtension(oid=oid, value=b"unrecognized"), critical=True
        )
        with self.assertWarnsRegex(RemovedInDjangoCA124Warning, self.deprecation_msg):
            ext = UnrecognizedExtension(cgext)

        with self.assertRaises(NotImplementedError):
            ext.from_dict("foo")

        with self.assertRaises(NotImplementedError):
            ext.from_extension("foo")


class SignedCertificateTimestampsTestCase(TestCaseMixin, TestCase):
    """Test PrecertificateSignedCertificateTimestamps extension."""

    ext_class_key = "signed_certificate_timestamps"
    ext_class_name = "SignedCertificateTimestamps"

    def test_parse_extensino(self) -> None:
        """Test parsing the extension (which fails)."""
        message = rf"^{self.ext_class_key}: Cannot parse extensions of this type\.$"
        with self.assertRaisesRegex(ValueError, message):
            parse_extension(self.ext_class_key, {})


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
            "admin_html": "<ul></ul>",
            "values": [[]],
            "expected": [],
            "expected_repr": "[]",
            "expected_serialized": [],
            "extension_type": x509.SubjectAlternativeName([]),
            "text": "",
        },
        "uri": {
            "admin_html": f"<ul><li>URI:{uri1}</li></ul>",
            "values": [[uri1], [uri(uri1)]],
            "expected": [uri(uri1)],
            "expected_repr": f"['URI:{uri1}']",
            "expected_serialized": [f"URI:{uri1}"],
            "extension_type": x509.SubjectAlternativeName([uri(uri1)]),
            "text": f"* URI:{uri1}",
        },
        "dns": {
            "admin_html": f"<ul><li>DNS:{dns1}</li></ul>",
            "values": [[dns1], [dns(dns1)]],
            "expected": [dns(dns1)],
            "expected_repr": f"['DNS:{dns1}']",
            "expected_serialized": [f"DNS:{dns1}"],
            "extension_type": x509.SubjectAlternativeName([dns(dns1)]),
            "text": f"* DNS:{dns1}",
        },
        "both": {
            "admin_html": f"<ul><li>URI:{uri1}</li><li>DNS:{dns1}</li></ul>",
            "values": [[uri1, dns1], [uri(uri1), dns(dns1)], [uri1, dns(dns1)], [uri(uri1), dns1]],
            "expected": [uri(uri1), dns(dns1)],
            "expected_repr": f"['URI:{uri1}', 'DNS:{dns1}']",
            "expected_serialized": [f"URI:{uri1}", f"DNS:{dns1}"],
            "extension_type": x509.SubjectAlternativeName([uri(uri1), dns(dns1)]),
            "text": f"* URI:{uri1}\n* DNS:{dns1}",
        },
        "all": {
            "admin_html": f"""<ul>
    <li>URI:{uri1}</li>
    <li>URI:{uri2}</li>
    <li>DNS:{dns1}</li>
    <li>DNS:{dns2}</li>
</ul>""",
            "values": [
                [uri1, uri2, dns1, dns2],
                [uri(uri1), uri(uri2), dns1, dns2],
                [uri1, uri2, dns(dns1), dns(dns2)],
                [uri(uri1), uri(uri2), dns(dns1), dns(dns2)],
            ],
            "expected": [uri(uri1), uri(uri2), dns(dns1), dns(dns2)],
            "expected_repr": f"['URI:{uri1}', 'URI:{uri2}', 'DNS:{dns1}', 'DNS:{dns2}']",
            "expected_serialized": [f"URI:{uri1}", f"URI:{uri2}", f"DNS:{dns1}", f"DNS:{dns2}"],
            "extension_type": x509.SubjectAlternativeName([uri(uri1), uri(uri2), dns(dns1), dns(dns2)]),
            "text": f"* URI:{uri1}\n* URI:{uri2}\n* DNS:{dns1}\n* DNS:{dns2}",
        },
        "order": {  # same as "all" above but other order
            "admin_html": f"""<ul>
    <li>DNS:{dns2}</li>
    <li>DNS:{dns1}</li>
    <li>URI:{uri2}</li>
    <li>URI:{uri1}</li>
</ul>""",
            "values": [
                [dns2, dns1, uri2, uri1],
                [dns(dns2), dns(dns1), uri2, uri1],
                [dns2, dns1, uri(uri2), uri(uri1)],
                [dns(dns2), dns(dns1), uri(uri2), uri(uri1)],
            ],
            "expected": [dns(dns2), dns(dns1), uri(uri2), uri(uri1)],
            "expected_repr": f"['DNS:{dns2}', 'DNS:{dns1}', 'URI:{uri2}', 'URI:{uri1}']",
            "expected_serialized": [f"DNS:{dns2}", f"DNS:{dns1}", f"URI:{uri2}", f"URI:{uri1}"],
            "extension_type": x509.SubjectAlternativeName([dns(dns2), dns(dns1), uri(uri2), uri(uri1)]),
            "text": f"* DNS:{dns2}\n* DNS:{dns1}\n* URI:{uri2}\n* URI:{uri1}",
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
            "admin_html": hex1,
            "values": [
                x509.SubjectKeyIdentifier(b1),
                b1,
                hex1,
            ],
            "expected": b1,
            "expected_repr": hex1,
            "expected_serialized": hex1,
            "extension_type": x509.SubjectKeyIdentifier(b1),
            "text": hex1,
        },
        "two": {
            "admin_html": hex2,
            "values": [
                x509.SubjectKeyIdentifier(b2),
                b2,
                hex2,
            ],
            "expected": b2,
            "expected_repr": hex2,
            "expected_serialized": hex2,
            "extension_type": x509.SubjectKeyIdentifier(b2),
            "text": hex2,
        },
        "three": {
            "admin_html": hex3,
            "values": [
                x509.SubjectKeyIdentifier(b3),
                b3,
                hex3,
            ],
            "expected": b3,
            "expected_repr": hex3,
            "expected_serialized": hex3,
            "extension_type": x509.SubjectKeyIdentifier(b3),
            "text": hex3,
        },
    }

    def test_ski_constructor(self) -> None:
        """Test passing x509.SubjectKeyIdentifier."""

        with self.silence_warnings():
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
            "admin_html": "<ul><li>OCSPMustStaple</li></ul>",
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
            "expected_serialized": ["status_request"],
            "text": "* OCSPMustStaple",
        },
        "two": {
            "admin_html": "<ul><li>OCSPMustStaple</li><li>MultipleCertStatusRequest</li></ul>",
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
                    TLSFeatureType.status_request,
                    TLSFeatureType.status_request_v2,
                ]
            ),
            "expected": frozenset([TLSFeatureType.status_request, TLSFeatureType.status_request_v2]),
            "expected_repr": "['MultipleCertStatusRequest', 'OCSPMustStaple']",
            "expected_serialized": ["status_request", "status_request_v2"],
            "text": "* MultipleCertStatusRequest\n* OCSPMustStaple",
        },
        "three": {
            "admin_html": "<ul><li>MultipleCertStatusRequest</li></ul>",
            "values": [
                {TLSFeatureType.status_request_v2},
                {"MultipleCertStatusRequest"},
            ],
            "extension_type": x509.TLSFeature(features=[TLSFeatureType.status_request_v2]),
            "expected": frozenset([TLSFeatureType.status_request_v2]),
            "expected_repr": "['MultipleCertStatusRequest']",
            "expected_serialized": ["status_request_v2"],
            "text": "* MultipleCertStatusRequest",
        },
    }

    def test_unknown_values(self) -> None:
        """Test passing unknown values."""
        with self.assertRaisesRegex(ValueError, r"^Unknown value: foo$"):
            TLSFeature({"value": ["foo"]})

        with self.assertRaisesRegex(ValueError, r"^Unknown value: True$"):
            TLSFeature({"value": [True]})


class CertificateExtensionTestCase(TestCaseMixin, TestCase):
    """Test output for all extensions in our certificate fixtures."""

    load_cas = "__all__"
    load_certs = "__all__"
    admin_html: typing.Dict[str, typing.Dict[x509.ObjectIdentifier, str]] = {
        "root": {},
        "child": {
            ExtensionOID.BASIC_CONSTRAINTS: f"CA: True, path length: {certs['child']['pathlen']}",
        },
        "ecc": {
            ExtensionOID.BASIC_CONSTRAINTS: f"CA: True, path length: {certs['ecc']['pathlen']}",
        },
        "dsa": {
            ExtensionOID.BASIC_CONSTRAINTS: f"CA: True, path length: {certs['dsa']['pathlen']}",
            ExtensionOID.SUBJECT_KEY_IDENTIFIER: certs["dsa"]["subject_key_identifier_serialized"]["value"],
        },
        "pwd": {
            ExtensionOID.BASIC_CONSTRAINTS: f"CA: True, path length: {certs['pwd']['pathlen']}",
        },
        "trustid_server_a52": {
            ExtensionOID.CERTIFICATE_POLICIES: """<ul>
  <li>Unknown OID (2.5.29.32.0):
    <ul>
      <li>User Notice:
          <ul>
            <li>Notice Reference:
              <ul>
                  <li>Organization: https://secure.identrust.com/certificates/policy/ts/index.html</li>
              </ul>
            </li>
          </ul>
      </li>
      <li>User Notice:
          <ul>
            <li>Explicit Text: This TrustID Server Certificate has been issued in accordance with IdenTrust&#x27;s TrustID Certificate Policy found at https://secure.identrust.com/certificates/policy/ts/index.html</li>
          </ul>
      </li>
    </ul>
  </li>
</ul>""",  # NOQA: E501
            ExtensionOID.EXTENDED_KEY_USAGE: """<ul>
  <li>serverAuth</li><li>clientAuth</li><li>ipsecEndSystem</li><li>ipsecTunnel</li><li>ipsecUser</li>
</ul>""",
        },
        "digicert_ev_root": {},
        "comodo": {},
        "comodo_dv": {
            ExtensionOID.BASIC_CONSTRAINTS: "CA: True, path length: 0",
            ExtensionOID.CERTIFICATE_POLICIES: """<ul>
  <li>Unknown OID (2.5.29.32.0)
    <ul><li>No Policy Qualifiers</li></ul>
  </li>
  <li>Unknown OID (2.23.140.1.2.1)
    <ul><li>No Policy Qualifiers</li></ul>
  </li>
</ul>""",
            ExtensionOID.EXTENDED_KEY_USAGE: "<ul><li>serverAuth</li><li>clientAuth</li></ul>",
        },
        "comodo_ev": {
            ExtensionOID.BASIC_CONSTRAINTS: "CA: True, path length: 0",
            ExtensionOID.CERTIFICATE_POLICIES: """<ul>
  <li>Unknown OID (2.5.29.32.0):
    <ul><li>https://secure.comodo.com/CPS</li></ul>
  </li>
</ul>""",
        },
        "digicert_global_root": {},
        "digicert_ha_intermediate": {
            ExtensionOID.BASIC_CONSTRAINTS: "CA: True, path length: 0",
            ExtensionOID.CERTIFICATE_POLICIES: """<ul>
  <li>Unknown OID (2.5.29.32.0):
    <ul><li>https://www.digicert.com/CPS</li></ul>
  </li>
</ul>
""",
            ExtensionOID.EXTENDED_KEY_USAGE: "<ul><li>serverAuth</li><li>clientAuth</li></ul>",
        },
        "digicert_sha2": {
            ExtensionOID.BASIC_CONSTRAINTS: "CA: True, path length: 0",
            ExtensionOID.CERTIFICATE_POLICIES: """<ul><li>Unknown OID (2.5.29.32.0):
                <ul><li>https://www.digicert.com/CPS</li></ul></li>""",
        },
        "dst_root_x3": {},
        "geotrust": {},
        "globalsign": {},
        "globalsign_dv": {
            ExtensionOID.BASIC_CONSTRAINTS: "CA: True, path length: 0",
            ExtensionOID.CERTIFICATE_POLICIES: """<ul>
  <li>Unknown OID (2.5.29.32.0):
    <ul><li>https://www.globalsign.com/repository/</li></ul>
  </li>
</ul>""",
        },
        "globalsign_r2_root": {},
        "godaddy_g2_intermediate": {
            ExtensionOID.CERTIFICATE_POLICIES: """<ul><li>Unknown OID (2.5.29.32.0):
    <ul><li>https://certs.godaddy.com/repository/</li></ul>
  </li>
</ul>""",
        },
        "godaddy_g2_root": {},
        "google_g3": {
            ExtensionOID.BASIC_CONSTRAINTS: "CA: True, path length: 0",
            ExtensionOID.CERTIFICATE_POLICIES: """<ul><li>Unknown OID (2.23.140.1.2.2):
                <ul><li>https://pki.goog/repository/ </li> </ul>
              </li></ul>""",
            ExtensionOID.EXTENDED_KEY_USAGE: "<ul><li>serverAuth</li><li>clientAuth</li></ul>",
        },
        "identrust_root_1": {},
        "letsencrypt_x1": {
            ExtensionOID.BASIC_CONSTRAINTS: "CA: True, path length: 0",
            ExtensionOID.CERTIFICATE_POLICIES: """<ul>
  <li>Unknown OID (2.23.140.1.2.1)
    <ul><li>No Policy Qualifiers</li></ul>
  </li>
  <li>Unknown OID (1.3.6.1.4.1.44947.1.1.1):
    <ul>
      <li>
          http://cps.root-x1.letsencrypt.org
      </li>
    </ul>
  </li>
</ul>""",
            ExtensionOID.NAME_CONSTRAINTS: "Excluded:<ul><li>DNS:.mil</li></ul>",
        },
        "letsencrypt_x3": {
            ExtensionOID.BASIC_CONSTRAINTS: "CA: True, path length: 0",
            ExtensionOID.CERTIFICATE_POLICIES: """<ul>
  <li>Unknown OID (2.23.140.1.2.1)
    <ul><li>No Policy Qualifiers</li></ul>
  </li>
  <li>Unknown OID (1.3.6.1.4.1.44947.1.1.1):
    <ul>
      <li>
          http://cps.root-x1.letsencrypt.org
      </li>
    </ul>
  </li>
</ul>""",
        },
        "rapidssl_g3": {
            ExtensionOID.BASIC_CONSTRAINTS: "CA: True, path length: 0",
            ExtensionOID.CERTIFICATE_POLICIES: """<ul><li>Unknown OID (2.16.840.1.113733.1.7.54):
                <ul><li>http://www.geotrust.com/resources/cps </li></ul></li></ul>""",
        },
        "startssl_class2": {
            ExtensionOID.BASIC_CONSTRAINTS: "CA: True, path length: 0",
            ExtensionOID.CERTIFICATE_POLICIES: """<ul>
              <li>Unknown OID (2.5.29.32.0):
                <ul><li>http://www.startssl.com/policy.pdf</li></ul>
              </li>
            </ul>""",
        },
        "startssl_class3": {
            ExtensionOID.BASIC_CONSTRAINTS: "CA: True, path length: 0",
            ExtensionOID.CERTIFICATE_POLICIES: """<ul>
              <li>Unknown OID (2.5.29.32.0):
                <ul><li>http://www.startssl.com/policy</li></ul>
              </li>
            </ul>""",
        },
        "startssl_root": {
            ExtensionOID.CERTIFICATE_POLICIES: """<ul>
  <li>Unknown OID (1.3.6.1.4.1.23223.1.1.1):
    <ul>
      <li>http://www.startssl.com/policy.pdf</li>
      <li>http://www.startssl.com/intermediate.pdf</li>
      <li>
          User Notice:
          <ul>
            <li>Explicit Text: Limited Liability, read the section *Legal Limitations* of the StartCom
                Certification Authority Policy available at http://www.startssl.com/policy.pdf</li>
            <li>Notice Reference:
              <ul>
                  <li>Organization: Start Commercial (StartCom) Ltd.</li>
                  <li>Notice Numbers: [1]</li>
              </ul>
            </li>
          </ul>
      </li>
    </ul>
  </li>
</ul>""",
            x509.ObjectIdentifier("2.16.840.1.113730.1.1"): "03:02:00:07",
            x509.ObjectIdentifier(
                "2.16.840.1.113730.1.13"
            ): "16:29:53:74:61:72:74:43:6F:6D:20:46:72:65:65:20:53:53:4C:20:43:65:72:74:69:66:69:63:61:74:69:6F:6E:20:41:75:74:68:6F:72:69:74:79",  # NOQA: E501
        },
        ##########################
        # Generated certificates #
        ##########################
        "all-extensions": {
            ExtensionOID.FRESHEST_CRL: f"""DistributionPoint:<ul>
                <li>Full Name: {certs['all-extensions']['freshest_crl_serialized']['value'][0]['full_name'][0]}</li>
            </ul>""",  # NOQA: E501
            ExtensionOID.INHIBIT_ANY_POLICY: "skip certs: 1",
            ExtensionOID.NAME_CONSTRAINTS: """Permitted: <ul><li>DNS:.org</li></ul>
                Excluded: <ul><li>DNS:.net</li></ul>""",
            ExtensionOID.EXTENDED_KEY_USAGE: """<ul>
                <li>clientAuth</li><li>codeSigning</li><li>emailProtection</li><li>serverAuth</li>
            </ul>""",
            ExtensionOID.OCSP_NO_CHECK: "Yes",
            ExtensionOID.POLICY_CONSTRAINTS: """<ul>
                <li>InhibitPolicyMapping: 2</li><li>RequireExplicitPolicy: 1</li>
            </ul>""",
            ExtensionOID.PRECERT_POISON: "Yes",
            ExtensionOID.TLS_FEATURE: "<ul><li>MultipleCertStatusRequest</li><li>OCSPMustStaple</li></ul>",
        },
        "alt-extensions": {
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER: """
<ul>
  <li>Key ID: <span class="django-ca-serial">30</span></li>
  <li>Authority certificate issuer:
    <ul><li>DNS:example.com</li></ul>
  </li>
  <li>Authority certificate issuer:
    <span class="django-ca-serial">01</span>
  </li>
</ul>""",
            ExtensionOID.CRL_DISTRIBUTION_POINTS: """
DistributionPoint:
<ul><li>Full Name: URI:https://example.com</li></ul>

DistributionPoint:
<ul>
  <li>Relative Name: /CN=rdn.ca.example.com</li>
  <li>CRL Issuer: URI:http://crl.ca.example.com, URI:http://crl.ca.example.net</li>
  <li>Reasons: ca_compromise, key_compromise</li>
</ul>""",
            ExtensionOID.EXTENDED_KEY_USAGE: """<ul>
                <li>clientAuth</li><li>codeSigning</li><li>emailProtection</li><li>serverAuth</li>
            </ul>""",
            ExtensionOID.NAME_CONSTRAINTS: "Permitted: <ul><li>DNS:.org</li></ul>",
            ExtensionOID.OCSP_NO_CHECK: "Yes",
            ExtensionOID.TLS_FEATURE: "<ul><li>OCSPMustStaple</li></ul>",
        },
        ##########################
        # 3rd party certificates #
        ##########################
        "cloudflare_1": {
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER: """<ul>
              <li>Key ID: <span class="django-ca-serial">
                  40:09:61:67:F0:BC:83:71:4F:DE:12:08:2C:6F:D4:D4:2B:76:3D:96
            </span></li>""",
            ExtensionOID.CERTIFICATE_POLICIES: """<ul>
              <li>Unknown OID (1.3.6.1.4.1.6449.1.2.2.7):
                <ul><li>https://secure.comodo.com/CPS</li></ul>
              </li>
              <li>Unknown OID (2.23.140.1.2.1) <ul><li>No Policy Qualifiers</li></ul></li>
            </ul>""",
            ExtensionOID.PRECERT_POISON: "Yes",
        },
        "comodo_dv-cert": {
            ExtensionOID.CERTIFICATE_POLICIES: """<ul>
                <li>Unknown OID (1.3.6.1.4.1.6449.1.2.2.7):
                    <ul><li>https://secure.comodo.com/CPS</li></ul>
                </li>

                <li>Unknown OID (2.23.140.1.2.1)
                    <ul><li>No Policy Qualifiers</li></ul>
                </li>
            </ul>""",
            ExtensionOID.EXTENDED_KEY_USAGE: "<ul><li>serverAuth</li><li>clientAuth</li></ul>",
        },
        "comodo_ev-cert": {
            ExtensionOID.CERTIFICATE_POLICIES: """<ul>
                <li>Unknown OID (1.3.6.1.4.1.6449.1.2.1.5.1):
                    <ul><li>https://secure.comodo.com/CPS</li></ul>
                </li>
                <li>Unknown OID (2.23.140.1.1)
                    <ul><li>No Policy Qualifiers</li></ul>
                </li>
            </ul>""",
            ExtensionOID.EXTENDED_KEY_USAGE: "<ul><li>serverAuth</li><li>clientAuth</li></ul>",
            ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS: """<table>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Timestamp</th>
                  <th>Log ID</th>
                  <th>Version</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Precertificate</td>
                  <td>A4:B9:09:90:B4:18:58:14:87:BB:13:A2:CC:67:70:0A:3C:35:98:04:F9:1B:DF:B8:E3:77:CD:0E:C8:0D:DC:10</td>
                  <td>2018-03-14 14:23:09.403000</td>
                  <td>v1</td>
                </tr>
                <tr>
                  <td>Precertificate</td>
                  <td>56:14:06:9A:2F:D7:C2:EC:D3:F5:E1:BD:44:B2:3E:C7:46:76:B9:BC:99:11:5C:C0:EF:94:98:55:D6:89:D0:DD</td>
                  <td>2018-03-14 14:23:08.912000</td>
                  <td>v1</td>
                </tr>
                <tr>
                  <td>Precertificate</td>
                  <td>EE:4B:BD:B7:75:CE:60:BA:E1:42:69:1F:AB:E1:9E:66:A3:0F:7E:5F:B0:72:D8:83:00:C4:7B:89:7A:A8:FD:CB</td>
                  <td>2018-03-14 14:23:09.352000</td>
                  <td>v1</td>
                </tr>
              </tbody>
            </table>""",
        },
        "digicert_ha_intermediate-cert": {
            ExtensionOID.CERTIFICATE_POLICIES: """<ul>
  <li>Unknown OID (2.16.840.1.114412.1.1):
    <ul><li>https://www.digicert.com/CPS</li></ul>
  </li>

  <li>Unknown OID (2.23.140.1.2.2)
    <ul><li>No Policy Qualifiers</li></ul>
  </li>
</ul>""",
            ExtensionOID.EXTENDED_KEY_USAGE: "<ul><li>serverAuth</li><li>clientAuth</li></ul>",
            ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS: """<table>
  <thead>
    <tr>
      <th>Type</th>
      <th>Timestamp</th>
      <th>Log ID</th>
      <th>Version</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Precertificate</td>
      <td>63:F2:DB:CD:E8:3B:CC:2C:CF:0B:72:84:27:57:6B:33:A4:8D:61:77:8F:BD:75:A6:38:B1:C7:68:54:4B:D8:8D</td>
      <td>2019-02-01 15:35:06.188000</td>
      <td>v1</td>
    </tr>
    <tr>
      <td>Precertificate</td>
      <td>6F:53:76:AC:31:F0:31:19:D8:99:00:A4:51:15:FF:77:15:1C:11:D9:02:C1:00:29:06:8D:B2:08:9A:37:D9:13</td>
      <td>2019-02-01 15:35:06.526000</td>
      <td>v1</td>
    </tr>
  </tbody>
</table>""",
        },
        "digicert_sha2-cert": {
            ExtensionOID.EXTENDED_KEY_USAGE: "<ul><li>serverAuth</li><li>clientAuth</li></ul>",
            ExtensionOID.CERTIFICATE_POLICIES: """<ul>
                <li>Unknown OID (2.16.840.1.114412.1.1):
                    <ul><li>https://www.digicert.com/CPS</li></ul>
                </li>

                <li>Unknown OID (2.23.140.1.2.2)
                    <ul><li>No Policy Qualifiers</li></ul>
                </li>
            </ul>""",
            ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS: """<table>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Timestamp</th>
                  <th>Log ID</th>
                  <th>Version</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Precertificate</td>
                  <td>EE:4B:BD:B7:75:CE:60:BA:E1:42:69:1F:AB:E1:9E:66:A3:0F:7E:5F:B0:72:D8:83:00:C4:7B:89:7A:A8:FD:CB</td>
                  <td>2019-06-07 08:47:02.367000</td>
                  <td>v1</td>
                </tr>
                <tr>
                  <td>Precertificate</td>
                  <td>87:75:BF:E7:59:7C:F8:8C:43:99:5F:BD:F3:6E:FF:56:8D:47:56:36:FF:4A:B5:60:C1:B4:EA:FF:5E:A0:83:0F</td>
                  <td>2019-06-07 08:47:02.566000</td>
                  <td>v1</td>
                </tr>
              </tbody>
            </table>""",
        },
        "globalsign_dv-cert": {
            ExtensionOID.CERTIFICATE_POLICIES: """<ul>
  <li>Unknown OID (1.3.6.1.4.1.4146.1.10):
    <ul><li>https://www.globalsign.com/repository/</li></ul>
  </li>
  <li>Unknown OID (2.23.140.1.2.1)
    <ul>
      <li>No Policy Qualifiers</li>
    </ul>
  </li>
</ul>""",
            ExtensionOID.EXTENDED_KEY_USAGE: "<ul><li>serverAuth</li><li>clientAuth</li></ul>",
        },
        "godaddy_g2_intermediate-cert": {
            ExtensionOID.CERTIFICATE_POLICIES: """<ul>
              <li>Unknown OID (2.16.840.1.114413.1.7.23.1):
                <ul><li>http://certificates.godaddy.com/repository/</li></ul>
              </li>
              <li>Unknown OID (2.23.140.1.2.1) <ul><li>No Policy Qualifiers</li></ul></li>
            </ul>""",
            ExtensionOID.EXTENDED_KEY_USAGE: "<ul><li>serverAuth</li><li>clientAuth</li></ul>",
            ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS: """<table>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Timestamp</th>
                  <th>Log ID</th>
                  <th>Version</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Precertificate</td>
                  <td>A4:B9:09:90:B4:18:58:14:87:BB:13:A2:CC:67:70:0A:3C:35:98:04:F9:1B:DF:B8:E3:77:CD:0E:C8:0D:DC:10</td>
                  <td>2019-03-27 09:13:54.342000</td>
                  <td>v1</td>
                </tr>
                <tr>
                  <td>Precertificate</td>
                  <td>EE:4B:BD:B7:75:CE:60:BA:E1:42:69:1F:AB:E1:9E:66:A3:0F:7E:5F:B0:72:D8:83:00:C4:7B:89:7A:A8:FD:CB</td>
                  <td>2019-03-27 09:13:55.237000</td>
                  <td>v1</td>
                </tr>
                <tr>
                  <td>Precertificate</td>
                  <td>44:94:65:2E:B0:EE:CE:AF:C4:40:07:D8:A8:FE:28:C0:DA:E6:82:BE:D8:CB:31:B5:3F:D3:33:96:B5:B6:81:A8</td>
                  <td>2019-03-27 09:13:56.485000</td>
                  <td>v1</td>
                </tr>
              </tbody>
            </table>""",
        },
        "google_g3-cert": {
            ExtensionOID.CERTIFICATE_POLICIES: """<ul>
              <li>Unknown OID (1.3.6.1.4.1.11129.2.5.3) <ul><li>No Policy Qualifiers</li></ul> </li>
              <li>Unknown OID (2.23.140.1.2.2) <ul><li>No Policy Qualifiers</li></ul> </li>
            </ul>""",
        },
        "letsencrypt_x1-cert": {
            ExtensionOID.CERTIFICATE_POLICIES: """
<ul>
  <li>Unknown OID (2.23.140.1.2.1)
    <ul><li>No Policy Qualifiers</li></ul>
  </li>
  <li>Unknown OID (1.3.6.1.4.1.44947.1.1.1):
    <ul>
      <li>http://cps.letsencrypt.org</li>
      <li>User Notice:
        <ul>
          <li>Explicit Text: This Certificate may only be relied upon by Relying Parties and only in
            accordance with the Certificate Policy found at https://letsencrypt.org/repository/
         </li>
        </ul>
      </li>
    </ul>
  </li>
</ul>""",
            ExtensionOID.EXTENDED_KEY_USAGE: "<ul><li>serverAuth</li><li>clientAuth</li></ul>",
        },
        "letsencrypt_x3-cert": {
            ExtensionOID.CERTIFICATE_POLICIES: """<ul>
              <li>Unknown OID (2.23.140.1.2.1)
                <ul><li>No Policy Qualifiers</li></ul>
              </li>
              <li>Unknown OID (1.3.6.1.4.1.44947.1.1.1):
                <ul><li>http://cps.letsencrypt.org</li></ul>
              </li>
            </ul>""",
            ExtensionOID.EXTENDED_KEY_USAGE: "<ul><li>serverAuth</li><li>clientAuth</li></ul>",
            ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS: """<table>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Timestamp</th>
                  <th>Log ID</th>
                  <th>Version</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Precertificate</td>
                  <td>6F:53:76:AC:31:F0:31:19:D8:99:00:A4:51:15:FF:77:15:1C:11:D9:02:C1:00:29:06:8D:B2:08:9A:37:D9:13</td>
                  <td>2019-06-25 03:40:03.920000</td>
                  <td>v1</td>
                </tr>
                <tr>
                  <td>Precertificate</td>
                  <td>29:3C:51:96:54:C8:39:65:BA:AA:50:FC:58:07:D4:B7:6F:BF:58:7A:29:72:DC:A4:C3:0C:F4:E5:45:47:F4:78</td>
                  <td>2019-06-25 03:40:03.862000</td>
                  <td>v1</td>
                </tr>
              </tbody>
            </table>""",
        },
        "multiple_ous": {},
        "rapidssl_g3-cert": {
            ExtensionOID.CERTIFICATE_POLICIES: """<ul>
              <li>Unknown OID (2.16.840.1.113733.1.7.54):
                <ul><li>https://www.rapidssl.com/legal</li></ul>
              </li>
            </ul>""",
            ExtensionOID.EXTENDED_KEY_USAGE: "<ul><li>serverAuth</li><li>clientAuth</li></ul>",
        },
        "startssl_class2-cert": {
            ExtensionOID.CERTIFICATE_POLICIES: """<ul>
              <li>Unknown OID (2.23.140.1.2.2) <ul><li>No Policy Qualifiers</li></ul> </li>
              <li>Unknown OID (1.3.6.1.4.1.23223.1.2.3):
                <ul>
                  <li>http://www.startssl.com/policy.pdf</li>
                  <li>User Notice:
                    <ul>
                      <li>Explicit Text: This certificate was issued according to the Class 2 Validation
                          requirements of the StartCom CA policy, reliance only for the intended purpose in
                          compliance of the relying party obligations.</li>
                      <li>Notice Reference:
                        <ul>
                          <li>Organization: StartCom Certification Authority</li>
                          <li>Notice Numbers: [1]</li>
                        </ul>
                      </li>
                    </ul>
                  </li>
                </ul>
              </li>
            </ul>""",
        },
        "startssl_class3-cert": {
            ExtensionOID.CERTIFICATE_POLICIES: """<ul>
              <li>Unknown OID (2.23.140.1.2.2)
                <ul><li>No Policy Qualifiers</li></ul>
              </li>
              <li>Unknown OID (1.3.6.1.4.1.23223.1.2.4):
                <ul>
                  <li>http://www.startssl.com/policy</li>
                </ul>
              </li>
            </ul>""",
        },
        "trustid_server_a52-cert": {
            ExtensionOID.CERTIFICATE_POLICIES: """
<ul>
  <li>Unknown OID (2.16.840.1.113839.0.6.3):
    <ul>
      <li>https://secure.identrust.com/certificates/policy/ts/</li>
      <li>User Notice:
        <ul>
          <li>Explicit Text: This TrustID Server Certificate has been issued in accordance with
              IdenTrust&#x27;s TrustID Certificate Policy found at
              https://secure.identrust.com/certificates/policy/ts/</li>
        </ul>
      </li>
    </ul>
  </li>
  <li>Unknown OID (2.23.140.1.2.2):
    <ul>
      <li>https://secure.identrust.com/certificates/policy/ts/</li>
      <li>User Notice:
        <ul>
          <li>Explicit Text: This TrustID Server Certificate has been issued in accordance with
            IdenTrust&#x27;s TrustID Certificate Policy found at
            https://secure.identrust.com/certificates/policy/ts/</li> </ul>
      </li>
    </ul>
  </li>
</ul>""",
            ExtensionOID.EXTENDED_KEY_USAGE: "<ul><li>serverAuth</li><li>clientAuth</li></ul>",
        },
    }

    def setUpCert(self, name: str) -> None:  # pylint: disable=invalid-name
        """Set up default values for certificates."""
        self.admin_html.setdefault(name, {})

        config = certs[name]
        if config.get("subject_alternative_name_serialized"):
            sans = [f"<li>{san}</li>" for san in config["subject_alternative_name_serialized"]["value"]]
            self.admin_html[name].setdefault(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME, f"<ul>{''.join(sans)}</ul>"
            )
        if config.get("issuer_alternative_name_serialized"):
            sans = [f"<li>{san}</li>" for san in config["issuer_alternative_name_serialized"]["value"]]
            self.admin_html[name].setdefault(
                ExtensionOID.ISSUER_ALTERNATIVE_NAME, f"<ul>{''.join(sans)}</ul>"
            )

        if config.get("key_usage_serialized"):
            kus = [f"<li>{ku}</li>" for ku in config["key_usage_serialized"]["value"]]
            self.admin_html[name].setdefault(ExtensionOID.KEY_USAGE, f"<ul>{''.join(kus)}</ul>")

        # NOTE: Custom extension class sorts values, but we render them in order as they appear in the
        #       certificate, so we still have to override this in some places.
        if config.get("extended_key_usage_serialized"):
            ekus = [f"<li>{eku}</li>" for eku in config["extended_key_usage_serialized"]["value"]]
            self.admin_html[name].setdefault(ExtensionOID.EXTENDED_KEY_USAGE, f"<ul>{''.join(ekus)}</ul>")

        if config.get("crl_distribution_points_serialized"):
            ext_config = config["crl_distribution_points_serialized"]["value"]
            full_names = []

            for dpoint in ext_config:
                if list(dpoint.keys()) == ["full_name"]:
                    full_names.append([f"<li>Full Name: {fn}</li>" for fn in dpoint["full_name"]])
                else:
                    full_names = []
                    break

            if full_names:
                self.admin_html[name].setdefault(
                    ExtensionOID.CRL_DISTRIBUTION_POINTS,
                    "\n".join(
                        [f"DistributionPoint: <ul>{''.join(full_name)}</ul>" for full_name in full_names]
                    ),
                )

        if certs[name].get("subject_key_identifier_serialized"):
            self.admin_html[name].setdefault(
                ExtensionOID.SUBJECT_KEY_IDENTIFIER,
                certs[name]["subject_key_identifier_serialized"]["value"],
            )

        aki = certs[name].get("authority_key_identifier_serialized", {}).get("value", {})
        if isinstance(aki, dict) and aki.get("key_identifier"):
            self.admin_html[name].setdefault(
                ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
                f"<ul><li>Key ID: <span class='django-ca-serial'>{aki['key_identifier']}</span></li></ul>",
            )

        aia = certs[name].get("authority_information_access_serialized", {}).get("value", {})
        if aia:
            lines = []
            if "issuers" in aia:
                issuers = [f"<li>{fn}</li>" for fn in aia["issuers"]]
                lines.append(f"CA Issuers: <ul>{''.join(issuers)}</ul>")
            if "ocsp" in aia:
                ocsp = [f"<li>{fn}</li>" for fn in aia["ocsp"]]
                lines.append(f"OCSP: <ul>{''.join(ocsp)}</ul>")
            self.admin_html[name].setdefault(ExtensionOID.AUTHORITY_INFORMATION_ACCESS, "\n".join(lines))

    def setUp(self) -> None:
        super().setUp()

        for name, ca in self.cas.items():
            self.setUpCert(name)
            self.admin_html[name].setdefault(ExtensionOID.BASIC_CONSTRAINTS, "CA: True")

        for name, cert in self.certs.items():
            self.setUpCert(name)
            self.admin_html[name].setdefault(ExtensionOID.BASIC_CONSTRAINTS, "CA: False")

    def test_cas_as_html(self) -> None:
        """Test output of CAs"""

        for name, ca in self.cas.items():
            for oid, ext in ca.x509_extensions.items():
                admin_html = self.admin_html[name][oid]
                admin_html = f"<div class='django-ca-extension-value'>{admin_html}</div>"
                actual = extension_as_admin_html(ext)
                self.assertInHTML(admin_html, mark_safe(actual), msg_prefix=actual)

    def test_certs_as_html(self) -> None:
        """Test output of CAs"""

        for name, cert in self.certs.items():
            for oid, ext in cert.x509_extensions.items():
                self.assertIn(oid, self.admin_html[name], name)
                admin_html = self.admin_html[name][oid]
                admin_html = f"<div class='django-ca-extension-value'>{admin_html}</div>"
                actual = extension_as_admin_html(ext)
                self.assertInHTML(admin_html, mark_safe(actual), msg_prefix=f"{name}, {oid}: {actual}")


class TypeErrorTests(TestCase):
    """Test some unlikely edge cases for serialization and textualization."""

    dotted_string = "1.2.3"
    oid = ObjectIdentifier(dotted_string)

    class UnknownExtensionType(x509.ExtensionType):
        """A self-defined, completely unknown extension type, only for testing."""

        oid = ObjectIdentifier("1.2.3")

        def public_bytes(self) -> bytes:
            return b""

    ext_type = UnknownExtensionType()
    ext = x509.Extension(oid=oid, critical=True, value=b"foo")  # type: ignore[type-var]

    def test_parse_unknown_key(self) -> None:
        """Test exception for parsing an extension with an unsupported key."""
        with self.assertRaisesRegex(ValueError, r"^wrong_key: Unknown extension key\.$"):
            parse_extension("wrong_key", {})

    def test_serialize_no_extension(self) -> None:
        """Test serializing an extension that is not an extension type."""
        with self.assertRaisesRegex(TypeError, r"^bytes: Not a cryptography\.x509\.ExtensionType\.$"):
            serialize_extension(self.ext)  # type: ignore[arg-type]

    def test_no_extension_as_text(self) -> None:
        """Test textualizing an extension that is not an extension type."""
        with self.assertRaisesRegex(TypeError, r"^bytes: Not a cryptography\.x509\.ExtensionType\.$"):
            extension_as_text(b"foo")  # type: ignore[arg-type]

    def test_unknown_extension_type_as_text(self) -> None:
        """Test textualizing an extension of unknown type."""
        with self.assertRaisesRegex(
            TypeError, r"^UnknownExtensionType \(oid: 1\.2\.3\): Unknown extension type\.$"
        ):
            extension_as_text(self.ext_type)

    def test_serialize_unknown_extension_type(self) -> None:
        """Test serializing an extension of unknown type."""
        with self.assertRaisesRegex(
            TypeError, r"^UnknownExtensionType \(oid: 1\.2\.3\): Unknown extension type\.$"
        ):
            serialize_extension(x509.Extension(oid=self.oid, critical=True, value=self.ext_type))

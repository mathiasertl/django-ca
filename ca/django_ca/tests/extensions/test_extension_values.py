# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU General
# Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca. If not, see
# <http://www.gnu.org/licenses/>.

"""Test various extension values for serialization, parsing and text representation."""

import typing
from typing import Any, Dict, List

from cryptography import x509
from cryptography.x509 import TLSFeatureType
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID

from django.test import TestCase
from django.utils.safestring import mark_safe

from django_ca.constants import EXTENSION_DEFAULT_CRITICAL, ExtendedKeyUsageOID
from django_ca.extensions import extension_as_text, parse_extension, serialize_extension
from django_ca.extensions.utils import extension_as_admin_html
from django_ca.tests.base import certs, dns, rdn, uri
from django_ca.tests.base.mixins import TestCaseMixin, TestCaseProtocol
from django_ca.typehints import CRLExtensionType, ParsableDistributionPoint, ParsablePolicyInformation

_TestValueDict = typing.TypedDict(
    "_TestValueDict",
    {
        "admin_html": str,
        "serialized": Any,
        "extension_type": x509.ExtensionType,
        "text": "str",
    },
)


# pylint: disable-next=inherit-non-class; False positive
class TestValueDict(_TestValueDict, total=False):
    """Value used to define generic test cases."""

    serialized_alternatives: List[Any]
    extension_type_alternatives: List[x509.ExtensionType]


TestValues = Dict[str, TestValueDict]


class ExtensionTestCaseMixin(TestCaseProtocol):
    """Mixin class for all extension types."""

    ext_class_key: str
    test_values: TestValues

    # pylint: disable-next=invalid-name  # unittest standard
    def assertSerialization(self, extension_type: x509.ExtensionType, serialized: Any, name: str) -> None:
        """Assert that the given `extension_type` serializes to the given `value`."""
        ext = x509.Extension(oid=extension_type.oid, critical=True, value=extension_type)
        self.assertEqual(serialize_extension(ext), {"critical": True, "value": serialized}, name)

        ext = x509.Extension(oid=extension_type.oid, critical=False, value=extension_type)
        self.assertEqual(serialize_extension(ext), {"critical": False, "value": serialized}, name)

    # pylint: disable-next=invalid-name  # unittest standard
    def assertParsed(self, serialized: Any, extension_type: x509.ExtensionType, name: str) -> None:
        """Assert that the given `serialized` value parses to the given `extension_type`."""
        oid = extension_type.oid
        ext = x509.Extension(oid=oid, critical=EXTENSION_DEFAULT_CRITICAL[oid], value=extension_type)
        self.assertEqual(parse_extension(self.ext_class_key, {"value": serialized}), ext, name)

        ext = x509.Extension(oid=oid, critical=True, value=extension_type)
        self.assertEqual(
            parse_extension(self.ext_class_key, {"value": serialized, "critical": True}), ext, name
        )
        ext = x509.Extension(oid=oid, critical=False, value=extension_type)
        self.assertEqual(
            parse_extension(self.ext_class_key, {"value": serialized, "critical": False}), ext, name
        )

        self.assertIs(parse_extension(self.ext_class_key, ext), ext)
        self.assertIs(parse_extension(self.ext_class_key, extension_type).value, extension_type)

    def test_as_admin_html(self) -> None:
        """Test the ``extension_as_admin_html`` function."""
        for name, config in self.test_values.items():
            extension_type = config["extension_type"]
            oid = extension_type.oid
            ext = x509.Extension(oid=oid, critical=EXTENSION_DEFAULT_CRITICAL[oid], value=extension_type)

            expected = f'\n<div class="django-ca-extension-value">{config["admin_html"]}</div>'
            actual = extension_as_admin_html(ext)

            msg_prefix = f"{name}, {oid}: actual:\n{actual}\n"
            self.assertInHTML(expected, mark_safe(actual), msg_prefix=msg_prefix)

    def test_as_text(self) -> None:
        """Test rendering the extension as text."""
        for name, config in self.test_values.items():
            self.assertEqual(extension_as_text(config["extension_type"]), config["text"], name)

            for extension_type in config.get("extension_type_alternatives", []):
                self.assertEqual(extension_as_text(extension_type), config["text"], name)

    def test_serialize(self) -> None:
        """Test serializing the extension."""
        for name, config in self.test_values.items():
            self.assertSerialization(config["extension_type"], config["serialized"], name)

            for extension_type in config.get("extension_type_alternatives", []):
                self.assertSerialization(extension_type, config["serialized"], name)

    def test_parse(self) -> None:
        """Test parsing the extension."""
        for name, config in self.test_values.items():
            self.assertParsed(config["serialized"], config["extension_type"], name)

            for serialized in config.get("serialized_alternatives", []):
                self.assertParsed(serialized, config["extension_type"], name)


class CRLDistributionPointsTestCaseMixin(ExtensionTestCaseMixin):
    """Base mixin for test cases for CRL based extensions."""

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

    cg_dps1: CRLExtensionType
    cg_dps2: CRLExtensionType
    cg_dps3: CRLExtensionType
    cg_dps4: CRLExtensionType

    def setUp(self) -> None:
        self.test_values = {
            "one": {
                "admin_html": f"""DistributionPoint:
  <ul>
      <li>Full Name: URI:{self.uri1}</li>
  </ul>""",
                "serialized_alternatives": [
                    [self.s1],
                    [self.cg_dp1],
                    [{"full_name": [self.uri1]}],
                    [{"full_name": [uri(self.uri1)]}],
                ],
                "serialized": [self.s1],
                "extension_type": self.cg_dps1,
                "text": f"* DistributionPoint:\n  * Full Name:\n    * URI:{self.uri1}",
            },
            "two": {
                "admin_html": f"""DistributionPoint:
  <ul>
      <li>Full Name: URI:{self.uri1}, DNS:{self.dns1}</li>
  </ul>""",
                "serialized_alternatives": [
                    [self.s2],
                    [self.cg_dp2],
                    [{"full_name": [self.uri1, self.dns1]}],
                    [{"full_name": [uri(self.uri1), dns(self.dns1)]}],
                ],
                "serialized": [self.s2],
                "extension_type": self.cg_dps2,
                "text": f"* DistributionPoint:\n  * Full Name:\n    * URI:{self.uri1}\n    * DNS:{self.dns1}",
            },
            "rdn": {
                "admin_html": f"""DistributionPoint:
  <ul>
      <li>Relative Name: {self.rdn1}</li>
  </ul>""",
                "serialized_alternatives": [[self.s3], [self.cg_dp3], [{"relative_name": self.cg_rdn1}]],
                "serialized": [self.s3],
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
                "serialized_alternatives": [[self.s4], [self.s5], [self.cg_dp4]],
                "serialized": [self.s4],
                "extension_type": self.cg_dps4,
                "text": f"""* DistributionPoint:
  * Full Name:
    * URI:{self.uri2}
  * CRL Issuer:
    * URI:{self.uri3}
  * Reasons: ca_compromise, key_compromise""",
            },
        }


class AuthorityInformationAccessTestCase(ExtensionTestCaseMixin, TestCase):
    """Test AuthorityInformationAccess extension."""

    ext_class_key = "authority_information_access"
    ext_class_name = "AuthorityInformationAccess"

    uri1 = "https://example1.com"
    uri2 = "https://example2.net"
    uri3 = "https://example3.org"
    uri4 = "https://example4.at"

    test_values = {
        "issuer": {
            "admin_html": f"CA Issuers:<ul><li>URI:{uri1}</li></ul>",
            "extension_type": x509.AuthorityInformationAccess(
                descriptions=[x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, uri(uri1))]
            ),
            "serialized": {"issuers": [f"URI:{uri1}"]},
            "serialized_alternatives": [
                {"issuers": [uri1]},
                {"issuers": [uri(uri1)]},
            ],
            "text": f"CA Issuers:\n  * URI:{uri1}",
        },
        "ocsp": {
            "admin_html": f"OCSP:<ul><li>URI:{uri2}</li></ul>",
            "extension_type": x509.AuthorityInformationAccess(
                descriptions=[x509.AccessDescription(AuthorityInformationAccessOID.OCSP, uri(uri2))]
            ),
            "serialized": {"ocsp": [f"URI:{uri2}"]},
            "serialized_alternatives": [
                {"ocsp": [uri2]},
                {"ocsp": [uri(uri2)]},
            ],
            "text": f"OCSP:\n  * URI:{uri2}",
        },
        "both": {
            "admin_html": f"CA Issuers:<ul><li>URI:{uri2}</li></ul> OCSP:<ul><li>URI:{uri1}</li></ul>",
            "extension_type": x509.AuthorityInformationAccess(
                descriptions=[
                    x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, uri(uri2)),
                    x509.AccessDescription(AuthorityInformationAccessOID.OCSP, uri(uri1)),
                ]
            ),
            "serialized": {"ocsp": [f"URI:{uri1}"], "issuers": [f"URI:{uri2}"]},
            "serialized_alternatives": [
                {"ocsp": [uri1], "issuers": [uri2]},
                {"ocsp": [uri(uri1)], "issuers": [uri(uri2)]},
            ],
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
            "serialized_alternatives": [
                {"ocsp": [uri1, uri2], "issuers": [uri3, uri4]},
                {"ocsp": [uri1, uri(uri2)], "issuers": [uri3, uri(uri4)]},
                {"ocsp": [uri(uri1), uri(uri2)], "issuers": [uri(uri3), uri(uri4)]},
            ],
            "serialized": {
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


class AuthorityKeyIdentifierTestCase(ExtensionTestCaseMixin, TestCase):
    """Test AuthorityKeyIdentifier extension."""

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
            "extension_type": x509.AuthorityKeyIdentifier(b1, None, None),
            "serialized": {"key_identifier": hex1},
            "serialized_alternatives": [hex1, {"key_identifier": hex1}],
            "text": f"* KeyID: {hex1}",
        },
        "two": {
            "admin_html": f"<ul><li>Key ID: <span class='django-ca-serial'>{hex2}</span></li></ul>",
            "extension_type": x509.AuthorityKeyIdentifier(b2, None, None),
            "serialized": {"key_identifier": hex2},
            "serialized_alternatives": [hex2],
            "text": f"* KeyID: {hex2}",
        },
        "three": {
            "admin_html": f"<ul><li>Key ID: <span class='django-ca-serial'>{hex3}</span></li></ul>",
            "extension_type": x509.AuthorityKeyIdentifier(b3, None, None),
            "serialized": {"key_identifier": hex3},
            "serialized_alternatives": [hex3],
            "text": f"* KeyID: {hex3}",
        },
        "issuer/serial": {
            "admin_html": f"""<ul>
    <li>Authority certificate issuer:
        <ul><li>DNS:{dns1}</li></ul>
    </li>
</ul>""",
            "extension_type": x509.AuthorityKeyIdentifier(None, [dns(dns1)], s1),
            "serialized": {
                "authority_cert_issuer": [f"DNS:{dns1}"],
                "authority_cert_serial_number": s1,
            },
            "serialized_alternatives": [
                {"authority_cert_issuer": [dns1], "authority_cert_serial_number": s1},
                {"authority_cert_issuer": [dns1], "authority_cert_serial_number": str(s1)},
            ],
            "text": f"* Issuer:\n  * DNS:{dns1}\n* Serial: {s1}",
        },
    }


class BasicConstraintsTestCase(ExtensionTestCaseMixin, TestCase):
    """Test BasicConstraints extension."""

    ext_class_key = "basic_constraints"
    ext_class_name = "BasicConstraints"

    test_values = {
        "no_ca": {
            "admin_html": "CA: False",
            "extension_type": x509.BasicConstraints(ca=False, path_length=None),
            "serialized": {"ca": False},
            "serialized_alternatives": [
                {"ca": False},
                {"ca": False, "path_length": 3},  # ignored b/c ca=False
                {"ca": False, "path_length": None},  # ignored b/c ca=False
            ],
            "text": "CA:FALSE",
        },
        "no_path_length": {
            # include div to make sure that there's no path length
            "admin_html": "CA: True",
            "extension_type": x509.BasicConstraints(ca=True, path_length=None),
            "serialized": {"ca": True, "path_length": None},
            "serialized_alternatives": [{"ca": True}, {"ca": True, "path_lenth": None}],
            "text": "CA:TRUE",
        },
        "path_length_zero": {
            "admin_html": "CA: True, path length: 0",
            "extension_type": x509.BasicConstraints(ca=True, path_length=0),
            "serialized": {"ca": True, "path_length": 0},
            "serialized_alternatives": [{"ca": True, "path_length": 0}],
            "text": "CA:TRUE, path length:0",
        },
        "path_length_three": {
            "admin_html": "CA: True, path length: 3",
            "extension_type": x509.BasicConstraints(ca=True, path_length=3),
            "serialized": {"ca": True, "path_length": 3},
            "serialized_alternatives": [{"ca": True, "path_length": 3}],
            "text": "CA:TRUE, path length:3",
        },
    }


class CRLDistributionPointsTestCase(CRLDistributionPointsTestCaseMixin, TestCase):
    """Test CRLDistributionPoints extension."""

    ext_class_key = "crl_distribution_points"
    ext_class_name = "CRLDistributionPoints"
    ext_class = x509.CRLDistributionPoints

    cg_dps1 = x509.CRLDistributionPoints([CRLDistributionPointsTestCaseMixin.cg_dp1])
    cg_dps2 = x509.CRLDistributionPoints([CRLDistributionPointsTestCaseMixin.cg_dp2])
    cg_dps3 = x509.CRLDistributionPoints([CRLDistributionPointsTestCaseMixin.cg_dp3])
    cg_dps4 = x509.CRLDistributionPoints([CRLDistributionPointsTestCaseMixin.cg_dp4])


class CertificatePoliciesTestCase(ExtensionTestCaseMixin, TestCase):
    """Test CertificatePolicies extension."""

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
    xpi1 = x509.PolicyInformation(policy_identifier=x509.ObjectIdentifier(oid), policy_qualifiers=[xun1])
    xpi2 = x509.PolicyInformation(policy_identifier=x509.ObjectIdentifier(oid), policy_qualifiers=[xun2])
    xpi3 = x509.PolicyInformation(policy_identifier=x509.ObjectIdentifier(oid), policy_qualifiers=[xun3])
    xpi4 = x509.PolicyInformation(
        policy_identifier=x509.ObjectIdentifier(oid), policy_qualifiers=[xun4_1, xun4_2]
    )
    xpi6 = x509.PolicyInformation(policy_identifier=x509.ObjectIdentifier(oid), policy_qualifiers=None)
    xpi7 = x509.PolicyInformation(policy_identifier=x509.ObjectIdentifier(oid), policy_qualifiers=[xun7])

    xcp1 = x509.CertificatePolicies(policies=[xpi1])
    xcp2 = x509.CertificatePolicies(policies=[xpi2])
    xcp3 = x509.CertificatePolicies(policies=[xpi3])
    xcp4 = x509.CertificatePolicies(policies=[xpi4])
    xcp5 = x509.CertificatePolicies(policies=[xpi1, xpi2, xpi4])
    xcp6 = x509.CertificatePolicies(policies=[xpi6])
    xcp7 = x509.CertificatePolicies(policies=[xpi7])

    test_values = {
        "one": {
            "admin_html": f"<ul><li>Unknown OID ({oid}):<ul><li>text1</li></li></ul>",
            "serialized_alternatives": [[un1], [un1_1], [xpi1]],
            "serialized": [un1],
            "extension_type": xcp1,
            "text": f"* Policy Identifier: {oid}\n  Policy Qualifiers:\n  * text1",
        },
        "two": {
            "admin_html": f"""
<ul>
    <li>Unknown OID ({oid}):
        <ul>
            <li>User Notice:
                <ul>
                    <li>Explicit Text: {text2}</li>
                </ul>
            </li>
        </ul>
    </li>
</ul>""",
            "serialized_alternatives": [[un2], [un2_1], [xpi2]],
            "serialized": [un2],
            "extension_type": xcp2,
            "text": f"""* Policy Identifier: {oid}
  Policy Qualifiers:
  * User Notice:
    * Explicit Text: {text2}""",
        },
        "three": {
            "admin_html": f"""
<ul>
    <li>Unknown OID ({oid}):
        <ul>
            <li>User Notice:<ul>
            <li>Notice Reference:
                <ul>
                    <li>Organization: {text3}</li>
                    <li>Notice Numbers: [1]</li>
                </ul>
            </li>
        </ul>
    </li>
</ul>""",
            "serialized_alternatives": [[un3], [un3_1], [xpi3]],
            "serialized": [un3],
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
    <li>Unknown OID ({oid}):
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
        </ul>
    </li>
</ul>""",
            "serialized_alternatives": [[un4], [xpi4]],
            "serialized": [un4],
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
            "serialized_alternatives": [[un1, un2, un4], [xpi1, xpi2, xpi4], [un1, xpi2, un4]],
            "serialized": [un1, un2, un4],
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
            "admin_html": """
<ul>
  <li>Unknown OID (2.5.29.32.0)
    <ul>
    <li>No Policy Qualifiers</li>
    </ul>
  </li>
</ul>""",
            "serialized": [un6],
            "extension_type": xcp6,
            "text": f"* Policy Identifier: {oid}\n  No Policy Qualifiers",
            "serialized_alternatives": [[un6], [xpi6]],
        },
        "seven": {
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
            "serialized": [un7],
            "extension_type": xcp7,
            "text": f"""* Policy Identifier: {oid}
  Policy Qualifiers:
  * User Notice:
    * Explicit Text: {text5}
    * Notice Reference:
      * Notice Numbers: [1]""",
            "serialized_alternatives": [[un7], [xpi7]],
        },
    }


class ExtendedKeyUsageTestCase(ExtensionTestCaseMixin, TestCase):
    """Test ExtendedKeyUsage extension."""

    ext_class_key = "extended_key_usage"
    ext_class_name = "ExtendedKeyUsage"

    test_values = {
        "one": {
            "admin_html": "<ul><li>serverAuth</li></ul>",
            "extension_type": x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            "serialized": ["serverAuth"],
            "serialized_alternatives": [
                {"serverAuth"},
                {ExtendedKeyUsageOID.SERVER_AUTH},
                [ExtendedKeyUsageOID.SERVER_AUTH],
            ],
            "text": "* serverAuth",
        },
        "two": {
            "admin_html": "<ul><li>clientAuth</li><li>serverAuth</li></ul>",
            "extension_type": x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]
            ),
            "serialized": ["clientAuth", "serverAuth"],
            "serialized_alternatives": [
                {"serverAuth", "clientAuth"},
                {ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH},
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH],
                [ExtendedKeyUsageOID.SERVER_AUTH, "clientAuth"],
            ],
            "text": "* clientAuth\n* serverAuth",
        },
        "three": {
            "admin_html": "<ul><li>clientAuth</li><li>serverAuth</li><li>timeStamping</li></ul>",
            "extension_type": x509.ExtendedKeyUsage(
                [
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                    ExtendedKeyUsageOID.SERVER_AUTH,
                    ExtendedKeyUsageOID.TIME_STAMPING,
                ]
            ),
            "serialized": ["clientAuth", "serverAuth", "timeStamping"],
            "serialized_alternatives": [
                {"serverAuth", "clientAuth", "timeStamping"},
                {
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                    ExtendedKeyUsageOID.SERVER_AUTH,
                    ExtendedKeyUsageOID.TIME_STAMPING,
                },
                {ExtendedKeyUsageOID.CLIENT_AUTH, "serverAuth", ExtendedKeyUsageOID.TIME_STAMPING},
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
            "text": "* clientAuth\n* serverAuth\n* timeStamping",
        },
    }


class FreshestCRLTestCase(CRLDistributionPointsTestCaseMixin, TestCase):
    """Test FreshestCRL extension."""

    ext_class_key = "freshest_crl"
    ext_class_name = "FreshestCRL"
    ext_class = x509.FreshestCRL

    cg_dps1 = x509.FreshestCRL([CRLDistributionPointsTestCaseMixin.cg_dp1])
    cg_dps2 = x509.FreshestCRL([CRLDistributionPointsTestCaseMixin.cg_dp2])
    cg_dps3 = x509.FreshestCRL([CRLDistributionPointsTestCaseMixin.cg_dp3])
    cg_dps4 = x509.FreshestCRL([CRLDistributionPointsTestCaseMixin.cg_dp4])


class InhibitAnyPolicyTestCase(ExtensionTestCaseMixin, TestCase):
    """Test InhibitAnyPolicy extension."""

    ext_class_key = "inhibit_any_policy"
    ext_class_name = "InhibitAnyPolicy"

    test_values = {
        "zero": {
            "admin_html": "skip certs: 0",
            "serialized_alternatives": [0],
            "serialized": 0,
            "extension_type": x509.InhibitAnyPolicy(0),
            "text": "0",
        },
        "one": {
            "admin_html": "skip certs: 1",
            "serialized_alternatives": [1],
            "serialized": 1,
            "extension_type": x509.InhibitAnyPolicy(1),
            "text": "1",
        },
    }


class IssuerAlternativeNameTestCase(ExtensionTestCaseMixin, TestCase):
    """Test IssuerAlternativeName extension."""

    ext_class_key = "issuer_alternative_name"
    ext_class_name = "IssuerAlternativeName"
    ext_class_type = x509.IssuerAlternativeName

    uri1 = value1 = "https://example.com"
    uri2 = value2 = "https://example.net"
    dns1 = value3 = "example.com"
    dns2 = value4 = "example.net"

    def setUp(self) -> None:
        super().setUp()

        # Set in setUp() because SubjectAlternativeName test case inherits and just sets ext_class_type
        self.test_values = {
            "uri": {
                "admin_html": f"<ul><li>URI:{self.uri1}</li></ul>",
                "extension_type": self.ext_class_type([uri(self.uri1)]),
                "serialized_alternatives": [[self.uri1], [uri(self.uri1)]],
                "serialized": [f"URI:{self.uri1}"],
                "text": f"* URI:{self.uri1}",
            },
            "dns": {
                "admin_html": f"<ul><li>DNS:{self.dns1}</li></ul>",
                "extension_type": self.ext_class_type([dns(self.dns1)]),
                "serialized": [f"DNS:{self.dns1}"],
                "serialized_alternatives": [[self.dns1], [dns(self.dns1)]],
                "text": f"* DNS:{self.dns1}",
            },
            "both": {
                "admin_html": f"<ul><li>URI:{self.uri1}</li><li>DNS:{self.dns1}</li></ul>",
                "extension_type": self.ext_class_type([uri(self.uri1), dns(self.dns1)]),
                "serialized": [f"URI:{self.uri1}", f"DNS:{self.dns1}"],
                "serialized_alternatives": [
                    [self.uri1, self.dns1],
                    [uri(self.uri1), dns(self.dns1)],
                    [self.uri1, dns(self.dns1)],
                    [uri(self.uri1), self.dns1],
                ],
                "text": f"* URI:{self.uri1}\n* DNS:{self.dns1}",
            },
            "all": {
                "admin_html": f"""<ul>
                <li>URI:{self.uri1}</li><li>URI:{self.uri2}</li><li>DNS:{self.dns1}</li><li>DNS:{self.dns2}</li>
            </ul>""",
                "extension_type": self.ext_class_type(
                    [uri(self.uri1), uri(self.uri2), dns(self.dns1), dns(self.dns2)]
                ),
                "serialized": [
                    f"URI:{self.uri1}",
                    f"URI:{self.uri2}",
                    f"DNS:{self.dns1}",
                    f"DNS:{self.dns2}",
                ],
                "serialized_alternatives": [
                    [self.uri1, self.uri2, self.dns1, self.dns2],
                    [uri(self.uri1), uri(self.uri2), self.dns1, self.dns2],
                    [self.uri1, self.uri2, dns(self.dns1), dns(self.dns2)],
                    [uri(self.uri1), uri(self.uri2), dns(self.dns1), dns(self.dns2)],
                ],
                "text": f"* URI:{self.uri1}\n* URI:{self.uri2}\n* DNS:{self.dns1}\n* DNS:{self.dns2}",
            },
            "order": {  # same as "all" above but other order
                "admin_html": f"""<ul>
                  <li>DNS:{self.dns2}</li><li>DNS:{self.dns1}</li><li>URI:{self.uri2}</li><li>URI:{self.uri1}</li>
            </ul>""",
                "extension_type": self.ext_class_type(
                    [dns(self.dns2), dns(self.dns1), uri(self.uri2), uri(self.uri1)]
                ),
                "serialized": [
                    f"DNS:{self.dns2}",
                    f"DNS:{self.dns1}",
                    f"URI:{self.uri2}",
                    f"URI:{self.uri1}",
                ],
                "serialized_alternatives": [
                    [self.dns2, self.dns1, self.uri2, self.uri1],
                    [dns(self.dns2), dns(self.dns1), self.uri2, self.uri1],
                    [self.dns2, self.dns1, uri(self.uri2), uri(self.uri1)],
                    [dns(self.dns2), dns(self.dns1), uri(self.uri2), uri(self.uri1)],
                ],
                "text": f"* DNS:{self.dns2}\n* DNS:{self.dns1}\n* URI:{self.uri2}\n* URI:{self.uri1}",
            },
        }


class KeyUsageTestCase(ExtensionTestCaseMixin, TestCase):
    """Test KeyUsage extension."""

    ext_class_key = "key_usage"
    ext_class_name = "KeyUsage"

    test_values = {
        "one": {
            "admin_html": "<ul><li>keyAgreement</li></ul>",
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
            "serialized": ["key_agreement"],
            "serialized_alternatives": [{"key_agreement"}, ["keyAgreement"]],
            "text": "* keyAgreement",
        },
        "two": {
            "admin_html": "<ul><li>keyAgreement</li><li>keyEncipherment</li></ul>",
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
            "serialized": ["key_agreement", "key_encipherment"],
            "serialized_alternatives": [
                {"key_agreement", "key_encipherment"},
                ["keyAgreement", "keyEncipherment"],
                ["keyEncipherment", "keyAgreement"],
                ["keyEncipherment", "key_agreement"],
            ],
            "text": "* keyAgreement\n* keyEncipherment",
        },
        "three": {
            "admin_html": "<ul><li>keyAgreement</li><li>keyEncipherment</li><li>nonRepudiation</li></ul>",
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
            "serialized": ["content_commitment", "key_agreement", "key_encipherment"],
            "serialized_alternatives": [
                {"key_agreement", "key_encipherment", "content_commitment"},
                ["keyAgreement", "keyEncipherment", "nonRepudiation"],
                ["nonRepudiation", "keyAgreement", "keyEncipherment"],
                ["nonRepudiation", "keyAgreement", "keyEncipherment"],
                ["content_commitment", "key_agreement", "key_encipherment"],
            ],
            "text": "* keyAgreement\n* keyEncipherment\n* nonRepudiation",
        },
    }


class NameConstraintsTestCase(ExtensionTestCaseMixin, TestCase):
    """Test NameConstraints extension."""

    ext_class_key = "name_constraints"
    ext_class_name = "NameConstraints"

    d1 = "example.com"
    d2 = "example.net"

    test_values = {
        "permitted": {
            "admin_html": f"Permitted:<ul><li>DNS:{d1}</li></ul>",
            "extension_type": x509.NameConstraints(permitted_subtrees=[dns(d1)], excluded_subtrees=None),
            "serialized": {"permitted": [f"DNS:{d1}"]},
            "serialized_alternatives": [
                {"permitted": [d1]},
                {"permitted": [f"DNS:{d1}"]},
                {"permitted": [dns(d1)]},
                {"permitted": [dns(d1)], "excluded": []},
            ],
            "text": f"Permitted:\n  * DNS:{d1}",
        },
        "excluded": {
            "admin_html": f"Excluded:<ul><li>DNS:{d1}</li></ul>",
            "serialized": {"excluded": [f"DNS:{d1}"]},
            "serialized_alternatives": [
                {"excluded": [d1]},
                {"excluded": [f"DNS:{d1}"]},
                {"excluded": [dns(d1)]},
                {"excluded": [dns(d1)], "permitted": []},
            ],
            "extension_type": x509.NameConstraints(permitted_subtrees=None, excluded_subtrees=[dns(d1)]),
            "text": f"Excluded:\n  * DNS:{d1}",
        },
        "both": {
            "admin_html": f"Permitted:<ul><li>DNS:{d1}</li></ul> Excluded:<ul><li>DNS:{d2}</li></ul>",
            "serialized": {"excluded": [f"DNS:{d2}"], "permitted": [f"DNS:{d1}"]},
            "serialized_alternatives": [
                {"permitted": [d1], "excluded": [d2]},
                {"permitted": [f"DNS:{d1}"], "excluded": [f"DNS:{d2}"]},
                {"permitted": [dns(d1)], "excluded": [dns(d2)]},
                {"permitted": [dns(d1)], "excluded": [d2]},
            ],
            "extension_type": x509.NameConstraints(permitted_subtrees=[dns(d1)], excluded_subtrees=[dns(d2)]),
            "text": f"Permitted:\n  * DNS:{d1}\nExcluded:\n  * DNS:{d2}",
        },
    }


class OCSPNoCheckTestCase(ExtensionTestCaseMixin, TestCase):
    """Test OCSPNoCheck extension."""

    ext_class_key = "ocsp_no_check"
    ext_class_name = "OCSPNoCheck"

    test_values: TestValues = {
        "empty": {
            "admin_html": "Yes",
            "serialized": None,
            "extension_type": x509.OCSPNoCheck(),
            "text": "Yes",
        },
    }


class PolicyConstraintsTestCase(ExtensionTestCaseMixin, TestCase):
    """Test PolicyConstraints extension."""

    ext_class_key = "policy_constraints"
    ext_class_name = "PolicyConstraints"

    test_values = {
        "rep_zero": {
            "admin_html": "<ul><li>RequireExplicitPolicy: 0</li></ul>",
            "serialized_alternatives": [{"require_explicit_policy": 0}],
            "serialized": {"require_explicit_policy": 0},
            "extension_type": x509.PolicyConstraints(require_explicit_policy=0, inhibit_policy_mapping=None),
            "text": "* RequireExplicitPolicy: 0",
        },
        "rep_one": {
            "admin_html": "<ul><li>RequireExplicitPolicy: 1</li></ul>",
            "serialized_alternatives": [{"require_explicit_policy": 1}],
            "serialized": {"require_explicit_policy": 1},
            "extension_type": x509.PolicyConstraints(require_explicit_policy=1, inhibit_policy_mapping=None),
            "text": "* RequireExplicitPolicy: 1",
        },
        "iap_zero": {
            "admin_html": "<ul><li>InhibitPolicyMapping: 0</li></ul>",
            "serialized_alternatives": [{"inhibit_policy_mapping": 0}],
            "serialized": {"inhibit_policy_mapping": 0},
            "extension_type": x509.PolicyConstraints(require_explicit_policy=None, inhibit_policy_mapping=0),
            "text": "* InhibitPolicyMapping: 0",
        },
        "iap_one": {
            "admin_html": "<ul><li>InhibitPolicyMapping: 1</li></ul>",
            "serialized_alternatives": [{"inhibit_policy_mapping": 1}],
            "serialized": {"inhibit_policy_mapping": 1},
            "extension_type": x509.PolicyConstraints(require_explicit_policy=None, inhibit_policy_mapping=1),
            "text": "* InhibitPolicyMapping: 1",
        },
        "both": {
            "admin_html": "<ul><li>InhibitPolicyMapping: 2</li><li>RequireExplicitPolicy: 3</li></ul>",
            "serialized_alternatives": [{"inhibit_policy_mapping": 2, "require_explicit_policy": 3}],
            "serialized": {"inhibit_policy_mapping": 2, "require_explicit_policy": 3},
            "extension_type": x509.PolicyConstraints(require_explicit_policy=3, inhibit_policy_mapping=2),
            "text": "* InhibitPolicyMapping: 2\n* RequireExplicitPolicy: 3",
        },
    }


class PrecertPoisonTestCase(ExtensionTestCaseMixin, TestCase):
    """Test PrecertPoison extension."""

    ext_class_key = "precert_poison"
    ext_class_name = "PrecertPoison"
    test_values: TestValues = {
        "empty": {
            "admin_html": "Yes",
            "serialized": None,
            "extension_type": x509.PrecertPoison(),
            "text": "Yes",
        },
    }


class PrecertificateSignedCertificateTimestampsTestCase(TestCaseMixin, TestCase):
    """Test the PrecertificateSignedCertificateTimestamps extension.

    Note that this extension cannot be created by cryptography, we thus have a very limited test set here.
    """

    default_ca = "comodo_ev"
    default_cert = "comodo_ev-cert"
    load_cas = (
        "comodo_ev",
        "digicert_ha_intermediate",
        "digicert_sha2",
        "godaddy_g2_intermediate",
        "letsencrypt_x3",
    )
    load_certs = (
        "comodo_ev-cert",
        "digicert_ha_intermediate-cert",
        "digicert_sha2-cert",
        "godaddy_g2_intermediate-cert",
        "letsencrypt_x3-cert",
    )
    oid = ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS

    def test_serialize(self) -> None:
        """Test serialization."""
        for key in self.load_certs:
            self.assertEqual(
                serialize_extension(self.certs[key].x509_extensions[self.oid]),
                certs[key]["precertificate_signed_certificate_timestamps"],
            )

    def test_parse(self) -> None:
        """Test parsing."""
        msg = r"^precertificate_signed_certificate_timestamps: Cannot parse extensions of this type\.$"
        with self.assertRaisesRegex(ValueError, msg):
            # TYPE NOTE: what we test
            parse_extension("precertificate_signed_certificate_timestamps", None)  # type: ignore[arg-type]


class SubjectAlternativeNameTestCase(IssuerAlternativeNameTestCase):
    """Test SubjectAlternativeName extension."""

    ext_class_key = "subject_alternative_name"
    ext_class_name = "SubjectAlternativeName"
    ext_class_type = x509.SubjectAlternativeName  # type: ignore[assignment]


class SubjectKeyIdentifierTestCase(ExtensionTestCaseMixin, TestCase):
    """Test SubjectKeyIdentifier extension."""

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
            "extension_type": x509.SubjectKeyIdentifier(b1),
            "serialized": hex1,
            "serialized_alternatives": [x509.SubjectKeyIdentifier(b1), b1, hex1],
            "text": hex1,
        },
        "two": {
            "admin_html": hex2,
            "extension_type": x509.SubjectKeyIdentifier(b2),
            "serialized": hex2,
            "serialized_alternatives": [x509.SubjectKeyIdentifier(b2), b2, hex2],
            "text": hex2,
        },
        "three": {
            "admin_html": hex3,
            "extension_type": x509.SubjectKeyIdentifier(b3),
            "serialized": hex3,
            "serialized_alternatives": [x509.SubjectKeyIdentifier(b3), b3, hex3],
            "text": hex3,
        },
    }


class TLSFeatureTestCase(ExtensionTestCaseMixin, TestCase):
    """Test TLSFeature extension."""

    ext_class_key = "tls_feature"
    ext_class_name = "TLSFeature"

    test_values: TestValues = {
        "one": {
            "admin_html": "<ul><li>OCSPMustStaple</li></ul>",
            "extension_type": x509.TLSFeature(features=[TLSFeatureType.status_request]),
            "serialized": ["status_request"],
            "text": "* OCSPMustStaple",
        },
        "two": {
            "admin_html": "<ul><li>OCSPMustStaple</li><li>MultipleCertStatusRequest</li></ul>",
            "extension_type": x509.TLSFeature(
                features=[TLSFeatureType.status_request, TLSFeatureType.status_request_v2]
            ),
            "extension_type_alternatives": [
                x509.TLSFeature(features=[TLSFeatureType.status_request_v2, TLSFeatureType.status_request])
            ],
            "serialized": ["status_request", "status_request_v2"],
            "serialized_alternatives": [
                ["status_request_v2", "status_request"],
                [TLSFeatureType.status_request, TLSFeatureType.status_request_v2],
                [TLSFeatureType.status_request_v2, TLSFeatureType.status_request],
            ],
            "text": "* MultipleCertStatusRequest\n* OCSPMustStaple",
        },
        "three": {
            "admin_html": "<ul><li>MultipleCertStatusRequest</li></ul>",
            "extension_type": x509.TLSFeature(features=[TLSFeatureType.status_request_v2]),
            "serialized": ["status_request_v2"],
            "text": "* MultipleCertStatusRequest",
        },
    }

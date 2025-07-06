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
from typing import Any, ClassVar, cast

from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID

from django.utils.functional import classproperty
from django.utils.safestring import mark_safe

from pytest_django.asserts import assertInHTML

from django_ca.constants import EXTENSION_DEFAULT_CRITICAL, ExtendedKeyUsageOID
from django_ca.extensions import extension_as_text
from django_ca.extensions.utils import extension_as_admin_html
from django_ca.tests.base.utils import dns, rdn, uri
from django_ca.typehints import CertificateExtension, CertificateExtensionType, CRLExtensionType


class _ExtensionExampleDict(typing.TypedDict):
    admin_html: str
    serialized: Any
    extension_type: CertificateExtensionType
    text: "str"


class ExtensionExampleDict(_ExtensionExampleDict, total=False):
    """Value used to define generic test cases."""

    serialized_alternatives: list[Any]
    extension_type_alternatives: list[CertificateExtensionType]


ExtensionExampleValues = dict[str, ExtensionExampleDict]


def pytest_generate_tests(metafunc: Any) -> None:
    """Generate parametrized test functions based on test_values property."""
    if hasattr(metafunc.cls, "test_values"):
        func_arg_list = metafunc.cls.test_values
        metafunc.parametrize("name,config", tuple(func_arg_list.items()))


class ExtensionTestCaseMixin:
    """Mixin class for all extension types."""

    ext_class_key: str
    test_values: ClassVar[ExtensionExampleValues]

    def test_as_admin_html(self, name: str, config: ExtensionExampleDict) -> None:
        """Test the ``extension_as_admin_html`` function."""
        extension_type = config["extension_type"]
        oid = extension_type.oid
        ext = cast(
            CertificateExtension,
            x509.Extension(oid=oid, critical=EXTENSION_DEFAULT_CRITICAL[oid], value=extension_type),
        )

        expected = f'\n<div class="django-ca-extension-value">{config["admin_html"]}</div>'
        actual = extension_as_admin_html(ext)

        msg_prefix = f"{name}, {oid}: actual:\n{actual}\n"
        assertInHTML(expected, mark_safe(actual), msg_prefix=msg_prefix)

    def test_as_text(self, name: str, config: ExtensionExampleDict) -> None:
        """Test rendering the extension as text."""
        assert extension_as_text(config["extension_type"]) == config["text"], name

        for extension_type in config.get("extension_type_alternatives", []):
            assert extension_as_text(extension_type) == config["text"], name


class CRLDistributionPointsTestCaseMixin(ExtensionTestCaseMixin):
    """Base mixin for test cases for CRL based extensions."""

    dns1 = "example.org"
    uri1 = "http://ca.example.com/crl"
    uri2 = "http://ca.example.net/crl"
    uri3 = "http://ca.example.com/"
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

    @classproperty  # pylint: disable-next=no-self-argument
    def test_values(cls) -> ExtensionExampleValues:
        """Overwritten because we access ext_class_type, so we can use subclasses."""
        rdn1 = [{"oid": NameOID.COMMON_NAME.dotted_string, "value": "example.com"}]

        s1 = {"full_name": [f"URI:{cls.uri1}"]}
        s2 = {"full_name": [f"URI:{cls.uri1}", f"DNS:{cls.dns1}"]}
        s3 = {"relative_name": rdn1}
        s4 = {
            "full_name": [f"URI:{cls.uri2}"],
            "crl_issuer": [f"URI:{cls.uri3}"],
            "reasons": ["ca_compromise", "key_compromise"],
        }
        s5 = {
            "full_name": [f"URI:{cls.uri2}"],
            "crl_issuer": [f"URI:{cls.uri3}"],
            "reasons": [x509.ReasonFlags.ca_compromise, x509.ReasonFlags.key_compromise],
        }
        s6 = {
            "full_name": [f"URI:{cls.uri2}"],
            "crl_issuer": [f"URI:{cls.uri3}"],
            "reasons": ["cACompromise", "keyCompromise"],
        }

        return {
            "one": {
                "admin_html": f"""DistributionPoint:
  <ul>
      <li>Full Name: URI:{cls.uri1}</li>
  </ul>""",
                "serialized_alternatives": [
                    [s1],
                    [cls.cg_dp1],
                    [{"full_name": [cls.uri1]}],
                    [{"full_name": [uri(cls.uri1)]}],
                ],
                "serialized": [s1],
                "extension_type": cls.cg_dps1,
                "text": f"* DistributionPoint:\n  * Full Name:\n    * URI:{cls.uri1}",
            },
            "two": {
                "admin_html": f"""DistributionPoint:
  <ul>
      <li>Full Name: URI:{cls.uri1}, DNS:{cls.dns1}</li>
  </ul>""",
                "serialized_alternatives": [
                    [s2],
                    [cls.cg_dp2],
                    [{"full_name": [cls.uri1, cls.dns1]}],
                    [{"full_name": [uri(cls.uri1), dns(cls.dns1)]}],
                ],
                "serialized": [s2],
                "extension_type": cls.cg_dps2,
                "text": f"* DistributionPoint:\n  * Full Name:\n    * URI:{cls.uri1}\n    * DNS:{cls.dns1}",
            },
            "rdn": {
                "admin_html": """DistributionPoint:
  <ul>
      <li>Relative Name:<ul><li>commonName (CN): example.com</li></ul></li>
  </ul>""",
                "serialized_alternatives": [[s3], [cls.cg_dp3], [{"relative_name": cls.cg_rdn1}]],
                "serialized": [s3],
                "extension_type": cls.cg_dps3,
                "text": "* DistributionPoint:\n  * Relative Name:\n    * commonName (CN): example.com",
            },
            "adv": {
                "admin_html": f"""DistributionPoint:
  <ul>
      <li>Full Name: URI:{cls.uri2}</li>
      <li>CRL Issuer: URI:{cls.uri3}</li>
      <li>Reasons: ca_compromise, key_compromise</li>
  </ul>""",
                "serialized_alternatives": [[s4], [s5], [s6], [cls.cg_dp4]],
                "serialized": [s4],
                "extension_type": cls.cg_dps4,
                "text": f"""* DistributionPoint:
  * Full Name:
    * URI:{cls.uri2}
  * CRL Issuer:
    * URI:{cls.uri3}
  * Reasons: ca_compromise, key_compromise""",
            },
        }


class TestAuthorityInformationAccess(ExtensionTestCaseMixin):
    """Test AuthorityInformationAccess extension."""

    ext_class_key = "authority_information_access"
    ext_class_name = "AuthorityInformationAccess"

    uri1 = "https://example1.com"
    uri2 = "https://example2.net"
    uri3 = "https://example3.org"
    uri4 = "https://example4.at"

    test_values: ClassVar[ExtensionExampleValues] = {
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
                    x509.AccessDescription(AuthorityInformationAccessOID.OCSP, uri(uri1)),
                    x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, uri(uri2)),
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
                    x509.AccessDescription(AuthorityInformationAccessOID.OCSP, uri(uri1)),
                    x509.AccessDescription(AuthorityInformationAccessOID.OCSP, uri(uri2)),
                    x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, uri(uri3)),
                    x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, uri(uri4)),
                ]
            ),
            "text": f"CA Issuers:\n  * URI:{uri3}\n  * URI:{uri4}\nOCSP:\n  * URI:{uri1}\n  * URI:{uri2}",
        },
    }


class TestAuthorityKeyIdentifier(ExtensionTestCaseMixin):
    """Test AuthorityKeyIdentifier extension."""

    ext_class_key = "authority_key_identifier"
    ext_class_name = "AuthorityKeyIdentifier"

    b1 = b"333333"
    b2 = b"DDDDDD"
    b3 = b"UUUUUU"
    hex1 = "33:33:33:33:33:33"
    hex2 = "44:44:44:44:44:44"
    hex3 = "55:55:55:55:55:55"
    dns1 = "example.org"
    s1 = 0

    test_values: ClassVar[ExtensionExampleValues] = {
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
    <li>Authority certificate serial number:
        <span class="django-ca-serial">00</span>
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


class TestBasicConstraints(ExtensionTestCaseMixin):
    """Test BasicConstraints extension."""

    ext_class_key = "basic_constraints"
    ext_class_name = "BasicConstraints"

    test_values: ClassVar[ExtensionExampleValues] = {
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
            "serialized_alternatives": [{"ca": True}, {"ca": True, "path_length": None}],
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


class TestCRLDistributionPoints(CRLDistributionPointsTestCaseMixin):
    """Test CRLDistributionPoints extension."""

    ext_class_key = "crl_distribution_points"
    ext_class_name = "CRLDistributionPoints"
    ext_class = x509.CRLDistributionPoints

    cg_dps1 = x509.CRLDistributionPoints([CRLDistributionPointsTestCaseMixin.cg_dp1])
    cg_dps2 = x509.CRLDistributionPoints([CRLDistributionPointsTestCaseMixin.cg_dp2])
    cg_dps3 = x509.CRLDistributionPoints([CRLDistributionPointsTestCaseMixin.cg_dp3])
    cg_dps4 = x509.CRLDistributionPoints([CRLDistributionPointsTestCaseMixin.cg_dp4])


class TestCertificatePolicies(ExtensionTestCaseMixin):
    """Test CertificatePolicies extension."""

    ext_class_name = "CertificatePolicies"
    ext_class_key = "certificate_policies"

    oid = "2.5.29.32.0"
    text1, text2, text3, text4, text5, text6 = (f"text{i}" for i in range(1, 7))

    xun1 = text1
    xun2 = x509.UserNotice(explicit_text=text2, notice_reference=None)
    xun3 = x509.UserNotice(
        explicit_text=None,
        notice_reference=x509.NoticeReference(organization=text3, notice_numbers=[1]),
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

    un1: ClassVar[dict[str, Any]] = {
        "policy_identifier": oid,
        "policy_qualifiers": [text1],
    }
    un1_1: ClassVar[dict[str, Any]] = {
        "policy_identifier": x509.ObjectIdentifier(oid),
        "policy_qualifiers": [text1],
    }
    un2: ClassVar[dict[str, Any]] = {
        "policy_identifier": oid,
        "policy_qualifiers": [{"explicit_text": text2}],
    }
    un2_1: ClassVar[dict[str, Any]] = {
        "policy_identifier": oid,
        "policy_qualifiers": [x509.UserNotice(explicit_text=text2, notice_reference=None)],
    }
    un3: ClassVar[dict[str, Any]] = {
        "policy_identifier": oid,
        "policy_qualifiers": [{"notice_reference": {"organization": text3, "notice_numbers": [1]}}],
    }
    un3_1: ClassVar[dict[str, Any]] = {
        "policy_identifier": oid,
        "policy_qualifiers": [
            {"notice_reference": x509.NoticeReference(organization=text3, notice_numbers=[1])}
        ],
    }
    un4: ClassVar[dict[str, Any]] = {
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
    un6: ClassVar[dict[str, Any]] = {"policy_identifier": oid, "policy_qualifiers": None}
    un7: ClassVar[dict[str, Any]] = {
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

    xcp1 = x509.CertificatePolicies(policies=[xpi1])
    xcp2 = x509.CertificatePolicies(policies=[xpi2])
    xcp3 = x509.CertificatePolicies(policies=[xpi3])
    xcp4 = x509.CertificatePolicies(policies=[xpi4])
    xcp5 = x509.CertificatePolicies(policies=[xpi1, xpi2, xpi4])
    xcp6 = x509.CertificatePolicies(policies=[xpi6])
    xcp7 = x509.CertificatePolicies(policies=[xpi7])

    test_values: ClassVar[ExtensionExampleValues] = {
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
            "serialized_alternatives": [
                [un1, un2, un4],
                [xpi1, xpi2, xpi4],
                [un1, xpi2, un4],
            ],
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


class TestExtendedKeyUsage(ExtensionTestCaseMixin):
    """Test ExtendedKeyUsage extension."""

    ext_class_key = "extended_key_usage"
    ext_class_name = "ExtendedKeyUsage"

    test_values: ClassVar[ExtensionExampleValues] = {
        "one": {
            "admin_html": "<ul><li>serverAuth</li></ul>",
            "extension_type": x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            "serialized": ["serverAuth"],
            "serialized_alternatives": [
                {"serverAuth"},
                {ExtendedKeyUsageOID.SERVER_AUTH},
                [ExtendedKeyUsageOID.SERVER_AUTH],
                [ExtendedKeyUsageOID.SERVER_AUTH.dotted_string],
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


class TestFreshestCRL(CRLDistributionPointsTestCaseMixin):
    """Test FreshestCRL extension."""

    ext_class_key = "freshest_crl"
    ext_class_name = "FreshestCRL"
    ext_class = x509.FreshestCRL

    cg_dps1 = x509.FreshestCRL([CRLDistributionPointsTestCaseMixin.cg_dp1])
    cg_dps2 = x509.FreshestCRL([CRLDistributionPointsTestCaseMixin.cg_dp2])
    cg_dps3 = x509.FreshestCRL([CRLDistributionPointsTestCaseMixin.cg_dp3])
    cg_dps4 = x509.FreshestCRL([CRLDistributionPointsTestCaseMixin.cg_dp4])


class TestInhibitAnyPolicy(ExtensionTestCaseMixin):
    """Test InhibitAnyPolicy extension."""

    ext_class_key = "inhibit_any_policy"
    ext_class_name = "InhibitAnyPolicy"

    test_values: ClassVar[ExtensionExampleValues] = {
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


class TestIssuerAlternativeName(ExtensionTestCaseMixin):
    """Test IssuerAlternativeName extension."""

    ext_class_key = "issuer_alternative_name"
    ext_class_name = "IssuerAlternativeName"
    ext_class_type = x509.IssuerAlternativeName

    uri1 = value1 = "https://example.com"
    uri2 = value2 = "https://example.net"
    dns1 = value3 = "example.com"
    dns2 = value4 = "example.net"

    @classproperty  # pylint: disable-next=no-self-argument
    def test_values(cls) -> ExtensionExampleValues:
        """Overwritten because we access ext_class_type, so we can use subclasses."""
        return {
            "uri": {
                "admin_html": f"<ul><li>URI:{cls.uri1}</li></ul>",
                "extension_type": cls.ext_class_type([uri(cls.uri1)]),
                "serialized_alternatives": [[cls.uri1], [uri(cls.uri1)]],
                "serialized": [f"URI:{cls.uri1}"],
                "text": f"* URI:{cls.uri1}",
            },
            "dns": {
                "admin_html": f"<ul><li>DNS:{cls.dns1}</li></ul>",
                "extension_type": cls.ext_class_type([dns(cls.dns1)]),
                "serialized": [f"DNS:{cls.dns1}"],
                "serialized_alternatives": [[cls.dns1], [dns(cls.dns1)]],
                "text": f"* DNS:{cls.dns1}",
            },
            "both": {
                "admin_html": f"<ul><li>URI:{cls.uri1}</li><li>DNS:{cls.dns1}</li></ul>",
                "extension_type": cls.ext_class_type([uri(cls.uri1), dns(cls.dns1)]),
                "serialized": [f"URI:{cls.uri1}", f"DNS:{cls.dns1}"],
                "serialized_alternatives": [
                    [cls.uri1, cls.dns1],
                    [uri(cls.uri1), dns(cls.dns1)],
                    [cls.uri1, dns(cls.dns1)],
                    [uri(cls.uri1), cls.dns1],
                ],
                "text": f"* URI:{cls.uri1}\n* DNS:{cls.dns1}",
            },
            "all": {
                "admin_html": f"""<ul>
                <li>URI:{cls.uri1}</li><li>URI:{cls.uri2}</li><li>DNS:{cls.dns1}</li><li>DNS:{cls.dns2}</li>
            </ul>""",
                "extension_type": cls.ext_class_type(
                    [uri(cls.uri1), uri(cls.uri2), dns(cls.dns1), dns(cls.dns2)]
                ),
                "serialized": [
                    f"URI:{cls.uri1}",
                    f"URI:{cls.uri2}",
                    f"DNS:{cls.dns1}",
                    f"DNS:{cls.dns2}",
                ],
                "serialized_alternatives": [
                    [cls.uri1, cls.uri2, cls.dns1, cls.dns2],
                    [uri(cls.uri1), uri(cls.uri2), cls.dns1, cls.dns2],
                    [cls.uri1, cls.uri2, dns(cls.dns1), dns(cls.dns2)],
                    [uri(cls.uri1), uri(cls.uri2), dns(cls.dns1), dns(cls.dns2)],
                ],
                "text": f"* URI:{cls.uri1}\n* URI:{cls.uri2}\n* DNS:{cls.dns1}\n* DNS:{cls.dns2}",
            },
            "order": {  # same as "all" above but other order
                "admin_html": f"""<ul>
                  <li>DNS:{cls.dns2}</li><li>DNS:{cls.dns1}</li><li>URI:{cls.uri2}</li><li>URI:{cls.uri1}</li>
            </ul>""",
                "extension_type": cls.ext_class_type(
                    [dns(cls.dns2), dns(cls.dns1), uri(cls.uri2), uri(cls.uri1)]
                ),
                "serialized": [
                    f"DNS:{cls.dns2}",
                    f"DNS:{cls.dns1}",
                    f"URI:{cls.uri2}",
                    f"URI:{cls.uri1}",
                ],
                "serialized_alternatives": [
                    [cls.dns2, cls.dns1, cls.uri2, cls.uri1],
                    [dns(cls.dns2), dns(cls.dns1), cls.uri2, cls.uri1],
                    [cls.dns2, cls.dns1, uri(cls.uri2), uri(cls.uri1)],
                    [dns(cls.dns2), dns(cls.dns1), uri(cls.uri2), uri(cls.uri1)],
                ],
                "text": f"* DNS:{cls.dns2}\n* DNS:{cls.dns1}\n* URI:{cls.uri2}\n* URI:{cls.uri1}",
            },
        }


class TestKeyUsage(ExtensionTestCaseMixin):
    """Test KeyUsage extension."""

    ext_class_key = "key_usage"
    ext_class_name = "KeyUsage"

    test_values: ClassVar[ExtensionExampleValues] = {
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


class TestNameConstraints(ExtensionTestCaseMixin):
    """Test NameConstraints extension."""

    ext_class_key = "name_constraints"
    ext_class_name = "NameConstraints"

    d1 = "example.com"
    d2 = "example.net"
    test_values: ClassVar[ExtensionExampleValues] = {
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


class TestOCSPNoCheck(ExtensionTestCaseMixin):
    """Test OCSPNoCheck extension."""

    ext_class_key = "ocsp_no_check"
    ext_class_name = "OCSPNoCheck"

    test_values: ClassVar[ExtensionExampleValues] = {
        "empty": {
            "admin_html": "Yes",
            "serialized": None,
            "extension_type": x509.OCSPNoCheck(),
            "text": "Yes",
        },
    }


class TestPolicyConstraints(ExtensionTestCaseMixin):
    """Test PolicyConstraints extension."""

    ext_class_key = "policy_constraints"
    ext_class_name = "PolicyConstraints"

    test_values: ClassVar[ExtensionExampleValues] = {
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


class TestPrecertPoison(ExtensionTestCaseMixin):
    """Test PrecertPoison extension."""

    ext_class_key = "precert_poison"
    ext_class_name = "PrecertPoison"

    test_values: ClassVar[ExtensionExampleValues] = {
        "empty": {
            "admin_html": "Yes",
            "serialized": None,
            "extension_type": x509.PrecertPoison(),
            "text": "Yes",
        },
    }


class TestPrecertificateSignedCertificateTimestamps:
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
    oid = ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS
    minimal_test_values: ClassVar[dict[str, Any]] = {
        "www.derstandard.at": {
            "admin_html": """
<table>
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
</table>
""",
            "text": """* Precertificate (v1):
    Timestamp: 2019-06-07 08:47:02.367000
    Log ID: EE:4B:BD:B7:75:CE:60:BA:E1:42:69:1F:AB:E1:9E:66:A3:0F:7E:5F:B0:72:D8:83:00:C4:7B:89:7A:A8:FD:CB
* Precertificate (v1):
    Timestamp: 2019-06-07 08:47:02.566000
    Log ID: 87:75:BF:E7:59:7C:F8:8C:43:99:5F:BD:F3:6E:FF:56:8D:47:56:36:FF:4A:B5:60:C1:B4:EA:FF:5E:A0:83:0F""",  # noqa: E501
        },
        "*.www.yahoo.com": {
            "admin_html": """
<table>
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
</table>
""",
            "text": """* Precertificate (v1):
    Timestamp: 2019-02-01 15:35:06.188000
    Log ID: 63:F2:DB:CD:E8:3B:CC:2C:CF:0B:72:84:27:57:6B:33:A4:8D:61:77:8F:BD:75:A6:38:B1:C7:68:54:4B:D8:8D
* Precertificate (v1):
    Timestamp: 2019-02-01 15:35:06.526000
    Log ID: 6F:53:76:AC:31:F0:31:19:D8:99:00:A4:51:15:FF:77:15:1C:11:D9:02:C1:00:29:06:8D:B2:08:9A:37:D9:13""",  # noqa: E501
        },
        "www.comodo.com": {
            "admin_html": """
<table>
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
</table>
""",
            "text": """* Precertificate (v1):
    Timestamp: 2018-03-14 14:23:09.403000
    Log ID: A4:B9:09:90:B4:18:58:14:87:BB:13:A2:CC:67:70:0A:3C:35:98:04:F9:1B:DF:B8:E3:77:CD:0E:C8:0D:DC:10
* Precertificate (v1):
    Timestamp: 2018-03-14 14:23:08.912000
    Log ID: 56:14:06:9A:2F:D7:C2:EC:D3:F5:E1:BD:44:B2:3E:C7:46:76:B9:BC:99:11:5C:C0:EF:94:98:55:D6:89:D0:DD
* Precertificate (v1):
    Timestamp: 2018-03-14 14:23:09.352000
    Log ID: EE:4B:BD:B7:75:CE:60:BA:E1:42:69:1F:AB:E1:9E:66:A3:0F:7E:5F:B0:72:D8:83:00:C4:7B:89:7A:A8:FD:CB""",  # noqa: E501
        },
        "derstandard.at": {
            "admin_html": """
<table>
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
</table>
""",
            "text": """* Precertificate (v1):
    Timestamp: 2019-03-27 09:13:54.342000
    Log ID: A4:B9:09:90:B4:18:58:14:87:BB:13:A2:CC:67:70:0A:3C:35:98:04:F9:1B:DF:B8:E3:77:CD:0E:C8:0D:DC:10
* Precertificate (v1):
    Timestamp: 2019-03-27 09:13:55.237000
    Log ID: EE:4B:BD:B7:75:CE:60:BA:E1:42:69:1F:AB:E1:9E:66:A3:0F:7E:5F:B0:72:D8:83:00:C4:7B:89:7A:A8:FD:CB
* Precertificate (v1):
    Timestamp: 2019-03-27 09:13:56.485000
    Log ID: 44:94:65:2E:B0:EE:CE:AF:C4:40:07:D8:A8:FE:28:C0:DA:E6:82:BE:D8:CB:31:B5:3F:D3:33:96:B5:B6:81:A8""",  # noqa: E501
        },
        "jabber.at": {
            "admin_html": """<table>
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
            "text": """* Precertificate (v1):
    Timestamp: 2019-06-25 03:40:03.920000
    Log ID: 6F:53:76:AC:31:F0:31:19:D8:99:00:A4:51:15:FF:77:15:1C:11:D9:02:C1:00:29:06:8D:B2:08:9A:37:D9:13
* Precertificate (v1):
    Timestamp: 2019-06-25 03:40:03.862000
    Log ID: 29:3C:51:96:54:C8:39:65:BA:AA:50:FC:58:07:D4:B7:6F:BF:58:7A:29:72:DC:A4:C3:0C:F4:E5:45:47:F4:78""",  # noqa: E501
        },
    }

    def test_as_admin_html(self, precertificate_signed_certificate_timestamps_pub: x509.Certificate) -> None:
        """Test the ``extension_as_admin_html`` function."""
        ext = precertificate_signed_certificate_timestamps_pub.extensions.get_extension_for_oid(
            ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS
        )
        common_names = precertificate_signed_certificate_timestamps_pub.subject.get_attributes_for_oid(
            NameOID.COMMON_NAME
        )
        name = cast(str, common_names[0].value)
        config = self.minimal_test_values[name]

        expected = f'\n<div class="django-ca-extension-value">{config["admin_html"]}</div>'
        actual = extension_as_admin_html(ext)  # type: ignore[arg-type]

        msg_prefix = f"{name}: actual:\n{actual}\n"
        assertInHTML(expected, mark_safe(actual), msg_prefix=msg_prefix)

    def test_as_text(self, precertificate_signed_certificate_timestamps_pub: x509.Certificate) -> None:
        """Test rendering the extension as text."""
        ext = precertificate_signed_certificate_timestamps_pub.extensions.get_extension_for_oid(
            ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS
        )
        common_names = precertificate_signed_certificate_timestamps_pub.subject.get_attributes_for_oid(
            NameOID.COMMON_NAME
        )
        name = cast(str, common_names[0].value)
        config = self.minimal_test_values[name]

        assert extension_as_text(ext.value) == config["text"], name

        for extension_type in config.get("extension_type_alternatives", []):
            assert extension_as_text(extension_type) == config["text"], name


class TestSubjectAlternativeName(TestIssuerAlternativeName):
    """Test SubjectAlternativeName extension."""

    ext_class_key = "subject_alternative_name"
    ext_class_name = "SubjectAlternativeName"
    ext_class_type = x509.SubjectAlternativeName  # type: ignore[assignment]


class TestSubjectKeyIdentifierTestCase(ExtensionTestCaseMixin):
    """Test SubjectKeyIdentifier extension."""

    ext_class_key = "subject_key_identifier"
    ext_class_name = "SubjectKeyIdentifier"

    hex1 = "33:33:33:33:33:33"
    hex2 = "44:44:44:44:44:44"
    hex3 = "55:55:55:55:55:55"
    b1 = b"333333"
    b2 = b"DDDDDD"
    b3 = b"UUUUUU"
    test_values: ClassVar[ExtensionExampleValues] = {
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


class TestTLSFeature(ExtensionTestCaseMixin):
    """Test TLSFeature extension."""

    ext_class_key = "tls_feature"
    ext_class_name = "TLSFeature"

    test_values: ClassVar[ExtensionExampleValues] = {
        "one": {
            "admin_html": "<ul><li>status_request (OCSPMustStaple)</li></ul>",
            "extension_type": x509.TLSFeature(features=[x509.TLSFeatureType.status_request]),
            "serialized": ["status_request"],
            "text": "* status_request (OCSPMustStaple)",
        },
        "two": {
            "admin_html": "<ul><li>status_request (OCSPMustStaple)</li>"
            "<li>status_request_v2 (MultipleCertStatusRequest)</li></ul>",
            "extension_type": x509.TLSFeature(
                features=[x509.TLSFeatureType.status_request, x509.TLSFeatureType.status_request_v2]
            ),
            "extension_type_alternatives": [
                x509.TLSFeature(
                    features=[x509.TLSFeatureType.status_request_v2, x509.TLSFeatureType.status_request]
                )
            ],
            "serialized": ["status_request", "status_request_v2"],
            "serialized_alternatives": [
                ["status_request_v2", "status_request"],
                [x509.TLSFeatureType.status_request, x509.TLSFeatureType.status_request_v2],
                [x509.TLSFeatureType.status_request_v2, x509.TLSFeatureType.status_request],
            ],
            "text": "* status_request (OCSPMustStaple)\n* status_request_v2 (MultipleCertStatusRequest)",
        },
        "three": {
            "admin_html": "<ul><li>status_request_v2 (MultipleCertStatusRequest)</li></ul>",
            "extension_type": x509.TLSFeature(features=[x509.TLSFeatureType.status_request_v2]),
            "serialized": ["status_request_v2"],
            "text": "* status_request_v2 (MultipleCertStatusRequest)",
        },
    }

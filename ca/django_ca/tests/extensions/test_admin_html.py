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

"""Test how extensions look like in the admin interface."""

import base64
import typing
from typing import Any

from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID

from django.test import TestCase
from django.utils.safestring import mark_safe

from django_ca.constants import EXTENDED_KEY_USAGE_NAMES, KEY_USAGE_NAMES, ExtensionOID
from django_ca.extensions.utils import extension_as_admin_html
from django_ca.models import X509CertMixin
from django_ca.tests.base.constants import CERT_DATA
from django_ca.tests.base.mixins import TestCaseMixin
from django_ca.utils import bytes_to_hex

if hasattr(x509, "Admissions"):  # pragma: only cryptography<44.0
    ALL_EXTENSIONS_ADMISSIONS = """
<ul>
    <li>Authority: URI:https://default-authority.admissions.example.com</li>
    <li>Admissions:
        <ul>
            <li>Admission Authority: URI:https://authority.admissions.example.com</li>
            <li>Naming Authority:
                <ul>
                    <li>ID: 1.2.3</li>
                    <li>URL: https://naming-auth.admissions.example.com</li>
                    <li>Text: https://naming-auth.admissions.example.com</li>
                </ul>
            </li>
            <li>Profession Infos:
                <ul>
                    <li>Profession Info:
                        <ul>
                            <li>Naming Authority:                                  
                                <ul>
                                    <li>URL: https://naming-auth.profession-info.admissions.example.com</li>
                                    <li>Text: naming-auth.profession-info.admissions.example.com text</li>
                                </ul>
                            </li>
                            <li>Profession items:
                                <ul>
                                    <li>prof_item</li>
                                </ul>
                            </li>
                            <li>Profession OIDs:
                                <ul>
                                    <li>1.2.3.5</li>
                                </ul>
                            </li>
                            <li>Registration number: registration-number</li>
                            <li>Add Profession Info:
                                61:64:64:2D:70:72:6F:66:65:73:73:69:6F:6E:2D:69:6E:66:6F</li>
                        </ul>
                    </li>
                    <li>Profession Info:
                        <ul>
                            <li>Naming Authority: No values.</li>
                            <li>Profession items: 
                                <ul>
                                    <li>prof_item_minimal</li>
                                </ul>
                            </li>
                        </ul>
                    </li>
                </ul>
            </li>
        </ul>
    </li>
</ul>"""
    ALT_EXTENSIONS_ADMISSIONS = """
<ul>
    <li>Admissions:
        <ul>
            <li>Profession Infos:
                <ul>
                    <li>Profession Info:
                        <ul>
                            <li>Profession items:
                                <ul>
                                    <li>prof_item</li>
                                </ul>
                            </li>
                        </ul>
                    </li>
                </ul>
            </li>
        </ul>
    </li>
</ul>"""
else:
    ALL_EXTENSIONS_ADMISSIONS = (
        "30:82:01:9B:86:30:68:74:74:70:73:3A:2F:2F:64:65:66:61:75:6C:74:2D:61:75:74:68:6F:72:69:74:79:2E:61:"
        "64:6D:69:73:73:69:6F:6E:73:2E:65:78:61:6D:70:6C:65:2E:63:6F:6D:30:82:01:65:30:82:01:61:A0:2A:86:28:"
        "68:74:74:70:73:3A:2F:2F:61:75:74:68:6F:72:69:74:79:2E:61:64:6D:69:73:73:69:6F:6E:73:2E:65:78:61:6D:"
        "70:6C:65:2E:63:6F:6D:A1:5B:30:59:06:02:2A:03:16:2A:68:74:74:70:73:3A:2F:2F:6E:61:6D:69:6E:67:2D:61:"
        "75:74:68:2E:61:64:6D:69:73:73:69:6F:6E:73:2E:65:78:61:6D:70:6C:65:2E:63:6F:6D:0C:27:6E:61:6D:69:6E:"
        "67:2D:61:75:74:68:2E:61:64:6D:69:73:73:69:6F:6E:73:2E:65:78:61:6D:70:6C:65:2E:63:6F:6D:20:74:65:78:"
        "74:30:81:D5:30:81:B7:A0:77:30:75:16:3A:68:74:74:70:73:3A:2F:2F:6E:61:6D:69:6E:67:2D:61:75:74:68:2E:"
        "70:72:6F:66:65:73:73:69:6F:6E:2D:69:6E:66:6F:2E:61:64:6D:69:73:73:69:6F:6E:73:2E:65:78:61:6D:70:6C:"
        "65:2E:63:6F:6D:0C:37:6E:61:6D:69:6E:67:2D:61:75:74:68:2E:70:72:6F:66:65:73:73:69:6F:6E:2D:69:6E:66:"
        "6F:2E:61:64:6D:69:73:73:69:6F:6E:73:2E:65:78:61:6D:70:6C:65:2E:63:6F:6D:20:74:65:78:74:30:0B:0C:09:"
        "70:72:6F:66:5F:69:74:65:6D:30:05:06:03:2A:03:05:13:13:72:65:67:69:73:74:72:61:74:69:6F:6E:2D:6E:75:"
        "6D:62:65:72:04:13:61:64:64:2D:70:72:6F:66:65:73:73:69:6F:6E:2D:69:6E:66:6F:30:19:A0:02:30:00:30:13:"
        "0C:11:70:72:6F:66:5F:69:74:65:6D:5F:6D:69:6E:69:6D:61:6C"
    )
    ALT_EXTENSIONS_ADMISSIONS = "30:15:30:13:30:11:30:0F:30:0D:30:0B:0C:09:70:72:6F:66:5F:69:74:65:6D"


class CertificateExtensionTestCase(TestCaseMixin, TestCase):
    """Test output for all extensions in our certificate fixtures."""

    load_cas = "__all__"
    load_certs = "__all__"
    admin_html: typing.ClassVar[dict[str, dict[x509.ObjectIdentifier, str]]] = {
        "root": {},
        "child": {
            ExtensionOID.BASIC_CONSTRAINTS: f"CA: True, path length: {CERT_DATA['child']['path_length']}",
        },
        "ec": {
            ExtensionOID.BASIC_CONSTRAINTS: f"CA: True, path length: {CERT_DATA['ec']['path_length']}",
        },
        "dsa": {
            ExtensionOID.BASIC_CONSTRAINTS: f"CA: True, path length: {CERT_DATA['dsa']['path_length']}",
        },
        "pwd": {
            ExtensionOID.BASIC_CONSTRAINTS: f"CA: True, path length: {CERT_DATA['pwd']['path_length']}",
        },
        "ed25519": {
            ExtensionOID.BASIC_CONSTRAINTS: f"CA: True, path length: {CERT_DATA['ed25519']['path_length']}",
            ExtensionOID.INHIBIT_ANY_POLICY: "skip certs: 1",
            ExtensionOID.NAME_CONSTRAINTS: """Permitted: <ul><li>DNS:.org</li></ul>
                    Excluded: <ul><li>DNS:.net</li></ul>""",
            ExtensionOID.POLICY_CONSTRAINTS: """<ul>
                    <li>InhibitPolicyMapping: 2</li><li>RequireExplicitPolicy: 1</li>
                </ul>""",
        },
        "ed448": {
            ExtensionOID.BASIC_CONSTRAINTS: f"CA: True, path length: {CERT_DATA['ed448']['path_length']}",
            ExtensionOID.NAME_CONSTRAINTS: "Permitted: <ul><li>DNS:.com</li></ul>",
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
            ExtensionOID.ADMISSIONS: ALL_EXTENSIONS_ADMISSIONS,
            ExtensionOID.EXTENDED_KEY_USAGE: """<ul>
                <li>clientAuth</li><li>codeSigning</li><li>emailProtection</li><li>serverAuth</li>
            </ul>""",
            ExtensionOID.OCSP_NO_CHECK: "Yes",
            ExtensionOID.PRECERT_POISON: "Yes",
            ExtensionOID.TLS_FEATURE: "<ul><li>status_request_v2 (MultipleCertStatusRequest)</li>"
            "<li>status_request (OCSPMustStaple)</li></ul>",
        },
        "alt-extensions": {
            ExtensionOID.ADMISSIONS: ALT_EXTENSIONS_ADMISSIONS,
            ExtensionOID.CRL_DISTRIBUTION_POINTS: """
DistributionPoint:
<ul><li>Full Name: URI:https://example.com</li></ul>

DistributionPoint:
<ul>
  <li>Relative Name: <ul><li>commonName (CN): rdn.ca.example.com</li></ul></li>
  <li>CRL Issuer: URI:http://crl.ca.example.com, URI:http://crl.ca.example.net</li>
  <li>Reasons: ca_compromise, key_compromise</li>
</ul>""",
            ExtensionOID.EXTENDED_KEY_USAGE: """<ul>
                <li>clientAuth</li><li>codeSigning</li><li>emailProtection</li><li>serverAuth</li>
            </ul>""",
            ExtensionOID.OCSP_NO_CHECK: "Yes",
            ExtensionOID.TLS_FEATURE: "<ul><li>status_request (OCSPMustStaple)</li></ul>",
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

    def setUpCert(self, name: str) -> None:  # pylint: disable=invalid-name,too-many-locals
        """Set up default values for certificates."""
        self.admin_html.setdefault(name, {})

        config = CERT_DATA[name]
        extensions = {ext["type"]: ext for ext in config["extensions"]}
        if authority_information_access := extensions.get("authority_information_access"):
            issuers = [
                aia["access_location"]
                for aia in authority_information_access["value"]
                if aia["access_method"] == AuthorityInformationAccessOID.CA_ISSUERS.dotted_string
            ]
            ocsp = [
                aia["access_location"]
                for aia in authority_information_access["value"]
                if aia["access_method"] == AuthorityInformationAccessOID.OCSP.dotted_string
            ]

            lines = []
            if issuers:
                issuer_lines = [f"<li>{fn['type']}:{fn['value']}</li>" for fn in issuers]
                lines.append(f"CA Issuers: <ul>{''.join(issuer_lines)}</ul>")
            if ocsp:
                ocsp_lines = [f"<li>{fn['type']}:{fn['value']}</li>" for fn in ocsp]
                lines.append(f"OCSP: <ul>{''.join(ocsp_lines)}</ul>")
            self.admin_html[name].setdefault(ExtensionOID.AUTHORITY_INFORMATION_ACCESS, "\n".join(lines))

        if authority_key_identifier := extensions.get("authority_key_identifier"):
            key_identifier = authority_key_identifier["value"].get("key_identifier")
            if key_identifier is not None:
                key_identifier = bytes_to_hex(base64.b64decode(key_identifier.encode()))

            self.admin_html[name].setdefault(
                ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
                f"<ul><li>Key ID: <span class='django-ca-serial'>{key_identifier}</span></li></ul>",
            )

        if crl_distribution_points := extensions.get("crl_distribution_points"):
            self._set_distribution_point_extension(
                name, crl_distribution_points, ExtensionOID.CRL_DISTRIBUTION_POINTS
            )

        # NOTE: Custom extension class sorts values, but we render them in order as they appear in the
        #       certificate, so we still have to override this in some places.
        if extended_key_usage := extensions.get("extended_key_usage"):
            oids = [x509.ObjectIdentifier(oid) for oid in extended_key_usage["value"]]
            lines = [f"<li>{EXTENDED_KEY_USAGE_NAMES[oid]}</li>" for oid in oids]
            self.admin_html[name].setdefault(ExtensionOID.EXTENDED_KEY_USAGE, f"<ul>{''.join(lines)}</ul>")

        if alternative_names := extensions.get("issuer_alternative_name"):
            sans = [f"<li>{san['type']}:{san['value']}</li>" for san in alternative_names["value"]]
            self.admin_html[name].setdefault(
                ExtensionOID.ISSUER_ALTERNATIVE_NAME, f"<ul>{''.join(sans)}</ul>"
            )

        if freshest_crl := extensions.get("freshest_crl"):
            self._set_distribution_point_extension(name, freshest_crl, ExtensionOID.FRESHEST_CRL)

        if key_usage := extensions.get("key_usage"):
            kus = sorted([f"<li>{KEY_USAGE_NAMES[ku]}</li>" for ku in key_usage["value"]])
            self.admin_html[name].setdefault(ExtensionOID.KEY_USAGE, f"<ul>{''.join(kus)}</ul>")

        if alternative_names := extensions.get("subject_alternative_name"):
            sans = [f"<li>{san['type']}:{san['value']}</li>" for san in alternative_names["value"]]
            self.admin_html[name].setdefault(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME, f"<ul>{''.join(sans)}</ul>"
            )

        if subject_key_identifier := extensions.get("subject_key_identifier"):
            value = base64.b64decode(subject_key_identifier["value"].encode())
            self.admin_html[name].setdefault(
                ExtensionOID.SUBJECT_KEY_IDENTIFIER,
                bytes_to_hex(value),
            )

        if CERT_DATA[name].get("ocsp_no_check"):
            self.admin_html[name].setdefault(ExtensionOID.OCSP_NO_CHECK, "Yes")

    def _set_distribution_point_extension(
        self, name: str, value: dict[str, Any], oid: x509.ObjectIdentifier
    ) -> None:
        full_names = []
        for dpoint in value["value"]:
            if dpoint["full_name"]:
                full_names.append(
                    [f"<li>Full Name: {fn['type']}:{fn['value']}</li>" for fn in dpoint["full_name"]]
                )
            else:
                full_names = []
                break
        if full_names:
            self.admin_html[name].setdefault(
                oid,
                "\n".join([f"DistributionPoint: <ul>{''.join(full_name)}</ul>" for full_name in full_names]),
            )

    def assertAdminHTML(self, name: str, cert: X509CertMixin) -> None:  # pylint: disable=invalid-name
        """Assert that the actual extension HTML is equivalent to the expected HTML."""
        for oid, ext in cert.extensions.items():
            assert oid in self.admin_html[name], (name, oid)
            admin_html = self.admin_html[name][oid]
            admin_html = f'\n<div class="django-ca-extension-value">{admin_html}</div>'
            actual = extension_as_admin_html(ext)
            msg_prefix = f"{name}, {oid}: actual:\n{actual}\n"
            self.assertInHTML(admin_html, mark_safe(actual), msg_prefix=msg_prefix)

    def test_cas_as_html(self) -> None:
        """Test output of CAs."""
        for name, ca in self.cas.items():
            self.setUpCert(name)
            self.admin_html[name].setdefault(ExtensionOID.BASIC_CONSTRAINTS, "CA: True")
            self.assertAdminHTML(name, ca)

    def test_certs_as_html(self) -> None:
        """Test output of CAs."""
        for name, cert in self.certs.items():
            self.setUpCert(name)
            self.admin_html[name].setdefault(ExtensionOID.BASIC_CONSTRAINTS, "CA: False")
            self.assertAdminHTML(name, cert)

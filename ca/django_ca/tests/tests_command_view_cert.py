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
# see <http://www.gnu.org/licenses/>

"""Test the view_cert management command."""

import typing
from io import BytesIO

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

from django.test import TestCase

from freezegun import freeze_time

from ..models import Certificate, Watcher
from .base import certs, override_settings, override_tmpcadir, timestamps
from .base.mixins import TestCaseMixin

output = {
    "root-cert": """Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
Authority Information Access{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
Basic Constraints (critical):
    CA:FALSE
CRL Distribution Points{crl_distribution_points_critical}:
    * DistributionPoint:
      * Full Name:
        * URI:{crl}
Extended Key Usage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
Key Usage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
    * {key_usage_2}
Subject Alternative Name{subject_alternative_name_critical}:
    * {subject_alternative_name_0}
Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}
Watchers:
Digest:
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
""",
    "child-cert": """Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
Authority Information Access{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
Basic Constraints (critical):
    CA:FALSE
CRL Distribution Points{crl_distribution_points_critical}:
    * DistributionPoint:
      * Full Name:
        * URI:{crl}
Extended Key Usage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
Key Usage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
    * {key_usage_2}
Subject Alternative Name{subject_alternative_name_critical}:
    * {subject_alternative_name_0}
Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}
Watchers:
Digest:
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
""",
    "ecc-cert": """Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
Authority Information Access{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
Basic Constraints (critical):
    CA:FALSE
CRL Distribution Points{crl_distribution_points_critical}:
    * DistributionPoint:
      * Full Name:
        * URI:{crl}
Extended Key Usage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
Key Usage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
    * {key_usage_2}
Subject Alternative Name{subject_alternative_name_critical}:
    * {subject_alternative_name_0}
Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}
Watchers:
Digest:
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
""",
    "pwd-cert": """Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
Authority Information Access{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
Basic Constraints (critical):
    CA:FALSE
CRL Distribution Points{crl_distribution_points_critical}:
    * DistributionPoint:
      * Full Name:
        * URI:{crl}
Extended Key Usage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
Key Usage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
    * {key_usage_2}
Subject Alternative Name{subject_alternative_name_critical}:
    * {subject_alternative_name_0}
Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}
Watchers:
Digest:
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
""",
    "dsa-cert": """Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
Authority Information Access{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
Basic Constraints (critical):
    CA:FALSE
CRL Distribution Points{crl_distribution_points_critical}:
    * DistributionPoint:
      * Full Name:
        * URI:{crl}
Extended Key Usage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
Key Usage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
    * {key_usage_2}
Subject Alternative Name{subject_alternative_name_critical}:
    * {subject_alternative_name_0}
Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}
Watchers:
Digest:
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
""",
    "profile-client": """Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
Authority Information Access{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
Basic Constraints (critical):
    CA:FALSE
CRL Distribution Points{crl_distribution_points_critical}:
    * DistributionPoint:
      * Full Name:
        * URI:{crl}
Extended Key Usage{extended_key_usage_critical}:
    * {extended_key_usage_0}
Key Usage{key_usage_critical}:
    * {key_usage_0}
Subject Alternative Name{subject_alternative_name_critical}:
    * {subject_alternative_name_0}
Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}
Watchers:
Digest:
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
""",
    "profile-server": """Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
Authority Information Access{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
Basic Constraints (critical):
    CA:FALSE
CRL Distribution Points{crl_distribution_points_critical}:
    * DistributionPoint:
      * Full Name:
        * URI:{crl}
Extended Key Usage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
Key Usage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
    * {key_usage_2}
Subject Alternative Name{subject_alternative_name_critical}:
    * {subject_alternative_name_0}
Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}
Watchers:
Digest:
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
""",
    "profile-webserver": """Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
Authority Information Access{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
Basic Constraints (critical):
    CA:FALSE
CRL Distribution Points{crl_distribution_points_critical}:
    * DistributionPoint:
      * Full Name:
        * URI:{crl}
Extended Key Usage{extended_key_usage_critical}:
    * {extended_key_usage_0}
Key Usage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
    * {key_usage_2}
Subject Alternative Name{subject_alternative_name_critical}:
    * {subject_alternative_name_0}
Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}
Watchers:
Digest:
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
""",
    "profile-enduser": """Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
Authority Information Access{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
Basic Constraints (critical):
    CA:FALSE
CRL Distribution Points{crl_distribution_points_critical}:
    * DistributionPoint:
      * Full Name:
        * URI:{crl}
Extended Key Usage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
    * {extended_key_usage_2}
Key Usage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
    * {key_usage_2}
Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}
Watchers:
Digest:
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
""",
    "profile-ocsp": """Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
Authority Information Access{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
Basic Constraints (critical):
    CA:FALSE
CRL Distribution Points{crl_distribution_points_critical}:
    * DistributionPoint:
      * Full Name:
        * URI:{crl}
Extended Key Usage{extended_key_usage_critical}:
    * {extended_key_usage_0}
Key Usage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
    * {key_usage_2}
Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}
Watchers:
Digest:
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
""",
    "no-extensions": """Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
Watchers:
Digest:
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
""",
    "all-extensions": """Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
Authority Information Access{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
Basic Constraints (critical):
    CA:FALSE
CRL Distribution Points{crl_distribution_points_critical}:
    * DistributionPoint:
      * Full Name:
        * URI:{crl}
Extended Key Usage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
    * {extended_key_usage_2}
    * {extended_key_usage_3}
Freshest CRL{freshest_crl_critical}:
    * DistributionPoint:
      * Full Name:
        * URI:{freshest_crl_0.full_name[0].value}
Inhibit anyPolicy{inhibit_any_policy_critical}:
    1
Issuer Alternative Name{issuer_alternative_name_critical}:
    * {issuer_alternative_name[0]}
Key Usage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
    * {key_usage_2}
Name Constraints{name_constraints_critical}:
    Permitted:
      * DNS:{name_constraints.permitted[0].value}
    Excluded:
      * DNS:{name_constraints.excluded[0].value}
OCSP No Check{ocsp_no_check_critical}:
    Yes
Policy Constraints{policy_constraints_critical}:
    * InhibitPolicyMapping: {policy_constraints.inhibit_policy_mapping}
    * RequireExplicitPolicy: {policy_constraints.require_explicit_policy}
{precert_poison}
Subject Alternative Name{subject_alternative_name_critical}:
    * {subject_alternative_name_0}
    * {subject_alternative_name_1}
    * {subject_alternative_name_2}
Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}
TLS Feature{tls_feature_critical}:
    * {tls_feature_0}
    * {tls_feature_1}
Watchers:
Digest:
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
""",
    "alt-extensions": """Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
Authority Information Access{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
Basic Constraints{basic_constraints_critical}:
    CA:FALSE
CRL Distribution Points{crl_distribution_points_critical}:
    * DistributionPoint:
      * Full Name:
        * URI:{crl_distribution_points[0].full_name[0].value}
    * DistributionPoint:
      * Relative Name: /CN=rdn.ca.example.com
      * CRL Issuer:
        * URI:{crl_distribution_points[1].crl_issuer[0].value}
        * URI:{crl_distribution_points[1].crl_issuer[1].value}
      * Reasons: ca_compromise, key_compromise
Extended Key Usage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
    * {extended_key_usage_2}
    * {extended_key_usage_3}
Issuer Alternative Name{issuer_alternative_name_critical}:
    * {issuer_alternative_name[0]}
    * {issuer_alternative_name[1]}
Key Usage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
    * {key_usage_2}
Name Constraints{name_constraints_critical}:
    Permitted:
      * DNS:{name_constraints.permitted[0].value}
OCSP No Check{ocsp_no_check_critical}:
    Yes
Subject Alternative Name{subject_alternative_name_critical}:
    * {subject_alternative_name[0]}
    * {subject_alternative_name[1]}
    * {subject_alternative_name[2]}
    * {subject_alternative_name[3]}
    * {subject_alternative_name[4]}
    * {subject_alternative_name[5]}
Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}
TLS Feature{tls_feature_critical}:
    * {tls_feature_0}
Watchers:
Digest:
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
""",
}


@override_settings(CA_MIN_KEY_SIZE=1024, CA_PROFILES={}, CA_DEFAULT_SUBJECT=tuple())
class ViewCertTestCase(TestCaseMixin, TestCase):
    """Main test class for this command."""

    load_cas = "__all__"
    load_certs = "__all__"

    def _get_format(self, cert: Certificate) -> typing.Dict[str, str]:
        return {
            "cn": cert.cn,
            "from": cert.not_before.strftime("%Y-%m-%d %H:%M"),
            "until": cert.not_after.strftime("%Y-%m-%d %H:%M"),
            "sha256": cert.get_fingerprint(hashes.SHA256()),
            "sha512": cert.get_fingerprint(hashes.SHA512()),
            "subjectKeyIdentifier": "",
            "authorityKeyIdentifier": "",
            "hpkp": cert.hpkp_pin,
        }

    def assertBasicOutput(self, status: str) -> None:  # pylint: disable=invalid-name
        """Test basic properties of output."""
        # pylint: disable=consider-using-f-string
        for key, cert in self.ca_certs:
            stdout, stderr = self.cmd("view_cert", cert.serial, stdout=BytesIO(), stderr=BytesIO())
            if cert.subject_alternative_name is None:
                self.assertEqual(
                    stdout.decode("utf-8"),
                    """Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: {status}
Watchers:
Digest:
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}

{pub[pem]}""".format(
                        status=status, **self.get_cert_context(key)
                    ),
                )
            elif len(cert.subject_alternative_name) != 1:
                continue  # no need to duplicate this here
            else:
                self.assertEqual(
                    stdout.decode("utf-8"),
                    """Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: {status}
Subject Alternative Name:
    * {subject_alternative_name_0}
Watchers:
Digest:
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}

{pub[pem]}""".format(
                        status=status, **self.get_cert_context(key)
                    ),
                )
            self.assertEqual(stderr, b"")

        # test with no pem but with extensions
        for key, cert in self.ca_certs:
            stdout, stderr = self.cmd(
                "view_cert", cert.serial, no_pem=True, extensions=True, stdout=BytesIO(), stderr=BytesIO()
            )
            self.assertEqual(
                stdout.decode("utf-8"),
                """Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: {status}
Authority Information Access{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
Basic Constraints (critical):
    CA:FALSE
CRL Distribution Points{crl_distribution_points_critical}:
    * DistributionPoint:
      * Full Name:
        * URI:{crl}
Extended Key Usage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
Key Usage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
    * {key_usage_2}
Subject Alternative Name{subject_alternative_name_critical}:
    * {subject_alternative_name_0}
Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}
Watchers:
Digest:
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
""".format(
                    status=status, **self.get_cert_context(key)
                ),
            )
            self.assertEqual(stderr, b"")

    @freeze_time(timestamps["before_everything"])
    def test_basic_not_yet_valid(self) -> None:
        """Basic tests when all certs are not yet valid."""
        self.assertBasicOutput(status="Not yet valid")

    @freeze_time(timestamps["everything_expired"])
    def test_basic_expired(self) -> None:
        """Basic tests when all certs are expired."""
        self.assertBasicOutput(status="Expired")

    @freeze_time(timestamps["everything_valid"])
    def test_certs(self) -> None:
        """Test main certs."""
        for name, cert in self.usable_certs:
            stdout, stderr = self.cmd(
                "view_cert", cert.serial, no_pem=True, extensions=True, stdout=BytesIO(), stderr=BytesIO()
            )
            self.assertEqual(stderr, b"")

            context = self.get_cert_context(name)
            self.assertEqual(stdout.decode("utf-8"), output[name].format(**context))

    @freeze_time(timestamps["everything_valid"])
    def test_der(self) -> None:
        """Test viewing a cert as DER."""
        # pylint: disable=consider-using-f-string
        stdout, stderr = self.cmd(
            "view_cert", self.cert.serial, format=Encoding.DER, stdout=BytesIO(), stderr=BytesIO()
        )
        expected = """Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
Subject Alternative Name{subject_alternative_name_critical}:
    * {subject_alternative_name[0]}
Watchers:
Digest:
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}

""".format(
            **self.get_cert_context("child-cert")
        )
        expected = expected.encode("utf-8") + certs["child-cert"]["pub"]["der"] + b"\n"

        self.assertEqual(stdout, expected)
        self.assertEqual(stderr, b"")

    def test_revoked(self) -> None:
        """Test viewing a revoked cert."""
        # pylint: disable=consider-using-f-string
        self.cert.revoked = True
        self.cert.save()
        stdout, stderr = self.cmd(
            "view_cert", self.cert.serial, no_pem=True, stdout=BytesIO(), stderr=BytesIO()
        )
        self.assertEqual(
            stdout.decode("utf-8"),
            """Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Revoked
Subject Alternative Name:
    * DNS:{cn}
Watchers:
Digest:
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
""".format(
                **certs["child-cert"]
            ),
        )
        self.assertEqual(stderr, b"")

    @freeze_time(timestamps["everything_valid"])
    @override_tmpcadir()
    def test_no_san_with_watchers(self) -> None:
        """Test a cert with no subjectAltNames but with watchers."""
        cert = self.certs["no-extensions"]
        watcher = Watcher.from_addr("user@example.com")
        cert.watchers.add(watcher)

        stdout, stderr = self.cmd("view_cert", cert.serial, no_pem=True, stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(
            stdout.decode("utf-8"),
            """Common Name: %(cn)s
Valid from: %(from)s
Valid until: %(until)s
Status: Valid
Watchers:
* user@example.com
Digest:
    sha256: %(sha256)s
    sha512: %(sha512)s
HPKP pin: %(hpkp)s
"""
            % self._get_format(cert),
        )
        self.assertEqual(stderr, b"")

    def assertContrib(self, name: str, expected: str, **context: str) -> None:  # pylint: disable=invalid-name
        """Assert basic contrib output."""
        cert = self.certs[name]
        stdout, stderr = self.cmd(
            "view_cert", cert.serial, no_pem=True, extensions=True, stdout=BytesIO(), stderr=BytesIO()
        )
        context.update(self.get_cert_context(name))
        self.assertEqual(stderr, b"")
        self.assertEqual(stdout.decode("utf-8"), expected.format(**context))

    @freeze_time("2019-04-01")
    def test_contrib_godaddy_derstandardat(self) -> None:
        """Test contrib godaddy cert for derstandard.at."""

        id1 = "A4:B9:09:90:B4:18:58:14:87:BB:13:A2:CC:67:70:0A:3C:35:98:04:F9:1B:DF:B8:E3:77:CD:0E:C8:0D:DC:10"  # NOQA: E501
        id2 = "EE:4B:BD:B7:75:CE:60:BA:E1:42:69:1F:AB:E1:9E:66:A3:0F:7E:5F:B0:72:D8:83:00:C4:7B:89:7A:A8:FD:CB"  # NOQA: E501
        id3 = "44:94:65:2E:B0:EE:CE:AF:C4:40:07:D8:A8:FE:28:C0:DA:E6:82:BE:D8:CB:31:B5:3F:D3:33:96:B5:B6:81:A8"  # NOQA: E501
        sct = f"""Precertificate Signed Certificate Timestamps:
    * Precertificate (v1):
        Timestamp: 2019-03-27 09:13:54.342000
        Log ID: {id1}
    * Precertificate (v1):
        Timestamp: 2019-03-27 09:13:55.237000
        Log ID: {id2}
    * Precertificate (v1):
        Timestamp: 2019-03-27 09:13:56.485000
        Log ID: {id3}"""

        self.assertContrib(
            "godaddy_g2_intermediate-cert",
            """Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
Authority Information Access{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
Basic Constraints{basic_constraints_critical}:
    {basic_constraints_text}
CRL Distribution Points:
    * DistributionPoint:
      * Full Name:
        * URI:http://crl.godaddy.com/gdig2s1-1015.crl
Certificate Policies{certificate_policies_critical}:
    * Policy Identifier: {certificate_policies_0[policy_identifier]}
      Policy Qualifiers:
      * http://certificates.godaddy.com/repository/
    * Policy Identifier: {certificate_policies_1[policy_identifier]}
      No Policy Qualifiers
Extended Key Usage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
Key Usage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
{sct}
Subject Alternative Name{subject_alternative_name_critical}:
    * {subject_alternative_name_0}
    * {subject_alternative_name_1}
    * {subject_alternative_name_2}
    * {subject_alternative_name_3}
    * {subject_alternative_name_4}
    * {subject_alternative_name_5}
    * {subject_alternative_name_6}
    * {subject_alternative_name_7}
    * {subject_alternative_name_8}
    * {subject_alternative_name_9}
    * {subject_alternative_name_10}
    * {subject_alternative_name_11}
    * {subject_alternative_name_12}
    * {subject_alternative_name_13}
    * {subject_alternative_name_14}
    * {subject_alternative_name_15}
    * {subject_alternative_name_16}
    * {subject_alternative_name_17}
    * {subject_alternative_name_18}
    * {subject_alternative_name_19}
    * {subject_alternative_name_20}
    * {subject_alternative_name_21}
    * {subject_alternative_name_22}
    * {subject_alternative_name_23}
    * {subject_alternative_name_24}
    * {subject_alternative_name_25}
    * {subject_alternative_name_26}
    * {subject_alternative_name_27}
    * {subject_alternative_name_28}
    * {subject_alternative_name_29}
    * {subject_alternative_name_30}
    * {subject_alternative_name_31}
    * {subject_alternative_name_32}
    * {subject_alternative_name_33}
    * {subject_alternative_name_34}
    * {subject_alternative_name_35}
    * {subject_alternative_name_36}
    * {subject_alternative_name_37}
    * {subject_alternative_name_38}
    * {subject_alternative_name_39}
    * {subject_alternative_name_40}
    * {subject_alternative_name_41}
    * {subject_alternative_name_42}
    * {subject_alternative_name_43}
    * {subject_alternative_name_44}
    * {subject_alternative_name_45}
    * {subject_alternative_name_46}
    * {subject_alternative_name_47}
    * {subject_alternative_name_48}
Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}
Watchers:
Digest:
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
""",
            sct=sct,
        )

    @freeze_time("2019-07-05")
    def test_contrib_letsencrypt_jabber_at(self) -> None:
        """Test contrib letsencrypt cert."""
        # pylint: disable=consider-using-f-string
        self.maxDiff = None
        name = "letsencrypt_x3-cert"
        context = self.get_cert_context(name)
        context[
            "id1"
        ] = "6F:53:76:AC:31:F0:31:19:D8:99:00:A4:51:15:FF:77:15:1C:11:D9:02:C1:00:29:06:8D:B2:08:9A:37:D9:13"  # NOQA: E501
        context[
            "id2"
        ] = "29:3C:51:96:54:C8:39:65:BA:AA:50:FC:58:07:D4:B7:6F:BF:58:7A:29:72:DC:A4:C3:0C:F4:E5:45:47:F4:78"  # NOQA: E501
        sct = """Precertificate Signed Certificate Timestamps{sct_critical}:
    * Precertificate ({sct_values[0][version]}):
        Timestamp: {sct_values[0][timestamp]}
        Log ID: {id1}
    * Precertificate ({sct_values[1][version]}):
        Timestamp: {sct_values[1][timestamp]}
        Log ID: {id2}""".format(
            **context
        )

        self.assertContrib(
            "letsencrypt_x3-cert",
            """Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
Authority Information Access{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
Basic Constraints{basic_constraints_critical}:
    {basic_constraints_text}
Certificate Policies{certificate_policies_critical}:
    * Policy Identifier: {certificate_policies_0[policy_identifier]}
      No Policy Qualifiers
    * Policy Identifier: {certificate_policies_1[policy_identifier]}
      Policy Qualifiers:
      * {certificate_policies_1[policy_qualifiers][0]}
Extended Key Usage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
Key Usage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
{sct}
Subject Alternative Name{subject_alternative_name_critical}:
    * {subject_alternative_name_0}
    * {subject_alternative_name_1}
    * {subject_alternative_name_2}
    * {subject_alternative_name_3}
    * {subject_alternative_name_4}
    * {subject_alternative_name_5}
    * {subject_alternative_name_6}
    * {subject_alternative_name_7}
    * {subject_alternative_name_8}
    * {subject_alternative_name_9}
Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}
Watchers:
Digest:
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
""",
            sct=sct,
        )

    @freeze_time("2018-12-01")
    def test_contrib_cloudflare_1(self) -> None:
        """Test contrib cloudflare cert."""
        # pylint: disable=consider-using-f-string
        self.assertContrib(
            "cloudflare_1",
            """Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
Authority Information Access{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
Basic Constraints{basic_constraints_critical}:
    {basic_constraints_text}
CRL Distribution Points:
    * DistributionPoint:
      * Full Name:
        * URI:http://crl.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crl
Certificate Policies{certificate_policies_critical}:
    * Policy Identifier: {certificate_policies_0[policy_identifier]}
      Policy Qualifiers:
      * https://secure.comodo.com/CPS
    * Policy Identifier: {certificate_policies_1[policy_identifier]}
      No Policy Qualifiers
Extended Key Usage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
Key Usage{key_usage_critical}:
    * {key_usage_0}
{precert_poison}
Subject Alternative Name{subject_alternative_name_critical}:
    * {subject_alternative_name_0}
    * {subject_alternative_name_1}
    * {subject_alternative_name_2}
    * {subject_alternative_name_3}
    * {subject_alternative_name_4}
    * {subject_alternative_name_5}
    * {subject_alternative_name_6}
    * {subject_alternative_name_7}
    * {subject_alternative_name_8}
    * {subject_alternative_name_9}
    * {subject_alternative_name_10}
    * {subject_alternative_name_11}
    * {subject_alternative_name_12}
    * {subject_alternative_name_13}
    * {subject_alternative_name_14}
    * {subject_alternative_name_15}
    * {subject_alternative_name_16}
    * {subject_alternative_name_17}
    * {subject_alternative_name_18}
    * {subject_alternative_name_19}
    * {subject_alternative_name_20}
    * {subject_alternative_name_21}
    * {subject_alternative_name_22}
    * {subject_alternative_name_23}
    * {subject_alternative_name_24}
    * {subject_alternative_name_25}
    * {subject_alternative_name_26}
    * {subject_alternative_name_27}
    * {subject_alternative_name_28}
    * {subject_alternative_name_29}
    * {subject_alternative_name_30}
    * {subject_alternative_name_31}
    * {subject_alternative_name_32}
    * {subject_alternative_name_33}
    * {subject_alternative_name_34}
    * {subject_alternative_name_35}
    * {subject_alternative_name_36}
    * {subject_alternative_name_37}
    * {subject_alternative_name_38}
    * {subject_alternative_name_39}
    * {subject_alternative_name_40}
    * {subject_alternative_name_41}
    * {subject_alternative_name_42}
    * {subject_alternative_name_43}
    * {subject_alternative_name_44}
    * {subject_alternative_name_45}
    * {subject_alternative_name_46}
    * {subject_alternative_name_47}
    * {subject_alternative_name_48}
    * {subject_alternative_name_49}
    * {subject_alternative_name_50}
    * {subject_alternative_name_51}
    * {subject_alternative_name_52}
    * {subject_alternative_name_53}
    * {subject_alternative_name_54}
    * {subject_alternative_name_55}
    * {subject_alternative_name_56}
    * {subject_alternative_name_57}
    * {subject_alternative_name_58}
    * {subject_alternative_name_59}
    * {subject_alternative_name_60}
    * {subject_alternative_name_61}
    * {subject_alternative_name_62}
    * {subject_alternative_name_63}
    * {subject_alternative_name_64}
    * {subject_alternative_name_65}
    * {subject_alternative_name_66}
    * {subject_alternative_name_67}
    * {subject_alternative_name_68}
    * {subject_alternative_name_69}
    * {subject_alternative_name_70}
    * {subject_alternative_name_71}
    * {subject_alternative_name_72}
    * {subject_alternative_name_73}
    * {subject_alternative_name_74}
    * {subject_alternative_name_75}
    * {subject_alternative_name_76}
    * {subject_alternative_name_77}
    * {subject_alternative_name_78}
    * {subject_alternative_name_79}
    * {subject_alternative_name_80}
    * {subject_alternative_name_81}
    * {subject_alternative_name_82}
    * {subject_alternative_name_83}
    * {subject_alternative_name_84}
Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}
Watchers:
Digest:
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
""".format(
                **self.get_cert_context("cloudflare_1")
            ),
        )

    def test_contrib_multiple_ous(self) -> None:
        """Test special contrib case with multiple OUs."""
        self.assertContrib(
            "multiple_ous",
            """Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
Watchers:
Digest:
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
""",
        )

    def test_unknown_cert(self) -> None:
        """Test viewing an unknown certificate."""
        name = "foobar"
        with self.assertCommandError(rf"^Error: argument cert: {name}: Certificate not found\.$"):
            self.cmd("view_cert", name, no_pem=True)


@override_settings(CA_MIN_KEY_SIZE=1024, CA_PROFILES={}, CA_DEFAULT_SUBJECT=tuple(), USE_TZ=True)
class ViewCertWithTZTestCase(ViewCertTestCase):
    """Main tests but with TZ support."""

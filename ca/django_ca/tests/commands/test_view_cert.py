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

"""Test the view_cert management command."""

import typing
from typing import Optional

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from django.test import TestCase, override_settings

from freezegun import freeze_time

from django_ca.models import Watcher
from django_ca.tests.base.constants import CERT_DATA, TIMESTAMPS
from django_ca.tests.base.mixins import TestCaseMixin
from django_ca.tests.base.utils import cmd, override_tmpcadir

expected = {
    "root-cert": """* Subject:
  * countryName (C): AT
  * stateOrProvinceName (ST): Vienna
  * localityName (L): Vienna
  * organizationName (O): Django CA
  * organizationalUnitName (OU): Django CA Testsuite
  * commonName (CN): {name}.example.com
* Serial: {serial_colons}
* Issuer:
  * commonName (CN): root.example.com
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid
* No watchers

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints (critical):
{basic_constraints_text}
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Extended Key Usage{extended_key_usage_critical}:
{extended_key_usage_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Alternative Name{subject_alternative_name_critical}:
{subject_alternative_name_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}
""",
    "child-cert": """* Subject:
  * countryName (C): AT
  * stateOrProvinceName (ST): Vienna
  * localityName (L): Vienna
  * organizationName (O): Django CA
  * organizationalUnitName (OU): Django CA Testsuite
  * commonName (CN): {name}.example.com
* Serial: {serial_colons}
* Issuer:
  * commonName (CN): child.example.com
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid
* No watchers

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints (critical):
  CA:FALSE
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Extended Key Usage{extended_key_usage_critical}:
{extended_key_usage_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Alternative Name{subject_alternative_name_critical}:
{subject_alternative_name_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}
""",
    "ec-cert": """* Subject:
  * countryName (C): AT
  * stateOrProvinceName (ST): Vienna
  * localityName (L): Vienna
  * organizationName (O): Django CA
  * organizationalUnitName (OU): Django CA Testsuite
  * commonName (CN): {name}.example.com
* Serial: {serial_colons}
* Issuer:
  * commonName (CN): ec.example.com
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid
* No watchers

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints (critical):
  CA:FALSE
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Extended Key Usage{extended_key_usage_critical}:
{extended_key_usage_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Alternative Name{subject_alternative_name_critical}:
{subject_alternative_name_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}
""",
    "ed25519-cert": """* Subject:
  * countryName (C): AT
  * stateOrProvinceName (ST): Vienna
  * localityName (L): Vienna
  * organizationName (O): Django CA
  * organizationalUnitName (OU): Django CA Testsuite
  * commonName (CN): {name}.example.com
* Serial: {serial_colons}
* Issuer:
  * commonName (CN): ed25519.example.com
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid
* No watchers

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints (critical):
{basic_constraints_text}
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Extended Key Usage{extended_key_usage_critical}:
{extended_key_usage_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Alternative Name{subject_alternative_name_critical}:
{subject_alternative_name_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}
""",
    "ed448-cert": """* Subject:
  * countryName (C): AT
  * stateOrProvinceName (ST): Vienna
  * localityName (L): Vienna
  * organizationName (O): Django CA
  * organizationalUnitName (OU): Django CA Testsuite
  * commonName (CN): {name}.example.com
* Serial: {serial_colons}
* Issuer:
  * commonName (CN): ed448.example.com
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid
* No watchers

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints (critical):
{basic_constraints_text}
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Extended Key Usage{extended_key_usage_critical}:
{extended_key_usage_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Alternative Name{subject_alternative_name_critical}:
{subject_alternative_name_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}
""",
    "pwd-cert": """* Subject:
  * countryName (C): AT
  * stateOrProvinceName (ST): Vienna
  * localityName (L): Vienna
  * organizationName (O): Django CA
  * organizationalUnitName (OU): Django CA Testsuite
  * commonName (CN): {name}.example.com
* Serial: {serial_colons}
* Issuer:
  * commonName (CN): pwd.example.com
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid
* No watchers

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints (critical):
{basic_constraints_text}
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Extended Key Usage{extended_key_usage_critical}:
{extended_key_usage_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Alternative Name{subject_alternative_name_critical}:
{subject_alternative_name_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}
""",
    "dsa-cert": """* Subject:
  * countryName (C): AT
  * stateOrProvinceName (ST): Vienna
  * localityName (L): Vienna
  * organizationName (O): Django CA
  * organizationalUnitName (OU): Django CA Testsuite
  * commonName (CN): {name}.example.com
* Serial: {serial_colons}
* Issuer:
  * commonName (CN): dsa.example.com
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid
* No watchers

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints (critical):
  CA:FALSE
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Extended Key Usage{extended_key_usage_critical}:
{extended_key_usage_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Alternative Name{subject_alternative_name_critical}:
{subject_alternative_name_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}
""",
    "profile-client": """* Subject:
  * countryName (C): AT
  * stateOrProvinceName (ST): Vienna
  * localityName (L): Vienna
  * organizationName (O): Django CA
  * organizationalUnitName (OU): Django CA Testsuite
  * commonName (CN): {name}.example.com
* Serial: {serial_colons}
* Issuer:
  * commonName (CN): child.example.com
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid
* No watchers

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints (critical):
{basic_constraints_text}
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Extended Key Usage{extended_key_usage_critical}:
{extended_key_usage_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Alternative Name{subject_alternative_name_critical}:
{subject_alternative_name_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}
""",
    "profile-server": """* Subject:
  * countryName (C): AT
  * stateOrProvinceName (ST): Vienna
  * localityName (L): Vienna
  * organizationName (O): Django CA
  * organizationalUnitName (OU): Django CA Testsuite
  * commonName (CN): {name}.example.com
* Serial: {serial_colons}
* Issuer:
  * commonName (CN): child.example.com
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid
* No watchers

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints (critical):
{basic_constraints_text}
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Extended Key Usage{extended_key_usage_critical}:
{extended_key_usage_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Alternative Name{subject_alternative_name_critical}:
{subject_alternative_name_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}
""",
    "profile-webserver": """* Subject:
  * countryName (C): AT
  * stateOrProvinceName (ST): Vienna
  * localityName (L): Vienna
  * organizationName (O): Django CA
  * organizationalUnitName (OU): Django CA Testsuite
  * commonName (CN): {name}.example.com
* Serial: {serial_colons}
* Issuer:
  * commonName (CN): child.example.com
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid
* No watchers

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints (critical):
{basic_constraints_text}
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Extended Key Usage{extended_key_usage_critical}:
{extended_key_usage_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Alternative Name{subject_alternative_name_critical}:
{subject_alternative_name_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}
""",
    "profile-enduser": """* Subject:
  * countryName (C): AT
  * stateOrProvinceName (ST): Vienna
  * localityName (L): Vienna
  * organizationName (O): Django CA
  * organizationalUnitName (OU): Django CA Testsuite
  * commonName (CN): {name}.example.com
* Serial: {serial_colons}
* Issuer:
  * commonName (CN): child.example.com
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid
* No watchers

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints (critical):
{basic_constraints_text}
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Extended Key Usage{extended_key_usage_critical}:
{extended_key_usage_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}
""",
    "profile-ocsp": """* Subject:
  * commonName (CN): {name}.example.com
* Serial: {serial_colons}
* Issuer:
  * commonName (CN): child.example.com
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid
* No watchers

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints (critical):
{basic_constraints_text}
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Extended Key Usage{extended_key_usage_critical}:
{extended_key_usage_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* OCSP No Check:
  Yes
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}
""",
    "no-extensions": """* Subject:
  * commonName (CN): {name}.example.com
* Serial: {serial_colons}
* Issuer:
  * commonName (CN): {ca}.example.com
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid
* No watchers

Certificate extensions:

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}
""",
    "empty-subject": """* Subject: (empty)
* Serial: {serial_colons}
* Issuer: (empty)
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid
* No watchers

Certificate extensions:
* Subject Alternative Name{subject_alternative_name_critical}:
{subject_alternative_name_text}

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}
""",
    "all-extensions": """* Subject:
  * countryName (C): AT
  * stateOrProvinceName (ST): Vienna
  * localityName (L): Vienna
  * organizationName (O): Example
  * organizationalUnitName (OU): Example OU
  * commonName (CN): all-extensions.example.com
  * emailAddress: user@example.com
* Serial: {serial_colons}
* Issuer:
  * commonName (CN): child.example.com
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid
* No watchers

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints (critical):
  CA:FALSE
* CRL Distribution Points{crl_distribution_points_critical}:
  * DistributionPoint:
    * Full Name:
      * URI:{extensions[crl_distribution_points][value][0][full_name][0][value]}
* Extended Key Usage{extended_key_usage_critical}:
{extended_key_usage_text}
* Freshest CRL{freshest_crl_critical}:
{freshest_crl_text}
* Inhibit anyPolicy{inhibit_any_policy_critical}:
  1
* Issuer Alternative Name{issuer_alternative_name_critical}:
{issuer_alternative_name_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Name Constraints{name_constraints_critical}:
{name_constraints_text}
* OCSP No Check{ocsp_no_check_critical}:
  Yes
* Policy Constraints{policy_constraints_critical}:
{policy_constraints_text}
{precert_poison}
* Subject Alternative Name{subject_alternative_name_critical}:
{subject_alternative_name_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}
* TLS Feature{tls_feature_critical}:
{tls_feature_text}

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}
""",
    "alt-extensions": """* Subject:
  * countryName (C): AT
  * stateOrProvinceName (ST): Vienna
  * localityName (L): Vienna
  * organizationName (O): Example
  * organizationalUnitName (OU): Example OU
  * commonName (CN): alt-extensions.example.com
  * emailAddress: user@example.com
* Serial: {serial_colons}
* Issuer:
  * commonName (CN): child.example.com
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid
* No watchers

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
  CA:FALSE
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Extended Key Usage{extended_key_usage_critical}:
{extended_key_usage_text}
* Issuer Alternative Name{issuer_alternative_name_critical}:
{issuer_alternative_name_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Name Constraints{name_constraints_critical}:
{name_constraints_text}
* OCSP No Check{ocsp_no_check_critical}:
  Yes
* Subject Alternative Name{subject_alternative_name_critical}:
{subject_alternative_name_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}
* TLS Feature{tls_feature_critical}:
{tls_feature_text}

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}
""",
}


@override_settings(CA_MIN_KEY_SIZE=1024, CA_PROFILES={}, CA_DEFAULT_SUBJECT=tuple())
class ViewCertTestCase(TestCaseMixin, TestCase):
    """Main test class for this command."""

    load_cas = "__all__"
    load_certs = "__all__"

    def assertBasicOutput(self, status: str) -> None:  # pylint: disable=invalid-name
        """Test basic properties of output."""
        # pylint: disable=consider-using-f-string
        for key, cert in self.ca_certs:
            stdout, stderr = cmd("view_cert", cert.serial, wrap=False)
            san = typing.cast(
                Optional[x509.Extension[x509.SubjectAlternativeName]],
                cert.extensions.get(ExtensionOID.SUBJECT_ALTERNATIVE_NAME),
            )
            if san is None:
                self.assertEqual(
                    stdout,
                    """Common Name: {cn}
Valid from: {valid_from_str}
Valid until: {valid_until_str}
Status: {status}
Watchers:
Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""".format(status=status, **self.get_cert_context(key)),
                )
            elif len(san.value) != 1:
                continue  # no need to duplicate this here
            else:
                self.assertEqual(
                    stdout,
                    """* Subject:
  * countryName (C): AT
  * stateOrProvinceName (ST): Vienna
  * localityName (L): Vienna
  * organizationName (O): Django CA
  * organizationalUnitName (OU): Django CA Testsuite
  * commonName (CN): {name}.example.com
* Serial: {serial_colons}
* Issuer:
  * commonName (CN): {ca}.example.com
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: {status}
* No watchers

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Extended Key Usage{extended_key_usage_critical}:
{extended_key_usage_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Alternative Name{subject_alternative_name_critical}:
{subject_alternative_name_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""".format(status=status, **self.get_cert_context(key)),
                )
            self.assertEqual(stderr, "")

        # test with no pem and no extensions
        for key, cert in self.ca_certs:
            stdout, stderr = cmd("view_cert", cert.serial, pem=False, extensions=False, wrap=False)
            self.assertEqual(
                stdout,
                """* Subject:
  * countryName (C): AT
  * stateOrProvinceName (ST): Vienna
  * localityName (L): Vienna
  * organizationName (O): Django CA
  * organizationalUnitName (OU): Django CA Testsuite
  * commonName (CN): {name}.example.com
* Serial: {serial_colons}
* Issuer:
  * commonName (CN): {ca}.example.com
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: {status}
* No watchers

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}
""".format(status=status, **self.get_cert_context(key)),
            )
            self.assertEqual(stderr, "")

    @freeze_time(TIMESTAMPS["before_everything"])
    def test_basic_not_yet_valid(self) -> None:
        """Basic tests when all certs are not yet valid."""
        self.assertBasicOutput(status="Not yet valid")

    @freeze_time(TIMESTAMPS["everything_expired"])
    def test_basic_expired(self) -> None:
        """Basic tests when all certs are expired."""
        self.assertBasicOutput(status="Expired")

    @freeze_time(TIMESTAMPS["everything_valid"])
    def test_certs(self) -> None:
        """Test main certs."""
        for name, cert in self.usable_certs:
            stdout, stderr = cmd("view_cert", cert.serial, pem=False, extensions=True, wrap=False)
            self.assertEqual(stderr, "")

            context = self.get_cert_context(name)
            self.assertEqual(stdout, expected[name].format(**context), name)

    def test_revoked(self) -> None:
        """Test viewing a revoked cert."""
        # pylint: disable=consider-using-f-string
        self.cert.revoked = True
        self.cert.save()
        stdout, stderr = cmd("view_cert", self.cert.serial, pem=False, wrap=False, extensions=False)
        self.assertEqual(
            stdout,
            """* Subject:
  * countryName (C): AT
  * stateOrProvinceName (ST): Vienna
  * localityName (L): Vienna
  * organizationName (O): Django CA
  * organizationalUnitName (OU): Django CA Testsuite
  * commonName (CN): child-cert.example.com
* Serial: {serial_colons}
* Issuer:
  * commonName (CN): child.example.com
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Revoked
* No watchers

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}
""".format(**CERT_DATA["child-cert"]),
        )
        self.assertEqual(stderr, "")

    @freeze_time(TIMESTAMPS["everything_valid"])
    @override_tmpcadir()
    def test_no_san_with_watchers(self) -> None:
        """Test a cert with no subjectAltNames but with watchers."""
        cert = self.certs["no-extensions"]
        watcher = Watcher.from_addr("user@example.com")
        cert.watchers.add(watcher)

        stdout, stderr = cmd("view_cert", cert.serial, pem=False, extensions=False, wrap=False)
        self.assertEqual(
            stdout,
            # pylint: disable-next=consider-using-f-string
            """* Subject:
  * commonName (CN): {name}.example.com
* Serial: {serial_colons}
* Issuer:
  * commonName (CN): {ca}.example.com
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid
* Watchers:
  * user@example.com

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}
""".format(**self.get_cert_context("no-extensions")),
        )
        self.assertEqual(stderr, "")

    def assertContrib(self, name: str, exp: str, **context: str) -> None:  # pylint: disable=invalid-name
        """Assert basic contrib output."""
        cert = self.certs[name]
        stdout, stderr = cmd("view_cert", cert.serial, pem=False, extensions=True, wrap=False)
        context.update(self.get_cert_context(name))
        self.assertEqual(stderr, "")
        self.assertEqual(stdout, exp.format(**context))

    @freeze_time("2019-04-01")
    def test_contrib_godaddy_derstandardat(self) -> None:
        """Test contrib godaddy cert for derstandard.at."""
        id1 = (
            "A4:B9:09:90:B4:18:58:14:87:BB:13:A2:CC:67:70:0A:3C:35:98:04:F9:1B:DF:B8:E3:77:CD:0E:C8:0D:DC:10"
        )
        id2 = (
            "EE:4B:BD:B7:75:CE:60:BA:E1:42:69:1F:AB:E1:9E:66:A3:0F:7E:5F:B0:72:D8:83:00:C4:7B:89:7A:A8:FD:CB"
        )
        id3 = (
            "44:94:65:2E:B0:EE:CE:AF:C4:40:07:D8:A8:FE:28:C0:DA:E6:82:BE:D8:CB:31:B5:3F:D3:33:96:B5:B6:81:A8"
        )
        sct = f"""* Precertificate Signed Certificate Timestamps:
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
            """* Subject:
  * organizationalUnitName (OU): Domain Control Validated
  * commonName (CN): derstandard.at
* Serial: {serial_colons}
* Issuer:
  * countryName (C): US
  * stateOrProvinceName (ST): Arizona
  * localityName (L): Scottsdale
  * organizationName (O): GoDaddy.com, Inc.
  * organizationalUnitName (OU): http://certs.godaddy.com/repository/
  * commonName (CN): Go Daddy Secure Certificate Authority - G2
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid
* No watchers

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Certificate Policies{certificate_policies_critical}:
{certificate_policies_text}
* Extended Key Usage{extended_key_usage_critical}:
{extended_key_usage_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
{sct}
* Subject Alternative Name{subject_alternative_name_critical}:
{subject_alternative_name_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}
""",
            sct=sct,
        )

    @freeze_time("2019-07-05")
    def test_contrib_letsencrypt_jabber_at(self) -> None:
        """Test contrib letsencrypt cert."""
        # pylint: disable=consider-using-f-string
        name = "letsencrypt_x3-cert"
        context = self.get_cert_context(name)
        context[
            "id1"
        ] = "6F:53:76:AC:31:F0:31:19:D8:99:00:A4:51:15:FF:77:15:1C:11:D9:02:C1:00:29:06:8D:B2:08:9A:37:D9:13"
        context[
            "id2"
        ] = "29:3C:51:96:54:C8:39:65:BA:AA:50:FC:58:07:D4:B7:6F:BF:58:7A:29:72:DC:A4:C3:0C:F4:E5:45:47:F4:78"

        sct = """* Precertificate Signed Certificate Timestamps:
  * Precertificate (v1):
      Timestamp: 2019-06-25 03:40:03.920000
      Log ID: {id1}
  * Precertificate (v1):
      Timestamp: 2019-06-25 03:40:03.862000
      Log ID: {id2}""".format(**context)

        self.assertContrib(
            "letsencrypt_x3-cert",
            """* Subject:
  * commonName (CN): jabber.at
* Serial: {serial_colons}
* Issuer:
  * countryName (C): US
  * organizationName (O): Let's Encrypt
  * commonName (CN): Let's Encrypt Authority X3
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid
* No watchers

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* Certificate Policies{certificate_policies_critical}:
{certificate_policies_text}
* Extended Key Usage{extended_key_usage_critical}:
{extended_key_usage_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
{sct}
* Subject Alternative Name{subject_alternative_name_critical}:
{subject_alternative_name_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}
""",
            sct=sct,
        )

    @freeze_time("2018-12-01")
    def test_contrib_cloudflare_1(self) -> None:
        """Test contrib cloudflare cert."""
        # pylint: disable=consider-using-f-string
        self.assertContrib(
            "cloudflare_1",
            """* Subject:
  * organizationalUnitName (OU): Domain Control Validated
  * organizationalUnitName (OU): PositiveSSL Multi-Domain
  * commonName (CN): sni24142.cloudflaressl.com
* Serial: {serial_colons}
* Issuer:
  * countryName (C): GB
  * stateOrProvinceName (ST): Greater Manchester
  * localityName (L): Salford
  * organizationName (O): COMODO CA Limited
  * commonName (CN): COMODO ECC Domain Validation Secure Server CA 2
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid
* No watchers

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Certificate Policies{certificate_policies_critical}:
{certificate_policies_text}
* Extended Key Usage{extended_key_usage_critical}:
{extended_key_usage_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
{precert_poison}
* Subject Alternative Name{subject_alternative_name_critical}:
{subject_alternative_name_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}
""".format(**self.get_cert_context("cloudflare_1")),
        )

    def test_contrib_multiple_ous(self) -> None:
        """Test special contrib case with multiple OUs."""
        self.assertContrib(
            "multiple_ous",
            """* Subject:
  * countryName (C): US
  * organizationName (O): VeriSign, Inc.
  * organizationalUnitName (OU): Class 3 Public Primary Certification Authority - G2
  * organizationalUnitName (OU): (c) 1998 VeriSign, Inc. - For authorized use only
  * organizationalUnitName (OU): VeriSign Trust Network
* Serial: {serial_colons}
* Issuer:
  * countryName (C): US
  * organizationName (O): VeriSign, Inc.
  * organizationalUnitName (OU): Class 3 Public Primary Certification Authority - G2
  * organizationalUnitName (OU): (c) 1998 VeriSign, Inc. - For authorized use only
  * organizationalUnitName (OU): VeriSign Trust Network
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid
* No watchers

Certificate extensions:

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}
""",
        )

    def test_unknown_cert(self) -> None:
        """Test viewing an unknown certificate."""
        name = "foobar"
        with self.assertCommandError(rf"^Error: argument cert: {name}: Certificate not found\.$"):
            cmd("view_cert", name)

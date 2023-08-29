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

"""Test cases for django-ca actions."""

import argparse
import os
import sys
from datetime import timedelta
from io import StringIO
from typing import Any, List
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from django.test import TestCase, override_settings

from django_ca.constants import ReasonFlags
from django_ca.management import actions
from django_ca.models import Certificate, CertificateAuthority
from django_ca.tests.base import certs, dns, override_tmpcadir, uri
from django_ca.tests.base.mixins import TestCaseMixin


class ParserTestCaseMixin(TestCaseMixin):
    """Mixin class that provides assertParserError."""

    parser: argparse.ArgumentParser
    script = os.path.basename(sys.argv[0])

    def assertParserError(  # pylint: disable=invalid-name
        self, args: List[str], expected: str, **kwargs: Any
    ) -> str:
        """Assert that given args throw a parser error."""

        kwargs.setdefault("script", self.script)
        expected = expected.format(**kwargs)

        buf = StringIO()
        with self.assertRaises(SystemExit), mock.patch("sys.stderr", buf):
            self.parser.parse_args(args)

        output = buf.getvalue()
        self.assertEqual(output, expected)
        return output


class AlternativeNameLegacyAction(ParserTestCaseMixin, TestCase):
    """Test AlternativeNameLegacyAction."""

    def setUp(self) -> None:
        super().setUp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument(
            "--alt", action=actions.AlternativeNameLegacyAction, extension_type=x509.SubjectAlternativeName
        )

    def assertValue(self, namespace: argparse.Namespace, value: Any) -> None:  # pylint: disable=invalid-name
        """Assert a given extension value."""

        extension = x509.Extension(oid=x509.SubjectAlternativeName.oid, critical=False, value=value)
        self.assertEqual(namespace.alt, extension)

    def test_basic(self) -> None:
        """Test basic functionality."""

        namespace = self.parser.parse_args([])
        self.assertEqual(namespace.alt, None)

        namespace = self.parser.parse_args(["--alt", "example.com"])
        self.assertValue(namespace, x509.SubjectAlternativeName([dns("example.com")]))

        namespace = self.parser.parse_args(["--alt", "example.com", "--alt", "https://example.net"])
        self.assertValue(
            namespace, x509.SubjectAlternativeName([dns("example.com"), uri("https://example.net")])
        )


class CertificationPracticeStatementActionTestCase(ParserTestCaseMixin, TestCase):
    """Test CertificationPracticeStatementAction."""

    def setUp(self) -> None:
        super().setUp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("--pi", action=actions.PolicyIdentifierAction)
        self.parser.add_argument("--cps", action=actions.CertificationPracticeStatementAction, dest="pi")

    def test_add_cps(self) -> None:
        """Basic test for adding a certification practice statement (CPS)."""
        oid = "1.2.3"
        cps = "http://example.com/cps"
        namespace = self.parser.parse_args(["--pi", oid, "--cps", cps])
        self.assertEqual(
            namespace.pi,
            x509.CertificatePolicies(
                policies=[
                    x509.PolicyInformation(
                        policy_identifier=x509.ObjectIdentifier(oid), policy_qualifiers=[cps]
                    )
                ]
            ),
        )

    def test_add_multiple_cps(self) -> None:
        """Test adding multiple CPS to the same policy identifier."""
        oid = "1.2.3"
        cps1 = "http://example.com/cps1"
        cps2 = "http://example.com/cps2"
        namespace = self.parser.parse_args(["--pi", oid, "--cps", cps1, "--cps", cps2])
        self.assertEqual(
            namespace.pi,
            x509.CertificatePolicies(
                policies=[
                    x509.PolicyInformation(
                        policy_identifier=x509.ObjectIdentifier(oid), policy_qualifiers=[cps1, cps2]
                    )
                ]
            ),
        )

    def test_add_multiple_cps_to_different_policy_identifiers(self) -> None:
        """Test adding multiple CPS to different policy identifiers."""
        oid1 = "1.2.3"
        oid2 = "1.2.4"
        cps1 = "http://example.com/cps1"
        cps2 = "http://example.com/cps2"
        namespace = self.parser.parse_args(["--pi", oid1, "--cps", cps1, "--pi", oid2, "--cps", cps2])
        self.assertEqual(
            namespace.pi,
            x509.CertificatePolicies(
                policies=[
                    x509.PolicyInformation(
                        policy_identifier=x509.ObjectIdentifier(oid1), policy_qualifiers=[cps1]
                    ),
                    x509.PolicyInformation(
                        policy_identifier=x509.ObjectIdentifier(oid2), policy_qualifiers=[cps2]
                    ),
                ]
            ),
        )

    def test_missing_policy_identifier(self) -> None:
        """Test not passing a policy information before."""
        self.assertParserError(
            ["--cps", "http://example.com/cps"],
            "usage: {script} [-h] [--pi OID] [--cps URL]\n"
            "{script}: error: argument --cps: Must be preceded by --policy-identifier.\n",
        )

    def test_invalid_url(self) -> None:
        """Test passing an invalid URL."""
        self.assertParserError(
            ["--pi", "1.2.3", "--cps", "not-a-url"],
            "usage: {script} [-h] [--pi OID] [--cps URL]\n"
            "{script}: error: argument --cps: not-a-url: Not a valid URL.\n",
        )


class ExtendedKeyUsageActionTestCase(ParserTestCaseMixin, TestCase):
    """Test ExtendedKeyUsageAction."""

    def setUp(self) -> None:
        super().setUp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("--eku", action=actions.ExtendedKeyUsageAction)

    def test_basic(self) -> None:
        """Test basic functionality of action."""
        namespace = self.parser.parse_args([])
        self.assertIsNone(namespace.eku)

        namespace = self.parser.parse_args(["--eku", "clientAuth"])
        self.assertEqual(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), namespace.eku)

        namespace = self.parser.parse_args(["--eku", "clientAuth", "serverAuth"])
        self.assertEqual(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]),
            namespace.eku,
        )

    def test_dotted_string_value(self) -> None:
        """Test passing a dotted string."""
        namespace = self.parser.parse_args(["--eku", "1.3.6.1.5.5.7.3.2"])
        self.assertEqual(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), namespace.eku)

    def test_duplicate_values(self) -> None:
        """Test wrong option values."""
        self.assertParserError(
            ["--eku", "clientAuth", "1.3.6.1.5.5.7.3.2"],
            "usage: {script} [-h] [--eku EKU [EKU ...]]\n"
            "{script}: error: argument --eku: 1.3.6.1.5.5.7.3.2: "
            "Extended Key Usage is added multiple times.\n",
        )

    def test_unknown_extended_key_usage(self) -> None:
        """Test wrong option values."""
        self.assertParserError(
            ["--eku", "FOO"],
            "usage: {script} [-h] [--eku EKU [EKU ...]]\n"
            "{script}: error: argument --eku: FOO: Not a dotted string or known Extended Key Usage.\n",
        )


class PolicyIdentifierActionTestCase(ParserTestCaseMixin, TestCase):
    """Test the PolicyIdentifierAction."""

    def setUp(self) -> None:
        super().setUp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("--pi", action=actions.PolicyIdentifierAction)

    def test_policy_identifier(self) -> None:
        """Basic test for adding a policy identifier."""
        oid = "1.2.3"
        namespace = self.parser.parse_args(["--pi", oid])
        self.assertEqual(
            namespace.pi,
            x509.CertificatePolicies(
                policies=[
                    x509.PolicyInformation(policy_identifier=x509.ObjectIdentifier(oid), policy_qualifiers=[])
                ]
            ),
        )

    def test_multiple_policy_identifiers(self) -> None:
        """Test adding multiple policy identifiers."""
        oid1 = "1.2.3"
        oid2 = "1.2.4"
        namespace = self.parser.parse_args(["--pi", oid1, "--pi", oid2])
        self.assertEqual(
            namespace.pi,
            x509.CertificatePolicies(
                policies=[
                    x509.PolicyInformation(
                        policy_identifier=x509.ObjectIdentifier(oid1), policy_qualifiers=[]
                    ),
                    x509.PolicyInformation(
                        policy_identifier=x509.ObjectIdentifier(oid2), policy_qualifiers=[]
                    ),
                ]
            ),
        )

    def test_any_policy_value_disallowed(self) -> None:
        """Test that the special anyPolicy value is correctly understood."""
        self.assertParserError(
            ["--pi", "anyPolicy"],
            "usage: {script} [-h] [--pi OID]\n"
            "{script}: error: argument --pi: anyPolicy is not allowed in this context.\n",
        )

    def test_any_policy_value(self) -> None:
        """Test that the special anyPolicy value is correctly understood."""
        parser = argparse.ArgumentParser()
        parser.add_argument("--pi", action=actions.PolicyIdentifierAction, allow_any_policy=True)

        oid = "anyPolicy"
        namespace = parser.parse_args(["--pi", oid])
        self.assertEqual(
            namespace.pi,
            x509.CertificatePolicies(
                policies=[
                    x509.PolicyInformation(
                        policy_identifier=x509.ObjectIdentifier("2.5.29.32.0"), policy_qualifiers=[]
                    )
                ]
            ),
        )

    def test_invalid_dotted_string(self) -> None:
        """Test passing a value that is not a dotted string."""
        self.assertParserError(
            ["--pi", "abc"],
            "usage: {script} [-h] [--pi OID]\n"
            "{script}: error: argument --pi: invalid ObjectIdentifier value: 'abc'\n",
        )


class IntegerRangeActionTestCase(ParserTestCaseMixin, TestCase):
    """Test the IntegerRangeAction."""

    def test_no_min_no_max(self) -> None:
        """Test action with no min/max values."""
        parser = argparse.ArgumentParser()
        parser.add_argument("--value", action=actions.IntegerRangeAction)
        self.assertEqual(parser.parse_args(["--value=0"]).value, 0)
        self.assertEqual(parser.parse_args(["--value=1"]).value, 1)
        self.assertEqual(parser.parse_args(["--value=-1"]).value, -1)

    def test_min_values(self) -> None:
        """Test the min value for the action."""
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("--value", action=actions.IntegerRangeAction, min=0)
        self.assertEqual(self.parser.parse_args(["--value=0"]).value, 0)
        self.assertEqual(self.parser.parse_args(["--value=1"]).value, 1)
        self.assertParserError(
            ["--value=-1"],
            "usage: {script} [-h] [--value INT]\n"
            "{script}: error: argument --value: INT must be equal or greater then 0.\n",
        )

    def test_max_values(self) -> None:
        """Test the max value for the action."""
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("--value", action=actions.IntegerRangeAction, max=0)
        self.assertEqual(self.parser.parse_args(["--value=0"]).value, 0)
        self.assertEqual(self.parser.parse_args(["--value=-1"]).value, -1)
        self.assertParserError(
            ["--value=1"],
            "usage: {script} [-h] [--value INT]\n"
            "{script}: error: argument --value: INT must be equal or smaller then 0.\n",
        )


class KeyUsageActionTestCase(ParserTestCaseMixin, TestCase):
    """Test KeyUsageAction."""

    def setUp(self) -> None:
        super().setUp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("--key-usage", action=actions.KeyUsageAction)

    def test_basic(self) -> None:
        """Test basic functionality of action."""
        namespace = self.parser.parse_args(["--key-usage", "keyCertSign"])
        self.assertEqual(self.key_usage(key_cert_sign=True, critical=False).value, namespace.key_usage)

        namespace = self.parser.parse_args(["--key-usage", "keyCertSign", "keyAgreement"])
        self.assertEqual(
            self.key_usage(key_cert_sign=True, key_agreement=True, critical=False).value, namespace.key_usage
        )

    def test_invalid_values(self) -> None:
        """Test passing invalid values."""
        self.assertParserError(
            ["--key-usage", "foo"],
            "usage: {script} [-h] [--key-usage KEY_USAGE [KEY_USAGE ...]]\n"
            "{script}: error: argument --key-usage: foo: Invalid key usage.\n",
        )

    def test_error(self) -> None:
        """Test wrong option values."""
        self.assertParserError(
            ["--key-usage", "encipherOnly"],
            "usage: {script} [-h] [--key-usage KEY_USAGE [KEY_USAGE ...]]\n"
            "{script}: error: argument --key-usage: encipher_only and decipher_only can only be true when "
            "key_agreement is true\n",
        )
        self.assertParserError(
            ["--key-usage", "decipherOnly"],
            "usage: {script} [-h] [--key-usage KEY_USAGE [KEY_USAGE ...]]\n"
            "{script}: error: argument --key-usage: encipher_only and decipher_only can only be true when "
            "key_agreement is true\n",
        )


class NameActionTestCase(ParserTestCaseMixin, TestCase):
    """Test NameAction."""

    def setUp(self) -> None:
        super().setUp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("--name", action=actions.NameAction)

    def test_basic(self) -> None:
        """Test basic functionality of action."""
        namespace = self.parser.parse_args(["--name=/CN=example.com"])
        self.assertEqual(namespace.name, x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")]))

    def test_error(self) -> None:
        """Test false option values."""
        self.assertParserError(
            ["--name=/WRONG=foobar"],
            "usage: {script} [-h] [--name NAME]\n"
            "{script}: error: argument --name: Unknown x509 name field: WRONG\n",
        )


class TLSFeatureActionTestCase(ParserTestCaseMixin, TestCase):
    """Test TLSFeatureAction."""

    def setUp(self) -> None:
        super().setUp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("--tls-feature", action=actions.TLSFeatureAction)

    def test_basic(self) -> None:
        """Test basic functionality of action."""
        namespace = self.parser.parse_args(["--tls-feature", "status_request"])
        self.assertEqual(x509.TLSFeature([x509.TLSFeatureType.status_request]), namespace.tls_feature)

        namespace = self.parser.parse_args(["--tls-feature", "status_request_v2"])
        self.assertEqual(x509.TLSFeature([x509.TLSFeatureType.status_request_v2]), namespace.tls_feature)

        namespace = self.parser.parse_args(["--tls-feature", "status_request", "status_request_v2"])
        self.assertEqual(
            x509.TLSFeature([x509.TLSFeatureType.status_request, x509.TLSFeatureType.status_request_v2]),
            namespace.tls_feature,
        )

    def test_error(self) -> None:
        """Test wrong option values."""
        self.assertParserError(
            ["--tls-feature", "FOO"],
            "usage: {script} [-h] [--tls-feature TLS_FEATURE [TLS_FEATURE ...]]\n"
            "{script}: error: argument --tls-feature: Unknown TLSFeature: FOO\n",
        )


class UserNoticeActionTestCase(ParserTestCaseMixin, TestCase):
    """Test UserNoticeAction."""

    def setUp(self) -> None:
        super().setUp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("--pi", action=actions.PolicyIdentifierAction)
        self.parser.add_argument("--notice", action=actions.UserNoticeAction, dest="pi")

    def test_add_notice(self) -> None:
        """Basic test for adding a user notice."""
        oid = "1.2.3"
        notice = "notice text"
        namespace = self.parser.parse_args(["--pi", oid, "--notice", notice])
        self.assertEqual(
            namespace.pi,
            x509.CertificatePolicies(
                policies=[
                    x509.PolicyInformation(
                        policy_identifier=x509.ObjectIdentifier(oid),
                        policy_qualifiers=[x509.UserNotice(notice_reference=None, explicit_text=notice)],
                    )
                ]
            ),
        )

    def test_add_multiple_notices(self) -> None:
        """Test adding multiple user notices to the same policy identifier."""
        oid = "1.2.3"
        notice1 = "notice text one"
        notice2 = "notice text two"
        namespace = self.parser.parse_args(["--pi", oid, "--notice", notice1, "--notice", notice2])
        self.assertEqual(
            namespace.pi,
            x509.CertificatePolicies(
                policies=[
                    x509.PolicyInformation(
                        policy_identifier=x509.ObjectIdentifier(oid),
                        policy_qualifiers=[
                            x509.UserNotice(notice_reference=None, explicit_text=notice1),
                            x509.UserNotice(notice_reference=None, explicit_text=notice2),
                        ],
                    )
                ]
            ),
        )

    def test_add_multiple_cps_to_different_policy_identifiers(self) -> None:
        """Test adding multiple user notices to different policy identifiers."""
        oid1 = "1.2.3"
        oid2 = "1.2.4"
        notice1 = "notice text one"
        notice2 = "notice text two"
        namespace = self.parser.parse_args(
            ["--pi", oid1, "--notice", notice1, "--pi", oid2, "--notice", notice2]
        )
        self.assertEqual(
            namespace.pi,
            x509.CertificatePolicies(
                policies=[
                    x509.PolicyInformation(
                        policy_identifier=x509.ObjectIdentifier(oid1),
                        policy_qualifiers=[x509.UserNotice(notice_reference=None, explicit_text=notice1)],
                    ),
                    x509.PolicyInformation(
                        policy_identifier=x509.ObjectIdentifier(oid2),
                        policy_qualifiers=[x509.UserNotice(notice_reference=None, explicit_text=notice2)],
                    ),
                ]
            ),
        )

    def test_missing_policy_identifier(self) -> None:
        """Test not passing a policy information before."""
        self.assertParserError(
            ["--notice", "http://example.com/cps"],
            "usage: {script} [-h] [--pi OID] [--notice TEXT]\n"
            "{script}: error: argument --notice: Must be preceded by --policy-identifier.\n",
        )

    def test_invalid_url(self) -> None:
        """Test passing a user notice that is too long."""
        self.assertParserError(
            ["--pi", "1.2.3", "--notice", "a" * 201],  # RFC 5280 says maximum length is 200 characters
            "usage: {script} [-h] [--pi OID] [--notice TEXT]\n"
            "{script}: error: argument --notice: TEXT must not be longer then 200 characters.\n",
        )


class FormatActionTestCase(ParserTestCaseMixin, TestCase):
    """Test FormatAction."""

    def setUp(self) -> None:
        super().setUp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("--action", action=actions.FormatAction)

    def test_basic(self) -> None:
        """Test basic functionality of action."""
        args = self.parser.parse_args(["--action=DER"])
        self.assertEqual(args.action, Encoding.DER)

        args = self.parser.parse_args(["--action=ASN1"])
        self.assertEqual(args.action, Encoding.DER)

        args = self.parser.parse_args(["--action=PEM"])
        self.assertEqual(args.action, Encoding.PEM)

    def test_error(self) -> None:
        """Test false option values."""
        self.assertParserError(
            ["--action=foo"],
            "usage: {script} [-h] [--action ACTION]\n"
            "{script}: error: argument --action: "
            "Unknown encoding: foo\n",
        )


class EllipticCurveActionTestCase(ParserTestCaseMixin, TestCase):
    """Test EllipticCurveAction."""

    def setUp(self) -> None:
        super().setUp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("--curve", action=actions.EllipticCurveAction)

    def test_basic(self) -> None:
        """Test basic functionality of action."""
        args = self.parser.parse_args(["--curve=sect409k1"])
        self.assertIsInstance(args.curve, ec.SECT409K1)

        args = self.parser.parse_args(["--curve=sect409r1"])
        self.assertIsInstance(args.curve, ec.SECT409R1)

        args = self.parser.parse_args(["--curve=brainpoolP512r1"])
        self.assertIsInstance(args.curve, ec.BrainpoolP512R1)

    def test_error(self) -> None:
        """Test false option values."""
        self.assertParserError(
            ["--curve=foo"],
            "usage: {script} [-h] [--curve {{secp256r1,secp384r1,secp521r1,...}}]\n"
            "{script}: error: argument --curve: invalid choice: 'foo' (choose from 'brainpoolP256r1', "
            "'brainpoolP384r1', 'brainpoolP512r1', 'secp192r1', 'secp224r1', 'secp256k1', 'secp256r1', "
            "'secp384r1', 'secp521r1', 'sect163k1', 'sect163r2', 'sect233k1', 'sect233r1', 'sect283k1', "
            "'sect283r1', 'sect409k1', 'sect409r1', 'sect571k1', 'sect571r1')\n",
        )


class AlgorithmActionTestCase(ParserTestCaseMixin, TestCase):
    """Test AlgorithmAction."""

    def setUp(self) -> None:
        super().setUp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("--algo", action=actions.AlgorithmAction)

    def test_basic(self) -> None:
        """Test basic functionality of action."""
        args = self.parser.parse_args(["--algo=SHA-256"])
        self.assertIsInstance(args.algo, hashes.SHA256)

        args = self.parser.parse_args(["--algo=SHA-512"])
        self.assertIsInstance(args.algo, hashes.SHA512)

    def test_error(self) -> None:
        """Test false option values."""
        self.assertParserError(
            ["--algo=foo"],
            "usage: {script} [-h] [--algo {{SHA-512,SHA-256,...}}]\n"
            "{script}: error: argument --algo: invalid choice: 'foo' (choose from 'SHA-224', 'SHA-256', "
            "'SHA-384', 'SHA-512', 'SHA3/224', 'SHA3/256', 'SHA3/384', 'SHA3/512')\n",
        )


class KeySizeActionTestCase(ParserTestCaseMixin, TestCase):
    """Test KeySizeAction."""

    def setUp(self) -> None:
        super().setUp()

        self.parser = argparse.ArgumentParser()
        # NOTE: explicitly set metavar here, because the default has curly braces causing troubles with
        #       string formatting in assertParserError.
        self.parser.add_argument("--size", action=actions.KeySizeAction, metavar="SIZE")

    def test_basic(self) -> None:
        """Test basic functionality of action."""
        args = self.parser.parse_args(["--size=2048"])
        self.assertEqual(args.size, 2048)

        args = self.parser.parse_args(["--size=4096"])
        self.assertEqual(args.size, 4096)

    def test_no_power_two(self) -> None:
        """Test giving values that are not the power of two."""
        expected = """usage: {script} [-h] [--size SIZE]
{script}: error: argument --size: %s: Must be a power of two (2048, 4096, ...).\n"""

        self.assertParserError(["--size=2047"], expected % 2047)
        self.assertParserError(["--size=2049"], expected % 2049)
        self.assertParserError(["--size=3084"], expected % 3084)
        self.assertParserError(["--size=4095"], expected % 4095)

    @override_settings(CA_MIN_KEY_SIZE=2048, CA_DEFAULT_KEY_SIZE=4096)
    def test_to_small(self) -> None:
        """Test giving values that are too small."""
        expected = """usage: {script} [-h] [--size SIZE]
{script}: error: argument --size: %s: Must be at least 2048 bits.\n"""

        self.assertParserError(["--size=1024"], expected % 1024)
        self.assertParserError(["--size=512"], expected % 512)
        self.assertParserError(["--size=256"], expected % 256)

    def test_no_str(self) -> None:
        """Test giving values that are too small."""
        expected = """usage: {script} [-h] [--size SIZE]
{script}: error: argument --size: foo: Must be an integer.\n"""

        self.assertParserError(["--size=foo"], expected)


class PasswordActionTestCase(ParserTestCaseMixin, TestCase):
    """Test PasswordAction."""

    def setUp(self) -> None:
        super().setUp()

        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("--password", nargs="?", action=actions.PasswordAction)

    def test_none(self) -> None:
        """Test passing no password option at all."""
        args = self.parser.parse_args([])
        self.assertIsNone(args.password)

    def test_given(self) -> None:
        """Test giving a password on the command line."""
        args = self.parser.parse_args(["--password=foobar"])
        self.assertEqual(args.password, b"foobar")

    @mock.patch("getpass.getpass", spec_set=True, return_value="prompted")
    def test_output(self, getpass: mock.MagicMock) -> None:
        """Test prompting the user for a password."""
        prompt = "new prompt: "
        parser = argparse.ArgumentParser()
        parser.add_argument("--password", nargs="?", action=actions.PasswordAction, prompt=prompt)
        args = parser.parse_args(["--password"])
        self.assertEqual(args.password, b"prompted")
        getpass.assert_called_once_with(prompt=prompt)

    @mock.patch("getpass.getpass", spec_set=True, return_value="prompted")
    def test_prompt(self, getpass: mock.MagicMock) -> None:
        """Test using a custom prompt."""
        parser = argparse.ArgumentParser()
        parser.add_argument("--password", nargs="?", action=actions.PasswordAction)
        args = parser.parse_args(["--password"])
        self.assertEqual(args.password, b"prompted")
        getpass.assert_called_once()


class CertificateActionTestCase(ParserTestCaseMixin, TestCase):
    """Test CertificateAction."""

    load_cas = "__usable__"
    load_certs = "__usable__"

    def setUp(self) -> None:
        super().setUp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("cert", action=actions.CertificateAction)

    def test_basic(self) -> None:
        """Test basic functionality of action."""
        for name, cert in self.certs.items():
            args = self.parser.parse_args([certs[name]["serial"]])
            self.assertEqual(args.cert, cert)

    def test_abbreviation(self) -> None:
        """Test using an abbreviation."""
        args = self.parser.parse_args([certs["root-cert"]["serial"][:6]])
        self.assertEqual(args.cert, self.certs["root-cert"])

    def test_missing(self) -> None:
        """Test giving an unknown cert."""
        serial = "foo"
        self.assertParserError(
            [serial],
            "usage: {script} [-h] cert\n"
            "{script}: error: argument cert: {serial}: Certificate not found.\n",
            serial=serial,
        )

    def test_multiple(self) -> None:
        """Test matching multiple certs with abbreviation."""
        # Manually set almost the same serial on second cert
        cert = Certificate(ca=self.cas["root"])
        cert.update_certificate(certs["root-cert"]["pub"]["parsed"])
        cert.serial = cert.serial[:-1] + "X"
        cert.save()

        serial = cert.serial[:8]
        self.assertParserError(
            [serial],
            "usage: {script} [-h] cert\n"
            "{script}: error: argument cert: {serial}: Multiple certificates match.\n",
            serial=serial,
        )


class CertificateAuthorityActionTestCase(ParserTestCaseMixin, TestCase):
    """Test CertificateAuthorityAction."""

    load_cas = "__usable__"

    def setUp(self) -> None:
        super().setUp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("ca", action=actions.CertificateAuthorityAction)

    @override_tmpcadir()
    def test_basic(self) -> None:
        """Test basic functionality of action."""
        for name, ca in self.usable_cas:
            args = self.parser.parse_args([certs[name]["serial"]])
            self.assertEqual(args.ca, ca)

    @override_tmpcadir()
    def test_abbreviation(self) -> None:
        """Test using an abbreviation."""
        args = self.parser.parse_args([certs["ec"]["serial"][:6]])
        self.assertEqual(args.ca, self.cas["ec"])

    def test_missing(self) -> None:
        """Test giving an unknown CA."""
        self.assertParserError(
            ["foo"],
            "usage: {script} [-h] ca\n"
            "{script}: error: argument ca: foo: Certificate authority not found.\n",
        )

    def test_multiple(self) -> None:
        """Test an abbreviation matching multiple CAs."""
        ca2 = CertificateAuthority(name="child-duplicate")
        ca2.update_certificate(certs["child"]["pub"]["parsed"])
        ca2.serial = ca2.serial[:-1] + "X"
        ca2.save()

        serial = ca2.serial[:8]
        self.assertParserError(
            [serial],
            "usage: {script} [-h] ca\n"
            "{script}: error: argument ca: {serial}: Multiple Certificate authorities match.\n",
            serial=serial,
        )

    @override_tmpcadir()
    def test_disabled(self) -> None:
        """Test using a disabled CA."""
        self.ca.enabled = False
        self.ca.save()

        expected = """usage: {script} [-h] ca
{script}: error: argument ca: {serial}: Certificate authority not found.\n"""

        self.assertParserError([self.ca.serial], expected, serial=self.ca.serial)

        # test allow_disabled=True
        parser = argparse.ArgumentParser()
        parser.add_argument("ca", action=actions.CertificateAuthorityAction, allow_disabled=True)

        args = parser.parse_args([self.ca.serial])
        self.assertEqual(args.ca, self.ca)

    def test_private_key_does_not_exists(self) -> None:
        """Test error case where private key for CA does not exist."""
        self.ca.private_key_path = "does-not-exist"
        self.ca.save()

        self.assertParserError(
            [self.ca.serial],
            "usage: {script} [-h] ca\n"
            "{script}: error: argument ca: {name}: {path}: Private key does not exist.\n",
            name=self.ca.name,
            path=self.ca.private_key_path,
        )

    @override_tmpcadir()
    def test_password(self) -> None:
        """Test that the action works with a password-encrypted CA."""
        args = self.parser.parse_args([certs["pwd"]["serial"]])
        self.assertEqual(args.ca, self.cas["pwd"])


class URLActionTestCase(ParserTestCaseMixin, TestCase):
    """Test URLAction."""

    def setUp(self) -> None:
        super().setUp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("--url", action=actions.URLAction)

    def test_basic(self) -> None:
        """Test basic functionality of action."""
        for url in ["http://example.com", "https://www.example.org"]:
            args = self.parser.parse_args([f"--url={url}"])
            self.assertEqual(args.url, url)

    def test_error(self) -> None:
        """Test false option values."""
        self.assertParserError(
            ["--url=foo"],
            "usage: {script} [-h] [--url URL]\n{script}: error: argument --url: foo: Not a valid URL.\n",
        )


class ExpiresActionTestCase(ParserTestCaseMixin, TestCase):
    """Test ExpiresAction."""

    def setUp(self) -> None:
        super().setUp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("--expires", action=actions.ExpiresAction)

    def test_basic(self) -> None:
        """Test basic functionality of action."""
        expires = timedelta(days=30)
        args = self.parser.parse_args(["--expires=30"])
        self.assertEqual(args.expires, expires)

    def test_default(self) -> None:
        """Test using the default value."""
        delta = timedelta(days=100)
        parser = argparse.ArgumentParser()
        parser.add_argument("--expires", action=actions.ExpiresAction, default=delta)
        args = parser.parse_args([])
        self.assertEqual(args.expires, delta)

    def test_negative(self) -> None:
        """Test passing a negative value."""
        # this always is one day more, because N days jumps to the next midnight.
        self.assertParserError(
            ["--expires=-1"],
            "usage: {script} [-h] [--expires EXPIRES]\n"
            "{script}: error: argument --expires: -1: Value must not be negative.\n",
        )

    def test_error(self) -> None:
        """Test false option values."""
        value = "foobar"
        self.assertParserError(
            [f"--expires={value}"],
            "usage: {script} [-h] [--expires EXPIRES]\n"
            f"{{script}}: error: argument --expires: {value}: Value must be an integer.\n",
        )


class ReasonActionTestCase(ParserTestCaseMixin, TestCase):
    """Test ReasonAction."""

    def setUp(self) -> None:
        super().setUp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("reason", action=actions.ReasonAction)

    def test_basic(self) -> None:
        """Test basic functionality of action."""
        args = self.parser.parse_args([ReasonFlags.unspecified.name])
        self.assertEqual(args.reason, ReasonFlags.unspecified)

    def test_error(self) -> None:
        """Test false option values."""
        whitespace = " " * len(f"usage: {self.script} ")
        self.assertParserError(
            ["foo"],
            "usage: {script} [-h]\n"
            + whitespace  # whitespace indent depends on length of the name of the script
            + "{{aa_compromise,affiliation_changed,ca_compromise,certificate_hold,"
            "cessation_of_operation,key_compromise,privilege_withdrawn,remove_from_crl,superseded,"
            "unspecified}}\n"
            "{script}: error: argument reason: invalid choice: 'foo' (choose from 'aa_compromise', "
            "'affiliation_changed', 'ca_compromise', 'certificate_hold', 'cessation_of_operation', "
            "'key_compromise', 'privilege_withdrawn', 'remove_from_crl', 'superseded', 'unspecified')\n",
        )


class MultipleURLActionTestCase(ParserTestCaseMixin, TestCase):
    """Test MultipleURLAction."""

    def setUp(self) -> None:
        super().setUp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("--url", action=actions.MultipleURLAction)

    def test_basic(self) -> None:
        """Test basic functionality of action."""
        urls = ["http://example.com", "https://www.example.org"]

        for url in urls:
            parser = argparse.ArgumentParser()
            parser.add_argument("--url", action=actions.MultipleURLAction)

            args = parser.parse_args([f"--url={url}"])
            self.assertEqual(args.url, [url])

        parser = argparse.ArgumentParser()
        parser.add_argument("--url", action=actions.MultipleURLAction)
        args = parser.parse_args([f"--url={urls[0]}", f"--url={urls[1]}"])
        self.assertEqual(args.url, urls)

    def test_none(self) -> None:
        """Test passing no value at all."""
        args = self.parser.parse_args([])
        self.assertEqual(args.url, [])

    def test_error(self) -> None:
        """Test false option values."""
        self.assertParserError(
            ["--url=foo"],
            "usage: {script} [-h] [--url URL]\n{script}: error: argument --url: foo: Not a valid URL.\n",
        )

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

"""Test utility functions."""

import doctest
import ipaddress
import os
import typing
import unittest
from contextlib import contextmanager
from datetime import datetime
from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

import django
from django.conf import settings
from django.core.exceptions import ValidationError
from django.test import TestCase

from freezegun import freeze_time

from .. import ca_settings
from .. import utils
from ..utils import ELLIPTIC_CURVE_NAMES
from ..utils import HASH_ALGORITHM_NAMES
from ..utils import NAME_RE
from ..utils import GeneralNameList
from ..utils import bytes_to_hex
from ..utils import format_general_name
from ..utils import format_name
from ..utils import format_relative_name
from ..utils import generate_private_key
from ..utils import get_cert_builder
from ..utils import is_power2
from ..utils import multiline_url_validator
from ..utils import parse_encoding
from ..utils import parse_general_name
from ..utils import parse_hash_algorithm
from ..utils import parse_key_curve
from ..utils import parse_name
from ..utils import read_file
from ..utils import validate_email
from ..utils import validate_hostname
from ..utils import validate_key_parameters
from ..utils import x509_name
from ..utils import x509_relative_name
from .base import dns
from .base import override_settings
from .base import override_tmpcadir

SuperclassTypeVar = typing.TypeVar("SuperclassTypeVar", bound=typing.Type[object])


def load_tests(  # pylint: disable=unused-argument
    loader: unittest.TestLoader, tests: unittest.TestSuite, ignore: typing.Optional[str] = None
) -> unittest.TestSuite:
    """Load doctests."""
    tests.addTests(doctest.DocTestSuite(utils))
    return tests


class ConstantsTestCase(TestCase):
    """Test various constants in the utils module."""

    def get_subclasses(
        self, cls: typing.Type[SuperclassTypeVar]
    ) -> typing.Set[typing.Type[SuperclassTypeVar]]:
        """Recursively get a list of subclasses.

        .. seealso:: https://stackoverflow.com/a/3862957
        """

        return set(cls.__subclasses__()).union(
            [s for c in cls.__subclasses__() for s in self.get_subclasses(c)]
        )

    @unittest.skipIf(
        settings.CRYPTOGRAPHY_VERSION < (3, 4), "cg<3.4 does not define hashes as subclasses"
    )  # pragma: cryptography<3.4  # remove skipIf when cg<3.4 is deprecated
    def test_hash_algorithms(self) -> None:
        """Test that ``utils.HASH_ALGORITHM_NAMES`` covers all known hash algorithms.

        The point of this test is that it fails if a new cryptography version adds new hash algorithms, thus
        allowing us to detect if the constant becomes out of date.
        """

        # MYPY NOTE: mypy does not allow passing abstract classes for type variables, see
        #            https://github.com/python/mypy/issues/5374#issuecomment-436638471
        subclasses = self.get_subclasses(hashes.HashAlgorithm)  # type: ignore[type-var, misc]

        # filter out hash algorithms that are not supported right now due to them having a digest size as
        # parameter
        subclasses = set(
            sc
            for sc in subclasses
            if sc not in [hashes.SHAKE128, hashes.SHAKE256, hashes.BLAKE2b, hashes.BLAKE2s]
        )

        self.assertEqual(len(utils.HASH_ALGORITHM_NAMES), len(subclasses))
        self.assertEqual(utils.HASH_ALGORITHM_NAMES, {e.name: e for e in subclasses})

    @unittest.skipIf(
        settings.CRYPTOGRAPHY_VERSION < (3, 4), "cg<3.4 does not define hashes as subclasses"
    )  # pragma: cryptography<3.4  # remove skipIf when cg<3.4 is deprecated
    def test_elliptic_curves(self) -> None:
        """Test that ``utils.HASH_ALGORITHM_NAMES`` covers all known elliptic curves.

        The point of this test is that it fails if a new cryptography version adds new curves, thus allowing
        us to detect if the constant becomes out of date.
        """

        # MYPY NOTE: mypy does not allow passing abstract classes for type variables, see
        #            https://github.com/python/mypy/issues/5374#issuecomment-436638471
        subclasses = self.get_subclasses(ec.EllipticCurve)  # type: ignore[type-var, misc]
        self.assertEqual(len(utils.ELLIPTIC_CURVE_NAMES), len(subclasses))
        self.assertEqual(utils.ELLIPTIC_CURVE_NAMES, {e.name: e for e in subclasses})


class NameMatchTest(TestCase):
    """Test parsing of names."""

    def match(self, value: str, expected: typing.List[typing.Tuple[str, str]]) -> None:
        """Helper function to use NAME_RE."""
        parsed_value = [(t[0], t[2]) for t in NAME_RE.findall(value)]
        self.assertEqual(parsed_value, expected)

    def test_empty(self) -> None:
        """Test parsing an empty subject."""
        self.match("", [])
        self.match(" ", [])
        self.match("  ", [])

    def test_single(self) -> None:
        """Test parsing a single token."""
        self.match("C=AT", [("C", "AT")])
        self.match('C="AT"', [("C", "AT")])
        self.match('C=" AT "', [("C", "AT")])

        # test quotes
        self.match('C=" AT \' DE"', [("C", "AT ' DE")])
        self.match("C=' AT \" DE'", [("C", 'AT " DE')])

        self.match("C=AT/DE", [("C", "AT")])  # slash is delimiter when unquoted
        self.match('C="AT/DE"', [("C", "AT/DE")])
        self.match("C='AT/DE/US'", [("C", "AT/DE/US")])
        self.match("C='AT/DE'", [("C", "AT/DE")])
        self.match("C='AT/DE/US'", [("C", "AT/DE/US")])

        self.match("C='AT \\' DE'", [("C", "AT \\' DE")])

    def test_two(self) -> None:
        """Test parsing two tokens."""
        self.match("C=AT/OU=example", [("C", "AT"), ("OU", "example")])
        self.match('C="AT"/OU=example', [("C", "AT"), ("OU", "example")])
        self.match('C=" AT "/OU=example', [("C", "AT"), ("OU", "example")])

        # test quotes
        self.match('C=" AT \' DE"/OU=example', [("C", "AT ' DE"), ("OU", "example")])
        self.match("C=' AT \" DE'/OU=example", [("C", 'AT " DE'), ("OU", "example")])

        self.match('C="AT/DE"/OU=example', [("C", "AT/DE"), ("OU", "example")])
        self.match("C='AT/DE/US'/OU=example", [("C", "AT/DE/US"), ("OU", "example")])
        self.match("C='AT/DE'/OU=example", [("C", "AT/DE"), ("OU", "example")])
        self.match("C='AT/DE/US'/OU=example", [("C", "AT/DE/US"), ("OU", "example")])

        self.match("C='AT \\' DE'/OU=example", [("C", "AT \\' DE"), ("OU", "example")])

        # now both are quoted
        self.match('C="AT"/OU="ex ample"', [("C", "AT"), ("OU", "ex ample")])
        self.match('C=" AT "/OU="ex ample"', [("C", "AT"), ("OU", "ex ample")])
        self.match('C=" AT \' DE"/OU="ex ample"', [("C", "AT ' DE"), ("OU", "ex ample")])
        self.match('C=\' AT " DE\'/OU="ex ample"', [("C", 'AT " DE'), ("OU", "ex ample")])
        self.match('C="AT/DE"/OU="ex ample"', [("C", "AT/DE"), ("OU", "ex ample")])
        self.match("C='AT/DE/US'/OU='ex ample'", [("C", "AT/DE/US"), ("OU", "ex ample")])
        self.match("C='AT/DE'/OU='ex ample'", [("C", "AT/DE"), ("OU", "ex ample")])
        self.match("C='AT/DE/US'/OU='ex ample'", [("C", "AT/DE/US"), ("OU", "ex ample")])

        self.match("C='AT \\' DE'/OU='ex ample'", [("C", "AT \\' DE"), ("OU", "ex ample")])

        # Now include a slash in OU
        self.match('C="AT"/OU="ex / ample"', [("C", "AT"), ("OU", "ex / ample")])
        self.match('C=" AT "/OU="ex / ample"', [("C", "AT"), ("OU", "ex / ample")])
        self.match('C=" AT \' DE"/OU="ex / ample"', [("C", "AT ' DE"), ("OU", "ex / ample")])
        self.match('C=\' AT " DE\'/OU="ex / ample"', [("C", 'AT " DE'), ("OU", "ex / ample")])
        self.match('C="AT/DE"/OU="ex / ample"', [("C", "AT/DE"), ("OU", "ex / ample")])
        self.match("C='AT/DE/US'/OU='ex / ample'", [("C", "AT/DE/US"), ("OU", "ex / ample")])
        self.match("C='AT/DE'/OU='ex / ample'", [("C", "AT/DE"), ("OU", "ex / ample")])
        self.match("C='AT/DE/US'/OU='ex / ample'", [("C", "AT/DE/US"), ("OU", "ex / ample")])
        self.match("C='AT \\' DE'/OU='ex / ample'", [("C", "AT \\' DE"), ("OU", "ex / ample")])

        # Append a slash in the end (It's a delimiter - doesn't influence the output)
        self.match('C="AT"/OU="ex / ample"/', [("C", "AT"), ("OU", "ex / ample")])
        self.match('C=" AT "/OU="ex / ample"/', [("C", "AT"), ("OU", "ex / ample")])
        self.match('C=" AT \' DE"/OU="ex / ample"/', [("C", "AT ' DE"), ("OU", "ex / ample")])
        self.match('C=\' AT " DE\'/OU="ex / ample"/', [("C", 'AT " DE'), ("OU", "ex / ample")])
        self.match('C="AT/DE"/OU="ex / ample"/', [("C", "AT/DE"), ("OU", "ex / ample")])
        self.match("C='AT/DE/US'/OU='ex / ample'/", [("C", "AT/DE/US"), ("OU", "ex / ample")])
        self.match("C='AT/DE'/OU='ex / ample'/", [("C", "AT/DE"), ("OU", "ex / ample")])
        self.match("C='AT/DE/US'/OU='ex / ample'/", [("C", "AT/DE/US"), ("OU", "ex / ample")])
        self.match("C='AT \\' DE'/OU='ex / ample'/", [("C", "AT \\' DE"), ("OU", "ex / ample")])

    def test_unquoted_slashes(self) -> None:
        """Test using unquoted slashes."""
        self.match("C=AT/DE/OU=example", [("C", "AT"), ("DE/OU", "example")])
        self.match('C=AT/DE/OU="ex ample"', [("C", "AT"), ("DE/OU", "ex ample")])
        self.match('C=AT/DE/OU="ex / ample"', [("C", "AT"), ("DE/OU", "ex / ample")])
        self.match('C=AT/DE/OU="ex / ample"/', [("C", "AT"), ("DE/OU", "ex / ample")])

    def test_full_examples(self) -> None:
        """Test some real examples."""
        expected = [
            ("C", "AT"),
            ("ST", "Vienna"),
            ("L", "Loc Fünf"),
            ("O", "Org Name"),
            ("OU", "Org Unit"),
            ("CN", "example.com"),
        ]

        self.match("/C=AT/ST=Vienna/L=Loc Fünf/O=Org Name/OU=Org Unit/CN=example.com", expected)
        self.match("/C=AT/ST=Vienna/L=\"Loc Fünf\"/O='Org Name'/OU=Org Unit/CN=example.com", expected)


class ReadFileTestCase(TestCase):
    """Test :py:func:`django_ca.utils.read_file`."""

    @override_tmpcadir()
    def test_basic(self) -> None:
        """Some basic tests."""
        name = "test-data"
        path = os.path.join(ca_settings.CA_DIR, name)
        data = b"test data"
        with open(path, "wb") as stream:
            stream.write(data)

        self.assertEqual(read_file(name), data)
        self.assertEqual(read_file(path), data)

    @override_tmpcadir()
    def test_file_not_found(self) -> None:
        """Test reading a file that does not exist."""
        name = "test-data"
        path = os.path.join(ca_settings.CA_DIR, name)

        msg = rf"\[Errno 2\] No such file or directory: '{path}'"
        with self.assertRaisesRegex(FileNotFoundError, msg):
            read_file(str(name))

        with self.assertRaisesRegex(FileNotFoundError, msg):
            read_file(str(path))

    @override_tmpcadir()
    def test_permission_denied(self) -> None:
        """Test reading a file when permission is denied."""
        name = "test-data"
        path = os.path.join(ca_settings.CA_DIR, name)
        data = b"test data"
        with open(path, "wb") as stream:
            stream.write(data)
        os.chmod(path, 0o000)

        try:
            msg = rf"\[Errno 13\] Permission denied: '{path}'"
            with self.assertRaisesRegex(PermissionError, msg):
                read_file(str(name))

            with self.assertRaisesRegex(PermissionError, msg):
                read_file(str(path))
        finally:
            os.chmod(path, 0o600)  # make sure we can delete CA_DIR


class ParseNameTestCase(TestCase):
    """Test :py:func:`django_ca.utils.parse_name`."""

    def assertSubject(  # pylint: disable=invalid-name
        self, actual: str, expected: typing.List[typing.Tuple[str, str]]
    ) -> None:
        """Test that the given subject matches."""
        self.assertEqual(parse_name(actual), expected)

    def test_basic(self) -> None:
        """Some basic tests."""
        self.assertSubject("/CN=example.com", [("CN", "example.com")])

        # leading or trailing spaces are always ok.
        self.assertSubject(" /CN = example.com ", [("CN", "example.com")])

        # emailAddress is special because of the case
        self.assertSubject("/emailAddress=user@example.com", [("emailAddress", "user@example.com")])

    def test_multiple(self) -> None:
        """Test subject with multiple tokens."""
        self.assertSubject("/C=AT/OU=foo/CN=example.com", [("C", "AT"), ("OU", "foo"), ("CN", "example.com")])
        self.assertSubject(
            "/C=AT/OU=foo/OU=bar/CN=example.com",
            [("C", "AT"), ("OU", "foo"), ("OU", "bar"), ("CN", "example.com")],
        )

    def test_case(self) -> None:
        """Test that case doesn't matter."""
        self.assertSubject(
            "/c=AT/ou=foo/cn=example.com/eMAIladdreSS=user@example.com",
            [("C", "AT"), ("OU", "foo"), ("CN", "example.com"), ("emailAddress", "user@example.com")],
        )

    def test_emtpy(self) -> None:
        """Test empty subjects."""
        self.assertSubject("", [])
        self.assertSubject("   ", [])

    def test_multiple_slashes(self) -> None:
        """Test that we ignore multiple slashes."""
        self.assertSubject("/C=AT/O=GNU", [("C", "AT"), ("O", "GNU")])
        self.assertSubject("//C=AT/O=GNU", [("C", "AT"), ("O", "GNU")])
        self.assertSubject("/C=AT//O=GNU", [("C", "AT"), ("O", "GNU")])
        self.assertSubject("/C=AT///O=GNU", [("C", "AT"), ("O", "GNU")])

    def test_empty_field(self) -> None:
        """Test empty fields."""
        self.assertSubject("/C=AT/O=GNU/OU=foo", [("C", "AT"), ("O", "GNU"), ("OU", "foo")])
        self.assertSubject("/C=/O=GNU/OU=foo", [("C", ""), ("O", "GNU"), ("OU", "foo")])
        self.assertSubject("/C=AT/O=/OU=foo", [("C", "AT"), ("O", ""), ("OU", "foo")])
        self.assertSubject("/C=AT/O=GNU/OU=", [("C", "AT"), ("O", "GNU"), ("OU", "")])
        self.assertSubject("/C=/O=/OU=", [("C", ""), ("O", ""), ("OU", "")])

    def test_no_slash_at_start(self) -> None:
        """Test that no slash at start is okay."""
        self.assertSubject("CN=example.com", [("CN", "example.com")])

    def test_multiple_ous(self) -> None:
        """Test multiple OUs."""
        self.assertSubject("/OU=foo/OU=bar", [("OU", "foo"), ("OU", "bar")])
        self.assertSubject(
            "/C=AT/O=bla/OU=foo/OU=bar/CN=example.com/",
            [("C", "AT"), ("O", "bla"), ("OU", "foo"), ("OU", "bar"), ("CN", "example.com")],
        )
        self.assertSubject(
            "/C=AT/O=bla/OU=foo/OU=bar/OU=hugo/CN=example.com/",
            [("C", "AT"), ("O", "bla"), ("OU", "foo"), ("OU", "bar"), ("OU", "hugo"), ("CN", "example.com")],
        )
        self.assertSubject(
            "/C=AT/CN=example.com/OU=foo/OU=bar",
            [("C", "AT"), ("OU", "foo"), ("OU", "bar"), ("CN", "example.com")],
        )

    def test_multiple_other(self) -> None:
        """Test multiple other tokens (only OUs work)."""
        with self.assertRaisesRegex(ValueError, '^Subject contains multiple "C" fields$'):
            parse_name("/C=AT/C=FOO")
        with self.assertRaisesRegex(ValueError, '^Subject contains multiple "CN" fields$'):
            parse_name("/CN=AT/CN=FOO")

    def test_unknown(self) -> None:
        """Test unknown field."""
        field = "ABC"
        with self.assertRaisesRegex(ValueError, "^Unknown x509 name field: ABC$") as e:
            parse_name(f"/{field}=example.com")
        self.assertEqual(e.exception.args, (f"Unknown x509 name field: {field}",))


class RelativeNameTestCase(TestCase):
    """Some tests related to relative names."""

    def test_format(self) -> None:
        """Test formatting..."""
        rdn = x509.RelativeDistinguishedName([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
        self.assertEqual(format_relative_name([("C", "AT"), ("CN", "example.com")]), "/C=AT/CN=example.com")
        self.assertEqual(format_relative_name(rdn), "/CN=example.com")

    def test_parse(self) -> None:
        """Test parsing..."""
        expected = x509.RelativeDistinguishedName([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
        self.assertEqual(x509_relative_name(expected), expected)
        self.assertEqual(x509_relative_name("/CN=example.com"), expected)
        self.assertEqual(x509_relative_name([("CN", "example.com")]), expected)


class ValidateEmailTestCase(TestCase):
    """Test :py:func:`django_ca.utils.validate_email`."""

    def test_basic(self) -> None:
        """Some basic tests."""
        self.assertEqual(validate_email("user@example.com"), "user@example.com")

    def test_i18n(self) -> None:
        """Test i18n domain."""
        self.assertEqual(validate_email("user@exämple.com"), "user@xn--exmple-cua.com")

    def test_invalid_domain(self) -> None:
        """Test with an invalid domain."""
        with self.assertRaisesRegex(ValueError, "^Invalid domain: example.com$"):
            validate_email("user@example com")

    def test_no_at(self) -> None:
        """Test without "@"."""
        with self.assertRaisesRegex(ValueError, "^Invalid email address: user$"):
            validate_email("user")

        with self.assertRaisesRegex(ValueError, "^Invalid email address: example.com$"):
            validate_email("example.com")


class ValidateHostnameTestCase(TestCase):
    """Test :py:func:`django_ca.utils.validate_hostname`."""

    def test_no_port(self) -> None:
        """Test with no port."""
        self.assertEqual(validate_hostname("localhost"), "localhost")
        self.assertEqual(validate_hostname("testserver"), "testserver")
        self.assertEqual(validate_hostname("example.com"), "example.com")
        self.assertEqual(validate_hostname("test.example.com"), "test.example.com")

    def test_with_port(self) -> None:
        """Test with a port."""
        self.assertEqual(validate_hostname("localhost:443", allow_port=True), "localhost:443")
        self.assertEqual(validate_hostname("testserver:443", allow_port=True), "testserver:443")
        self.assertEqual(validate_hostname("example.com:443", allow_port=True), "example.com:443")
        self.assertEqual(validate_hostname("test.example.com:443", allow_port=True), "test.example.com:443")
        self.assertEqual(validate_hostname("test.example.com:1", allow_port=True), "test.example.com:1")
        self.assertEqual(validate_hostname("example.com:65535", allow_port=True), "example.com:65535")

    def test_invalid_hostname(self) -> None:
        """Test with an invalid hostname."""
        with self.assertRaisesRegex(ValueError, "example..com: Not a valid hostname"):
            validate_hostname("example..com")

    def test_no_allow_port(self) -> None:
        """Test passing a port when it's not allowed."""
        with self.assertRaisesRegex(ValueError, "^localhost:443: Not a valid hostname$"):
            validate_hostname("localhost:443")
        with self.assertRaisesRegex(ValueError, "^test.example.com:443: Not a valid hostname$"):
            validate_hostname("test.example.com:443")

    def test_port_errors(self) -> None:
        """Test passing an invalid port."""
        with self.assertRaisesRegex(ValueError, "^no-int: Port must be an integer$"):
            validate_hostname("localhost:no-int", allow_port=True)
        with self.assertRaisesRegex(ValueError, "^0: Port must be between 1 and 65535$"):
            validate_hostname("localhost:0", allow_port=True)
        with self.assertRaisesRegex(ValueError, "^-5: Port must be between 1 and 65535$"):
            validate_hostname("localhost:-5", allow_port=True)
        with self.assertRaisesRegex(ValueError, "^65536: Port must be between 1 and 65535$"):
            validate_hostname("localhost:65536", allow_port=True)
        with self.assertRaisesRegex(ValueError, "^100000: Port must be between 1 and 65535$"):
            validate_hostname("localhost:100000", allow_port=True)
        with self.assertRaisesRegex(ValueError, "^colon: Port must be an integer$"):
            validate_hostname("localhost:double:colon", allow_port=True)


class GeneratePrivateKeyTestCase(TestCase):
    """Test :py:func:`django_ca.utils.generate_private_key`."""

    def test_invalid_type(self) -> None:
        """Test passing an invalid key type."""
        with self.assertRaisesRegex(ValueError, r"^FOO: Invalid key type\.$"):
            generate_private_key(16, "FOO", None)  # type: ignore[call-overload]


class ParseGeneralNameTest(TestCase):
    """Test :py:func:`django_ca.utils.parse_general_name`."""

    def test_ipv4(self) -> None:
        """Test parsing an IPv4 address."""
        self.assertEqual(parse_general_name("1.2.3.4"), x509.IPAddress(ipaddress.ip_address("1.2.3.4")))
        self.assertEqual(parse_general_name("ip:1.2.3.4"), x509.IPAddress(ipaddress.ip_address("1.2.3.4")))

    def test_ipv4_network(self) -> None:
        """Test parsing an IPv4 network."""
        self.assertEqual(parse_general_name("1.2.3.0/24"), x509.IPAddress(ipaddress.ip_network("1.2.3.0/24")))
        self.assertEqual(
            parse_general_name("ip:1.2.3.0/24"), x509.IPAddress(ipaddress.ip_network("1.2.3.0/24"))
        )

    def test_ipv6(self) -> None:
        """Test parsing an IPv6 address."""
        self.assertEqual(parse_general_name("fd00::32"), x509.IPAddress(ipaddress.ip_address("fd00::32")))
        self.assertEqual(parse_general_name("ip:fd00::32"), x509.IPAddress(ipaddress.ip_address("fd00::32")))

    def test_ipv6_network(self) -> None:
        """Test parsing an IPv6 network,"""
        self.assertEqual(parse_general_name("fd00::0/32"), x509.IPAddress(ipaddress.ip_network("fd00::0/32")))
        self.assertEqual(
            parse_general_name("ip:fd00::0/32"), x509.IPAddress(ipaddress.ip_network("fd00::0/32"))
        )

    def test_domain(self) -> None:
        """Test parsing a domain."""
        self.assertEqual(parse_general_name("DNS:example.com"), x509.DNSName("example.com"))
        self.assertEqual(parse_general_name("DNS:.example.com"), x509.DNSName(".example.com"))

        self.assertEqual(parse_general_name("example.com"), x509.DNSName("example.com"))
        self.assertEqual(parse_general_name(".example.com"), x509.DNSName(".example.com"))

    def test_wildcard_domain(self) -> None:
        """Test parsing a wildcard domain."""
        self.assertEqual(parse_general_name("*.example.com"), x509.DNSName("*.example.com"))
        self.assertEqual(parse_general_name("DNS:*.example.com"), x509.DNSName("*.example.com"))

        # Wildcard subdomains are allowed in DNS entries, however RFC 2595 limits their use to a single
        # wildcard in the outermost level
        msg = r"^Could not parse name: %s$"

        # pylint: disable=consider-using-f-string  # reuse the message string
        with self.assertRaisesRegex(ValueError, msg % r"test\.\*\.example\.com"):
            parse_general_name("test.*.example.com")
        with self.assertRaisesRegex(ValueError, msg % r"\*\.\*\.example\.com"):
            parse_general_name("*.*.example.com")
        with self.assertRaisesRegex(ValueError, msg % r"example\.com\.\*"):
            parse_general_name("example.com.*")
        # pylint: enable=consider-using-f-string

    def test_dirname(self) -> None:
        """Test parsing a dirname."""
        self.assertEqual(
            parse_general_name("/CN=example.com"),
            x509.DirectoryName(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
                    ]
                )
            ),
        )
        self.assertEqual(
            parse_general_name("dirname:/CN=example.com"),
            x509.DirectoryName(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
                    ]
                )
            ),
        )
        self.assertEqual(
            parse_general_name("dirname:/C=AT/CN=example.com"),
            x509.DirectoryName(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COUNTRY_NAME, "AT"),
                        x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
                    ]
                )
            ),
        )

    def test_uri(self) -> None:
        """Test parsing a URI."""
        url = "https://example.com"
        self.assertEqual(parse_general_name(url), x509.UniformResourceIdentifier(url))
        self.assertEqual(parse_general_name(f"uri:{url}"), x509.UniformResourceIdentifier(url))

    def test_rid(self) -> None:
        """Test parsing a Registered ID."""
        self.assertEqual(parse_general_name("rid:2.5.4.3"), x509.RegisteredID(NameOID.COMMON_NAME))

    def test_othername(self) -> None:
        """Test parsing an otherName name."""
        self.assertEqual(
            parse_general_name("otherName:2.5.4.3;UTF8:example.com"),
            x509.OtherName(NameOID.COMMON_NAME, b"example.com"),
        )

    def test_unicode_domains(self) -> None:
        """Test some unicode domains."""
        self.assertEqual(
            parse_general_name("https://exämple.com/test"),
            x509.UniformResourceIdentifier("https://xn--exmple-cua.com/test"),
        )
        self.assertEqual(
            parse_general_name("https://exämple.com:8000/test"),
            x509.UniformResourceIdentifier("https://xn--exmple-cua.com:8000/test"),
        )
        self.assertEqual(
            parse_general_name("https://exämple.com:8000/test"),
            x509.UniformResourceIdentifier("https://xn--exmple-cua.com:8000/test"),
        )
        self.assertEqual(
            parse_general_name("uri:https://exämple.com:8000/test"),
            x509.UniformResourceIdentifier("https://xn--exmple-cua.com:8000/test"),
        )

        self.assertEqual(parse_general_name("exämple.com"), x509.DNSName("xn--exmple-cua.com"))
        self.assertEqual(parse_general_name(".exämple.com"), x509.DNSName(".xn--exmple-cua.com"))
        self.assertEqual(parse_general_name("*.exämple.com"), x509.DNSName("*.xn--exmple-cua.com"))
        self.assertEqual(parse_general_name("dns:exämple.com"), x509.DNSName("xn--exmple-cua.com"))
        self.assertEqual(parse_general_name("dns:.exämple.com"), x509.DNSName(".xn--exmple-cua.com"))
        self.assertEqual(parse_general_name("dns:*.exämple.com"), x509.DNSName("*.xn--exmple-cua.com"))

    def test_wrong_email(self) -> None:
        """Test using an invalid email."""
        with self.assertRaisesRegex(ValueError, r"^Could not parse name: user@$"):
            parse_general_name("user@")

        with self.assertRaisesRegex(ValueError, "^Invalid domain: $"):
            parse_general_name("email:user@")

    def test_othername_octetstring(self) -> None:
        """Test an octet string."""
        self.assertEqual(
            parse_general_name("otherName:1.3.6.1.4.1.311.25.1;OctetString:09CFF1A8F6DEFD4B85CE95FFA1B54217"),
            x509.OtherName(
                x509.oid.ObjectIdentifier("1.3.6.1.4.1.311.25.1"),
                b"\x04\x10\t\xcf\xf1\xa8\xf6\xde\xfdK\x85\xce\x95\xff\xa1\xb5B\x17",
            ),
        )

        with self.assertRaisesRegex(ValueError, "^Incorrect otherName format: foobar$"):
            parse_general_name("otherName:foobar")

        with self.assertRaisesRegex(ValueError, "^Unsupported ASN type in otherName: MagicString$"):
            parse_general_name("otherName:1.2.3;MagicString:Broken")

    def test_error(self) -> None:
        """Try parsing an unparseable IP address (b/c it has a network)."""
        with self.assertRaisesRegex(ValueError, r"^Could not parse IP address\.$"):
            parse_general_name("ip:1.2.3.4/24")

    def test_unparseable(self) -> None:
        """test some unparseable domains."""
        with self.assertRaisesRegex(ValueError, r"^Could not parse name: http://ex ample\.com$"):
            parse_general_name("http://ex ample.com")
        with self.assertRaisesRegex(ValueError, r"^Could not parse DNS name in URL: http://ex ample\.com$"):
            parse_general_name("uri:http://ex ample.com")
        with self.assertRaisesRegex(ValueError, r"^Could not parse DNS name: ex ample\.com"):
            parse_general_name("dns:ex ample.com")


class FormatGeneralNameTest(TestCase):
    """Test :py:func:`django_ca.utils.format_general_name`."""

    def test_basic(self) -> None:
        """Some basic tests."""
        self.assertEqual(format_general_name(x509.DNSName("example.com")), "DNS:example.com")
        self.assertEqual(
            format_general_name(x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))), "IP:127.0.0.1"
        )

    def test_dirname(self) -> None:
        """Test formatting a dirname."""
        name = x509.DirectoryName(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "AT"),
                    x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
                ]
            )
        )
        self.assertEqual(format_general_name(name), "dirname:/C=AT/CN=example.com")


class ParseHashAlgorithm(TestCase):
    """Test :py:func:`django_ca.utils.parse_hash_algorithm`."""

    def test_basic(self) -> None:
        """Some basic tests."""
        self.assertIsInstance(parse_hash_algorithm(), hashes.SHA512)
        self.assertIsInstance(parse_hash_algorithm(hashes.SHA512), hashes.SHA512)
        self.assertIsInstance(parse_hash_algorithm(hashes.SHA512()), hashes.SHA512)
        self.assertIsInstance(parse_hash_algorithm("SHA512"), hashes.SHA512)

        for name, cls in HASH_ALGORITHM_NAMES.items():
            self.assertIsInstance(parse_hash_algorithm(name), cls)

        with self.assertRaisesRegex(ValueError, "^Unknown hash algorithm: foo$"):
            parse_hash_algorithm("foo")

        with self.assertRaisesRegex(ValueError, "^Unknown type passed: bool$"):
            parse_hash_algorithm(False)  # type: ignore[arg-type]


class FormatNameTestCase(TestCase):
    """Test :py:func:`django_ca.utils.format_name`."""

    def test_basic(self) -> None:
        """Some basic tests."""

        subject = "/C=AT/ST=Vienna/L=Vienna/O=O/OU=OU/CN=example.com/emailAddress=user@example.com"
        subject_dict = [
            ("C", "AT"),
            ("ST", "Vienna"),
            ("L", "Vienna"),
            ("O", "O"),
            ("OU", "OU"),
            ("CN", "example.com"),
            ("emailAddress", "user@example.com"),
        ]
        self.assertEqual(format_name(subject_dict), subject)

    def test_x509(self) -> None:
        """Test passing a x509.Name."""
        subject = "/C=AT/ST=Vienna/L=Vienna/O=O/OU=OU/CN=example.com/emailAddress=user@example.com"
        name = x509.Name(
            [
                x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "AT"),
                x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "Vienna"),
                x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Vienna"),
                x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "O"),
                x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, "OU"),
                x509.NameAttribute(x509.NameOID.COMMON_NAME, "example.com"),
                x509.NameAttribute(x509.NameOID.EMAIL_ADDRESS, "user@example.com"),
            ]
        )
        self.assertEqual(format_name(name), subject)


class Power2TestCase(TestCase):
    """Test :py:func:`django_ca.utils.is_power2`."""

    def test_true(self) -> None:
        """Test some numbers that are power of two."""
        for i in range(0, 20):
            self.assertTrue(is_power2(2 ** i))

    def test_false(self) -> None:
        """Test some numbers that are not power of two."""
        self.assertFalse(is_power2(0))
        self.assertFalse(is_power2(3))
        self.assertFalse(is_power2(5))

        for i in range(2, 20):
            self.assertFalse(is_power2((2 ** i) - 1))
            self.assertFalse(is_power2((2 ** i) + 1))


class ParseKeyCurveTestCase(TestCase):
    """Test :py:func:`django_ca.utils.parse_key_curve`."""

    def test_basic(self) -> None:
        """Some basic tests."""
        self.assertIsInstance(parse_key_curve(), type(ca_settings.CA_DEFAULT_ECC_CURVE))
        self.assertIsInstance(parse_key_curve("SECT409R1"), ec.SECT409R1)
        self.assertIsInstance(parse_key_curve("SECP521R1"), ec.SECP521R1)
        self.assertIsInstance(parse_key_curve("SECP192R1"), ec.SECP192R1)

        for name, cls in ELLIPTIC_CURVE_NAMES.items():
            self.assertIsInstance(parse_key_curve(name), cls)

    def test_error(self) -> None:
        """Test some error cases."""
        with self.assertRaisesRegex(ValueError, "^FOOBAR: Not a known Eliptic Curve$"):
            parse_key_curve("FOOBAR")

        with self.assertRaisesRegex(ValueError, "^ECDH: Not a known Eliptic Curve$"):
            parse_key_curve("ECDH")  # present in the module, but *not* an EllipticCurve


class ParseEncodingTestCase(TestCase):
    """Test :py:func:`django_ca.utils.parse_encoding`."""

    def test_basic(self) -> None:
        """Some basic tests."""
        self.assertEqual(parse_encoding(), Encoding.PEM)
        self.assertEqual(parse_encoding("PEM"), Encoding.PEM)
        self.assertEqual(parse_encoding(Encoding.PEM), Encoding.PEM)

        self.assertEqual(parse_encoding("DER"), Encoding.DER)
        self.assertEqual(parse_encoding("ASN1"), Encoding.DER)
        self.assertEqual(parse_encoding(Encoding.DER), Encoding.DER)

        self.assertEqual(parse_encoding("OpenSSH"), Encoding.OpenSSH)
        self.assertEqual(parse_encoding(Encoding.OpenSSH), Encoding.OpenSSH)

    def test_error(self) -> None:
        """Test some error cases."""
        with self.assertRaisesRegex(ValueError, "^Unknown encoding: foo$"):
            parse_encoding("foo")

        with self.assertRaisesRegex(ValueError, "^Unknown type passed: bool$"):
            parse_encoding(True)  # type: ignore[arg-type]


class AddColonsTestCase(TestCase):
    """Test :py:func:`django_ca.utils.add_colons`."""

    def test_basic(self) -> None:
        """Some basic tests."""
        self.assertEqual(utils.add_colons(""), "")
        self.assertEqual(utils.add_colons("a"), "0a")
        self.assertEqual(utils.add_colons("ab"), "ab")
        self.assertEqual(utils.add_colons("abc"), "0a:bc")
        self.assertEqual(utils.add_colons("abcd"), "ab:cd")
        self.assertEqual(utils.add_colons("abcde"), "0a:bc:de")
        self.assertEqual(utils.add_colons("abcdef"), "ab:cd:ef")
        self.assertEqual(utils.add_colons("abcdefg"), "0a:bc:de:fg")

    def test_pad(self) -> None:
        """Test padding."""
        self.assertEqual(utils.add_colons("a", pad="z"), "za")
        self.assertEqual(utils.add_colons("ab", pad="z"), "ab")
        self.assertEqual(utils.add_colons("abc", pad="z"), "za:bc")

    def test_no_pad(self) -> None:
        """Test disabling padding."""
        self.assertEqual(utils.add_colons("a", pad=""), "a")
        self.assertEqual(utils.add_colons("ab", pad=""), "ab")
        self.assertEqual(utils.add_colons("abc", pad=""), "ab:c")

    def test_zero_padding(self) -> None:
        """Test when there is no padding."""
        self.assertEqual(
            utils.add_colons("F570A555BC5000FA301E8C75FFB31684FCF64436"),
            "F5:70:A5:55:BC:50:00:FA:30:1E:8C:75:FF:B3:16:84:FC:F6:44:36",
        )
        self.assertEqual(
            utils.add_colons("85BDA79A857379A4C9E910DAEA21C896D16394"),
            "85:BD:A7:9A:85:73:79:A4:C9:E9:10:DA:EA:21:C8:96:D1:63:94",
        )


class IntToHexTestCase(TestCase):
    """Test :py:func:`django_ca.utils.int_to_hex`."""

    def test_basic(self) -> None:
        """Test the first view numbers."""
        self.assertEqual(utils.int_to_hex(0), "0")
        self.assertEqual(utils.int_to_hex(1), "1")
        self.assertEqual(utils.int_to_hex(2), "2")
        self.assertEqual(utils.int_to_hex(3), "3")
        self.assertEqual(utils.int_to_hex(4), "4")
        self.assertEqual(utils.int_to_hex(5), "5")
        self.assertEqual(utils.int_to_hex(6), "6")
        self.assertEqual(utils.int_to_hex(7), "7")
        self.assertEqual(utils.int_to_hex(8), "8")
        self.assertEqual(utils.int_to_hex(9), "9")
        self.assertEqual(utils.int_to_hex(10), "A")
        self.assertEqual(utils.int_to_hex(11), "B")
        self.assertEqual(utils.int_to_hex(12), "C")
        self.assertEqual(utils.int_to_hex(13), "D")
        self.assertEqual(utils.int_to_hex(14), "E")
        self.assertEqual(utils.int_to_hex(15), "F")
        self.assertEqual(utils.int_to_hex(16), "10")
        self.assertEqual(utils.int_to_hex(17), "11")
        self.assertEqual(utils.int_to_hex(18), "12")
        self.assertEqual(utils.int_to_hex(19), "13")
        self.assertEqual(utils.int_to_hex(20), "14")
        self.assertEqual(utils.int_to_hex(21), "15")
        self.assertEqual(utils.int_to_hex(22), "16")
        self.assertEqual(utils.int_to_hex(23), "17")
        self.assertEqual(utils.int_to_hex(24), "18")
        self.assertEqual(utils.int_to_hex(25), "19")
        self.assertEqual(utils.int_to_hex(26), "1A")
        self.assertEqual(utils.int_to_hex(27), "1B")
        self.assertEqual(utils.int_to_hex(28), "1C")
        self.assertEqual(utils.int_to_hex(29), "1D")
        self.assertEqual(utils.int_to_hex(30), "1E")
        self.assertEqual(utils.int_to_hex(31), "1F")
        self.assertEqual(utils.int_to_hex(32), "20")
        self.assertEqual(utils.int_to_hex(33), "21")
        self.assertEqual(utils.int_to_hex(34), "22")
        self.assertEqual(utils.int_to_hex(35), "23")
        self.assertEqual(utils.int_to_hex(36), "24")
        self.assertEqual(utils.int_to_hex(37), "25")
        self.assertEqual(utils.int_to_hex(38), "26")
        self.assertEqual(utils.int_to_hex(39), "27")
        self.assertEqual(utils.int_to_hex(40), "28")
        self.assertEqual(utils.int_to_hex(41), "29")
        self.assertEqual(utils.int_to_hex(42), "2A")
        self.assertEqual(utils.int_to_hex(43), "2B")
        self.assertEqual(utils.int_to_hex(44), "2C")
        self.assertEqual(utils.int_to_hex(45), "2D")
        self.assertEqual(utils.int_to_hex(46), "2E")
        self.assertEqual(utils.int_to_hex(47), "2F")
        self.assertEqual(utils.int_to_hex(48), "30")
        self.assertEqual(utils.int_to_hex(49), "31")

    def test_high(self) -> None:
        """Test some high numbers."""
        self.assertEqual(utils.int_to_hex(1513282098), "5A32DA32")
        self.assertEqual(utils.int_to_hex(1513282099), "5A32DA33")
        self.assertEqual(utils.int_to_hex(1513282100), "5A32DA34")
        self.assertEqual(utils.int_to_hex(1513282101), "5A32DA35")
        self.assertEqual(utils.int_to_hex(1513282102), "5A32DA36")
        self.assertEqual(utils.int_to_hex(1513282103), "5A32DA37")
        self.assertEqual(utils.int_to_hex(1513282104), "5A32DA38")
        self.assertEqual(utils.int_to_hex(1513282105), "5A32DA39")
        self.assertEqual(utils.int_to_hex(1513282106), "5A32DA3A")
        self.assertEqual(utils.int_to_hex(1513282107), "5A32DA3B")
        self.assertEqual(utils.int_to_hex(1513282108), "5A32DA3C")
        self.assertEqual(utils.int_to_hex(1513282109), "5A32DA3D")
        self.assertEqual(utils.int_to_hex(1513282110), "5A32DA3E")
        self.assertEqual(utils.int_to_hex(1513282111), "5A32DA3F")
        self.assertEqual(utils.int_to_hex(1513282112), "5A32DA40")
        self.assertEqual(utils.int_to_hex(1513282113), "5A32DA41")


class BytesToHexTestCase(TestCase):
    """Test :py:func:`~django_ca.utils.byutes_to_hex`."""

    def test_basic(self) -> None:
        """Some basic test cases."""
        self.assertEqual(bytes_to_hex(b"test"), "74:65:73:74")
        self.assertEqual(bytes_to_hex(b"foo"), "66:6F:6F")
        self.assertEqual(bytes_to_hex(b"bar"), "62:61:72")
        self.assertEqual(bytes_to_hex(b""), "")
        self.assertEqual(bytes_to_hex(b"a"), "61")


class SanitizeSerialTestCase(TestCase):
    """Test :py:func:`~django_ca.utils.sanitize_serial`."""

    def test_already_sanitized(self) -> None:
        """Test some already sanitized input."""
        self.assertEqual(utils.sanitize_serial("A"), "A")
        self.assertEqual(utils.sanitize_serial("5A32DA3B"), "5A32DA3B")
        self.assertEqual(utils.sanitize_serial("1234567890ABCDEF"), "1234567890ABCDEF")

    def test_sanitized(self) -> None:
        """Test some input that can be correctly sanitized."""
        self.assertEqual(utils.sanitize_serial("5A:32:DA:3B"), "5A32DA3B")
        self.assertEqual(utils.sanitize_serial("0A:32:DA:3B"), "A32DA3B")
        self.assertEqual(utils.sanitize_serial("0a:32:da:3b"), "A32DA3B")

    def test_zero(self) -> None:
        """An imported CA might have a serial of just a ``0``, so it must not be stripped."""
        self.assertEqual(utils.sanitize_serial("0"), "0")

    def test_invalid_input(self) -> None:
        """Test some input that raises an exception."""

        with self.assertRaisesRegex(ValueError, r"^ABCXY: Serial has invalid characters$"):
            utils.sanitize_serial("ABCXY")


class X509NameTestCase(TestCase):
    """Test :py:func:`django_ca.utils.x509_name`."""

    name = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "AT"),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "Vienna"),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Vienna"),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "O"),
            x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, "OU"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "example.com"),
            x509.NameAttribute(x509.NameOID.EMAIL_ADDRESS, "user@example.com"),
        ]
    )

    def test_str(self) -> None:
        """Test passing a string."""
        subject = "/C=AT/ST=Vienna/L=Vienna/O=O/OU=OU/CN=example.com/emailAddress=user@example.com"
        self.assertEqual(x509_name(subject), self.name)

    def test_tuple(self) -> None:
        """Test passing a tuple."""
        subject = [
            ("C", "AT"),
            ("ST", "Vienna"),
            ("L", "Vienna"),
            ("O", "O"),
            ("OU", "OU"),
            ("CN", "example.com"),
            ("emailAddress", "user@example.com"),
        ]
        self.assertEqual(x509_name(subject), self.name)


class MultilineURLValidatorTestCase(TestCase):
    """Test :py:func:`django_ca.utils.multiline_url_validator`."""

    @contextmanager
    def assertValidationError(self, value: str) -> typing.Iterator[None]:  # pylint: disable=invalid-name
        """Wrapper to assert a validation error.

        Django 3.2 adds the value to ValidationError. This method turns into a useless one-liner as soon as we
        drop support for Django<3.1.
        """
        with self.assertRaises(ValidationError) as e:
            yield

        if django.VERSION[:2] < (3, 2):
            params = None
        else:
            params = {"value": value}

        self.assertEqual(e.exception.args, ("Enter a valid URL.", "invalid", params))

    def test_basic(self) -> None:
        """Basic working tests."""
        multiline_url_validator("")
        multiline_url_validator("http://example.com")
        multiline_url_validator("http://example.com\nhttp://www.example.org")
        multiline_url_validator(
            """http://example.com\nhttp://www.example.org
http://www.example.net"""
        )

    def test_error(self) -> None:
        """Test various invalid cases."""
        with self.assertValidationError("foo"):
            multiline_url_validator("foo")

        with self.assertValidationError("foo"):
            multiline_url_validator("foo\nhttp://www.example.com")

        with self.assertValidationError("foo"):
            multiline_url_validator("http://www.example.com\nfoo")

        with self.assertRaises(ValidationError):
            multiline_url_validator("http://www.example.com\nfoo\nhttp://example.org")


class GetCertBuilderTestCase(TestCase):
    """Test :py:func:`django_ca.utils.get_cert_builder`."""

    def parse_date(self, date: str) -> datetime:
        """Helper to parse a date."""
        return datetime.strptime(date, "%Y%m%d%H%M%SZ")

    @freeze_time("2018-11-03 11:21:33")
    @override_settings(CA_DEFAULT_EXPIRES=100)
    def test_basic(self) -> None:
        """Basic tests."""

        # pylint: disable=protected-access; only way to test builder attributes
        after = datetime(2020, 10, 23, 11, 21)
        before = datetime(2018, 11, 3, 11, 21)
        builder = get_cert_builder(after)
        self.assertEqual(builder._not_valid_after, after)
        self.assertEqual(builder._not_valid_before, before)
        self.assertIsInstance(builder._serial_number, int)

    @freeze_time("2021-01-23 14:42:11.1234")
    def test_datetime(self) -> None:
        """Basic tests."""

        expires = datetime.utcnow() + timedelta(days=10)
        self.assertNotEqual(expires.second, 0)
        self.assertNotEqual(expires.microsecond, 0)
        expires_expected = datetime(2021, 2, 2, 14, 42)
        builder = get_cert_builder(expires)
        self.assertEqual(builder._not_valid_after, expires_expected)  # pylint: disable=protected-access
        self.assertIsInstance(builder._serial_number, int)  # pylint: disable=protected-access

    @freeze_time("2021-01-23 14:42:11.1234")
    def test_serial(self) -> None:
        """Test manually setting a serial."""
        after = datetime(2022, 10, 23, 11, 21)
        builder = get_cert_builder(after, serial=123)
        self.assertEqual(builder._serial_number, 123)  # pylint: disable=protected-access
        self.assertEqual(builder._not_valid_after, after)  # pylint: disable=protected-access

    @freeze_time("2021-01-23 14:42:11")
    def test_negative_datetime(self) -> None:
        """Test passing a datetime in the past."""
        msg = r"^expires must be in the future$"
        with self.assertRaisesRegex(ValueError, msg):
            get_cert_builder(datetime.utcnow() - timedelta(seconds=60))

    def test_invalid_type(self) -> None:
        """Test passing an invalid type."""
        with self.assertRaises(TypeError):
            get_cert_builder("a string")  # type: ignore[arg-type]


class ValidateKeyParametersTest(TestCase):
    """Test :py:func:`django_ca.utils.validate_key_parameters`."""

    def test_basic(self) -> None:
        """Some basic tests."""
        self.assertEqual(validate_key_parameters(), (ca_settings.CA_DEFAULT_KEY_SIZE, "RSA", None))
        self.assertEqual(
            validate_key_parameters(key_type=None), (ca_settings.CA_DEFAULT_KEY_SIZE, "RSA", None)
        )

    def test_wrong_values(self) -> None:
        """Test validating various bogus values."""
        with self.assertRaisesRegex(ValueError, "^FOOBAR: Unknown key type$"):
            validate_key_parameters(4096, "FOOBAR")  # type: ignore[call-overload]

        with self.assertRaisesRegex(ValueError, "^4000: Key size must be a power of two$"):
            validate_key_parameters(4000, "RSA")

        with self.assertRaisesRegex(ValueError, "^16: Key size must be least 1024 bits$"):
            validate_key_parameters(16, "RSA")


class GeneralNameListTestCase(TestCase):
    """Test GeneralNameList."""

    dns1 = "example.com"
    dns2 = "example.net"

    @contextmanager
    def assertAddTrue(self) -> typing.Iterator[None]:  # pylint: disable=invalid-name
        """Just a shortcut when we somehow add True"""

        msg = r"^Cannot parse general name True: Must be of type str \(was: bool\)\.$"
        with self.assertRaisesRegex(ValueError, msg):
            yield

    def test_init(self) -> None:
        """Test various different item initializations."""
        self.assertEqual(GeneralNameList(), [])
        self.assertEqual(GeneralNameList([self.dns1]), [dns(self.dns1)])
        self.assertEqual(GeneralNameList([dns(self.dns1)]), [dns(self.dns1)])
        self.assertEqual(GeneralNameList([dns(self.dns1), self.dns2]), [dns(self.dns1), dns(self.dns2)])

        # we also accept a str or generalName
        self.assertEqual(GeneralNameList(self.dns1), [dns(self.dns1)])
        self.assertEqual(GeneralNameList(dns(self.dns1)), [dns(self.dns1)])

        with self.assertAddTrue():
            GeneralNameList([True])  # type: ignore[list-item]

    def test_add(self) -> None:
        """Test add()."""
        values: typing.List[
            typing.Tuple[
                GeneralNameList,
                typing.Union[GeneralNameList, typing.List[typing.Union[x509.GeneralName, str]]],
                GeneralNameList,
            ]
        ] = [
            (GeneralNameList(), GeneralNameList([self.dns1]), GeneralNameList([self.dns1])),
            (GeneralNameList(), GeneralNameList([dns(self.dns1)]), GeneralNameList([self.dns1])),
            (GeneralNameList(), [self.dns1], GeneralNameList([self.dns1])),
            (GeneralNameList(), [dns(self.dns1)], GeneralNameList([self.dns1])),
            (GeneralNameList([self.dns1]), [dns(self.dns1)], GeneralNameList([self.dns1, self.dns1])),
            (GeneralNameList([dns(self.dns1)]), [dns(self.dns1)], GeneralNameList([self.dns1, self.dns1])),
            (GeneralNameList([dns(self.dns2)]), [dns(self.dns1)], GeneralNameList([self.dns2, self.dns1])),
        ]

        for gnl1, gnl2, exp in values:
            got = gnl1 + gnl2
            self.assertEqual(got, exp)
            self.assertIsNot(gnl1, got)
            self.assertIsNot(gnl2, got)

        empty = GeneralNameList()
        with self.assertAddTrue():
            empty + [True]  # type: ignore[list-item] # pylint: disable=pointless-statement

    def test_append(self) -> None:
        """Test append()."""
        gnl1 = GeneralNameList()
        self.assertIsNone(gnl1.append(self.dns1))  # type: ignore[func-returns-value]
        self.assertEqual(gnl1, GeneralNameList([self.dns1]))
        self.assertIsNone(gnl1.append(dns(self.dns2)))  # type: ignore[func-returns-value]
        self.assertEqual(gnl1, GeneralNameList([self.dns1, self.dns2]))

        with self.assertAddTrue():
            gnl1.append(True)  # type: ignore[arg-type]
        self.assertEqual(gnl1, GeneralNameList([self.dns1, self.dns2]))

    def test_contains(self) -> None:
        """Test contains()."""
        self.assertNotIn(self.dns1, GeneralNameList())
        self.assertNotIn(dns(self.dns1), GeneralNameList())

        self.assertIn(self.dns1, GeneralNameList([self.dns1]))
        self.assertIn(dns(self.dns1), GeneralNameList([self.dns1]))
        self.assertNotIn(self.dns1, GeneralNameList([self.dns2]))
        self.assertNotIn(dns(self.dns1), GeneralNameList([self.dns2]))
        self.assertNotIn(self.dns1, GeneralNameList([dns(self.dns2)]))
        self.assertNotIn(dns(self.dns1), GeneralNameList([dns(self.dns2)]))

        # Should not raise an error - it's just False
        self.assertNotIn(True, GeneralNameList([dns(self.dns2)]))

    def test_count(self) -> None:
        """Test count()."""
        gnl1 = GeneralNameList()
        self.assertEqual(gnl1.count(self.dns1), 0)
        self.assertEqual(gnl1.count(dns(self.dns2)), 0)
        self.assertEqual(gnl1.count(True), 0)  # type: ignore[arg-type]

        gnl1 = GeneralNameList([self.dns1])
        self.assertEqual(gnl1.count(self.dns1), 1)
        self.assertEqual(gnl1.count(dns(self.dns1)), 1)
        self.assertEqual(gnl1.count(dns(self.dns2)), 0)
        self.assertEqual(gnl1.count(self.dns2), 0)
        self.assertEqual(gnl1.count(True), 0)  # type: ignore[arg-type]

    def test_eq(self) -> None:
        """Test list equality."""
        self.assertEqual(GeneralNameList(), [])
        self.assertEqual(GeneralNameList(), GeneralNameList())
        self.assertEqual(GeneralNameList([self.dns1]), GeneralNameList([self.dns1]))
        self.assertEqual(GeneralNameList([self.dns1]), GeneralNameList([dns(self.dns1)]))
        self.assertEqual(GeneralNameList([self.dns1]), [self.dns1])
        self.assertEqual(GeneralNameList([self.dns1]), [dns(self.dns1)])

        self.assertNotEqual(GeneralNameList([self.dns1]), GeneralNameList([self.dns2]))
        self.assertNotEqual(GeneralNameList([self.dns1]), GeneralNameList([dns(self.dns2)]))
        self.assertNotEqual(GeneralNameList([self.dns1]), [self.dns2])
        self.assertNotEqual(GeneralNameList([self.dns1]), [dns(self.dns2)])

        # Should not raise an error - it's just False
        self.assertNotEqual(GeneralNameList([self.dns1]), [True])

    def test_extend(self) -> None:
        """Test extend()."""
        gnl1 = GeneralNameList()
        self.assertIsNone(gnl1.extend([self.dns1]))  # type: ignore[func-returns-value]
        self.assertEqual(gnl1, GeneralNameList([self.dns1]))

        gnl2 = GeneralNameList()
        self.assertIsNone(gnl2.extend([dns(self.dns1)]))  # type: ignore[func-returns-value]
        self.assertEqual(gnl2, GeneralNameList([self.dns1]))

        gnl3 = GeneralNameList([self.dns1])
        self.assertIsNone(gnl3.extend([dns(self.dns1), self.dns2]))  # type: ignore[func-returns-value]
        self.assertEqual(gnl3, GeneralNameList([self.dns1, self.dns1, self.dns2]))

    def test_iadd(self) -> None:
        """Test infix add (e.g. ``self += value``)."""
        values: typing.List[
            typing.Tuple[
                GeneralNameList,
                typing.Union[GeneralNameList, typing.List[typing.Union[x509.GeneralName, str]]],
                GeneralNameList,
            ]
        ] = [
            (GeneralNameList(), GeneralNameList([self.dns1]), GeneralNameList([self.dns1])),
            (GeneralNameList(), GeneralNameList([dns(self.dns1)]), GeneralNameList([self.dns1])),
            (GeneralNameList(), [self.dns1], GeneralNameList([self.dns1])),
            (GeneralNameList(), [dns(self.dns1)], GeneralNameList([self.dns1])),
            (GeneralNameList([self.dns1]), [dns(self.dns1)], GeneralNameList([self.dns1, self.dns1])),
            (GeneralNameList([dns(self.dns1)]), [dns(self.dns1)], GeneralNameList([self.dns1, self.dns1])),
            (GeneralNameList([dns(self.dns2)]), [dns(self.dns1)], GeneralNameList([self.dns2, self.dns1])),
        ]

        for gnl1, gnl2, exp in values:
            gnl1 += gnl2
            self.assertEqual(gnl1, exp)

        empty = GeneralNameList()
        with self.assertAddTrue():
            empty += [True]  # type: ignore[list-item] # what we're testing

    def test_index(self) -> None:
        """Test index()."""
        gnl1 = GeneralNameList()
        with self.assertRaises(ValueError):
            gnl1.index(self.dns1)
        with self.assertRaises(ValueError):
            gnl1.index(dns(self.dns1))

        gnl2 = GeneralNameList([self.dns1])
        self.assertEqual(gnl2.index(self.dns1), 0)
        self.assertEqual(gnl2.index(dns(self.dns1)), 0)
        with self.assertRaises(ValueError):
            gnl1.index(self.dns2)
        with self.assertRaises(ValueError):
            gnl1.index(dns(self.dns2))

    def test_insert(self) -> None:
        """Test insert()."""
        gnl1 = GeneralNameList()
        gnl1.insert(0, self.dns1)
        self.assertEqual(gnl1, [self.dns1])

        gnl1.insert(0, dns(self.dns2))
        self.assertEqual(gnl1, [self.dns2, self.dns1])

        with self.assertAddTrue():
            gnl1.insert(0, True)  # type: ignore[arg-type] # what we're testing
        self.assertEqual(gnl1, [self.dns2, self.dns1])

    def test_remove(self) -> None:
        """Test remove()."""
        gnl1 = GeneralNameList([self.dns1, self.dns2])
        self.assertIsNone(gnl1.remove(self.dns1))  # type: ignore[func-returns-value]
        self.assertEqual(gnl1, [self.dns2])
        self.assertIsNone(gnl1.remove(dns(self.dns2)))  # type: ignore[func-returns-value]
        self.assertEqual(gnl1, [])

    def test_repr(self) -> None:
        """Test repr()."""
        self.assertEqual(repr(GeneralNameList()), "<GeneralNameList: []>")
        self.assertEqual(repr(GeneralNameList([self.dns1])), f"<GeneralNameList: ['DNS:{self.dns1}']>")
        self.assertEqual(repr(GeneralNameList([dns(self.dns1)])), f"<GeneralNameList: ['DNS:{self.dns1}']>")

    def test_serialize(self) -> None:
        """Test serialization."""
        gnl1 = GeneralNameList([self.dns1, dns(self.dns2), self.dns1])
        self.assertEqual(list(gnl1.serialize()), [f"DNS:{self.dns1}", f"DNS:{self.dns2}", f"DNS:{self.dns1}"])

    def test_setitem(self) -> None:
        """Test setter, e.g. ``e[0] = ...``."""
        gnl1 = GeneralNameList()

        with self.assertRaisesRegex(IndexError, r"^list assignment index out of range$"):
            gnl1[0] = dns(self.dns1)
        with self.assertRaisesRegex(IndexError, r"^list assignment index out of range$"):
            gnl1[0] = self.dns1
        self.assertEqual(len(gnl1), 0)

        gnl2 = GeneralNameList([self.dns1])
        gnl2[0] = self.dns2
        self.assertEqual(gnl2, GeneralNameList([self.dns2]))

        gnl3 = GeneralNameList([self.dns1])
        gnl3[0] = dns(self.dns2)
        self.assertEqual(gnl3, GeneralNameList([self.dns2]))

        # but we can only add parseable stuff
        gnl4 = GeneralNameList([self.dns1])
        with self.assertRaisesRegex(TypeError, r"^0/True: Invalid key/value type\.$"):
            gnl4[0] = True  # type: ignore[call-overload] # what we're testing

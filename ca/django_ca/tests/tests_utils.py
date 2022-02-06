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
from cryptography.hazmat.primitives.asymmetric import ed448
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import ObjectIdentifier

import django
from django.core.exceptions import ValidationError
from django.test import TestCase

from freezegun import freeze_time

from .. import ca_settings
from .. import utils
from ..deprecation import RemovedInDjangoCA122Warning
from ..utils import ELLIPTIC_CURVE_NAMES
from ..utils import HASH_ALGORITHM_NAMES
from ..utils import OID_NAME_MAPPINGS
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
from ..utils import parse_name_x509
from ..utils import read_file
from ..utils import shlex_split
from ..utils import split_str
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

    def test_nameoid_completeness(self) -> None:
        """Test that we support all NameOID instances."""
        known_oids = [v for v in vars(NameOID).values() if isinstance(v, x509.ObjectIdentifier)]
        self.assertCountEqual(known_oids, list(OID_NAME_MAPPINGS.keys()))


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


class ParseNameX509TestCase(TestCase):
    """Test :py:func:`django_ca.utils.parse_name_x509`."""

    def assertSubject(  # pylint: disable=invalid-name
        self, actual: str, expected: typing.List[typing.Tuple[ObjectIdentifier, str]]
    ) -> None:
        """Test that the given subject matches."""
        self.assertEqual(parse_name_x509(actual), [x509.NameAttribute(oid, value) for oid, value in expected])

    def test_basic(self) -> None:
        """Some basic tests."""
        self.assertSubject("/CN=example.com", [(NameOID.COMMON_NAME, "example.com")])

        # leading or trailing spaces are always ok.
        self.assertSubject(" /CN = example.com ", [(NameOID.COMMON_NAME, "example.com")])

        # emailAddress is special because of the case
        self.assertSubject("/emailAddress=user@example.com", [(NameOID.EMAIL_ADDRESS, "user@example.com")])

    def test_multiple(self) -> None:
        """Test subject with multiple tokens."""
        self.assertSubject(
            "/C=AT/OU=foo/CN=example.com",
            [
                (NameOID.COUNTRY_NAME, "AT"),
                (NameOID.ORGANIZATIONAL_UNIT_NAME, "foo"),
                (NameOID.COMMON_NAME, "example.com"),
            ],
        )
        self.assertSubject(
            "/C=AT/OU=foo/OU=bar/CN=example.com",
            [
                (NameOID.COUNTRY_NAME, "AT"),
                (NameOID.ORGANIZATIONAL_UNIT_NAME, "foo"),
                (NameOID.ORGANIZATIONAL_UNIT_NAME, "bar"),
                (NameOID.COMMON_NAME, "example.com"),
            ],
        )

    def test_case(self) -> None:
        """Test that case doesn't matter."""
        self.assertSubject(
            "/c=AT/ou=foo/cn=example.com/eMAIladdreSS=user@example.com",
            [
                (NameOID.COUNTRY_NAME, "AT"),
                (NameOID.ORGANIZATIONAL_UNIT_NAME, "foo"),
                (NameOID.COMMON_NAME, "example.com"),
                (NameOID.EMAIL_ADDRESS, "user@example.com"),
            ],
        )

    def test_emtpy(self) -> None:
        """Test empty subjects."""
        self.assertSubject("", [])
        self.assertSubject("   ", [])

    def test_multiple_slashes(self) -> None:
        """Test that we ignore multiple slashes."""
        self.assertSubject("/C=AT/O=GNU", [(NameOID.COUNTRY_NAME, "AT"), (NameOID.ORGANIZATION_NAME, "GNU")])
        self.assertSubject("//C=AT/O=GNU", [(NameOID.COUNTRY_NAME, "AT"), (NameOID.ORGANIZATION_NAME, "GNU")])
        self.assertSubject("/C=AT//O=GNU", [(NameOID.COUNTRY_NAME, "AT"), (NameOID.ORGANIZATION_NAME, "GNU")])
        self.assertSubject(
            "/C=AT///O=GNU", [(NameOID.COUNTRY_NAME, "AT"), (NameOID.ORGANIZATION_NAME, "GNU")]
        )

    def test_empty_field(self) -> None:
        """Test empty fields."""
        self.assertSubject(
            "/C=AT/O=GNU/OU=foo",
            [
                (NameOID.COUNTRY_NAME, "AT"),
                (NameOID.ORGANIZATION_NAME, "GNU"),
                (NameOID.ORGANIZATIONAL_UNIT_NAME, "foo"),
            ],
        )
        self.assertSubject(
            "/C=AT/O=/OU=foo",
            [
                (NameOID.COUNTRY_NAME, "AT"),
                (NameOID.ORGANIZATION_NAME, ""),
                (NameOID.ORGANIZATIONAL_UNIT_NAME, "foo"),
            ],
        )
        self.assertSubject(
            "/C=AT/O=GNU/OU=",
            [
                (NameOID.COUNTRY_NAME, "AT"),
                (NameOID.ORGANIZATION_NAME, "GNU"),
                (NameOID.ORGANIZATIONAL_UNIT_NAME, ""),
            ],
        )
        self.assertSubject(
            "/O=/OU=",
            [
                (NameOID.ORGANIZATION_NAME, ""),
                (NameOID.ORGANIZATIONAL_UNIT_NAME, ""),
            ],
        )

    def test_no_slash_at_start(self) -> None:
        """Test that no slash at start is okay."""
        self.assertSubject("CN=example.com", [(NameOID.COMMON_NAME, "example.com")])

    def test_multiple_ous(self) -> None:
        """Test multiple OUs."""
        self.assertSubject(
            "/C=AT/OU=foo/OU=bar/CN=example.com",
            [
                (NameOID.COUNTRY_NAME, "AT"),
                (NameOID.ORGANIZATIONAL_UNIT_NAME, "foo"),
                (NameOID.ORGANIZATIONAL_UNIT_NAME, "bar"),
                (NameOID.COMMON_NAME, "example.com"),
            ],
        )
        self.assertSubject(
            "/OU=foo/OU=bar",
            [(NameOID.ORGANIZATIONAL_UNIT_NAME, "foo"), (NameOID.ORGANIZATIONAL_UNIT_NAME, "bar")],
        )
        self.assertSubject(
            "/C=AT/O=bla/OU=foo/OU=bar/CN=example.com/",
            [
                (NameOID.COUNTRY_NAME, "AT"),
                (NameOID.ORGANIZATION_NAME, "bla"),
                (NameOID.ORGANIZATIONAL_UNIT_NAME, "foo"),
                (NameOID.ORGANIZATIONAL_UNIT_NAME, "bar"),
                (NameOID.COMMON_NAME, "example.com"),
            ],
        )
        self.assertSubject(
            "/C=AT/O=bla/OU=foo/OU=bar/OU=hugo/CN=example.com/",
            [
                (NameOID.COUNTRY_NAME, "AT"),
                (NameOID.ORGANIZATION_NAME, "bla"),
                (NameOID.ORGANIZATIONAL_UNIT_NAME, "foo"),
                (NameOID.ORGANIZATIONAL_UNIT_NAME, "bar"),
                (NameOID.ORGANIZATIONAL_UNIT_NAME, "hugo"),
                (NameOID.COMMON_NAME, "example.com"),
            ],
        )
        self.assertSubject(
            "/C=AT/DC=com/DC=example/CN=example.com",
            [
                (NameOID.COUNTRY_NAME, "AT"),
                (NameOID.DOMAIN_COMPONENT, "com"),
                (NameOID.DOMAIN_COMPONENT, "example"),
                (NameOID.COMMON_NAME, "example.com"),
            ],
        )

    def test_exotic_name_oids(self) -> None:
        """Test parsing a few of the more exotic names."""
        self.assertSubject(
            "/DC=foo/serialNumber=serial/title=phd",
            [(NameOID.DOMAIN_COMPONENT, "foo"), (NameOID.SERIAL_NUMBER, "serial"), (NameOID.TITLE, "phd")],
        )
        self.assertSubject(
            "/C=AT/DC=foo/serialNumber=serial/CN=example.com/uid=123/title=phd",
            [
                (NameOID.COUNTRY_NAME, "AT"),
                (NameOID.DOMAIN_COMPONENT, "foo"),
                (NameOID.SERIAL_NUMBER, "serial"),
                (NameOID.COMMON_NAME, "example.com"),
                (NameOID.USER_ID, "123"),
                (NameOID.TITLE, "phd"),
            ],
        )

    def test_aliases(self) -> None:
        """Test aliases (commonName vs. CN etc)."""

        self.assertSubject(
            "commonName=example.com/surname=Ertl/userid=0",
            [
                (NameOID.COMMON_NAME, "example.com"),
                (NameOID.SURNAME, "Ertl"),
                (NameOID.USER_ID, "0"),
            ],
        )

    def test_unknown(self) -> None:
        """Test unknown field."""
        field = "ABC"
        with self.assertRaisesRegex(ValueError, "^Unknown x509 name field: ABC$") as e:
            parse_name_x509(f"/{field}=example.com")
        self.assertEqual(e.exception.args, (f"Unknown x509 name field: {field}",))

    def test_deprecation(self) -> None:
        """Test old parse_name() function."""

        with self.assertWarnsRegex(
            RemovedInDjangoCA122Warning,
            r"^parse_name\(\) has been deprecated, use parse_name_x509\(\) instead$",
        ):
            self.assertEqual(parse_name("/CN=example.com"), [("CN", "example.com")])


class RelativeNameTestCase(TestCase):
    """Some tests related to relative names."""

    def test_format(self) -> None:
        """Test formatting..."""
        rdn = x509.RelativeDistinguishedName([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
        with self.assertWarnsRegex(
            RemovedInDjangoCA122Warning, r"^This function is deprecated, use format_name\(\) instead\.$"
        ):
            self.assertEqual(format_relative_name(rdn), "/CN=example.com")

        self.assertEqual(format_name(rdn), "/CN=example.com")

    def test_parse(self) -> None:
        """Test parsing..."""
        expected = x509.RelativeDistinguishedName([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
        self.assertEqual(x509_relative_name("/CN=example.com"), expected)

    def test_deprecated(self) -> None:
        """Test deprecated input values."""
        # pylint: disable=consider-using-f-string
        expected = x509.RelativeDistinguishedName([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
        msg = r"^Passing a %s to x509_relative_name\(\) is deprecated, pass a str instead$"
        with self.assertWarnsRegex(
            RemovedInDjangoCA122Warning, msg % x509.RelativeDistinguishedName.__name__
        ):
            self.assertEqual(x509_relative_name(expected), expected)  # type: ignore[arg-type]
        with self.assertWarnsRegex(RemovedInDjangoCA122Warning, msg % "list"):
            self.assertEqual(x509_relative_name([("CN", "example.com")]), expected)  # type: ignore[arg-type]


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

    def test_key_types(self) -> None:
        """Test generating various private key types."""
        ecc_key = generate_private_key(None, "ECC", ec.BrainpoolP256R1())
        self.assertIsInstance(ecc_key, ec.EllipticCurvePrivateKey)
        self.assertIsInstance(ecc_key.curve, ec.BrainpoolP256R1)

        ed448_key = generate_private_key(None, "Ed448", None)
        self.assertIsInstance(ed448_key, ed448.Ed448PrivateKey)

    def test_invalid_type(self) -> None:
        """Test passing an invalid key type."""
        with self.assertRaisesRegex(ValueError, r"^FOO: Unknown key type$"):
            generate_private_key(16, "FOO", None)  # type: ignore[call-overload]


class ParseGeneralNameTest(TestCase):
    """Test :py:func:`django_ca.utils.parse_general_name`."""

    def assertOtherName(self, typ: str, value: str, expected: bytes) -> None:  # pylint: disable=invalid-name
        """Assert that the otherName of given type and value is parsed to the respective DER encoded value."""
        self.assertEqual(
            parse_general_name(f"otherName:2.5.4.3;{typ}:{value}"),
            x509.OtherName(NameOID.COMMON_NAME, expected),
        )

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
        self.assertOtherName("UTF8", "example", b"\x0c\x07example")
        # try fooling the parser with too many delimiters
        self.assertOtherName("UTF8", "example;wrong:val", b"\x0c\x11example;wrong:val")

        for typ in ("UNIV", "UNIVERSALSTRING"):
            self.assertOtherName(typ, "ex", b"\x1c\x08\x00\x00\x00e\x00\x00\x00x")
        for typ in ("IA5", "IA5STRING"):
            self.assertOtherName(typ, "example", b"\x16\x07example")
        for typ in ("BOOL", "BOOLEAN"):
            for val in ["TRUE", "true", "y", "Y", "YES", "yes"]:
                self.assertOtherName(typ, val, b"\x01\x01\xff")
            for val in ["FALSE", "false", "N", "n", "NO", "no"]:
                self.assertOtherName(typ, val, b"\x01\x01\x00")
        for typ in ("INT", "INTEGER"):
            self.assertOtherName(typ, "0", b"\x02\x01\x00")
            self.assertOtherName(typ, "1", b"\x02\x01\x01")
            self.assertOtherName(typ, "-1", b"\x02\x01\xff")
            self.assertOtherName(typ, "0x123", b"\x02\x02\x01#")
        for typ in ("GENTIME", "GENERALIZEDTIME"):
            self.assertOtherName(typ, "202110052214Z", b"\x18\x0f20211005220104Z")
        for typ in ("UTC", "UTCTIME"):
            self.assertOtherName(typ, "2110052214Z", b"\x17\r211005220104Z")
        self.assertOtherName("NULL", "", b"\x05\x00")

    def test_othername_errors(self) -> None:
        """Test some error conditions."""
        with self.assertRaises(ValueError):
            parse_general_name("otherName:2.5.4.3;UTC:123")
        with self.assertRaisesRegex(
            ValueError, r"^Unsupported BOOL specification for otherName: WRONG: Must be TRUE or FALSE$"
        ):
            parse_general_name("otherName:2.5.4.3;BOOL:WRONG")
        with self.assertRaisesRegex(
            ValueError, r"^Invalid NULL specification for otherName: Value must not be present$"
        ):
            parse_general_name("otherName:2.5.4.3;NULL:VALUE")

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

    def assertFormatParse(self, value: str) -> None:  # pylint: disable=invalid-name
        """Test formatting and then parsing again the given value as common name."""
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value)])
        self.assertEqual(name, x509_name(format_name(name)))

        # Same, but with a different value in front
        name = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "AT"),
                x509.NameAttribute(NameOID.COMMON_NAME, value),
            ]
        )
        self.assertEqual(name, x509_name(format_name(name)))

        # Same, but with a different value at the end
        name = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, value),
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, "user@example.com"),
            ]
        )
        self.assertEqual(name, x509_name(format_name(name)))

        # Same, but with values both before and after the value in question
        name = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "AT"),
                x509.NameAttribute(NameOID.COMMON_NAME, value),
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, "user@example.com"),
            ]
        )
        self.assertEqual(name, x509_name(format_name(name)))

    def test_x509(self) -> None:
        """Test passing a x509.Name."""
        subject = "/C=AT/ST=Vienna/L=Vienna/O=O/OU=OU/CN=example.com/emailAddress=user@example.com"
        name = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "AT"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Vienna"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Vienna"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "O"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "OU"),
                x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, "user@example.com"),
            ]
        )
        self.assertEqual(format_name(name), subject)

    def test_escaping(self) -> None:
        """Test various edge cases when quoting/unquoting strings."""
        self.assertFormatParse("with/slash")
        self.assertFormatParse('with"double-quote')
        self.assertFormatParse("with'single-quote")
        self.assertFormatParse("both'single\"double-quotes")
        self.assertFormatParse("everything: slash/quote'double\"and\\backslash")
        self.assertFormatParse('no single-quote: slash/double"quote')
        self.assertFormatParse('no single-quote but with backslash: slash/double"quote\\backslash')
        self.assertFormatParse("multiple\\\\backslash")

    def test_deprecated(self) -> None:
        """Test passing a deprecated list."""

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
        with self.assertWarnsRegex(
            RemovedInDjangoCA122Warning,
            r"^Passing a list to format_name\(\) is deprecated, pass a str instead$",
        ):
            self.assertEqual(format_name(subject_dict), subject)  # type: ignore[arg-type]


class Power2TestCase(TestCase):
    """Test :py:func:`django_ca.utils.is_power2`."""

    def test_true(self) -> None:
        """Test some numbers that are power of two."""
        for i in range(0, 20):
            self.assertTrue(is_power2(2**i))

    def test_false(self) -> None:
        """Test some numbers that are not power of two."""
        self.assertFalse(is_power2(0))
        self.assertFalse(is_power2(3))
        self.assertFalse(is_power2(5))

        for i in range(2, 20):
            self.assertFalse(is_power2((2**i) - 1))
            self.assertFalse(is_power2((2**i) + 1))


class ParseKeyCurveTestCase(TestCase):
    """Test :py:func:`django_ca.utils.parse_key_curve`."""

    def test_basic(self) -> None:
        """Some basic tests."""
        self.assertIsInstance(parse_key_curve(), ca_settings.CA_DEFAULT_ECC_CURVE)
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
            x509.NameAttribute(NameOID.COUNTRY_NAME, "AT"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Vienna"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Vienna"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "O"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "OU"),
            x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, "user@example.com"),
        ]
    )

    def test_str(self) -> None:
        """Test passing a string."""
        subject = "/C=AT/ST=Vienna/L=Vienna/O=O/OU=OU/CN=example.com/emailAddress=user@example.com"
        self.assertEqual(x509_name(subject), self.name)

    def test_deprecated_tuple(self) -> None:
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
        with self.assertWarnsRegex(
            RemovedInDjangoCA122Warning,
            r"^Passing a list to x509_name\(\) is deprecated, pass a str instead$",
        ):
            self.assertEqual(x509_name(subject), self.name)  # type: ignore[arg-type]

    def test_multiple_other(self) -> None:
        """Test multiple other tokens (only OUs work)."""
        with self.assertRaisesRegex(ValueError, '^Subject contains multiple "C" fields$'):
            x509_name("/C=AT/C=DE")
        with self.assertRaisesRegex(ValueError, '^Subject contains multiple "CN" fields$'):
            x509_name("/CN=AT/CN=FOO")


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
        with self.assertRaises(AttributeError):
            get_cert_builder("a string")  # type: ignore[arg-type]


class ValidateKeyParametersTest(TestCase):
    """Test :py:func:`django_ca.utils.validate_key_parameters`."""

    def test_wrong_values(self) -> None:
        """Test validating various bogus values."""
        with self.assertRaisesRegex(ValueError, "^FOOBAR: Unknown key type$"):
            validate_key_parameters(4096, "FOOBAR")  # type: ignore[arg-type]

        with self.assertRaisesRegex(ValueError, "^4000: Key size must be a power of two$"):
            validate_key_parameters(4000, "RSA")

        with self.assertRaisesRegex(ValueError, "^16: Key size must be least 1024 bits$"):
            validate_key_parameters(16, "RSA")

        with self.assertRaisesRegex(ValueError, r"^secp192r1: Must be a subclass of ec\.EllipticCurve$"):
            validate_key_parameters(16, "ECC", "secp192r1")  # type: ignore[arg-type]  # what we're testing


class SplitStrTestCase(TestCase):
    """Test split_str()."""

    def test_basic(self) -> None:
        """Some basic split_str() test cases."""
        self.assertCountEqual(split_str("foo", "/"), ["foo"])
        self.assertCountEqual(split_str("foo bar", "/"), ["foo bar"])
        self.assertCountEqual(split_str("foo/bar", "/"), ["foo", "bar"])
        self.assertCountEqual(split_str("foo'/'bar", "/"), ["foo/bar"])
        self.assertCountEqual(split_str('foo"/"bar', "/"), ["foo/bar"])
        self.assertCountEqual(split_str("'foo/bar'", "/"), ["foo/bar"])
        self.assertCountEqual(split_str('"foo/bar"', "/"), ["foo/bar"])
        self.assertCountEqual(split_str('"foo/bar"/bla', "/"), ["foo/bar", "bla"])

    def test_start_end_delimiters(self) -> None:
        """Test what happens when the delimiter is at the start/end of the string."""

        self.assertCountEqual(split_str("foo/", "/"), ["foo"])
        self.assertCountEqual(split_str("/foo", "/"), ["foo"])
        self.assertCountEqual(split_str("/foo/", "/"), ["foo"])

        self.assertCountEqual(split_str("foo/bar/", "/"), ["foo", "bar"])
        self.assertCountEqual(split_str("/foo/bar", "/"), ["foo", "bar"])
        self.assertCountEqual(split_str("/foo/bar/", "/"), ["foo", "bar"])
        self.assertCountEqual(split_str("/C=AT/CN=example.com/", "/"), ["C=AT", "CN=example.com"])

    def test_quotes(self) -> None:
        """Test quoting a little bit."""
        self.assertCountEqual(split_str(r"foo/bar", "/"), ["foo", "bar"])
        self.assertCountEqual(split_str(r"foo'/'bar", "/"), ["foo/bar"])
        self.assertCountEqual(split_str(r'foo"/"bar', "/"), ["foo/bar"])
        self.assertCountEqual(split_str(r'fo"o/b"ar', "/"), ["foo/bar"])

        # escape quotes inside quotes
        self.assertCountEqual(split_str(r'"foo\"bar"', "/"), ['foo"bar'])

        # backslash is not interpreted as escape inside single quotes, b/c of shlex.escapedquotes.
        # --> The middle "'" is not special and so the quotation is not closed
        with self.assertRaises(ValueError):
            list(split_str(r"'foo\'bar'", "/"))

    def test_escape(self) -> None:
        """Test the escape char."""

        self.assertCountEqual(split_str(r"foo\/bar", "/"), ["foo/bar"])
        self.assertCountEqual(split_str(r"foo\\/bar", "/"), ["foo\\", "bar"])

        # Escape the double quote - so it has no special meaning
        self.assertCountEqual(split_str(r"foo\"bar", "/"), [r'foo"bar'])
        self.assertCountEqual(split_str(r"foo\"/\"bar", "/"), [r'foo"', '"bar'])

        # both tokens quoted in single quotes:
        self.assertCountEqual(split_str(r"'foo\\'/'bar'", "/"), [r"foo\\", "bar"])

    def test_escaping_non_special_characters(self) -> None:
        """Test how a backslash in front of a non-special character behaves."""

        # Backslash in front of normal character in unquoted string- the backslash is ignored
        self.assertCountEqual(split_str(r"foo\xbar", "/"), ["fooxbar"])

        # Inside a quoted or double-quoted string, single backslash is preserved
        self.assertCountEqual(split_str(r'"foo\xbar"', "/"), [r"foo\xbar"])
        self.assertCountEqual(split_str(r"'foo\xbar'", "/"), [r"foo\xbar"])

        # In a double-quoted string, backslash is interpreted as escape -> single backslash in result
        self.assertCountEqual(split_str(r'"foo\\xbar"', "/"), [r"foo\xbar"])

        # ... but in single quote it's not an escape -> double backslash in result
        self.assertCountEqual(split_str(r"'foo\\xbar'", "/"), [r"foo\\xbar"])

    def test_escaped_delimiters(self) -> None:
        """Test escaping delimiters."""

        # No quotes, single backslash preceeding "/" --> "/" is escaped
        self.assertCountEqual(split_str(r"foo\/bar", "/"), ["foo/bar"])

        # No quotes, but *double* backslash preceeding "/" --> backslash itself is escaped, slash is delimiter
        self.assertCountEqual(split_str(r"foo\\/bar", "/"), ["foo\\", "bar"])

        # With quotes/double quotes, no backslashes -> slash is inside quoted string -> it's not a delimiter
        self.assertCountEqual(split_str('"foo/bar"/bla', "/"), ["foo/bar", "bla"])
        self.assertCountEqual(split_str("'foo/bar'/bla", "/"), ["foo/bar", "bla"])

        # With quotes/double quotes, with one backslash
        self.assertCountEqual(split_str(r'"foo\/bar"/bla', "/"), [r"foo\/bar", "bla"])
        self.assertCountEqual(split_str(r"'foo\/bar'/bla", "/"), [r"foo\/bar", "bla"])

        # With double quotes and a double backslash -> backslash is escape char -> single backslash in result
        self.assertCountEqual(split_str(r'"foo\\/bar"/bla', "/"), [r"foo\/bar", "bla"])

        # With single quotes and a double backslash -> backslash is *not* escape char -> double backslash
        self.assertCountEqual(split_str(r"'foo\\/bar'/bla", "/"), [r"foo\\/bar", "bla"])

    def test_quote_errors(self) -> None:
        """Try messing with some quotation errors."""

        with self.assertRaises(ValueError):
            list(split_str(r"foo'bar", "/"))
        with self.assertRaises(ValueError):
            list(split_str(r'foo"bar', "/"))
        with self.assertRaises(ValueError):
            list(split_str(r"foo'bar/bla", "/"))
        with self.assertRaises(ValueError):
            list(split_str(r'foo"bar/bla', "/"))

    def test_commenters(self) -> None:
        """Test that default comment characters play no special role."""

        self.assertCountEqual(split_str("foo#bar", "/"), ["foo#bar"])
        self.assertCountEqual(split_str("foo/#bar", "/"), ["foo", "#bar"])
        self.assertCountEqual(split_str("foo#/bar", "/"), ["foo#", "bar"])
        self.assertCountEqual(split_str("foo'#'bar", "/"), ["foo#bar"])
        self.assertCountEqual(split_str("'foo#bar'/bla#baz", "/"), ["foo#bar", "bla#baz"])

    def test_wordchars(self) -> None:
        """Test that non-wordchars also work properly."""

        # From the docs: If whitespace_split is set to True, this will have no effect.
        self.assertCountEqual(split_str("foo=bar/what=ever", "/"), ["foo=bar", "what=ever"])

    def test_punctuation_chars(self) -> None:
        """Test that punctuation chars do not affect the parsing.

        We test this here because documentation is not exactly clear about this parameter. But if we pass
        `punctuation_chars=False` to shlex, this test fails, so we test for that too.
        """
        self.assertCountEqual(split_str("foo|bar", "/"), ["foo|bar"])
        self.assertCountEqual(split_str("(foo|bar)/bla/baz(bla", "/"), ["(foo|bar)", "bla", "baz(bla"])
        self.assertCountEqual(split_str("(foo|{b,}ar)/bla/baz(bla", "/"), ["(foo|{b,}ar)", "bla", "baz(bla"])

    def test_shlex_split(self) -> None:
        """Test deprecation for old name."""

        with self.assertWarnsRegex(
            RemovedInDjangoCA122Warning, r"^shlex_split\(\) has been deprecated, use split_str\(\) instead$"
        ):
            self.assertEqual(shlex_split("foo/bar", "/"), ["foo", "bar"])


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

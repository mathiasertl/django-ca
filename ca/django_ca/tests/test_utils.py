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

"""Test utility functions."""

import doctest
import ipaddress
import itertools
import os
import typing
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Iterable, Iterator, Optional, Tuple, Type

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import NameOID, ObjectIdentifier

import django
from django.conf import settings
from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings

from freezegun import freeze_time

from django_ca import ca_settings, constants, utils
from django_ca.tests.base import dns, override_tmpcadir, rdn, uri
from django_ca.utils import (
    bytes_to_hex,
    format_general_name,
    format_name,
    generate_private_key,
    get_cert_builder,
    is_power2,
    merge_x509_names,
    multiline_url_validator,
    parse_encoding,
    parse_general_name,
    parse_hash_algorithm,
    parse_key_curve,
    parse_name_x509,
    read_file,
    serialize_name,
    split_str,
    validate_email,
    validate_hostname,
    validate_private_key_parameters,
    validate_public_key_parameters,
    x509_name,
    x509_relative_name,
)

SuperclassTypeVar = typing.TypeVar("SuperclassTypeVar", bound=Type[object])


def load_tests(  # pylint: disable=unused-argument
    loader: unittest.TestLoader, tests: unittest.TestSuite, ignore: Optional[str] = None
) -> unittest.TestSuite:
    """Load doctests."""
    tests.addTests(doctest.DocTestSuite(utils))
    return tests


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
        self, actual: str, expected: Iterable[Tuple[ObjectIdentifier, str]]
    ) -> None:
        """Test that the given subject matches."""
        self.assertEqual(
            parse_name_x509(actual), tuple(x509.NameAttribute(oid, value) for oid, value in expected)
        )

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
            (
                (NameOID.COMMON_NAME, "example.com"),
                (NameOID.SURNAME, "Ertl"),
                (NameOID.USER_ID, "0"),
            ),
        )

    def test_unknown(self) -> None:
        """Test unknown field."""
        field = "ABC"
        with self.assertRaisesRegex(ValueError, "^Unknown x509 name field: ABC$") as e:
            parse_name_x509(f"/{field}=example.com")
        self.assertEqual(e.exception.args, (f"Unknown x509 name field: {field}",))


class RelativeNameTestCase(TestCase):
    """Some tests related to relative names."""

    def test_format(self) -> None:
        """Test formatting..."""
        val = rdn([(NameOID.COMMON_NAME, "example.com")])
        self.assertEqual(format_name(val), "/CN=example.com")

    def test_parse(self) -> None:
        """Test parsing..."""
        self.assertEqual(x509_relative_name("/CN=example.com"), rdn([(NameOID.COMMON_NAME, "example.com")]))


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
        ec_key = generate_private_key(None, "EC", ec.BrainpoolP256R1())
        self.assertIsInstance(ec_key, ec.EllipticCurvePrivateKey)
        self.assertIsInstance(ec_key.curve, ec.BrainpoolP256R1)

        ed448_key = generate_private_key(None, "Ed448", None)
        self.assertIsInstance(ed448_key, ed448.Ed448PrivateKey)

    def test_dsa_default_key_size(self) -> None:
        """Test the default DSA key size."""

        key = generate_private_key(None, "DSA", None)
        self.assertIsInstance(key, dsa.DSAPrivateKey)
        self.assertEqual(key.key_size, ca_settings.CA_DEFAULT_KEY_SIZE)

    def test_invalid_type(self) -> None:
        """Test passing an invalid key type."""
        with self.assertRaisesRegex(ValueError, r"^FOO: Unknown key type\.$"):
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
        self.assertEqual(parse_general_name("DNS:example.com"), dns("example.com"))
        self.assertEqual(parse_general_name("DNS:.example.com"), dns(".example.com"))

        self.assertEqual(parse_general_name("example.com"), dns("example.com"))
        self.assertEqual(parse_general_name(".example.com"), dns(".example.com"))

    def test_wildcard_domain(self) -> None:
        """Test parsing a wildcard domain."""
        self.assertEqual(parse_general_name("*.example.com"), dns("*.example.com"))
        self.assertEqual(parse_general_name("DNS:*.example.com"), dns("*.example.com"))

        # Wildcard subdomains are allowed in DNS entries, however RFC 2595 limits their use to a single
        # wildcard in the outermost level
        msg = r"^Could not parse name: %s$"

        with self.assertRaisesRegex(ValueError, msg % r"test\.\*\.example\.com"):
            parse_general_name("test.*.example.com")
        with self.assertRaisesRegex(ValueError, msg % r"\*\.\*\.example\.com"):
            parse_general_name("*.*.example.com")
        with self.assertRaisesRegex(ValueError, msg % r"example\.com\.\*"):
            parse_general_name("example.com.*")

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
        self.assertEqual(parse_general_name(url), uri(url))
        self.assertEqual(parse_general_name(f"uri:{url}"), uri(url))

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
            uri("https://xn--exmple-cua.com/test"),
        )
        self.assertEqual(
            parse_general_name("https://exämple.com:8000/test"),
            uri("https://xn--exmple-cua.com:8000/test"),
        )
        self.assertEqual(
            parse_general_name("https://exämple.com:8000/test"),
            uri("https://xn--exmple-cua.com:8000/test"),
        )
        self.assertEqual(
            parse_general_name("uri:https://exämple.com:8000/test"),
            uri("https://xn--exmple-cua.com:8000/test"),
        )

        self.assertEqual(parse_general_name("exämple.com"), dns("xn--exmple-cua.com"))
        self.assertEqual(parse_general_name(".exämple.com"), dns(".xn--exmple-cua.com"))
        self.assertEqual(parse_general_name("*.exämple.com"), dns("*.xn--exmple-cua.com"))
        self.assertEqual(parse_general_name("dns:exämple.com"), dns("xn--exmple-cua.com"))
        self.assertEqual(parse_general_name("dns:.exämple.com"), dns(".xn--exmple-cua.com"))
        self.assertEqual(parse_general_name("dns:*.exämple.com"), dns("*.xn--exmple-cua.com"))

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
        """Try parsing an unparsable IP address (b/c it has a network)."""
        with self.assertRaisesRegex(ValueError, r"^Could not parse IP address\.$"):
            parse_general_name("ip:1.2.3.4/24")

    def test_unparsable(self) -> None:
        """test some unparsable domains."""
        with self.assertRaisesRegex(ValueError, r"^Could not parse name: http://ex ample\.com$"):
            parse_general_name("http://ex ample.com")
        with self.assertRaisesRegex(ValueError, r"^Could not parse DNS name in URL: http://ex ample\.com$"):
            parse_general_name("uri:http://ex ample.com")
        with self.assertRaisesRegex(ValueError, r"^Could not parse DNS name: ex ample\.com"):
            parse_general_name("dns:ex ample.com")
        with self.assertRaisesRegex(
            ValueError, r"^Cannot parse general name False: Must be of type str \(was: bool\)\.$"
        ):
            parse_general_name(False)  # type: ignore[arg-type]  # what we test


class FormatGeneralNameTest(TestCase):
    """Test :py:func:`django_ca.utils.format_general_name`."""

    def test_basic(self) -> None:
        """Some basic tests."""
        self.assertEqual(format_general_name(dns("example.com")), "DNS:example.com")
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

        for cls, name in constants.HASH_ALGORITHM_KEYS.items():
            # variable digest hash algorithms are not supported by this function
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


class SerializeName(TestCase):
    """Test the serialize_name function."""

    def test_name(self) -> None:
        """Test passing a standard Name."""
        self.assertEqual(
            serialize_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])),
            [("CN", "example.com")],
        )
        self.assertEqual(
            serialize_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COUNTRY_NAME, "AT"),
                        x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
                    ]
                )
            ),
            [("C", "AT"), ("CN", "example.com")],
        )

    @unittest.skipIf(settings.CRYPTOGRAPHY_VERSION < (37, 0), "cg<36 does not yet have bytes.")
    def test_bytes(self) -> None:
        """Test names with byte values - probably never happens."""
        name = x509.Name(
            [x509.NameAttribute(NameOID.X500_UNIQUE_IDENTIFIER, b"example.com", _type=_ASN1Type.BitString)]
        )
        self.assertEqual(serialize_name(name), [("x500UniqueIdentifier", "65:78:61:6D:70:6C:65:2E:63:6F:6D")])


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


class ParseEllipticCurveTestCase(TestCase):
    """Test :py:func:`django_ca.utils.parse_key_curve`."""

    def test_basic(self) -> None:
        """Some basic tests."""
        self.assertIsInstance(parse_key_curve("SECT409R1"), ec.SECT409R1)
        self.assertIsInstance(parse_key_curve("SECP521R1"), ec.SECP521R1)
        self.assertIsInstance(parse_key_curve("SECP192R1"), ec.SECP192R1)

        for name, cls in constants.ELLIPTIC_CURVE_TYPES.items():
            self.assertIsInstance(parse_key_curve(name), cls)

    def test_error(self) -> None:
        """Test some error cases."""
        with self.assertRaisesRegex(ValueError, "^FOOBAR: Not a known Elliptic Curve$"):
            parse_key_curve("FOOBAR")

        with self.assertRaisesRegex(ValueError, "^ECDH: Not a known Elliptic Curve$"):
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

    def test_multiple_other(self) -> None:
        """Test multiple other tokens (only OUs work)."""
        with self.assertRaisesRegex(ValueError, '^Subject contains multiple "C" fields$'):
            x509_name("/C=AT/C=DE")
        with self.assertRaisesRegex(ValueError, '^Subject contains multiple "CN" fields$'):
            x509_name("/CN=AT/CN=FOO")


class MergeX509NamesTestCase(TestCase):
    """Test ``django_ca.utils.merge_x509_name``."""

    cc1 = x509.NameAttribute(NameOID.COUNTRY_NAME, "AT")
    cc2 = x509.NameAttribute(NameOID.COUNTRY_NAME, "US")
    org1 = x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Org")
    org2 = x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Other Org")
    ou1 = x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Example Org Unit")
    ou2 = x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Other Org Unit")
    ou3 = x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Example Org Unit2")
    ou4 = x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Other Org Unit2")
    common_name1 = x509.NameAttribute(NameOID.COMMON_NAME, "example.com")
    common_name2 = x509.NameAttribute(NameOID.COMMON_NAME, "example.net")
    email1 = x509.NameAttribute(NameOID.EMAIL_ADDRESS, "user@xample.com")
    email2 = x509.NameAttribute(NameOID.EMAIL_ADDRESS, "user@xample.net")

    def assertMerged(  # pylint: disable=invalid-name  # unittest standard
        self,
        base: Iterable[x509.NameAttribute],
        update: Iterable[x509.NameAttribute],
        merged: Iterable[x509.NameAttribute],
    ) -> None:
        """Assert that the given base and update are merged to the expected value."""
        base_name = x509.Name(base)
        update_name = x509.Name(update)
        merged_name = x509.Name(merged)
        self.assertEqual(merge_x509_names(base_name, update_name), merged_name)

    def test_full_merge(self) -> None:
        """Test a basic merge."""
        # Order here matches the order from ca_settings.CA_DEFAULT_NAME_ORDER
        expected = [self.cc1, self.org1, self.ou1, self.common_name1, self.email1]

        self.assertMerged([self.cc1, self.org1, self.ou1], [self.common_name1, self.email1], expected)
        self.assertMerged([self.cc1, self.org1], [self.ou1, self.common_name1, self.email1], expected)
        self.assertMerged([self.cc1], [self.org1, self.ou1, self.common_name1, self.email1], expected)

    def test_order(self) -> None:
        """Test passing subjects in different order."""
        expected = [self.cc1, self.org1, self.ou1, self.common_name1, self.email1]

        # For-loop for splitting expected between every element
        for i in range(1, len(expected)):
            base = expected[:i]
            update = expected[i:]

            # loop through every possible permutation
            for base_perm in itertools.permutations(base):
                for update_perm in itertools.permutations(update):
                    self.assertMerged(base_perm, update_perm, expected)

    def test_merging_multiple_org_units(self) -> None:
        """Test merging names with multiple org units."""
        expected = [self.cc1, self.org1, self.ou1, self.ou2, self.common_name1]
        self.assertMerged([self.cc1, self.org1, self.ou1, self.ou2], [self.common_name1], expected)
        self.assertMerged([self.cc1, self.org1], [self.common_name1, self.ou1, self.ou2], expected)

    def test_overwriting_attributes(self) -> None:
        """Test overwriting attributes when merging."""
        expected = [self.cc2, self.org2, self.ou3, self.ou4, self.common_name2, self.email2]
        self.assertMerged([self.cc1], expected, expected)
        self.assertMerged([self.cc1, self.ou1], expected, expected)
        self.assertMerged([self.cc1, self.ou1, self.ou2, self.email2, self.common_name1], expected, expected)

    def test_unsortable_values(self) -> None:
        """Test merging unsortable values."""
        sortable = x509.Name([self.cc1, self.common_name1])
        unsortable = x509.Name([self.cc1, x509.NameAttribute(NameOID.INN, "unsortable")])
        with self.assertRaisesRegex(ValueError, r"Unsortable name"):
            merge_x509_names(unsortable, sortable)
        with self.assertRaisesRegex(ValueError, r"Unsortable name"):
            merge_x509_names(sortable, unsortable)


class MultilineURLValidatorTestCase(TestCase):
    """Test :py:func:`django_ca.utils.multiline_url_validator`."""

    @contextmanager
    def assertValidationError(self, value: str) -> Iterator[None]:  # pylint: disable=invalid-name
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


class ValidatePrivateKeyParametersTest(TestCase):
    """Test :py:func:`django_ca.utils.validate_private_key_parameters`."""

    def test_default_parameters(self) -> None:
        """Test that default values are returned"""
        self.assertEqual(
            (ca_settings.CA_DEFAULT_KEY_SIZE, None), validate_private_key_parameters("RSA", None, None)
        )
        self.assertEqual(
            (ca_settings.CA_DEFAULT_KEY_SIZE, None), validate_private_key_parameters("DSA", None, None)
        )

        key_size, elliptic_curve = validate_private_key_parameters("EC", None, None)
        self.assertIsNone(key_size)
        self.assertIsInstance(elliptic_curve, ca_settings.CA_DEFAULT_ELLIPTIC_CURVE)

        self.assertEqual((None, None), validate_private_key_parameters("Ed25519", None, None))
        self.assertEqual((None, None), validate_private_key_parameters("Ed448", None, None))

    def test_valid_parameters(self) -> None:
        """Test valid parameters."""
        self.assertEqual((8192, None), validate_private_key_parameters("RSA", 8192, None))
        self.assertEqual((8192, None), validate_private_key_parameters("DSA", 8192, None))

        key_size, elliptic_curve = validate_private_key_parameters("EC", None, ec.BrainpoolP384R1())
        self.assertIsNone(key_size)
        self.assertIsInstance(elliptic_curve, ec.BrainpoolP384R1)

    def test_wrong_values(self) -> None:
        """Test validating various bogus values."""
        key_size = ca_settings.CA_DEFAULT_KEY_SIZE
        elliptic_curve = ca_settings.CA_DEFAULT_ELLIPTIC_CURVE()
        with self.assertRaisesRegex(ValueError, "^FOOBAR: Unknown key type$"):
            validate_private_key_parameters("FOOBAR", 4096, None)  # type: ignore[call-overload]

        with self.assertRaisesRegex(ValueError, r"^foo: Key size must be an int\.$"):
            validate_private_key_parameters("RSA", "foo", None)  # type: ignore[call-overload]

        with self.assertRaisesRegex(ValueError, "^4000: Key size must be a power of two$"):
            validate_private_key_parameters("RSA", 4000, None)

        with self.assertRaisesRegex(ValueError, "^16: Key size must be least 1024 bits$"):
            validate_private_key_parameters("RSA", 16, None)

        with self.assertRaisesRegex(ValueError, r"^Key size is not supported for EC keys\.$"):
            validate_private_key_parameters("EC", key_size, elliptic_curve)

        with self.assertRaisesRegex(ValueError, r"^secp192r1: Must be a subclass of ec\.EllipticCurve$"):
            validate_private_key_parameters("EC", None, "secp192r1")  # type: ignore

        for key_type in ("Ed448", "Ed25519"):
            with self.assertRaisesRegex(ValueError, rf"^Key size is not supported for {key_type} keys\.$"):
                validate_private_key_parameters(key_type, key_size, None)  # type: ignore
            with self.assertRaisesRegex(
                ValueError, rf"^Elliptic curves are not supported for {key_type} keys\.$"
            ):
                validate_private_key_parameters(key_type, None, elliptic_curve)  # type: ignore


class ValidatePublicKeyParametersTest(TestCase):
    """Test :py:func:`django_ca.utils.validate_public_key_parameters`."""

    def test_valid_parameters(self) -> None:
        """Test valid parameters."""
        for key_type in ("RSA", "DSA", "EC"):
            for algorithm in (hashes.SHA256(), hashes.SHA512()):
                validate_public_key_parameters(key_type, algorithm)  # type: ignore[arg-type]
        for key_type in ("Ed448", "Ed25519"):
            validate_public_key_parameters(key_type, None)  # type: ignore[arg-type]

    def test_invalid_parameters(self) -> None:
        """Test invalid parameters."""
        with self.assertRaisesRegex(ValueError, "^FOOBAR: Unknown key type$"):
            validate_public_key_parameters("FOOBAR", None)  # type: ignore[arg-type]
        for key_type in ("RSA", "DSA", "EC"):
            msg = rf"^{key_type}: algorithm must be an instance of hashes.HashAlgorithm\.$"
            with self.assertRaisesRegex(ValueError, msg):
                validate_public_key_parameters(key_type, True)  # type: ignore[arg-type]

        for key_type in ("Ed448", "Ed25519"):
            msg = rf"^{key_type} keys do not allow an algorithm for signing\.$"
            with self.assertRaisesRegex(ValueError, msg):
                validate_public_key_parameters(key_type, hashes.SHA256())  # type: ignore[arg-type]


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
        """Test quoting."""
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

        # Backslash in front of normal character in unquoted string - the backslash is ignored
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

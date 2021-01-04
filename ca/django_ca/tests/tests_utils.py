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
from contextlib import contextmanager
from datetime import datetime
from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from django.core.exceptions import ValidationError
from django.test import TestCase

from freezegun import freeze_time

from .. import ca_settings
from .. import utils
from ..utils import NAME_RE
from ..utils import GeneralNameList
from ..utils import format_general_name
from ..utils import format_name
from ..utils import format_relative_name
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
from ..utils import x509_relative_name
from .base import DjangoCATestCase
from .base import dns
from .base import override_settings
from .base import override_tmpcadir


def load_tests(loader, tests, ignore):  # pylint: disable=unused-argument
    """Load doctests."""
    tests.addTests(doctest.DocTestSuite(utils))
    return tests


class NameMatchTest(TestCase):
    """Test parsing of names."""

    def match(self, value, expected):
        """Helper function to use NAME_RE."""
        value = [(t[0], t[2]) for t in NAME_RE.findall(value)]
        self.assertEqual(value, expected)

    def test_empty(self):
        """Test parsing an empty subject."""
        self.match('', [])
        self.match(' ', [])
        self.match('  ', [])

    def test_single(self):
        """Test parsing a single token."""
        self.match('C=AT', [('C', 'AT')])
        self.match('C="AT"', [('C', 'AT')])
        self.match('C=" AT "', [('C', 'AT')])

        # test quotes
        self.match('C=" AT \' DE"', [('C', 'AT \' DE')])
        self.match('C=\' AT " DE\'', [('C', 'AT " DE')])

        self.match('C=AT/DE', [('C', 'AT')])  # slash is delimiter when unquoted
        self.match('C="AT/DE"', [('C', 'AT/DE')])
        self.match("C='AT/DE/US'", [('C', 'AT/DE/US')])
        self.match("C='AT/DE'", [('C', 'AT/DE')])
        self.match("C='AT/DE/US'", [('C', 'AT/DE/US')])

        self.match("C='AT \\' DE'", [('C', "AT \\' DE")])

    def test_two(self):
        """Test parsing two tokens."""
        self.match('C=AT/OU=example', [('C', 'AT'), ('OU', 'example')])
        self.match('C="AT"/OU=example', [('C', 'AT'), ('OU', 'example')])
        self.match('C=" AT "/OU=example', [('C', 'AT'), ('OU', 'example')])

        # test quotes
        self.match('C=" AT \' DE"/OU=example', [('C', 'AT \' DE'), ('OU', 'example')])
        self.match('C=\' AT " DE\'/OU=example', [('C', 'AT " DE'), ('OU', 'example')])

        self.match('C="AT/DE"/OU=example', [('C', 'AT/DE'), ('OU', 'example')])
        self.match("C='AT/DE/US'/OU=example", [('C', 'AT/DE/US'), ('OU', 'example')])
        self.match("C='AT/DE'/OU=example", [('C', 'AT/DE'), ('OU', 'example')])
        self.match("C='AT/DE/US'/OU=example", [('C', 'AT/DE/US'), ('OU', 'example')])

        self.match("C='AT \\' DE'/OU=example", [('C', "AT \\' DE"), ('OU', 'example')])

        # now both are quoted
        self.match('C="AT"/OU="ex ample"', [('C', 'AT'), ('OU', 'ex ample')])
        self.match('C=" AT "/OU="ex ample"', [('C', 'AT'), ('OU', 'ex ample')])
        self.match('C=" AT \' DE"/OU="ex ample"', [('C', 'AT \' DE'), ('OU', 'ex ample')])
        self.match('C=\' AT " DE\'/OU="ex ample"', [('C', 'AT " DE'), ('OU', 'ex ample')])
        self.match('C="AT/DE"/OU="ex ample"', [('C', 'AT/DE'), ('OU', 'ex ample')])
        self.match("C='AT/DE/US'/OU='ex ample'", [('C', 'AT/DE/US'), ('OU', 'ex ample')])
        self.match("C='AT/DE'/OU='ex ample'", [('C', 'AT/DE'), ('OU', 'ex ample')])
        self.match("C='AT/DE/US'/OU='ex ample'", [('C', 'AT/DE/US'), ('OU', 'ex ample')])

        self.match("C='AT \\' DE'/OU='ex ample'", [('C', "AT \\' DE"), ('OU', 'ex ample')])

        # Now include a slash in OU
        self.match('C="AT"/OU="ex / ample"', [('C', 'AT'), ('OU', 'ex / ample')])
        self.match('C=" AT "/OU="ex / ample"', [('C', 'AT'), ('OU', 'ex / ample')])
        self.match('C=" AT \' DE"/OU="ex / ample"', [('C', 'AT \' DE'), ('OU', 'ex / ample')])
        self.match('C=\' AT " DE\'/OU="ex / ample"', [('C', 'AT " DE'), ('OU', 'ex / ample')])
        self.match('C="AT/DE"/OU="ex / ample"', [('C', 'AT/DE'), ('OU', 'ex / ample')])
        self.match("C='AT/DE/US'/OU='ex / ample'", [('C', 'AT/DE/US'), ('OU', 'ex / ample')])
        self.match("C='AT/DE'/OU='ex / ample'", [('C', 'AT/DE'), ('OU', 'ex / ample')])
        self.match("C='AT/DE/US'/OU='ex / ample'", [('C', 'AT/DE/US'), ('OU', 'ex / ample')])
        self.match("C='AT \\' DE'/OU='ex / ample'", [('C', "AT \\' DE"), ('OU', 'ex / ample')])

        # Append a slash in the end (It's a delimiter - doesn't influence the output)
        self.match('C="AT"/OU="ex / ample"/', [('C', 'AT'), ('OU', 'ex / ample')])
        self.match('C=" AT "/OU="ex / ample"/', [('C', 'AT'), ('OU', 'ex / ample')])
        self.match('C=" AT \' DE"/OU="ex / ample"/', [('C', 'AT \' DE'), ('OU', 'ex / ample')])
        self.match('C=\' AT " DE\'/OU="ex / ample"/', [('C', 'AT " DE'), ('OU', 'ex / ample')])
        self.match('C="AT/DE"/OU="ex / ample"/', [('C', 'AT/DE'), ('OU', 'ex / ample')])
        self.match("C='AT/DE/US'/OU='ex / ample'/", [('C', 'AT/DE/US'), ('OU', 'ex / ample')])
        self.match("C='AT/DE'/OU='ex / ample'/", [('C', 'AT/DE'), ('OU', 'ex / ample')])
        self.match("C='AT/DE/US'/OU='ex / ample'/", [('C', 'AT/DE/US'), ('OU', 'ex / ample')])
        self.match("C='AT \\' DE'/OU='ex / ample'/", [('C', "AT \\' DE"), ('OU', 'ex / ample')])

    def test_unquoted_slashes(self):
        """Test using unquoted slashes."""
        self.match('C=AT/DE/OU=example', [('C', 'AT'), ('DE/OU', 'example')])
        self.match('C=AT/DE/OU="ex ample"', [('C', 'AT'), ('DE/OU', 'ex ample')])
        self.match('C=AT/DE/OU="ex / ample"', [('C', 'AT'), ('DE/OU', 'ex / ample')])
        self.match('C=AT/DE/OU="ex / ample"/', [('C', 'AT'), ('DE/OU', 'ex / ample')])

    def test_full_examples(self):
        """Test some real examples."""
        expected = [('C', 'AT'), ('ST', 'Vienna'), ('L', 'Loc Fünf'), ('O', 'Org Name'),
                    ('OU', 'Org Unit'), ('CN', 'example.com')]

        self.match('/C=AT/ST=Vienna/L=Loc Fünf/O=Org Name/OU=Org Unit/CN=example.com', expected)
        self.match('/C=AT/ST=Vienna/L="Loc Fünf"/O=\'Org Name\'/OU=Org Unit/CN=example.com', expected)


class ReadFileTestCase(DjangoCATestCase):
    """Test :py:func:`django_ca.utils.read_file`."""

    @override_tmpcadir()
    def test_basic(self):
        """Some basic tests."""
        name = 'test-data'
        path = os.path.join(ca_settings.CA_DIR, name)
        data = b'test data'
        with open(path, 'wb') as stream:
            stream.write(data)

        self.assertEqual(read_file(name), data)
        self.assertEqual(read_file(path), data)

    @override_tmpcadir()
    def test_file_not_found(self):
        """Test reading a file that does not exist."""
        name = 'test-data'
        path = os.path.join(ca_settings.CA_DIR, name)

        msg = r"\[Errno 2\] No such file or directory: u?'%s'" % path
        with self.assertRaisesRegex(FileNotFoundError, msg):
            read_file(str(name))

        with self.assertRaisesRegex(FileNotFoundError, msg):
            read_file(str(path))

    @override_tmpcadir()
    def test_permission_denied(self):
        """Test reading a file when permission is denied."""
        name = 'test-data'
        path = os.path.join(ca_settings.CA_DIR, name)
        data = b'test data'
        with open(path, 'wb') as stream:
            stream.write(data)
        os.chmod(path, 0o000)

        try:
            msg = r"\[Errno 13\] Permission denied: u?'%s'" % path
            with self.assertRaisesRegex(PermissionError, msg):
                read_file(str(name))

            with self.assertRaisesRegex(PermissionError, msg):
                read_file(str(path))
        finally:
            os.chmod(path, 0o600)  # make sure we can delete CA_DIR


class ParseNameTestCase(DjangoCATestCase):
    """Test :py:func:`django_ca.utils.parse_name`."""

    def assertSubject(self, actual, expected):  # pylint: disable=arguments-differ
        self.assertEqual(parse_name(actual), expected)

    def test_basic(self):
        """Some basic tests."""
        self.assertSubject('/CN=example.com', [('CN', 'example.com')])

        # leading or trailing spaces are always ok.
        self.assertSubject(' /CN = example.com ', [('CN', 'example.com')])

        # emailAddress is special because of the case
        self.assertSubject('/emailAddress=user@example.com', [('emailAddress', 'user@example.com')])

    def test_multiple(self):
        """Test subject with multiple tokens."""
        self.assertSubject('/C=AT/OU=foo/CN=example.com', [('C', 'AT'), ('OU', 'foo'), ('CN', 'example.com')])

    def test_case(self):
        """Test that case doesn't matter."""
        self.assertSubject(
            '/c=AT/ou=foo/cn=example.com/eMAIladdreSS=user@example.com',
            [('C', 'AT'), ('OU', 'foo'), ('CN', 'example.com'), ('emailAddress', 'user@example.com')])

    def test_emtpy(self):
        """Test empty subjects."""
        self.assertSubject('', [])
        self.assertSubject('   ', [])

    def test_multiple_slashes(self):
        """Test that we ignore multiple slashes."""
        self.assertSubject('/C=AT/O=GNU', [('C', 'AT'), ('O', 'GNU')])
        self.assertSubject('//C=AT/O=GNU', [('C', 'AT'), ('O', 'GNU')])
        self.assertSubject('/C=AT//O=GNU', [('C', 'AT'), ('O', 'GNU')])
        self.assertSubject('/C=AT///O=GNU', [('C', 'AT'), ('O', 'GNU')])

    def test_empty_field(self):
        """Test empty fields."""
        self.assertSubject('/C=AT/O=GNU/OU=foo', [('C', 'AT'), ('O', 'GNU'), ('OU', 'foo')])
        self.assertSubject('/C=/O=GNU/OU=foo', [('C', ''), ('O', 'GNU'), ('OU', 'foo')])
        self.assertSubject('/C=AT/O=/OU=foo', [('C', 'AT'), ('O', ''), ('OU', 'foo')])
        self.assertSubject('/C=AT/O=GNU/OU=', [('C', 'AT'), ('O', 'GNU'), ('OU', '')])
        self.assertSubject('/C=/O=/OU=', [('C', ''), ('O', ''), ('OU', '')])

    def test_no_slash_at_start(self):
        """Test that no slash at start is okay."""
        self.assertSubject('CN=example.com', [('CN', 'example.com')])

    def test_multiple_ous(self):
        """Test multiple OUs."""
        self.assertSubject('/OU=foo/OU=bar', [('OU', 'foo'), ('OU', 'bar')])
        self.assertSubject('/C=AT/O=bla/OU=foo/OU=bar/CN=example.com/',
                           [('C', 'AT'), ('O', 'bla'), ('OU', 'foo'), ('OU', 'bar'), ('CN', 'example.com')])
        self.assertSubject('/C=AT/O=bla/OU=foo/OU=bar/OU=hugo/CN=example.com/',
                           [('C', 'AT'), ('O', 'bla'), ('OU', 'foo'), ('OU', 'bar'), ('OU', 'hugo'),
                            ('CN', 'example.com')])

    def test_multiple_other(self):
        """Test multiple other tokens (only OUs work)."""
        with self.assertRaisesRegex(ValueError, '^Subject contains multiple "C" fields$'):
            parse_name('/C=AT/C=FOO')
        with self.assertRaisesRegex(ValueError, '^Subject contains multiple "CN" fields$'):
            parse_name('/CN=AT/CN=FOO')

    def test_unknown(self):
        """Test unknown field."""
        field = 'ABC'
        with self.assertRaisesRegex(ValueError, '^Unknown x509 name field: ABC$') as e:
            parse_name('/%s=example.com' % field)
        self.assertEqual(e.exception.args, ('Unknown x509 name field: %s' % field, ))


class RelativeNameTestCase(TestCase):
    """Some tests related to relative names."""

    def test_format(self):
        """Test formatting..."""
        rdn = x509.RelativeDistinguishedName([x509.NameAttribute(NameOID.COMMON_NAME, 'example.com')])
        self.assertEqual(format_relative_name([('C', 'AT'), ('CN', 'example.com')]), '/C=AT/CN=example.com')
        self.assertEqual(format_relative_name(rdn), '/CN=example.com')

    def test_parse(self):
        """Test parsing..."""
        expected = x509.RelativeDistinguishedName([x509.NameAttribute(NameOID.COMMON_NAME, 'example.com')])
        self.assertEqual(x509_relative_name('/CN=example.com'), expected)
        self.assertEqual(x509_relative_name([('CN', 'example.com')]), expected)


class ValidateEmailTestCase(DjangoCATestCase):
    """Test :py:func:`django_ca.utils.validate_email`."""

    def test_basic(self):
        """Some basic tests."""
        self.assertEqual(validate_email('user@example.com'), 'user@example.com')

    def test_i18n(self):
        """Test i18n domain."""
        self.assertEqual(validate_email('user@exämple.com'), 'user@xn--exmple-cua.com')

    def test_invalid_domain(self):
        """Test with an invalid domain."""
        with self.assertRaisesRegex(ValueError, '^Invalid domain: example.com$'):
            validate_email('user@example com')

    def test_no_at(self):
        """Test without "@"."""
        with self.assertRaisesRegex(ValueError, '^Invalid email address: user$'):
            validate_email('user')

        with self.assertRaisesRegex(ValueError, '^Invalid email address: example.com$'):
            validate_email('example.com')


class ValidateHostnameTestCase(TestCase):
    """Test :py:func:`django_ca.utils.validate_hostname`."""

    def test_no_port(self):
        """Test with no port."""
        self.assertEqual(validate_hostname('localhost'), 'localhost')
        self.assertEqual(validate_hostname('testserver'), 'testserver')
        self.assertEqual(validate_hostname('example.com'), 'example.com')
        self.assertEqual(validate_hostname('test.example.com'), 'test.example.com')

    def test_with_port(self):
        """Test with a port."""
        self.assertEqual(validate_hostname('localhost:443', allow_port=True), 'localhost:443')
        self.assertEqual(validate_hostname('testserver:443', allow_port=True), 'testserver:443')
        self.assertEqual(validate_hostname('example.com:443', allow_port=True), 'example.com:443')
        self.assertEqual(validate_hostname('test.example.com:443', allow_port=True), 'test.example.com:443')
        self.assertEqual(validate_hostname('test.example.com:1', allow_port=True), 'test.example.com:1')
        self.assertEqual(validate_hostname('example.com:65535', allow_port=True), 'example.com:65535')

    def test_invalid_hostname(self):
        """Test with an invalid hostname."""
        with self.assertRaisesRegex(ValueError, 'example..com: Not a valid hostname'):
            validate_hostname('example..com')

    def test_no_allow_port(self):
        """Test passing a port when it's not allowed."""
        with self.assertRaisesRegex(ValueError, '^localhost:443: Not a valid hostname$'):
            validate_hostname('localhost:443')
        with self.assertRaisesRegex(ValueError, '^test.example.com:443: Not a valid hostname$'):
            validate_hostname('test.example.com:443')

    def test_port_errors(self):
        """Test passing an invalid port."""
        with self.assertRaisesRegex(ValueError, '^no-int: Port must be an integer$'):
            validate_hostname('localhost:no-int', allow_port=True)
        with self.assertRaisesRegex(ValueError, '^0: Port must be between 1 and 65535$'):
            validate_hostname('localhost:0', allow_port=True)
        with self.assertRaisesRegex(ValueError, '^-5: Port must be between 1 and 65535$'):
            validate_hostname('localhost:-5', allow_port=True)
        with self.assertRaisesRegex(ValueError, '^65536: Port must be between 1 and 65535$'):
            validate_hostname('localhost:65536', allow_port=True)
        with self.assertRaisesRegex(ValueError, '^100000: Port must be between 1 and 65535$'):
            validate_hostname('localhost:100000', allow_port=True)
        with self.assertRaisesRegex(ValueError, '^colon: Port must be an integer$'):
            validate_hostname('localhost:double:colon', allow_port=True)


class ParseGeneralNameTest(TestCase):
    """Test :py:func:`django_ca.utils.parse_general_name`."""

    def test_ipv4(self):
        """Test parsing an IPv4 address."""
        self.assertEqual(parse_general_name('1.2.3.4'), x509.IPAddress(ipaddress.ip_address('1.2.3.4')))
        self.assertEqual(parse_general_name('ip:1.2.3.4'), x509.IPAddress(ipaddress.ip_address('1.2.3.4')))

    def test_ipv4_network(self):
        """Test parsing an IPv4 network."""
        self.assertEqual(parse_general_name('1.2.3.0/24'),
                         x509.IPAddress(ipaddress.ip_network('1.2.3.0/24')))
        self.assertEqual(parse_general_name('ip:1.2.3.0/24'),
                         x509.IPAddress(ipaddress.ip_network('1.2.3.0/24')))

    def test_ipv6(self):
        """Test parsing an IPv6 address."""
        self.assertEqual(parse_general_name('fd00::32'), x509.IPAddress(ipaddress.ip_address('fd00::32')))
        self.assertEqual(parse_general_name('ip:fd00::32'), x509.IPAddress(ipaddress.ip_address('fd00::32')))

    def test_ipv6_network(self):
        """Test parsing an IPv6 network,"""
        self.assertEqual(parse_general_name('fd00::0/32'),
                         x509.IPAddress(ipaddress.ip_network('fd00::0/32')))
        self.assertEqual(parse_general_name('ip:fd00::0/32'),
                         x509.IPAddress(ipaddress.ip_network('fd00::0/32')))

    def test_domain(self):
        """Test parsing a domain."""
        self.assertEqual(parse_general_name('DNS:example.com'), x509.DNSName('example.com'))
        self.assertEqual(parse_general_name('DNS:.example.com'), x509.DNSName('.example.com'))

        self.assertEqual(parse_general_name('example.com'), x509.DNSName('example.com'))
        self.assertEqual(parse_general_name('.example.com'), x509.DNSName('.example.com'))

    def test_wildcard_domain(self):
        """Test parsing a wildcard domain."""
        self.assertEqual(parse_general_name('*.example.com'), x509.DNSName('*.example.com'))
        self.assertEqual(parse_general_name('DNS:*.example.com'), x509.DNSName('*.example.com'))

        # Wildcard subdomains are allowed in DNS entries, however RFC 2595 limits their use to a single
        # wildcard in the outermost level
        msg = r'^Could not parse name: %s$'

        with self.assertRaisesRegex(ValueError, msg % r'test\.\*\.example\.com'):
            parse_general_name('test.*.example.com')
        with self.assertRaisesRegex(ValueError, msg % r'\*\.\*\.example\.com'):
            parse_general_name('*.*.example.com')
        with self.assertRaisesRegex(ValueError, msg % r'example\.com\.\*'):
            parse_general_name('example.com.*')

    def test_dirname(self):
        """Test parsing a dirname."""
        self.assertEqual(parse_general_name('/CN=example.com'), x509.DirectoryName(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'example.com'),
        ])))
        self.assertEqual(parse_general_name('dirname:/CN=example.com'), x509.DirectoryName(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'example.com'),
        ])))
        self.assertEqual(parse_general_name('dirname:/C=AT/CN=example.com'), x509.DirectoryName(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, 'AT'),
            x509.NameAttribute(NameOID.COMMON_NAME, 'example.com'),
        ])))

    def test_uri(self):
        """Test parsing a URI."""
        url = 'https://example.com'
        self.assertEqual(parse_general_name(url), x509.UniformResourceIdentifier(url))
        self.assertEqual(parse_general_name('uri:%s' % url), x509.UniformResourceIdentifier(url))

    def test_rid(self):
        """Test parsing a Registered ID."""
        self.assertEqual(parse_general_name('rid:2.5.4.3'), x509.RegisteredID(NameOID.COMMON_NAME))

    def test_othername(self):
        """Test parsing an otherName name."""
        self.assertEqual(parse_general_name('otherName:2.5.4.3;UTF8:example.com'), x509.OtherName(
            NameOID.COMMON_NAME, b'example.com'
        ))

    def test_unicode_domains(self):
        """Test some unicode domains."""
        self.assertEqual(parse_general_name('https://exämple.com/test'),
                         x509.UniformResourceIdentifier('https://xn--exmple-cua.com/test'))
        self.assertEqual(parse_general_name('https://exämple.com:8000/test'),
                         x509.UniformResourceIdentifier('https://xn--exmple-cua.com:8000/test'))
        self.assertEqual(parse_general_name('https://exämple.com:8000/test'),
                         x509.UniformResourceIdentifier('https://xn--exmple-cua.com:8000/test'))
        self.assertEqual(parse_general_name('uri:https://exämple.com:8000/test'),
                         x509.UniformResourceIdentifier('https://xn--exmple-cua.com:8000/test'))

        self.assertEqual(parse_general_name('exämple.com'), x509.DNSName('xn--exmple-cua.com'))
        self.assertEqual(parse_general_name('.exämple.com'), x509.DNSName('.xn--exmple-cua.com'))
        self.assertEqual(parse_general_name('*.exämple.com'), x509.DNSName('*.xn--exmple-cua.com'))
        self.assertEqual(parse_general_name('dns:exämple.com'), x509.DNSName('xn--exmple-cua.com'))
        self.assertEqual(parse_general_name('dns:.exämple.com'), x509.DNSName('.xn--exmple-cua.com'))
        self.assertEqual(parse_general_name('dns:*.exämple.com'), x509.DNSName('*.xn--exmple-cua.com'))

    def test_wrong_email(self):
        """Test using an invalid email."""
        with self.assertRaisesRegex(ValueError, r'^Could not parse name: user@$'):
            parse_general_name('user@')

        with self.assertRaisesRegex(ValueError, '^Invalid domain: $'):
            parse_general_name('email:user@')

    def test_othername_octetstring(self):
        """Test an octet string."""
        self.assertEqual(parse_general_name(
                         'otherName:1.3.6.1.4.1.311.25.1;OctetString:09CFF1A8F6DEFD4B85CE95FFA1B54217'),
                         x509.OtherName(
                         x509.oid.ObjectIdentifier('1.3.6.1.4.1.311.25.1'),
                         b'\x04\x10\t\xcf\xf1\xa8\xf6\xde\xfdK\x85\xce\x95\xff\xa1\xb5B\x17'))

        with self.assertRaisesRegex(ValueError, '^Incorrect otherName format: foobar$'):
            parse_general_name('otherName:foobar')

        with self.assertRaisesRegex(ValueError, '^Unsupported ASN type in otherName: MagicString$'):
            parse_general_name('otherName:1.2.3;MagicString:Broken')

    def test_error(self):
        """Try parsing an unparseable IP address (b/c it has a network)."""
        with self.assertRaisesRegex(ValueError, r'^Could not parse IP address\.$'):
            parse_general_name('ip:1.2.3.4/24')

    def test_unparseable(self):
        """test some unparseable domains."""
        with self.assertRaisesRegex(ValueError, r'^Could not parse name: http://ex ample\.com$'):
            parse_general_name('http://ex ample.com')
        with self.assertRaisesRegex(ValueError, r'^Could not parse DNS name in URL: http://ex ample\.com$'):
            parse_general_name('uri:http://ex ample.com')
        with self.assertRaisesRegex(ValueError, r'^Could not parse DNS name: ex ample\.com'):
            parse_general_name('dns:ex ample.com')


class FormatGeneralNameTest(TestCase):
    """Test :py:func:`django_ca.utils.format_general_name`."""

    def test_basic(self):
        """Some basic tests."""
        self.assertEqual(format_general_name(x509.DNSName('example.com')), 'DNS:example.com')
        self.assertEqual(format_general_name(x509.IPAddress(ipaddress.IPv4Address('127.0.0.1'))),
                         'IP:127.0.0.1')

    def test_dirname(self):
        """Test formatting a dirname."""
        name = x509.DirectoryName(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, 'AT'),
            x509.NameAttribute(NameOID.COMMON_NAME, 'example.com'),
        ]))
        self.assertEqual(format_general_name(name), 'dirname:/C=AT/CN=example.com')


class ParseHashAlgorithm(TestCase):
    """Test :py:func:`django_ca.utils.parse_hash_algorithm`."""

    def test_basic(self):
        """Some basic tests."""
        self.assertIsInstance(parse_hash_algorithm(), hashes.SHA512)
        self.assertIsInstance(parse_hash_algorithm(hashes.SHA512), hashes.SHA512)
        self.assertIsInstance(parse_hash_algorithm(hashes.SHA512()), hashes.SHA512)
        self.assertIsInstance(parse_hash_algorithm('SHA512'), hashes.SHA512)

        with self.assertRaisesRegex(ValueError, '^Unknown hash algorithm: foo$'):
            parse_hash_algorithm('foo')

        with self.assertRaisesRegex(ValueError, '^Unknown type passed: bool$'):
            parse_hash_algorithm(False)


class FormatNameTestCase(TestCase):
    """Test :py:func:`django_ca.utils.format_name`."""

    def test_basic(self):
        """Some basic tests."""
        subject = '/C=AT/ST=Vienna/L=Vienna/O=O/OU=OU/CN=example.com/emailAddress=user@example.com'

        subject_dict = [('C', 'AT'), ('ST', 'Vienna'), ('L', 'Vienna'), ('O', 'O'), ('OU', 'OU'),
                        ('CN', 'example.com'), ('emailAddress', 'user@example.com'), ]
        self.assertEqual(format_name(subject_dict), subject)


class Power2TestCase(TestCase):
    """Test :py:func:`django_ca.utils.is_power2`."""

    def test_true(self):
        """Test some numbers that are power of two."""
        for i in range(0, 20):
            self.assertTrue(is_power2(2 ** i))

    def test_false(self):
        """Test some numbers that are not power of two."""
        self.assertFalse(is_power2(0))
        self.assertFalse(is_power2(3))
        self.assertFalse(is_power2(5))

        for i in range(2, 20):
            self.assertFalse(is_power2((2 ** i) - 1))
            self.assertFalse(is_power2((2 ** i) + 1))


class ParseKeyCurveTestCase(TestCase):
    """Test :py:func:`django_ca.utils.parse_key_curve`."""

    def test_basic(self):
        """Some basic tests."""
        self.assertIsInstance(parse_key_curve(), type(ca_settings.CA_DEFAULT_ECC_CURVE))
        self.assertIsInstance(parse_key_curve('SECT409R1'), ec.SECT409R1)
        self.assertIsInstance(parse_key_curve('SECP521R1'), ec.SECP521R1)
        self.assertIsInstance(parse_key_curve('SECP192R1'), ec.SECP192R1)

    def test_error(self):
        """Test some error cases."""
        with self.assertRaisesRegex(ValueError, '^FOOBAR: Not a known Eliptic Curve$'):
            parse_key_curve('FOOBAR')

        with self.assertRaisesRegex(ValueError, '^ECDH: Not a known Eliptic Curve$'):
            parse_key_curve('ECDH')  # present in the module, but *not* an EllipticCurve


class ParseEncodingTestCase(TestCase):
    """Test :py:func:`django_ca.utils.parse_encoding`."""

    def test_basic(self):
        """Some basic tests."""
        self.assertEqual(parse_encoding(), Encoding.PEM)
        self.assertEqual(parse_encoding('PEM'), Encoding.PEM)
        self.assertEqual(parse_encoding(Encoding.PEM), Encoding.PEM)

        self.assertEqual(parse_encoding('DER'), Encoding.DER)
        self.assertEqual(parse_encoding('ASN1'), Encoding.DER)
        self.assertEqual(parse_encoding(Encoding.DER), Encoding.DER)

        self.assertEqual(parse_encoding('OpenSSH'), Encoding.OpenSSH)
        self.assertEqual(parse_encoding(Encoding.OpenSSH), Encoding.OpenSSH)

    def test_error(self):
        """Test some error cases."""
        with self.assertRaisesRegex(ValueError, '^Unknown encoding: foo$'):
            parse_encoding('foo')

        with self.assertRaisesRegex(ValueError, '^Unknown type passed: bool$'):
            parse_encoding(True)


class AddColonsTestCase(TestCase):
    """Test :py:func:`django_ca.utils.add_colons`."""

    def test_basic(self):
        """Some basic tests."""
        self.assertEqual(utils.add_colons(''), '')
        self.assertEqual(utils.add_colons('a'), '0a')
        self.assertEqual(utils.add_colons('ab'), 'ab')
        self.assertEqual(utils.add_colons('abc'), '0a:bc')
        self.assertEqual(utils.add_colons('abcd'), 'ab:cd')
        self.assertEqual(utils.add_colons('abcde'), '0a:bc:de')
        self.assertEqual(utils.add_colons('abcdef'), 'ab:cd:ef')
        self.assertEqual(utils.add_colons('abcdefg'), '0a:bc:de:fg')

    def test_pad(self):
        """Test padding."""
        self.assertEqual(utils.add_colons('a', pad='z'), 'za')
        self.assertEqual(utils.add_colons('ab', pad='z'), 'ab')
        self.assertEqual(utils.add_colons('abc', pad='z'), 'za:bc')

    def test_no_pad(self):
        """Test disabling padding."""
        self.assertEqual(utils.add_colons('a', pad=None), 'a')
        self.assertEqual(utils.add_colons('ab', pad=None), 'ab')
        self.assertEqual(utils.add_colons('abc', pad=None), 'ab:c')

    def test_zero_padding(self):
        """Test when there is no padding."""
        self.assertEqual(
            utils.add_colons('F570A555BC5000FA301E8C75FFB31684FCF64436'),
            'F5:70:A5:55:BC:50:00:FA:30:1E:8C:75:FF:B3:16:84:FC:F6:44:36'
        )
        self.assertEqual(
            utils.add_colons('85BDA79A857379A4C9E910DAEA21C896D16394'),
            '85:BD:A7:9A:85:73:79:A4:C9:E9:10:DA:EA:21:C8:96:D1:63:94'
        )


class IntToHexTestCase(TestCase):
    """Test :py:func:`django_ca.utils.int_to_hex`."""

    def test_basic(self):
        """Test the first view numbers."""
        self.assertEqual(utils.int_to_hex(0), '0')
        self.assertEqual(utils.int_to_hex(1), '1')
        self.assertEqual(utils.int_to_hex(2), '2')
        self.assertEqual(utils.int_to_hex(3), '3')
        self.assertEqual(utils.int_to_hex(4), '4')
        self.assertEqual(utils.int_to_hex(5), '5')
        self.assertEqual(utils.int_to_hex(6), '6')
        self.assertEqual(utils.int_to_hex(7), '7')
        self.assertEqual(utils.int_to_hex(8), '8')
        self.assertEqual(utils.int_to_hex(9), '9')
        self.assertEqual(utils.int_to_hex(10), 'A')
        self.assertEqual(utils.int_to_hex(11), 'B')
        self.assertEqual(utils.int_to_hex(12), 'C')
        self.assertEqual(utils.int_to_hex(13), 'D')
        self.assertEqual(utils.int_to_hex(14), 'E')
        self.assertEqual(utils.int_to_hex(15), 'F')
        self.assertEqual(utils.int_to_hex(16), '10')
        self.assertEqual(utils.int_to_hex(17), '11')
        self.assertEqual(utils.int_to_hex(18), '12')
        self.assertEqual(utils.int_to_hex(19), '13')
        self.assertEqual(utils.int_to_hex(20), '14')
        self.assertEqual(utils.int_to_hex(21), '15')
        self.assertEqual(utils.int_to_hex(22), '16')
        self.assertEqual(utils.int_to_hex(23), '17')
        self.assertEqual(utils.int_to_hex(24), '18')
        self.assertEqual(utils.int_to_hex(25), '19')
        self.assertEqual(utils.int_to_hex(26), '1A')
        self.assertEqual(utils.int_to_hex(27), '1B')
        self.assertEqual(utils.int_to_hex(28), '1C')
        self.assertEqual(utils.int_to_hex(29), '1D')
        self.assertEqual(utils.int_to_hex(30), '1E')
        self.assertEqual(utils.int_to_hex(31), '1F')
        self.assertEqual(utils.int_to_hex(32), '20')
        self.assertEqual(utils.int_to_hex(33), '21')
        self.assertEqual(utils.int_to_hex(34), '22')
        self.assertEqual(utils.int_to_hex(35), '23')
        self.assertEqual(utils.int_to_hex(36), '24')
        self.assertEqual(utils.int_to_hex(37), '25')
        self.assertEqual(utils.int_to_hex(38), '26')
        self.assertEqual(utils.int_to_hex(39), '27')
        self.assertEqual(utils.int_to_hex(40), '28')
        self.assertEqual(utils.int_to_hex(41), '29')
        self.assertEqual(utils.int_to_hex(42), '2A')
        self.assertEqual(utils.int_to_hex(43), '2B')
        self.assertEqual(utils.int_to_hex(44), '2C')
        self.assertEqual(utils.int_to_hex(45), '2D')
        self.assertEqual(utils.int_to_hex(46), '2E')
        self.assertEqual(utils.int_to_hex(47), '2F')
        self.assertEqual(utils.int_to_hex(48), '30')
        self.assertEqual(utils.int_to_hex(49), '31')

    def test_high(self):
        """Test some high numbers."""
        self.assertEqual(utils.int_to_hex(1513282098), '5A32DA32')
        self.assertEqual(utils.int_to_hex(1513282099), '5A32DA33')
        self.assertEqual(utils.int_to_hex(1513282100), '5A32DA34')
        self.assertEqual(utils.int_to_hex(1513282101), '5A32DA35')
        self.assertEqual(utils.int_to_hex(1513282102), '5A32DA36')
        self.assertEqual(utils.int_to_hex(1513282103), '5A32DA37')
        self.assertEqual(utils.int_to_hex(1513282104), '5A32DA38')
        self.assertEqual(utils.int_to_hex(1513282105), '5A32DA39')
        self.assertEqual(utils.int_to_hex(1513282106), '5A32DA3A')
        self.assertEqual(utils.int_to_hex(1513282107), '5A32DA3B')
        self.assertEqual(utils.int_to_hex(1513282108), '5A32DA3C')
        self.assertEqual(utils.int_to_hex(1513282109), '5A32DA3D')
        self.assertEqual(utils.int_to_hex(1513282110), '5A32DA3E')
        self.assertEqual(utils.int_to_hex(1513282111), '5A32DA3F')
        self.assertEqual(utils.int_to_hex(1513282112), '5A32DA40')
        self.assertEqual(utils.int_to_hex(1513282113), '5A32DA41')


class SanitizeSerialTestCase(TestCase):
    """Test :py:func:`~django_ca.utils.sanitize_serial`."""

    def test_already_sanitized(self):
        """Test some already sanitized input."""
        self.assertEqual(utils.sanitize_serial('A'), 'A')
        self.assertEqual(utils.sanitize_serial('5A32DA3B'), '5A32DA3B')
        self.assertEqual(utils.sanitize_serial('1234567890ABCDEF'), '1234567890ABCDEF')

    def test_sanitized(self):
        """Test some input that can be correctly sanitized."""
        self.assertEqual(utils.sanitize_serial('5A:32:DA:3B'), '5A32DA3B')
        self.assertEqual(utils.sanitize_serial('0A:32:DA:3B'), 'A32DA3B')
        self.assertEqual(utils.sanitize_serial('0a:32:da:3b'), 'A32DA3B')

    def test_zero(self):
        """An imported CA might have a serial of just a ``0``, so it must not be stripped."""
        self.assertEqual(utils.sanitize_serial('0'), '0')

    def test_invalid_input(self):
        """Test some input that raises an exception."""

        with self.assertRaisesRegex(ValueError, r'^ABCXY: Serial has invalid characters$'):
            utils.sanitize_serial('ABCXY')


class MultilineURLValidatorTestCase(TestCase):
    """Test :py:func:`django_ca.utils.multiline_url_validator`."""

    def test_basic(self):
        """Basic working tests."""
        multiline_url_validator('')
        multiline_url_validator('http://example.com')
        multiline_url_validator('http://example.com\nhttp://www.example.org')
        multiline_url_validator('''http://example.com\nhttp://www.example.org
http://www.example.net''')

    def test_error(self):
        """Test various invalid cases."""
        with self.assertRaises(ValidationError) as e:
            multiline_url_validator('foo')
        self.assertEqual(e.exception.args, ('Enter a valid URL.', 'invalid', None))

        with self.assertRaises(ValidationError):
            multiline_url_validator('foo\nhttp://www.example.com')
        self.assertEqual(e.exception.args, ('Enter a valid URL.', 'invalid', None))

        with self.assertRaises(ValidationError):
            multiline_url_validator('http://www.example.com\nfoo')
        self.assertEqual(e.exception.args, ('Enter a valid URL.', 'invalid', None))

        with self.assertRaises(ValidationError):
            multiline_url_validator('http://www.example.com\nfoo\nhttp://example.org')
        self.assertEqual(e.exception.args, ('Enter a valid URL.', 'invalid', None))


class GetCertBuilderTestCase(DjangoCATestCase):
    """Test :py:func:`django_ca.utils.get_cert_builder`."""

    def parse_date(self, date):
        """Helper to parse a date."""
        return datetime.strptime(date, '%Y%m%d%H%M%SZ')

    @freeze_time('2018-11-03 11:21:33')
    @override_settings(CA_DEFAULT_EXPIRES=100)
    def test_basic(self):
        """Basic tests."""

        # pylint: disable=protected-access; only way to test builder attributes
        after = datetime(2020, 10, 23, 11, 21)
        before = datetime(2018, 11, 3, 11, 21)
        builder = get_cert_builder(timedelta(days=720))
        self.assertEqual(builder._not_valid_after, after)
        self.assertEqual(builder._not_valid_before, before)
        self.assertIsInstance(builder._serial_number, int)

        builder = get_cert_builder(None)
        self.assertEqual(builder._not_valid_after, datetime(2019, 2, 11, 11, 21))
        self.assertEqual(builder._not_valid_before, before)  # before shouldn't change
        self.assertIsInstance(builder._serial_number, int)

    @freeze_time('2018-11-03 11:21:33')
    def test_negative(self):
        """Test passing a date in the past."""
        with self.assertRaisesRegex(ValueError,
                                    r'^The not valid after date must be after the not valid before date\.$'):
            get_cert_builder(datetime(2017, 12, 12))


class ValidateKeyParametersTest(TestCase):
    """Test :py:func:`django_ca.utils.validate_key_parameters`."""

    def test_basic(self):
        """Some basic tests."""
        self.assertEqual(validate_key_parameters(), (ca_settings.CA_DEFAULT_KEY_SIZE, 'RSA', None))
        self.assertEqual(validate_key_parameters(key_type=None),
                         (ca_settings.CA_DEFAULT_KEY_SIZE, 'RSA', None))

    def test_wrong_values(self):
        """Test validating various bogus values."""
        with self.assertRaisesRegex(ValueError, '^FOOBAR: Unknown key type$'):
            validate_key_parameters(4096, 'FOOBAR')

        with self.assertRaisesRegex(ValueError, '^4000: Key size must be a power of two$'):
            validate_key_parameters(4000, 'RSA')

        with self.assertRaisesRegex(ValueError, '^16: Key size must be least 1024 bits$'):
            validate_key_parameters(16, 'RSA')


class GeneralNameListTestCase(DjangoCATestCase):
    """Test GeneralNameList."""
    dns1 = 'example.com'
    dns2 = 'example.net'

    @contextmanager
    def assertAddTrue(self):  # pylint: disable=invalid-name
        """Just a shortcut when we somehow add True"""

        msg = r'^Cannot parse general name True: Must be of type str \(was: bool\)\.$'
        with self.assertRaisesRegex(ValueError, msg):
            yield

    def test_init(self):
        """Test various different item initializations."""
        self.assertEqual(GeneralNameList(), [])
        self.assertEqual(GeneralNameList([self.dns1]), [dns(self.dns1)])
        self.assertEqual(GeneralNameList([dns(self.dns1)]), [dns(self.dns1)])
        self.assertEqual(GeneralNameList([dns(self.dns1), self.dns2]),
                         [dns(self.dns1), dns(self.dns2)])

        # we also accept a str or generalName
        self.assertEqual(GeneralNameList(self.dns1), [dns(self.dns1)])
        self.assertEqual(GeneralNameList(dns(self.dns1)), [dns(self.dns1)])

        with self.assertAddTrue():
            GeneralNameList([True])

    def test_add(self):
        """Test add()."""
        values = [
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
            empty + [True]  # pylint: disable=pointless-statement

    def test_append(self):
        """Test append()."""
        gnl1 = GeneralNameList()
        self.assertIsNone(gnl1.append(self.dns1))
        self.assertEqual(gnl1, GeneralNameList([self.dns1]))
        self.assertIsNone(gnl1.append(dns(self.dns2)))
        self.assertEqual(gnl1, GeneralNameList([self.dns1, self.dns2]))

        with self.assertAddTrue():
            gnl1.append(True)
        self.assertEqual(gnl1, GeneralNameList([self.dns1, self.dns2]))

    def test_contains(self):
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

    def test_count(self):
        """Test count()."""
        gnl1 = GeneralNameList()
        self.assertEqual(gnl1.count(self.dns1), 0)
        self.assertEqual(gnl1.count(dns(self.dns2)), 0)
        self.assertEqual(gnl1.count(True), 0)

        gnl1 = GeneralNameList([self.dns1])
        self.assertEqual(gnl1.count(self.dns1), 1)
        self.assertEqual(gnl1.count(dns(self.dns1)), 1)
        self.assertEqual(gnl1.count(dns(self.dns2)), 0)
        self.assertEqual(gnl1.count(self.dns2), 0)
        self.assertEqual(gnl1.count(True), 0)

    def test_eq(self):
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

    def test_extend(self):
        """Test extend()."""
        gnl1 = GeneralNameList()
        self.assertIsNone(gnl1.extend([self.dns1]))
        self.assertEqual(gnl1, GeneralNameList([self.dns1]))

        gnl2 = GeneralNameList()
        self.assertIsNone(gnl2.extend([dns(self.dns1)]))
        self.assertEqual(gnl2, GeneralNameList([self.dns1]))

        gnl3 = GeneralNameList([self.dns1])
        self.assertIsNone(gnl3.extend([dns(self.dns1), self.dns2]))
        self.assertEqual(gnl3, GeneralNameList([self.dns1, self.dns1, self.dns2]))

    def test_iadd(self):
        """Test infix add (e.g. ``self += value``)."""
        values = [
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
            empty += [True]

    def test_index(self):
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

    def test_insert(self):
        """Test insert()."""
        gnl1 = GeneralNameList()
        gnl1.insert(0, self.dns1)
        self.assertEqual(gnl1, [self.dns1])

        gnl1.insert(0, dns(self.dns2))
        self.assertEqual(gnl1, [self.dns2, self.dns1])

        with self.assertAddTrue():
            gnl1.insert(0, True)
        self.assertEqual(gnl1, [self.dns2, self.dns1])

    def test_remove(self):
        """Test remove()."""
        gnl1 = GeneralNameList([self.dns1, self.dns2])
        self.assertIsNone(gnl1.remove(self.dns1))
        self.assertEqual(gnl1, [self.dns2])
        self.assertIsNone(gnl1.remove(dns(self.dns2)))
        self.assertEqual(gnl1, [])

    def test_repr(self):
        """Test repr()."""
        self.assertEqual(repr(GeneralNameList()), '<GeneralNameList: []>')
        self.assertEqual(repr(GeneralNameList([self.dns1])),
                         "<GeneralNameList: ['DNS:%s']>" % self.dns1)
        self.assertEqual(repr(GeneralNameList([dns(self.dns1)])),
                         "<GeneralNameList: ['DNS:%s']>" % self.dns1)

    def test_serialize(self):
        """Test serialization."""
        gnl1 = GeneralNameList([self.dns1, dns(self.dns2), self.dns1])
        self.assertEqual(list(gnl1.serialize()),
                         ['DNS:%s' % self.dns1, 'DNS:%s' % self.dns2, 'DNS:%s' % self.dns1])

    def test_setitem(self):
        """Test setter, e.g. ``e[0] = ...``."""
        gnl1 = GeneralNameList()

        with self.assertRaisesRegex(IndexError, r'^list assignment index out of range$'):
            gnl1[0] = dns(self.dns1)
        with self.assertRaisesRegex(IndexError, r'^list assignment index out of range$'):
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
        with self.assertAddTrue():
            gnl4[0] = True

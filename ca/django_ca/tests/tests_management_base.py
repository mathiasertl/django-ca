# -*- coding: utf-8 -*-
#
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

import argparse
from datetime import datetime
from datetime import timedelta

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding

from ..extensions import KeyUsage
from ..management import base
from ..models import CertificateAuthority
from ..subject import Subject
from .base import DjangoCATestCase
from .base import DjangoCAWithCATestCase
from .base import DjangoCAWithCertTestCase
from .base import child_pubkey
from .base import override_settings

try:
    import unittest.mock as mock
except ImportError:
    import mock


class SubjectActionTestCase(DjangoCATestCase):
    def setUp(self):
        super(SubjectActionTestCase, self).setUp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument('--subject', action=base.SubjectAction)

    def test_basic(self):
        ns = self.parser.parse_args(['--subject=/CN=example.com'])
        self.assertEqual(ns.subject, Subject([('CN', 'example.com')]))

        ns = self.parser.parse_args(['--subject=/ST=foo/CN=example.com'])
        self.assertEqual(ns.subject, Subject([('ST', 'foo'), ('CN', 'example.com')]))

        ns = self.parser.parse_args(['--subject=/ST=/CN=example.com'])
        self.assertEqual(ns.subject, Subject([('ST', ''), ('CN', 'example.com')]))

    def test_order(self):
        # this should be an ordered dict
        ns = self.parser.parse_args(['--subject=/CN=example.com/ST=foo'])
        self.assertEqual(ns.subject, Subject([('ST', 'foo'), ('CN', 'example.com')]))

    def test_multiple(self):
        # this should be an ordered dict
        ns = self.parser.parse_args(['--subject=/C=AT/OU=foo/OU=bar'])
        self.assertEqual(ns.subject, Subject([('C', 'AT'), ('OU', 'foo'), ('OU', 'bar')]))

    def test_error(self):
        self.assertParserError(['--subject=/WRONG=foobar'],
                               'usage: setup.py [-h] [--subject SUBJECT]\n'
                               'setup.py: error: Unknown x509 name field: WRONG\n')


class MultiValueExtensionAction(DjangoCATestCase):
    def setUp(self):
        super(MultiValueExtensionAction, self).setUp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument('-e', action=base.MultiValueExtensionAction, extension=KeyUsage)

    def test_basic(self):
        ns = self.parser.parse_args(['-e=critical,keyAgreement'])
        self.assertEqual(ns.e, KeyUsage('critical,keyAgreement'))
        self.assertTrue(ns.e.critical)
        self.assertEqual(ns.e.value, ['keyAgreement'])

        # test a non-critical value
        ns = self.parser.parse_args(['-e=keyAgreement'])
        self.assertEqual(ns.e, KeyUsage('keyAgreement'))
        self.assertFalse(ns.e.critical)
        self.assertEqual(ns.e.value, ['keyAgreement'])

    def test_error(self):
        self.assertParserError(['-e=foobar'],
                               'usage: setup.py [-h] [-e E]\n'
                               'setup.py: error: Invalid extension value: foobar: Unknown value(s): foobar\n')


class FormatActionTestCase(DjangoCATestCase):
    def setUp(self):
        super(FormatActionTestCase, self).setUp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument('--action', action=base.FormatAction)

    def test_basic(self):
        ns = self.parser.parse_args(['--action=DER'])
        self.assertEqual(ns.action, Encoding.DER)

        ns = self.parser.parse_args(['--action=ASN1'])
        self.assertEqual(ns.action, Encoding.DER)

        ns = self.parser.parse_args(['--action=PEM'])
        self.assertEqual(ns.action, Encoding.PEM)

    def test_case(self):
        ns = self.parser.parse_args(['--action=der'])
        self.assertEqual(ns.action, Encoding.DER)

        ns = self.parser.parse_args(['--action=asn1'])
        self.assertEqual(ns.action, Encoding.DER)

        ns = self.parser.parse_args(['--action= pEm'])
        self.assertEqual(ns.action, Encoding.PEM)

    def test_error(self):
        self.assertParserError(['--action=foo'],
                               'usage: setup.py [-h] [--action ACTION]\n'
                               'setup.py: error: Unknown format "FOO".\n')


class CurveActionTestCase(DjangoCATestCase):
    def setUp(self):
        super(CurveActionTestCase, self).setUp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument('--curve', action=base.KeyCurveAction)

    def test_basic(self):
        ns = self.parser.parse_args(['--curve=SECT409K1'])
        self.assertIsInstance(ns.curve, ec.SECT409K1)

        ns = self.parser.parse_args(['--curve=SECT409R1'])
        self.assertIsInstance(ns.curve, ec.SECT409R1)

    def test_error(self):
        self.assertParserError(['--curve=foo'],
                               'usage: setup.py [-h] [--curve CURVE]\n'
                               'setup.py: error: foo: Not a known Eliptic Curve\n')


class AlgorithmActionTestCase(DjangoCATestCase):
    def setUp(self):
        super(AlgorithmActionTestCase, self).setUp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument('--algo', action=base.AlgorithmAction)

    def test_basic(self):
        ns = self.parser.parse_args(['--algo=sha256'])
        self.assertIsInstance(ns.algo, hashes.SHA256)

        ns = self.parser.parse_args(['--algo=md5'])
        self.assertIsInstance(ns.algo, hashes.MD5)

        ns = self.parser.parse_args(['--algo=sha512'])
        self.assertIsInstance(ns.algo, hashes.SHA512)

    def test_case(self):
        ns = self.parser.parse_args(['--algo=sHa256'])
        self.assertIsInstance(ns.algo, hashes.SHA256)

        ns = self.parser.parse_args(['--algo=mD5'])
        self.assertIsInstance(ns.algo, hashes.MD5)

        ns = self.parser.parse_args(['--algo=sHa512'])
        self.assertIsInstance(ns.algo, hashes.SHA512)

    def test_error(self):
        self.assertParserError(['--algo=foo'],
                               'usage: setup.py [-h] [--algo ALGO]\n'
                               'setup.py: error: Unknown hash algorithm: foo\n')


class KeySizeActionTestCase(DjangoCATestCase):
    def setUp(self):
        super(KeySizeActionTestCase, self).setUp()

        self.parser = argparse.ArgumentParser()
        self.parser.add_argument('--size', type=int, action=base.KeySizeAction)

    def test_basic(self):
        ns = self.parser.parse_args(['--size=2048'])
        self.assertEqual(ns.size, 2048)

        ns = self.parser.parse_args(['--size=4096'])
        self.assertEqual(ns.size, 4096)

    def test_no_power_two(self):
        expected = '''usage: setup.py [-h] [--size SIZE]
setup.py: error: --size must be a power of two (2048, 4096, ...)\n'''

        self.assertParserError(['--size=2047'], expected)
        self.assertParserError(['--size=2049'], expected)
        self.assertParserError(['--size=3084'], expected)
        self.assertParserError(['--size=4095'], expected)

    @override_settings(CA_MIN_KEY_SIZE=2048)
    def test_to_small(self):
        expected = '''usage: setup.py [-h] [--size SIZE]
setup.py: error: --size must be at least 2048 bits.\n'''

        self.assertParserError(['--size=1024'], expected)
        self.assertParserError(['--size=512'], expected)
        self.assertParserError(['--size=256'], expected)


class PasswordActionTestCase(DjangoCATestCase):
    def setUp(self):
        super(PasswordActionTestCase, self).setUp()

        self.parser = argparse.ArgumentParser()
        self.parser.add_argument('--password', nargs='?', action=base.PasswordAction)

    def test_none(self):
        ns = self.parser.parse_args([])
        self.assertIsNone(ns.password)

    def test_given(self):
        ns = self.parser.parse_args(['--password=foobar'])
        self.assertEqual(ns.password, b'foobar')

    @mock.patch('getpass.getpass', return_value='prompted')
    def test_output(self, getpass):
        prompt = 'new prompt: '
        parser = argparse.ArgumentParser()
        parser.add_argument('--password', nargs='?', action=base.PasswordAction, prompt=prompt)
        ns = parser.parse_args(['--password'])
        self.assertEqual(ns.password, b'prompted')

        getpass.assert_called_once_with(prompt=prompt)

    @mock.patch("getpass.getpass", return_value="prompted")
    def test_prompt(self, getpass):
        parser = argparse.ArgumentParser()
        parser.add_argument('--password', nargs='?', action=base.PasswordAction)
        ns = parser.parse_args(['--password'])

        self.assertEqual(ns.password, b'prompted')


class CertificateActionTestCase(DjangoCAWithCertTestCase):
    def setUp(self):
        super(CertificateActionTestCase, self).setUp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument('cert', action=base.CertificateAction)

    def test_basic(self):
        ns = self.parser.parse_args([self.cert.serial])
        self.assertEqual(ns.cert, self.cert)

    def test_abbreviation(self):
        ns = self.parser.parse_args([self.cert.serial[:4]])
        self.assertEqual(ns.cert, self.cert)

    def test_missing(self):
        serial = 'foo'
        self.assertParserError([serial],
                               'usage: setup.py [-h] cert\n'
                               'setup.py: error: %s: Certificate not found.\n' % serial)

    def test_multiple(self):
        # Create a second cert and manually set almost the same serial
        cert2 = self.create_cert(self.ca, self.csr_pem, [('CN', 'example.com')])
        cert2.serial = self.cert.serial[:-1] + 'X'
        cert2.save()

        serial = cert2.serial[:8]
        self.assertParserError([serial],
                               'usage: setup.py [-h] cert\n'
                               'setup.py: error: %s: Multiple certificates match.\n'
                               % serial)


class CertificateAuthorityActionTestCase(DjangoCAWithCATestCase):
    def setUp(self):
        super(CertificateAuthorityActionTestCase, self).setUp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument('ca', action=base.CertificateAuthorityAction)

    def test_basic(self):
        ns = self.parser.parse_args([self.ca.serial])
        self.assertEqual(ns.ca, self.ca)

    def test_abbreviation(self):
        ns = self.parser.parse_args([self.ca.serial[:4]])
        self.assertEqual(ns.ca, self.ca)

    def test_missing(self):
        self.assertParserError(['foo'],
                               '''usage: setup.py [-h] ca\n'''
                               '''setup.py: error: foo: Certificate authority not found.\n''')

    def test_multiple(self):
        # Create a second CA and manually set (almost) the same serial
        ca2 = self.load_ca(name='child', x509=child_pubkey)
        ca2.serial = self.ca.serial[:-1] + 'X'
        ca2.save()

        serial = ca2.serial[:8]
        self.assertParserError([serial],
                               'usage: setup.py [-h] ca\n'
                               'setup.py: error: %s: Multiple Certificate authorities match.\n'
                               % serial)

    def test_disabled(self):
        ca = CertificateAuthority.objects.first()
        ca.enabled = False
        ca.save()

        expected = '''usage: setup.py [-h] ca
setup.py: error: %s: Certificate authority not found.\n''' % ca.serial

        self.assertParserError([ca.serial], expected)

        # test allow_disabled=True
        parser = argparse.ArgumentParser()
        parser.add_argument('ca', action=base.CertificateAuthorityAction, allow_disabled=True)

        ns = parser.parse_args([ca.serial])
        self.assertEqual(ns.ca, ca)

    def test_pkey_doesnt_exists(self):
        ca = CertificateAuthority.objects.first()
        ca.private_key_path = '/does-not-exist'
        ca.save()

        expected = '''usage: setup.py [-h] ca
setup.py: error: %s: %s: Private key does not exist.\n''' % (ca.name, ca.private_key_path)

        self.assertParserError([ca.serial], expected)

    def test_password(self):
        # Test that the action works with a password-encrypted ca
        ns = self.parser.parse_args([self.pwd_ca.serial])
        self.assertEqual(ns.ca, self.pwd_ca)


class URLActionTestCase(DjangoCATestCase):
    def setUp(self):
        super(URLActionTestCase, self).setUp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument('--url', action=base.URLAction)

    def test_basic(self):
        for url in ['http://example.com', 'https://www.example.org']:
            ns = self.parser.parse_args(['--url=%s' % url])
            self.assertEqual(ns.url, url)

    def test_error(self):
        self.assertParserError(['--url=foo'], 'usage: setup.py [-h] [--url URL]\n'
                                              'setup.py: error: foo: Not a valid URL.\n')


class ExpiresActionTestCase(DjangoCATestCase):
    def setUp(self):
        super(ExpiresActionTestCase, self).setUp()
        self.now = datetime(2016, 9, 9)

    def test_basic(self):
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument('--expires', action=base.ExpiresAction, default=100, now=self.now)

        # this always is one day more, because N days jumps to the next midnight.
        expires = self.now + timedelta(days=31)
        ns = self.parser.parse_args(['--expires=30'])
        self.assertEqual(ns.expires, expires)

    def test_default(self):
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument('--expires', action=base.ExpiresAction, default=100, now=self.now)

        # this always is one day more, because N days jumps to the next midnight.
        expires = self.now + timedelta(days=101)
        ns = self.parser.parse_args([])
        self.assertEqual(ns.expires, expires)

    def test_default_datetime(self):
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument('--expires', action=base.ExpiresAction, default=self.now)

        # this always is one day more, because N days jumps to the next midnight.
        ns = self.parser.parse_args([])
        self.assertEqual(ns.expires, self.now)

    def test_negative(self):
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument('--expires', action=base.ExpiresAction, default=100, now=self.now)

        # this always is one day more, because N days jumps to the next midnight.
        self.assertParserError(['--expires=-1'], 'usage: setup.py [-h] [--expires EXPIRES]\n'
                               'setup.py: error: Expires must not be negative.\n')


class MultipleURLActionTestCase(DjangoCATestCase):
    def setUp(self):
        super(MultipleURLActionTestCase, self).setUp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument('--url', action=base.MultipleURLAction, default=[])

    def test_basic(self):
        urls = ['http://example.com', 'https://www.example.org']

        for url in urls:
            parser = argparse.ArgumentParser()
            parser.add_argument('--url', action=base.MultipleURLAction)

            ns = parser.parse_args(['--url=%s' % url])
            self.assertEqual(ns.url, [url])

        parser = argparse.ArgumentParser()
        parser.add_argument('--url', action=base.MultipleURLAction, default=[])
        ns = parser.parse_args(['--url=%s' % urls[0], '--url=%s' % urls[1]])
        self.assertEqual(ns.url, urls)

    def test_error(self):
        self.assertParserError(['--url=foo'], 'usage: setup.py [-h] [--url URL]\n'
                                              'setup.py: error: foo: Not a valid URL.\n')

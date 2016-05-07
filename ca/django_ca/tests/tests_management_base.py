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
import os
import tempfile

from OpenSSL import crypto

from ..management import base
from ..models import CertificateAuthority
from .base import override_settings
from .base import override_tmpcadir
from .base import DjangoCAWithCATestCase
from .base import DjangoCATestCase


class SubjectActionTestCase(DjangoCATestCase):
    def setUp(self):
        super(SubjectActionTestCase, self).setUp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument('--subject', action=base.SubjectAction)

    def test_basic(self):
        ns = self.parser.parse_args(['--subject=/CN=example.com'])
        self.assertEqual(ns.subject, {'CN': 'example.com'})

        ns = self.parser.parse_args(['--subject=/ST=foo/CN=example.com'])
        self.assertEqual(ns.subject, {'ST': 'foo', 'CN': 'example.com'})

        ns = self.parser.parse_args(['--subject=/ST=/CN=example.com'])
        self.assertEqual(ns.subject, {'ST': '', 'CN': 'example.com'})

    def test_error(self):
        self.assertParserError(['--subject=ST=/CN=example.com'], 
                               'usage: setup.py [-h] [--subject SUBJECT]\n'
                               'setup.py: error: Unparseable subject: Does not start with a "/".\n')

class FormatActionTestCase(DjangoCATestCase):
    def setUp(self):
        super(FormatActionTestCase, self).setUp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument('--action', action=base.FormatAction)

    def test_basic(self):
        ns = self.parser.parse_args(['--action=DER'])
        self.assertEqual(ns.action, crypto.FILETYPE_ASN1)

        ns = self.parser.parse_args(['--action=ASN1'])
        self.assertEqual(ns.action, crypto.FILETYPE_ASN1)

        ns = self.parser.parse_args(['--action=PEM'])
        self.assertEqual(ns.action, crypto.FILETYPE_PEM)

        ns = self.parser.parse_args(['--action=TEXT'])
        self.assertEqual(ns.action, crypto.FILETYPE_TEXT)

    def test_case(self):
        ns = self.parser.parse_args(['--action=der'])
        self.assertEqual(ns.action, crypto.FILETYPE_ASN1)

        ns = self.parser.parse_args(['--action= pEm'])
        self.assertEqual(ns.action, crypto.FILETYPE_PEM)

    def test_error(self):
        self.assertParserError(['--action=foo'],
                               'usage: setup.py [-h] [--action ACTION]\n'
                               'setup.py: error: Unknown format "FOO".\n')


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


@override_tmpcadir()
class CertificateAuthorityActionTestCase(DjangoCAWithCATestCase):
    def setUp(self):
        super(CertificateAuthorityActionTestCase, self).setUp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument('ca', action=base.CertificateAuthorityAction)

    def test_basic(self):
        ns = self.parser.parse_args([self.ca.serial])
        self.assertEqual(ns.ca, self.ca)

    def test_missing(self):
        self.assertParserError(['foo'],
                               '''usage: setup.py [-h] ca\n'''
                               '''setup.py: error: FOO: Unknown Certiciate Authority.\n''')

    def test_disabled(self):
        ca = CertificateAuthority.objects.first()
        ca.enabled = False
        ca.save()

        expected = '''usage: setup.py [-h] ca
setup.py: error: %s: Unknown Certiciate Authority.\n''' % ca.serial

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

    def test_unparseable(self):

        fd, path = tempfile.mkstemp()
        stream = os.fdopen(fd, 'w')

        try:
            ca = CertificateAuthority.objects.first()
            ca.private_key_path = path
            ca.save()

            expected = '''usage: setup.py [-h] ca
setup.py: error: %s: %s: Could not read private key.\n''' % (ca.name, ca.private_key_path)

            stream.write('unparseable')
            stream.close()

            self.assertParserError([ca.serial], expected)
        finally:
            stream.close()
            os.remove(path)

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

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

from io import StringIO

from OpenSSL import crypto
from django.test import TestCase
from mock import patch

from ..management import base
from .base import override_settings
from .base import override_tmpcadir
from .base import DjangoCAWithCATestCase


class FormatActionTestCase(TestCase):
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
        buf = StringIO()

        with self.assertRaises(SystemExit), patch('sys.stderr', buf):
            self.parser.parse_args(['--action=foo'])

        self.assertEqual(buf.getvalue(), '''usage: setup.py [-h] [--action ACTION]
setup.py: error: Unknown format "FOO".\n''')


class KeySizeActionTestCase(TestCase):
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
        buf = StringIO()
        with self.assertRaises(SystemExit), patch('sys.stderr', buf):
            self.parser.parse_args(['--size=2047'])
        self.assertEqual(buf.getvalue(), '''usage: setup.py [-h] [--size SIZE]
setup.py: error: --size must be a power of two (2048, 4096, ...)\n''')

    @override_settings(CA_MIN_KEY_SIZE=2048)
    def test_to_small(self):
        buf = StringIO()
        with self.assertRaises(SystemExit), patch('sys.stderr', buf):
            self.parser.parse_args(['--size=1024'])

        self.assertEqual(buf.getvalue(), '''usage: setup.py [-h] [--size SIZE]
setup.py: error: --size must be at least 2048 bits.\n''')


@override_tmpcadir()
class CertificateAuthorityActionTestCase(DjangoCAWithCATestCase):
    def setUp(self):
        super(CertificateAuthorityActionTestCase, self).setUp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument('ca', action=base.CertificateAuthorityAction)

    def test_basic(self):
        ns = self.parser.parse_args([self.ca.serial])
        self.assertEqual(ns.ca, self.ca)

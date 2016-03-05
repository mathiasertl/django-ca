"""Test utility functions."""

from datetime import datetime

from django.test import TestCase

from django_ca.utils import format_date
from django_ca.utils import get_basic_cert
from django_ca.utils import is_power2
from django_ca.utils import parse_date


class FormatDateTestCase(TestCase):
    def test_format(self):
        d = datetime(2016, 3, 5, 14, 53, 12)
        self.assertEqual(format_date(d), '20160305145312Z')

    def test_parse(self):
        d = datetime(2016, 3, 5, 14, 53, 12)
        formatted = '20160305145312Z'
        self.assertEqual(parse_date(formatted), d)

    def test_indempotent(self):
        d = datetime(2016, 3, 5, 14, 53, 12)
        f = format_date(d)
        self.assertEqual(d, parse_date(f))


class Power2TestCase(TestCase):
    def test_true(self):
        for i in range(0, 20):
            self.assertTrue(is_power2(2 ** i))

    def test_false(self):
        self.assertFalse(is_power2(0))
        self.assertFalse(is_power2(3))
        self.assertFalse(is_power2(5))

        for i in range(2, 20):
            self.assertFalse(is_power2((2 ** i) - 1))
            self.assertFalse(is_power2((2 ** i) + 1))


class GetBasicCertTestCase(TestCase):
    def test_basic(self):
        cert = get_basic_cert(720)
        self.assertFalse(cert.has_expired())

"""Test utility functions."""

from datetime import datetime

from django.test import TestCase

from django_ca.utils import format_date
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

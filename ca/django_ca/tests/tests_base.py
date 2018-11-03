"""
This file demonstrates writing tests using the unittest module. These will pass
when you run "manage.py test".

Replace this with more appropriate tests for your application.
"""

import tempfile

from django.test import TestCase

from .. import ca_settings
from .base import DjangoCATestCase
from .base import DjangoCAWithCATestCase
from .base import override_settings
from .base import override_tmpcadir


class TestDjangoCATestCase(DjangoCATestCase):
    # test the base test-class

    @override_tmpcadir()
    def test_override_tmpcadir(self):
        ca_dir = ca_settings.CA_DIR
        self.assertTrue(ca_dir.startswith(tempfile.gettempdir()))

    def test_tmpcadir(self):
        old_ca_dir = ca_settings.CA_DIR

        with self.tmpcadir():
            ca_dir = ca_settings.CA_DIR
            self.assertNotEqual(ca_dir, old_ca_dir)
            self.assertTrue(ca_dir.startswith(tempfile.gettempdir()))

        self.assertEqual(ca_settings.CA_DIR, old_ca_dir)  # ensure that they're equal again


class OverrideSettingsFuncTestCase(TestCase):
    @override_settings(CA_MIN_KEY_SIZE=256)
    def test_basic(self):
        self.assertEqual(ca_settings.CA_MIN_KEY_SIZE, 256)


@override_settings(CA_MIN_KEY_SIZE=512)
class OverrideSettingsClassOnlyTestCase(DjangoCATestCase):
    def test_basic(self):
        self.assertEqual(ca_settings.CA_MIN_KEY_SIZE, 512)

    def test_second(self):
        self.assertEqual(ca_settings.CA_MIN_KEY_SIZE, 512)


@override_settings(CA_MIN_KEY_SIZE=128)
class OverrideSettingsClassTestCase(DjangoCATestCase):
    def test_basic(self):
        self.assertEqual(ca_settings.CA_MIN_KEY_SIZE, 128)

    @override_settings(CA_MIN_KEY_SIZE=256)
    def test_double(self):
        self.assertEqual(ca_settings.CA_MIN_KEY_SIZE, 256)

    def test_wrong_base(self):
        msg = r'^Only subclasses of DjangoCATestCase can use override_settings$'
        with self.assertRaisesRegex(ValueError, msg):
            @override_settings(CA_MIN_KEY_SIZE=256)
            class DummyTest(TestCase):
                pass

        msg = r'^Only subclasses of DjangoCATestCase can use override_settings$'
        with self.assertRaisesRegex(ValueError, msg):
            @override_settings(CA_MIN_KEY_SIZE=256)
            class DummyTestTwo:
                pass


class OverrideCaDirForFuncTestCase(DjangoCATestCase):
    @classmethod
    def setUpClass(cls):
        super(OverrideCaDirForFuncTestCase, cls).setUpClass()
        cls.seen_dirs = set()

    @override_tmpcadir()
    def test_a(self):
        # add three tests to make sure that every test case sees a different dir
        self.assertTrue(ca_settings.CA_DIR.startswith(tempfile.gettempdir()), ca_settings.CA_DIR)
        self.assertNotIn(ca_settings.CA_DIR, self.seen_dirs)
        self.seen_dirs.add(ca_settings.CA_DIR)

    @override_tmpcadir()
    def test_b(self):
        self.assertTrue(ca_settings.CA_DIR.startswith(tempfile.gettempdir()), ca_settings.CA_DIR)
        self.assertNotIn(ca_settings.CA_DIR, self.seen_dirs)
        self.seen_dirs.add(ca_settings.CA_DIR)

    @override_tmpcadir()
    def test_c(self):
        self.assertTrue(ca_settings.CA_DIR.startswith(tempfile.gettempdir()), ca_settings.CA_DIR)
        self.assertNotIn(ca_settings.CA_DIR, self.seen_dirs)
        self.seen_dirs.add(ca_settings.CA_DIR)

    def test_no_classes(self):
        msg = r'^Only functions can use override_tmpcadir\(\)$'
        with self.assertRaisesRegex(ValueError, msg):
            @override_tmpcadir()
            class Foo():
                pass


class CommandTestCase(DjangoCAWithCATestCase):
    def test_basic(self):
        self.cmd_e2e(['list_cas'])

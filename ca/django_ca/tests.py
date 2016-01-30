"""
This file demonstrates writing tests using the unittest module. These will pass
when you run "manage.py test".

Replace this with more appropriate tests for your application.
"""

import os
import shutil
import tempfile

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.test.utils import override_settings as _override_settings
from django.utils.six.moves import reload_module

from . import ca_settings


class override_settings(_override_settings):
    """Enhance override_settings to also reload django_ca.ca_settings."""

    def enable(self):
        super(override_settings, self).enable()
        reload_module(ca_settings)

    def disable(self):
        super(override_settings, self).disable()
        reload_module(ca_settings)


class override_tmpcadir(override_settings):
    """Sets the CA_DIR directory to a temporary directory.

    .. NOTE: This also takes any additional settings.
    """

    def __init__(self, **kwargs):
        super(override_tmpcadir, self).__init__(**kwargs)
        self.options['CA_DIR'] = tempfile.mkdtemp()

    def disable(self):
        super(override_tmpcadir, self).disable()
        shutil.rmtree(self.options['CA_DIR'])


class DjangoCATestCase(TestCase):
    """Base class for all testcases with some enhancements."""

    def settings(self, **kwargs):
        return override_settings(**kwargs)

    def tmpcadir(self, **kwargs):
        return override_tmpcadir(**kwargs)


class TestDjangoCATestCase(DjangoCATestCase):
    @override_tmpcadir()
    def test_override_tmpcadir(self):
        ca_dir = ca_settings.CA_DIR
        self.assertTrue(ca_dir.startswith(tempfile.gettempdir()))
        self.assertEqual(ca_settings.CA_KEY, os.path.join(ca_dir, 'ca.key'))
        self.assertEqual(ca_settings.CA_CRT, os.path.join(ca_dir, 'ca.crt'))

    def test_tmpcadir(self):
        old_ca_dir = ca_settings.CA_DIR

        with self.tmpcadir():
            ca_dir = ca_settings.CA_DIR
            self.assertNotEqual(ca_dir, old_ca_dir)
            self.assertTrue(ca_dir.startswith(tempfile.gettempdir()))
            self.assertEqual(ca_settings.CA_KEY, os.path.join(ca_dir, 'ca.key'))
            self.assertEqual(ca_settings.CA_CRT, os.path.join(ca_dir, 'ca.crt'))

        self.assertEqual(ca_settings.CA_DIR, old_ca_dir)  # ensure that they're equal again


class InitCATest(DjangoCATestCase):
    @override_tmpcadir()
    def test_basic(self):
        call_command('init_ca', 'AT', 'Vienna', 'Vienna', 'HTU Wien', 'FSINF', 'ca.fsinf.at',
                     key_size=2048)

    @override_tmpcadir()
    def test_key_exists(self):
        # test that creating a CA twice doesn't work
        call_command('init_ca', 'AT', 'Vienna', 'Vienna', 'HTU Wien', 'FSINF', 'ca.fsinf.at',
                     key_size=2048)
        with self.assertRaises(CommandError):
            call_command('init_ca', 'AT', 'Vienna', 'Vienna', 'HTU Wien', 'FSINF', 'ca.fsinf.at',
                         key_size=2048)

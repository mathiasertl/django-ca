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

from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase

from .. import ca_settings
from .base import override_settings


class SettingsTestCase(TestCase):
    def test_none_profiles(self):
        self.assertIn('client', ca_settings.CA_PROFILES)

        with override_settings(CA_PROFILES={'client': None}):
            self.assertNotIn('client', ca_settings.CA_PROFILES)

    def test_ca_profile_update(self):
        desc = 'testdesc'
        with override_settings(CA_PROFILES={'client': {'desc': desc}}):
            self.assertEqual(ca_settings.CA_PROFILES['client']['desc'], desc)


class ImproperlyConfiguredTestCase(TestCase):
    def test_default_ecc_curve(self):
        with self.assertRaisesRegex(ImproperlyConfigured, r'^Unkown CA_DEFAULT_ECC_CURVE: foo$'):
            with override_settings(CA_DEFAULT_ECC_CURVE='foo'):
                pass

        with self.assertRaisesRegex(ImproperlyConfigured, r'^ECDH: Not an EllipticCurve\.$'):
            with override_settings(CA_DEFAULT_ECC_CURVE='ECDH'):
                pass

        with self.assertRaisesRegex(ImproperlyConfigured, '^CA_DEFAULT_KEY_SIZE cannot be lower then 1024$'):
            with override_settings(CA_MIN_KEY_SIZE=1024, CA_DEFAULT_KEY_SIZE=512):
                pass

    def test_digest_algorithm(self):
        with self.assertRaisesRegex(ImproperlyConfigured, r'^Unkown CA_DIGEST_ALGORITHM: foo$'):
            with override_settings(CA_DIGEST_ALGORITHM='foo'):
                pass

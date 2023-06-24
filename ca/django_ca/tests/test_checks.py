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

"""Test django-ca system checks."""


from django.apps import apps
from django.core import checks
from django.test import TestCase

from django_ca.checks import check_cache
from django_ca.tests.base.mixins import TestCaseMixin


class SystemChecksTestCase(TestCaseMixin, TestCase):
    """Test django-ca system checks."""

    def test_no_cache(self) -> None:
        """Test check if no caches are configured."""

        app_config = apps.get_app_config("django_ca")
        expected = checks.Error(
            "django-ca requires a (shared) cache to be configured.",
            hint="https://docs.djangoproject.com/en/dev/topics/cache/",
            id="django-ca.caches.E001",
        )
        with self.settings(CACHES={}):
            errors = check_cache([app_config])
        self.assertEqual(errors, [expected])

        with self.settings(CACHES={}):
            errors = check_cache(None)
        self.assertEqual(errors, [expected])

    def test_loc_mem_cache(self) -> None:
        """Test what happens if LocMemCache is used."""

        app_config = apps.get_app_config("django_ca")
        expected = checks.Warning(
            "django-ca requires a shared cache like Redis or Memcached unless the application server uses only a single process.",  # NOQA: E501
            hint="https://docs.djangoproject.com/en/dev/topics/cache/",
            id="django-ca.caches.W001",
        )
        setting = {
            "default": {
                "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            }
        }
        with self.settings(CACHES=setting):
            errors = check_cache([app_config])
        self.assertEqual(errors, [expected])
        with self.settings(CACHES=setting):
            errors = check_cache(None)
        self.assertEqual(errors, [expected])

    def test_django_ca_not_checked(self) -> None:
        """Test that no checks are run if django_ca is not checked."""
        app_config = apps.get_app_config("auth")
        errors = check_cache([app_config])
        self.assertEqual(errors, [])

    def test_redis_cache(self) -> None:
        """Test if redis cache backend is used."""

        app_config = apps.get_app_config("django_ca")
        setting = {
            "default": {
                "BACKEND": "django.core.cache.backends.redis.RedisCache",
            }
        }
        with self.settings(CACHES=setting):
            errors = check_cache([app_config])
        self.assertEqual(errors, [])

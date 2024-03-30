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

"""System checks for django-ca.

.. seealso:: https://docs.djangoproject.com/en/dev/topics/checks/
"""

from typing import Any, Optional

from django.apps import AppConfig
from django.conf import settings
from django.core import checks

# List of cache backends that do not share the data between multiple worker processes
_UNSUPPORTED_BACKENDS = (
    "django.core.cache.backends.filebased.FileBasedCache",
    "django.core.cache.backends.locmem.LocMemCache",
    "django.core.cache.backends.dummy.DummyCache",
)


# TYPE NOTE: django-stubs does not type-hint the decorator
@checks.register(checks.Tags.caches, deploy=True)  # type: ignore[type-var]
def check_cache(app_configs: Optional[list[AppConfig]], **kwargs: Any) -> list[checks.CheckMessage]:
    """Check that a cache is configured and issue a warning if the cache is not a shared cache."""
    # only run checks if manage.py check is run with no app labels (== all) or the django_ca app label
    if app_configs is not None and not [config for config in app_configs if config.name == "django_ca"]:
        return []

    errors: list[checks.CheckMessage] = []

    config = settings.CACHES.get("default")
    if config is None:
        errors.append(
            checks.Error(
                "django-ca requires a (shared) cache to be configured.",
                hint="https://docs.djangoproject.com/en/dev/topics/cache/",
                id="django-ca.caches.E001",
            )
        )
    elif config.get("BACKEND") in _UNSUPPORTED_BACKENDS:
        errors.append(
            checks.Warning(
                "django-ca requires a shared cache like Redis or Memcached unless the application server uses only a single process.",  # NOQA: E501
                hint="https://docs.djangoproject.com/en/dev/topics/cache/",
                id="django-ca.caches.W001",
            )
        )
    return errors

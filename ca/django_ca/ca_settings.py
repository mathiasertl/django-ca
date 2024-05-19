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

"""Keep track of internal settings for django-ca."""

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

# Decide if we should use Celery or not
CA_USE_CELERY = getattr(settings, "CA_USE_CELERY", None)
if CA_USE_CELERY is None:
    try:
        from celery import shared_task

        CA_USE_CELERY = True
    except ImportError:
        CA_USE_CELERY = False
elif CA_USE_CELERY is True:
    try:
        from celery import shared_task  # noqa: F401
    except ImportError as ex:
        raise ImproperlyConfigured("CA_USE_CELERY set to True, but Celery is not installed") from ex

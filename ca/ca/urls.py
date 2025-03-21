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

"""Root URL configuration for the django-ca Django project."""

from django.conf import settings
from django.contrib import admin
from django.urls import URLPattern, URLResolver, include, path

admin.autodiscover()

urlpatterns: list[URLPattern | URLResolver] = [
    path(getattr(settings, "CA_URL_PATH", "django_ca/"), include("django_ca.urls")),
]

if getattr(settings, "ENABLE_ADMIN", True):
    urlpatterns.append(path("admin/", admin.site.urls))

# Append additional URL patterns
for pattern in settings.EXTEND_URL_PATTERNS:
    urlpatterns.append(pattern.pattern)

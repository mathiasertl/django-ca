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
# see <http://www.gnu.org/licenses/>.

"""django-ca custom URL converters.

.. seealso:: https://docs.djangoproject.com/en/dev/topics/http/urls/
"""
# pylint: disable=no-self-use,missing-function-docstring; All functions are given by Django

from django.urls.converters import SlugConverter

from .utils import sanitize_serial


class HexConverter:
    """Converter that accepts colon-separated hex values."""
    regex = '[0-9A-F:]+'

    def to_python(self, value):
        return value

    def to_url(self, value):
        return value


class SerialConverter(HexConverter):
    """Extends base to call :py:func:`~django-ca.utils.sanitize_serial` for the value."""

    def to_python(self, value):
        return sanitize_serial(value)


class Base64Converter:
    """Converter that accepts Base64 encoded data."""
    regex = '[a-zA-Z0-9=+/]+'

    def to_python(self, value):
        return value

    def to_url(self, value):
        return value


class AcmeSlugConverter(SlugConverter):
    """ACME slugs consist of alphanumeric characters only."""
    regex = '[a-zA-Z0-9]+'

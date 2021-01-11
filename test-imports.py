#!/usr/bin/env python3
#
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

"""Test if various imports work, mainly used to test that all dependencies are installed."""

# flake8: NOQA: E408
# pylint: disable=wrong-import-position

import os

import django
from django.conf import settings

settings.configure(
    SECRET_KEY='dummy',
    INSTALLED_APPS=[
        'django.contrib.auth',
        'django.contrib.contenttypes',
        'django_ca',
    ],
    BASE_DIR=os.getcwd(),
)
django.setup()

from django_ca.extensions import Extension
from django_ca.acme import constants
from django_ca import models
from django_ca import views

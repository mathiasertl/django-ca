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
# pylint: disable=wrong-import-position,unused-import,reimported

import argparse
import os

import django
from django.conf import settings

parser = argparse.ArgumentParser("Test imports.")
parser.add_argument('--extra', help="Test extras_require.")
args = parser.parse_args()

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

# NOTE: extras are tested in the wheel-test-* stages in Dockerfile
if args.extra == 'acme':
    from django_ca.acme import messages
    from django_ca.acme import utils
    from django_ca.acme import views
elif args.extra == 'celery':
    from django_ca import tasks
elif args.extra == 'redis':
    import redis_cache
elif args.extra:
    print('Error: %s: Unknown extra.' % args.extra)

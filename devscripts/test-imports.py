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
import sys

import django
from django.conf import settings

parser = argparse.ArgumentParser("Test imports.")
parser.add_argument("--extra", help="Test extras_require.")
args = parser.parse_args()

settings.configure(
    SECRET_KEY="dummy",
    INSTALLED_APPS=[
        "django.contrib.auth",
        "django.contrib.contenttypes",
        "django.contrib.staticfiles",
        "django.contrib.admin",
        "django_ca",
    ],
    BASE_DIR=os.getcwd(),
    TEMPLATES=[
        {
            "BACKEND": "django.template.backends.django.DjangoTemplates",
            "DIRS": [],
            "APP_DIRS": True,
            "OPTIONS": {
                "context_processors": [
                    "django.template.context_processors.debug",
                    "django.template.context_processors.request",
                    "django.contrib.auth.context_processors.auth",
                    "django.contrib.messages.context_processors.messages",
                ],
            },
        },
    ],
)
django.setup()

from django.contrib.staticfiles import finders
from django.template.loader import TemplateDoesNotExist
from django.template.loader import get_template

from django_ca import models
from django_ca import views
from django_ca.acme import constants
from django_ca.extensions import Extension

# Test if (some) templates can be loaded
for template in [
    "admin/django_ca/certificate/add_form.html",
    "admin/django_ca/certificate/change_form.html",
    "admin/django_ca/certificate/revoke_form.html",
    "django_ca/admin/extensions/base/base.html",
    "django_ca/admin/submit_line.html",
    "django_ca/forms/widgets/profile.html",
    "django_ca/forms/widgets/subjecttextinput.html",
]:
    try:
        get_template(template)
    except TemplateDoesNotExist:
        print(f"{template}: Could not load template.")
        sys.exit(1)

for static_file in [
    "django_ca/admin/js/profilewidget.js",
    "django_ca/admin/css/base.css",
]:
    if finders.find(static_file) is None:
        print(f"{static_file}: Could not find static file.")
        sys.exit(1)

# Check that tests are **not** included
try:
    from django_ca import tests

    print(f"Was able to import django_ca.tests from {tests.__path__}")
    sys.exit(1)
except ImportError:
    pass
try:
    from django_ca.tests import base

    print(f"Was able to import django_ca.tests from {base.__path__}")
    sys.exit(1)
except ImportError:
    pass

# NOTE: extras are tested in the wheel-test-* stages in Dockerfile
if args.extra == "acme":
    from django_ca.acme import messages
    from django_ca.acme import utils
    from django_ca.acme import views
elif args.extra == "celery":
    from django_ca import tasks
elif args.extra == "redis":
    import redis_cache
elif args.extra:
    print("Error: %s: Unknown extra." % args.extra)

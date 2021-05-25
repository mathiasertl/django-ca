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

"""Script to test if all runtime dependencies are installed.

This script is used mainly to test that build artifacts (e.g. wheels) install all dependencies. The
:file:`Dockerfile` in this project will install the source distribution and wheel in pristine environments
and run this script to detect any mistakes.

.. NOTE::

    Do not use any libraries here that are not needed in production. Installing extra dependencies for the
    test defeats the main purpose of this script.
"""

# NOTE: Disable import warnings, the whole point of this module to do imports later
# flake8: NOQA: E408
# pylint: disable=wrong-import-position,unused-import,reimported

import argparse
import os
import sys

from setuptools.config import read_configuration

import django
from django.conf import settings

# Add source dir to path if not present. This happens at least when this script started in a Docker image.
ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
SRC_DIR = os.path.join(ROOT_DIR, "ca")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

setup_cfg = read_configuration(os.path.join(ROOT_DIR, "setup.cfg"))
ALL_EXTRAS = list(setup_cfg["options"]["extras_require"])

parser = argparse.ArgumentParser("Test imports.")
extra_group = parser.add_mutually_exclusive_group()
extra_group.add_argument(
    "--all-extras",
    action="store_const",
    const=ALL_EXTRAS,
    default=[],
    dest="extra",
    help="Test all known extras.",
)
extra_group.add_argument(
    "--extra",
    action="append",
    choices=ALL_EXTRAS,
    help="Test an extra from extras_require, can be given multiple times. Valid choices are %(choices)s.",
    metavar="EXTRA",
)
args = parser.parse_args()

settings.configure(
    SECRET_KEY="dummy",
    INSTALLED_APPS=[
        "django.contrib.auth",
        "django.contrib.contenttypes",
        "django.contrib.staticfiles",
        "django.contrib.admin",
        # Third-party django apps
        "django_object_actions",
        # django-ca itself
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
from django_ca import subject
from django_ca import utils
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
if "acme" in args.extra:
    from django_ca.acme import messages
    from django_ca.acme import utils
    from django_ca.acme import views
if "celery" in args.extra:
    from django_ca import tasks
if "redis" in args.extra:
    import redis_cache
if "mysql" in args.extra:
    import MySQLdb
if "postgres" in args.extra:
    import psycopg2

#!/usr/bin/env python3
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
# see <http://www.gnu.org/licenses/>.


"""Common functions for various top-level utility scripts."""

import os
import sys

import django

try:
    from termcolor import colored
except ImportError:

    def colored(msg, *args, **kwargs):
        return msg


ROOTDIR = os.path.dirname(os.path.realpath(__file__))
CADIR = os.path.join(ROOTDIR, "ca")

if CADIR not in sys.path:
    sys.path.insert(0, CADIR)


def setup_django(settings_module="ca.test_settings"):
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", settings_module)
    django.setup()


def error(msg, **kwargs):
    print(colored(msg, "red"), **kwargs)


def warn(msg, **kwargs):
    print(colored(msg, "yellow"), **kwargs)


def ok(msg=" OK.", **kwargs):
    print(colored(msg, "green"), **kwargs)


def bold(msg):
    return colored(msg, attrs=["bold"])


def abort(msg):
    print(msg)
    sys.exit(1)

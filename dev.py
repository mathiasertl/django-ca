#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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

import argparse
import os
import subprocess
import sys

parser = argparse.ArgumentParser(
    description='Helper-script for various tasks during development.'
)
commands = parser.add_subparsers(dest='command')
cq_parser = commands.add_parser('code-quality', help='Run various checks for coding standards.')
ti_parser = commands.add_parser('test-imports', help='Import django-ca modules to test dependencies.')
args = parser.parse_args()

_rootdir = os.path.dirname(os.path.realpath(__file__))


def setup_django(settings_module="ca.test_settings"):
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", settings_module)
    sys.path.insert(0, os.path.join(_rootdir, 'ca'))

    import django
    django.setup()


if args.command == 'code-quality':
    print('isort --check-only --diff -rc ca/ fabfile.py setup.py')
    status = subprocess.call(['isort', '--check-only', '--diff', '-rc',
                              'ca/', 'fabfile.py', 'setup.py'])
    if status != 0:
        sys.exit(status)

    print('flake8 ca/ fabfile.py setup.py')
    status = subprocess.call(['flake8', 'ca/', 'fabfile.py', 'setup.py'])
    if status != 0:
        sys.exit(status)

    print('python -Wd manage.py check')
    status = subprocess.call(['python', '-Wd', 'manage.py', 'check'], cwd=os.path.join(_rootdir, 'ca'))
    if status != 0:
        sys.exit(status)
elif args.command == 'test-imports':
    setup_django('ca.settings')

    # useful when run in docker_test, where localsettings uses YAML
    from django.conf import settings  # NOQA

    # import some modules - if any dependency is not installed, this will fail
    from django_ca import utils, models, views, extensions, subject  # NOQA
else:
    parser.print_help()

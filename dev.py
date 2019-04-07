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
dt_parser = commands.add_parser('docker-test', help='Build the Docker image using various base images.')
dt_parser.add_argument('-i', '--image', action='append', dest='images',
                       help='Base images to test on, may be given multiple times.')
dt_parser.add_argument('-c', '--cache', dest='no_cache', default='True', action='store_false',
                       help='Use Docker cache to speed up builds.')
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

    # useful when run in docker-test, where localsettings uses YAML
    from django.conf import settings  # NOQA

    # import some modules - if any dependency is not installed, this will fail
    from django_ca import utils, models, views, extensions, subject  # NOQA

elif args.command == 'docker-test':
    images = args.images or [
        'default',

        # Currently supported Alpine releases:
        #   https://wiki.alpinelinux.org/wiki/Alpine_Linux:Releases

        'python:2.7-alpine3.9',
        'python:3.5-alpine3.9',
        'python:3.6-alpine3.9',
        'python:3.7-alpine3.9',
        'python:2.7-alpine3.8',
        'python:3.5-alpine3.8',
        'python:3.6-alpine3.8',
        'python:3.7-alpine3.8',
        'python:2.7-alpine3.7',
        'python:3.5-alpine3.7',
        'python:3.6-alpine3.7',
        'python:3.7-alpine3.7',
    ]

    for image in images:
        print('### Testing %s ###' % image)
        tag = 'django-ca-test-%s' % image

        cmd = ['docker', 'build', ]

        if args.no_cache:
            cmd.append('--no-cache')
        if image != 'default':
            cmd += ['--build-arg', 'IMAGE=%s' % image, ]

        cmd += ['-t', tag, ]
        cmd.append('.')

        print(' '.join(cmd))

        try:
            subprocess.check_call(cmd)
        except Exception:
            print('### Failed image is %s' % image)
        finally:
            subprocess.call(['docker', 'image', 'rm', tag])
else:
    parser.print_help()

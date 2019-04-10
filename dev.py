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
import warnings

import coverage
import cryptography
import django
import packaging.version

PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3

suites_parser = argparse.ArgumentParser(add_help=False)
suites_parser.add_argument('-s', '--suites', action='append', default=[], nargs='+',
                           help="Modules to test (e.g. tests_modules).")

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

test_parser = commands.add_parser('test', parents=[suites_parser])
test_parser.add_argument('--recreate-fixtures', action='store_true', default=False,
                         help="Recreate fixtures")

cov_parser = commands.add_parser('coverage', parents=[suites_parser])
cov_parser.add_argument('--fail-under', type=int, default=100, metavar='[0-100]',
                        help='Fail if coverage is below given percentage (default: %(default)s%%).')

args = parser.parse_args()

_rootdir = os.path.dirname(os.path.realpath(__file__))


def setup_django(settings_module="ca.test_settings"):
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", settings_module)
    sys.path.insert(0, os.path.join(_rootdir, 'ca'))

    django.setup()


def test(suites):
    warnings.filterwarnings(action='always')
    warnings.filterwarnings(action='error', module='django_ca')

    # ignore this warning in some modules to get cleaner output
    msg = "Using or importing the ABCs from 'collections' instead of from 'collections.abc' is deprecated"
    warnings.filterwarnings(action='ignore', category=DeprecationWarning, module='webtest.lint',
                            message=msg)
    warnings.filterwarnings(action='ignore', category=DeprecationWarning, module='markupsafe',
                            message=msg)
    warnings.filterwarnings(action='ignore', category=DeprecationWarning, module='jinja2',
                            message=msg)

    work_dir = os.path.join(_rootdir, 'ca')

    os.chdir(work_dir)
    sys.path.insert(0, work_dir)

    suites = ['django_ca.tests.%s' % s for s in suites]

    from django.core.management import call_command
    call_command('test', *suites)


def exclude_versions(cov, sw, this_version, version, version_str):
    if version == this_version:
        cov.exclude(r'(pragma|PRAGMA)[:\s]?\s*only %s>%s' % (sw, version_str))
        cov.exclude(r'(pragma|PRAGMA)[:\s]?\s*only %s<%s' % (sw, version_str))
    else:
        cov.exclude(r'(pragma|PRAGMA)[:\s]?\s*only %s==%s' % (sw, version_str))

        if version > this_version:
            cov.exclude(r'(pragma|PRAGMA)[:\s]?\s*only %s>=%s' % (sw, version_str))
            cov.exclude(r'(pragma|PRAGMA)[:\s]?\s*only %s>%s' % (sw, version_str))

        if version < this_version:
            cov.exclude(r'(pragma|PRAGMA)[:\s]?\s*only %s<=%s' % (sw, version_str))
            cov.exclude(r'(pragma|PRAGMA)[:\s]?\s*only %s<%s' % (sw, version_str))


if args.command == 'test':
    setup_django()
    if args.recreate_fixtures:
        os.environ['UPDATE_FIXTURES'] = '1'
        test(['tests_managers'])
    else:
        test(args.suites)
elif args.command == 'coverage':
    report_dir = os.path.join(_rootdir, 'docs', 'build', 'coverage')
    cov = coverage.Coverage(cover_pylib=False, branch=True, source=['django_ca'],
                            omit=['*migrations/*', '*/tests/tests*', ])

    # exclude python-version specific code
    if PY2:
        cov.exclude('only py3')
    else:
        cov.exclude('only py2')

    # exclude code that requires SCT
    from cryptography.hazmat.backends import default_backend
    if not default_backend()._lib.CRYPTOGRAPHY_OPENSSL_110F_OR_GREATER:
        cov.exclude(r'pragma:\s*only SCT')

    # exclude django-version specific code
    django_versions = [(1, 11), (2, 0), (2, 1), (2, 2), (2, 3)]

    for version in django_versions:
        version_str = '.'.join([str(v) for v in version])
        exclude_versions(cov, 'django', django.VERSION[:2], version, version_str)

    # exclude cryptography-version specific code
    this_version = packaging.version.parse(cryptography.__version__).release[:2]
    cryptography_versions = [(2, 2), (2, 3), (2, 4), (2, 5), (2, 6)]
    for ver in cryptography_versions:
        version_str = '.'.join([str(v) for v in ver])
        exclude_versions(cov, 'cryptography', this_version, ver, version_str)

    cov.start()

    setup_django()
    test(args.suites)

    cov.stop()
    cov.save()

    total_coverage = cov.html_report(directory=report_dir)
    if total_coverage < args.fail_under:
        if args.fail_under == 100.0:
            print('Error: Coverage was only %.2f%% (should be 100%%).' % total_coverage)
        else:
            print('Error: Coverage was only %.2f%% (should be above %.2f%%).' % (
                total_coverage, args.fail_under))
        sys.exit(2)  # coverage cli utility also exits with 2

elif args.command == 'code-quality':
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

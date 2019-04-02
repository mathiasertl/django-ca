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

import os
import subprocess
import sys

from setuptools import Command
from setuptools import setup

long_description = """django-ca is a tool to manage TLS certificate authorities and easily issue and revoke
certificates. It is based `cryptography <https://cryptography.io/>`_ and `Django
<https://www.djangoproject.com/>`_. It can be used as an app in an existing Django project or stand-alone with
the basic project included.  Everything can be managed via the command line via `manage.py` commands - so no
webserver is needed, if you’re happy with the command-line.

Features:

* Set up a secure local certificate authority in just a few minutes.
* Written in Python 2.7/Python3.5+, requires Django 1.11 or later.
* Manage your entire certificate authority from the command line and/or via Djangos admin
  interface.
* Get email notifications about certificates about to expire.
* Certificate validation using Certificate Revocation Lists (CRLs) and via an included OCSP
  responder.

Please see https://django-ca.readthedocs.org for more extensive documentation.
"""

PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3
_rootdir = os.path.dirname(os.path.realpath(__file__))

install_requires = [
    'asn1crypto>=0.24.0',
    'cryptography>=2.2',
    'django-object-actions>=1.0',
    'idna>=2.6',
    'ocspbuilder>=0.10.2',
    'oscrypto>=0.19.0',
    'packaging',
]

if PY2:
    install_requires.append('ipaddress>=1.0.18')
    install_requires.append('Django>=1.11,<2.0')
else:
    install_requires.append('Django>=1.11')


class BaseCommand(Command):
    user_options = [
        ('suite=', None, 'Testsuite to run', ),
        ('count=', None, 'Number of times to run the test-suite', ),
    ]

    def initialize_options(self):
        self.suite = ''
        self.count = '1'

    def finalize_options(self):
        pass

    def run_tests(self):
        import warnings
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

        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ca.test_settings")
        import django
        django.setup()

        suite = 'django_ca'
        if self.suite:
            suite += '.tests.%s' % self.suite

        from django.core.management import call_command
        for i in range(0, int(self.count)):
            call_command('test', suite)


class TestCommand(BaseCommand):
    description = 'Run the test-suite for django-ca.'

    def run(self):
        self.run_tests()


class CoverageCommand(BaseCommand):
    description = 'Generate test-coverage for django-ca.'

    user_options = [
        ('fail-under=', None, 'Fail if coverage is below given percentage (default: 100%).', ),
    ] + BaseCommand.user_options

    def initialize_options(self):
        # NOTE: super() doesn't work here in py2 for some reason.
        #super(CoverageCommand, self).initialize_options()
        self.suite = ''
        self.count = '1'
        self.fail_under = 100

    def finalize_options(self):
        #super(CoverageCommand, self).finalize_options()
        self.fail_under = float(self.fail_under)

    def exclude_versions(self, cov, sw, this_version, version, version_str):
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

    def run(self):
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ca.test_settings")

        work_dir = os.path.join(_rootdir, 'ca')
        report_dir = os.path.join(_rootdir, 'docs', 'build', 'coverage')
        os.chdir(work_dir)

        import coverage

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
        from django import VERSION
        django_versions = [(1, 11), (2, 0), (2, 1), (2, 2), (2, 3)]
        this_version = VERSION[:2]

        for version in django_versions:
            version_str = '.'.join([str(v) for v in version])
            self.exclude_versions(cov, 'django', this_version, version, version_str)

        # exclude cryptography-version specific code
        import cryptography
        from packaging import version
        this_version = version.parse(cryptography.__version__).release[:2]
        cryptography_versions = [(2, 2), (2, 3), (2, 4), (2, 5), (2, 6)]
        for ver in cryptography_versions:
            version_str = '.'.join([str(v) for v in ver])
            self.exclude_versions(cov, 'cryptography', this_version, ver, version_str)

        cov.start()

        self.run_tests()

        cov.stop()
        cov.save()

        total_coverage = cov.html_report(directory=report_dir)
        if total_coverage < self.fail_under:
            if self.fail_under == 100.0:
                print('Error: Coverage was only %.2f%% (should be 100%%).' % total_coverage)
            else:
                print('Error: Coverage was only %.2f%% (should be above %.2f%%).' % (
                    total_coverage, self.fail_under))
            sys.exit(2)  # coverage cli utility also exits with 2


class RecreateFixturesCommand(BaseCommand):
    description = 'Recreate some certificate fixtures.'

    def run(self):
        os.environ['UPDATE_FIXTURES'] = '1'
        self.suite = 'tests_managers'
        self.run_tests()


class QualityCommand(Command):
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ca.test_settings")

        print('isort --check-only --diff -rc ca/ fabfile.py setup.py')
        status = subprocess.call(['isort', '--check-only', '--diff', '-rc',
                                  'ca/', 'fabfile.py', 'setup.py'])
        if status != 0:
            sys.exit(status)

        print('flake8 ca/ fabfile.py setup.py')
        status = subprocess.call(['flake8', 'ca/', 'fabfile.py', 'setup.py'])
        if status != 0:
            sys.exit(status)

        work_dir = os.path.join(_rootdir, 'ca')

        os.chdir(work_dir)
        print('python -Wd manage.py check')
        status = subprocess.call(['python', '-Wd', 'manage.py', 'check'])
        if status != 0:
            sys.exit(status)


class DockerTest(Command):
    user_options = [
        ('base=', None, 'Only build from specified base image.'),
    ]

    def initialize_options(self):
        self.base = None

    def finalize_options(self):
        pass

    def run_image(self, image='default'):
        print('### Testing %s ###' % image)
        tag = 'django-ca-test-%s' % image

        cmd = ['docker', 'build', '--no-cache', '-t', tag, ]
        if image != 'default':
            cmd += ['--build-arg', 'IMAGE=%s' % image, ]
        cmd.append('.')

        try:
            print(' '.join(cmd))
            subprocess.check_call(cmd)
        except Exception:
            print('### Failed image is %s' % image)
        finally:
            subprocess.call(['docker', 'image', 'rm', tag])

    def run(self):
        if self.base:
            images = [self.base]
        else:
            images = [
                'default',

                # alpine 3.9
                'python:2.7-alpine3.9',
                'python:3.5-alpine3.9',
                'python:3.6-alpine3.9',
                'python:3.7-alpine3.9',

                # alpine 3.8
                'python:2.7-alpine3.8',
                'python:3.5-alpine3.8',
                'python:3.6-alpine3.8',
                'python:3.7-alpine3.8',
            ]

        for image in images:
            self.run_image(image)


class TestImportsCommand(Command):
    description = 'Import some modules to make sure that all dependencies are installed.'
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        work_dir = os.path.join(_rootdir, 'ca')
        os.chdir(work_dir)
        sys.path.insert(0, work_dir)

        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ca.settings")
        import django
        django.setup()

        # useful when run in docker_test, where localsettings uses YAML
        from django.conf import settings  # NOQA

        # import some modules
        from django_ca import utils, models, views, extensions, subject  # NOQA


def find_package_data(dir):
    data = []
    package_root = os.path.join('ca', 'django_ca')
    for root, dirs, files in os.walk(os.path.join(package_root, dir)):
        for file in files:
            data.append(os.path.join(root, file).lstrip(package_root))
    return data


package_data = find_package_data('static') + find_package_data('templates')

setup(
    name='django-ca',
    version='1.12.0',
    description='A Django app providing a SSL/TLS certificate authority.',
    long_description=long_description,
    author='Mathias Ertl',
    author_email='mati@er.tl',
    url='https://github.com/mathiasertl/django-ca',
    packages=[
        'django_ca',
        'django_ca.management',
        'django_ca.management.commands',
        'django_ca.migrations',
        'django_ca.templatetags',
    ],
    package_dir={'': 'ca'},
    package_data={'': package_data},
    zip_safe=False,  # because of the static files
    install_requires=install_requires,
    cmdclass={
        'coverage': CoverageCommand,
        'test': TestCommand,
        'code_quality': QualityCommand,
        'docker_test': DockerTest,
        'recreate_fixtures': RecreateFixturesCommand,
        'test_imports': TestImportsCommand,
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Framework :: Django :: 1.11',
        'Framework :: Django :: 2.1',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Security :: Cryptography',
        'Topic :: Security',
    ],
)

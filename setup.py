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
import sys

from distutils.cmd import Command
from setuptools import setup


long_description = """django-ca is a small project to manage TLS certificate authorities and easily
issue certificates. It is based on `pyOpenSSL <https://pyopenssl.readthedocs.org/>`_ and `Django
<https://www.djangoproject.com/>`_. It can be used as an app in an existing Django project or
stand-alone with the basic project included. Certificates can be managed through Djangos admin
interface or via manage.py commands - so no webserver is needed, if you’re happy with the
command-line.

Features:

* Set up a secure local certificate authority in just a few minutes.
* Written in Python 2.7/Python3.4+.
* Manage your entire certificate authority from the command line and/or via Djangos admin interface.
* Get email notifications about certificates about to expire.
* Support generating for certificate revocation lists (CRLs).
* Generates index files that can be used with the openssl ocsp command for a crude OCSP service.

Please see https://django-ca.readthedocs.org for more extensive documentation.
"""

_rootdir = os.path.dirname(os.path.realpath(__file__))


class BaseCommand(Command):
    user_options = [
        ('suite=', None, 'Testsuite to run', )
    ]

    def initialize_options(self):
        self.suite = ''

    def finalize_options(self):
        pass

    def run_tests(self):
        work_dir = os.path.join(_rootdir, 'ca')

        os.chdir(work_dir)
        sys.path.insert(0, work_dir)

        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ca.settings")
        import django
        django.setup()

        suite = 'django_ca'
        if self.suite:
            suite += '.tests.%s' % self.suite

        from django.core.management import call_command
        call_command('check')
        call_command('test', suite)


class TestCommand(BaseCommand):
    description = 'Run the test-suite for django-ca.'

    def run(self):
        self.run_tests()

class CoverageCommand(BaseCommand):
    description = 'Generate test-coverage for django-ca.'

    def run(self):
        work_dir = os.path.join(_rootdir, 'ca')
        report_dir = os.path.join(_rootdir, 'docs', 'build', 'coverage')
        os.chdir(work_dir)

        import coverage

        cov = coverage.Coverage(cover_pylib=False, branch=True,
                                source=['django_ca'],
                                omit=['*migrations/*', '*/tests/tests*' ]
                               )
        cov.start()

        self.run_tests()

        cov.stop()
        cov.save()

        cov.html_report(directory=report_dir)

def find_package_data(dir):
    data = []
    package_root = os.path.join('ca', 'django_ca')
    for root, dirs, files in os.walk(os.path.join(package_root, dir)):
        for file in files:
            data.append(os.path.join(root, file).lstrip(package_root))
    return data

package_data = find_package_data('static') + \
               find_package_data('templates')

setup(
    name='django-ca',
    version='1.1.1',
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
    install_requires=[
        'Django>=1.8',
        'pyOpenSSL>=16.0',
    ],
    cmdclass={
        'coverage': CoverageCommand,
        'test': TestCommand,
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Framework :: Django :: 1.8',
        'Framework :: Django :: 1.9',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Topic :: Security :: Cryptography',
        'Topic :: Security',
    ],
)

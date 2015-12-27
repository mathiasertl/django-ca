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

from distutils.core import setup


long_description = """django-ca is a Django app that provides a SSL/TLS certificate authority. The
app can be included in any Django project or (if installed via directly via git) includes it's own
basic project.

Features::

    * Set up a secure certificate authority in just a few minutes.
    * Manage the certificate authority either via command line or the Django admin interface.
    * Written in pure Python, requires Python 3.4+.
    * Get e-mail notifications when certificates expire.
    * Generates certificate revocation lists (CRLs) and OCSP index files.
"""

setup(
    name='django-ca',
    version='1.0.0a1',
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
    ],
    package_dir={'': 'ca'},
    zip_safe=False,  # because of the static files
    install_requires=[
        'Django>=1.9',
        'pyOpenSSL>=0.15',
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Framework :: Django :: 1.9',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Topic :: Security :: Cryptography',
        'Topic :: Security',
    ],
)

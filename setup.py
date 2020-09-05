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

import os

from setuptools import setup

long_description = """django-ca is a tool to manage TLS certificate authorities and easily issue and revoke
certificates. It is based `cryptography <https://cryptography.io/>`_ and `Django
<https://www.djangoproject.com/>`_. It can be used as an app in an existing Django project or stand-alone with
the basic project included.  Everything can be managed via the command line via `manage.py` commands - so no
webserver is needed, if you’re happy with the command-line.

Features:

* Set up a secure local certificate authority in just a few minutes.
* Written in Python Python3.5+, requires Django 2.2+ or later.
* Manage your entire certificate authority from the command line and/or via Djangos admin interface.
* Get email notifications about certificates about to expire.
* Certificate validation using Certificate Revocation Lists (CRLs) and via an included OCSP responder.

Please see https://django-ca.readthedocs.org for more extensive documentation.
"""

install_requires = [
    'django>=2.2',
    'asn1crypto>=1.0.1',
    'cryptography>=2.7',
    'django-object-actions>=1.1',
    'idna>=2.8',
    'packaging',
]


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
    version='1.16.1',
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
    python_requires='>=3.5',
    zip_safe=False,  # because of the static files
    install_requires=install_requires,
    extras_require={
        'redis': ['hiredis>=1.0', 'redis>=3.2', 'django-redis-cache>=1.8.0'],
        'celery': ['celery>=4.2'],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Framework :: Django :: 2.2',
        'Framework :: Django :: 3.0',
        'Framework :: Django :: 3.1',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Security :: Cryptography',
        'Topic :: Security',
    ],
)

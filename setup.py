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

"""setuptools based setup.py file for django-ca."""

import os
import sys

from setuptools import find_packages
from setuptools import setup

BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # directory of this file

LONG_DESCRIPTION = """django-ca is a tool to manage TLS certificate authorities and easily issue and revoke
certificates. It is based `cryptography <https://cryptography.io/>`_ and `Django
<https://www.djangoproject.com/>`_. It can be used as an app in an existing Django project or stand-alone with
the basic project included.  Everything can be managed via the command line via `manage.py` commands - so no
webserver is needed, if you’re happy with the command-line.

Features:

* Set up a secure local certificate authority in just a few minutes.
* Written in Python Python3.6+, requires Django 2.2+ or later.
* Manage your entire certificate authority from the command line and/or via Djangos admin interface.
* Get email notifications about certificates about to expire.
* Certificate validation using Certificate Revocation Lists (CRLs) and via an included OCSP responder.

Please see https://django-ca.readthedocs.org for more extensive documentation.
"""

# these values are separate variables, since they are validated automatically
install_requires = [
    "Django>=2.2",
    "asn1crypto>=1.0.1",
    "cryptography>=3.0",
    "django-object-actions>=1.1",
    "idna>=2.10",
    "packaging",
    "typing-extensions; python_version < '3.8'",
]

package_path = os.path.join(BASE_DIR, "ca")
package_root = os.path.join(package_path, "django_ca")

if os.path.exists(package_path):
    sys.path.insert(0, package_path)

# https://packaging.python.org/guides/single-sourcing-package-version/
import django_ca  # NOQA: E402, pylint: disable=wrong-import-position


def find_package_data(path):
    """Find static package data for given path."""
    data = []
    prefix = len(package_root) + 1
    for root, _dirs, files in os.walk(os.path.join(package_root, path)):
        for file in files:
            data.append(os.path.join(root, file)[prefix:])
    return data


package_data = find_package_data("static") + find_package_data("templates")

setup(
    name="django-ca",
    version=django_ca.__version__,
    description="A Django app providing a SSL/TLS certificate authority.",
    long_description=LONG_DESCRIPTION,
    author="Mathias Ertl",
    author_email="mati@er.tl",
    url="https://github.com/mathiasertl/django-ca",
    packages=find_packages("ca", exclude=("ca", "django_ca.tests", "django_ca.tests.base")),
    package_dir={"": "ca"},
    package_data={"": package_data},
    python_requires=">=3.6",
    zip_safe=False,  # because of the static files
    install_requires=install_requires,
    extras_require={
        "acme": [
            "acme>=1.12",
            # https://josepy.readthedocs.io/en/stable/changelog/
            # * 1.5.0 (2020-11-03) adds support for Python 3.9
            "josepy>=1.5.0",
            "requests",
        ],
        "redis": [
            "hiredis>=1.1",  # 2.0 released: 2021-03-28
            "redis>=3.5",
            "django-redis-cache>=2.1",  # 3.0 drops support for Django 2.2
        ],
        "celery": ["celery>=5.0"],
        "mysql": ["mysqlclient>=1.4"],  # 2.0 release: 2020-07-02
        "postgres": ["psycopg2>2.8"],
    },
)

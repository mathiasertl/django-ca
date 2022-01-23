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
DOCS_DIR = os.path.join(BASE_DIR, "docs", "source")

package_path = os.path.join(BASE_DIR, "ca")
package_root = os.path.join(package_path, "django_ca")

if os.path.exists(package_path):
    sys.path.insert(0, package_path)


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
    packages=find_packages("ca", exclude=("ca", "django_ca.tests", "django_ca.tests.base")),
    package_dir={"": "ca"},
    package_data={"": package_data},
)

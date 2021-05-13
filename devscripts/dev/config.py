# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca. If not,
# see <http://www.gnu.org/licenses/>.

"""Module to parse ``pyproject.toml`` and augment with auto-generated values."""

import os

import toml


def minor_to_major(version):
    if version.count(".") == 1:
        return version
    return ".".join(version.split(".", 2)[:2])


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(os.path.dirname(BASE_DIR))
PYPROJECT_PATH = os.path.join(ROOT_DIR, "pyproject.toml")

with open(PYPROJECT_PATH) as stream:
    FULL_CONFIG = toml.load(stream)

CONFIG = FULL_CONFIG["django-ca"]["release"]
CONFIG["python-map"] = {minor_to_major(pyver): pyver for pyver in CONFIG["python"]}
CONFIG["python-major"] = [minor_to_major(pyver) for pyver in CONFIG["python"]]
CONFIG["django-map"] = {djver.rsplit(".", 1)[0]: djver for djver in CONFIG["django"]}
CONFIG["django-major"] = [djver.rsplit(".", 1)[0] for djver in CONFIG["django"]]
CONFIG["cryptography-map"] = {minor_to_major(cgver): cgver for cgver in CONFIG["cryptography"]}
CONFIG["cryptography-major"] = [minor_to_major(cgver) for cgver in CONFIG["cryptography"]]
CONFIG["idna-map"] = {minor_to_major(idnaver): idnaver for idnaver in CONFIG["idna"]}
CONFIG["idna-major"] = [minor_to_major(idnaver) for idnaver in CONFIG["idna"]]

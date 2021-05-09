#!/usr/bin/env python3
#
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

"""Script to make sure that the source code is in a consistent state."""

import difflib
import os
import sys

import toml
import yaml
from termcolor import colored

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

no_errors = 0


def check(path):
    print("* Checking %s:" % colored(path, attrs=["bold"]))


def ok(msg):
    print(colored("[OK]", "green"), msg)


def fail(msg):
    global no_errors
    no_errors += 1
    print(colored("[ERR]", "red", attrs=["bold"]), msg)


def check_travis():
    check(".travis.yml")
    with open(os.path.join(ROOT_DIR, ".travis.yml")) as stream:
        travis_config = yaml.load(stream, Loader=Loader)

    # check the list of tested python versions
    if list(sorted(travis_config["python"])) == pyver_major:
        ok("Python versions")
    else:
        fail("Python versions: Have %s, expected %s" % (list(sorted(travis_config["python"])), pyver_major))

    # check the job matrix
    expected_matrix = []
    for djver in sorted(config["django"]):
        for cgver in sorted(config["cryptography"]):
            expected_matrix.append(f"DJANGO={djver} CRYPTOGRAPHY={cgver}")

    if expected_matrix != travis_config["env"]["jobs"]:
        for line in difflib.Differ().compare(travis_config["env"]["jobs"], expected_matrix):
            print(line)
    else:
        ok("Job matrix (%s items)" % len(expected_matrix))


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)
PYPROJECT_PATH = os.path.join(os.path.dirname(BASE_DIR), "pyproject.toml")

with open(os.path.join(ROOT_DIR, "pyproject.toml")) as stream:
    data = toml.load(stream)

config = data["django-ca"]["release"]
pyver_major = list(sorted([pyver.rsplit(".", 1)[0] for pyver in config["python"]]))

check_travis()

if no_errors != 0:
    sys.exit(1)

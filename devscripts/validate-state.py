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

import configparser
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

CANONICAL_PYPI_NAMES = {
    "django": "Django",
    "cryptography": "cryptography",
}


def check(path):
    print("* Checking %s:" % colored(path, attrs=["bold"]))


def ok(msg):
    print(colored("[OK]", "green"), msg)


def minor_to_major(version):
    if version.count(".") == 1:
        return version
    return ".".join(version.split(".", 2)[:2])


def fail(msg):
    global no_errors
    no_errors += 1
    print(colored("[ERR]", "red", attrs=["bold"]), msg)


def simple_diff(what, actual, expected):
    if expected == actual:
        ok(what)
    else:
        fail(f"{what}: Have {actual}, expected {expected}.")


def check_travis():
    check(".travis.yml")
    with open(os.path.join(ROOT_DIR, ".travis.yml")) as stream:
        travis_config = yaml.load(stream, Loader=Loader)

    # check the list of tested python versions
    simple_diff("Python versions", travis_config["python"], pyver_major)

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


def check_github_actions_tests():
    relpath = os.path.join(".github", "workflows", "tests.yml")
    full_path = os.path.join(ROOT_DIR, relpath)
    check(relpath)
    with open(full_path) as stream:
        action_config = yaml.load(stream, Loader=Loader)
    matrix = action_config["jobs"]["tests"]["strategy"]["matrix"]

    simple_diff("Python versions", matrix["python-version"], pyver_major)
    simple_diff("Django versions", matrix["django-version"], config["django"])
    simple_diff("cryptography versions", matrix["cryptography-version"], config["cryptography"])


def check_tox():
    check("tox.ini")
    tox_config = configparser.ConfigParser()
    tox_config.read(os.path.join(ROOT_DIR, "tox.ini"))

    # Mapping of additional testenv specific requirements
    tox_deps = tox_config["testenv"]["deps"].splitlines()
    tox_env_reqs = dict([line.split(": ", 1) for line in tox_deps if ": " in line])

    for component in ["django", "cryptography"]:
        # First, check if there are any left over conditional settings for this component
        simple_diff(
            f"{component} conditional settings",
            [e for e in tox_env_reqs if e.startswith(component)],
            [f"{component}{major}" for major in config[f"{component}-map"]]
        )

        for major, minor in config[f"{component}-map"].items():
            name = f"{component}{major}"
            expected = f"{CANONICAL_PYPI_NAMES[component]}=={minor}"
            if name not in tox_env_reqs:
                continue  # handled in simple-diff above

            if tox_env_reqs[name] != f"{CANONICAL_PYPI_NAMES[component]}=={minor}":
                fail(f"conditional dependency for {name}: Have {tox_env_reqs[name]}, expected {expected}.")


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)
PYPROJECT_PATH = os.path.join(os.path.dirname(BASE_DIR), "pyproject.toml")

with open(os.path.join(ROOT_DIR, "pyproject.toml")) as stream:
    data = toml.load(stream)

config = data["django-ca"]["release"]
config["django-map"] = {djver.rsplit(".", 1)[0]: djver for djver in config["django"]}
config["cryptography-map"] = {minor_to_major(cgver): cgver for cgver in config["cryptography"]}

pyver_major = list(sorted([pyver.rsplit(".", 1)[0] for pyver in config["python"]]))

check_travis()
print()
check_github_actions_tests()
print()
check_tox()

if no_errors != 0:
    sys.exit(1)

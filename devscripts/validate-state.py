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
import importlib.util
import os
import sys

import yaml
from termcolor import colored

from dev.config import CONFIG
from dev.config import ROOT_DIR

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

CANONICAL_PYPI_NAMES = {
    "django": "Django",
    "cryptography": "cryptography",
    "idna": "idna",
}


def check_path(path):
    print("* Checking %s:" % colored(path, attrs=["bold"]))


def import_mod(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def ok(msg):
    print(colored("[OK]", "green"), msg)
    return 0


def minor_to_major(version):
    if version.count(".") == 1:
        return version
    return ".".join(version.split(".", 2)[:2])


def fail(msg):
    print(colored("[ERR]", "red", attrs=["bold"]), msg)
    return 1


def simple_diff(what, actual, expected) -> int:
    if expected == actual:
        return ok(what)
    else:
        return fail(f"{what}: Have {actual}, expected {expected}.")


def check(func):
    errors = func()
    if errors == 1:
        print(colored(f"{errors} error found.", "red", attrs=["bold"]))
    elif errors:
        print(colored(f"{errors} errors found.", "red", attrs=["bold"]))
    else:
        print(colored("No errors found.", "green"))
    print()  # to get a delimiter line to next check or summary
    return errors


def check_travis():
    errors = 0
    check_path(".travis.yml")
    with open(os.path.join(ROOT_DIR, ".travis.yml")) as stream:
        travis_config = yaml.load(stream, Loader=Loader)

    # check the list of tested python versions
    # NOTE: Travis needs newest job first (see .travis.yml), so we reverse expected list
    errors += simple_diff("Python versions", travis_config["python"], list(reversed(CONFIG["python-map"])))

    # check the job matrix
    expected_matrix = []
    for djver in sorted(CONFIG["django"]):
        for cgver in sorted(CONFIG["cryptography"]):
            expected_matrix.append(f"DJANGO={djver} CRYPTOGRAPHY={cgver}")

    if expected_matrix != travis_config["env"]["jobs"]:
        errors += 1
        for line in difflib.Differ().compare(travis_config["env"]["jobs"], expected_matrix):
            print(line)
    else:
        ok("Job matrix (%s items)" % len(expected_matrix))
    return errors


def check_github_actions_tests():
    relpath = os.path.join(".github", "workflows", "tests.yml")
    full_path = os.path.join(ROOT_DIR, relpath)
    check_path(relpath)
    with open(full_path) as stream:
        action_config = yaml.load(stream, Loader=Loader)
    matrix = action_config["jobs"]["tests"]["strategy"]["matrix"]

    errors = simple_diff("Python versions", matrix["python-version"], list(CONFIG["python-map"]))
    errors += simple_diff("Django versions", matrix["django-version"], CONFIG["django"])
    errors += simple_diff("cryptography versions", matrix["cryptography-version"], CONFIG["cryptography"])
    return errors


def check_tox():
    errors = 0
    check_path("tox.ini")
    tox_config = configparser.ConfigParser()
    tox_config.read(os.path.join(ROOT_DIR, "tox.ini"))

    # Mapping of additional testenv specific requirements
    tox_deps = tox_config["testenv"]["deps"].splitlines()
    tox_env_reqs = dict([line.split(": ", 1) for line in tox_deps if ": " in line])

    # Check that there is a testenv listing all versions
    expected_envlist = "py{%s}-django{%s}-cryptography{%s}-idna{%s}" % (
        ",".join([pyver.replace(".", "") for pyver in CONFIG["python-map"]]),
        ",".join(CONFIG["django-map"]),
        ",".join(CONFIG["cryptography-map"]),
        ",".join(CONFIG["idna-map"]),
    )
    if expected_envlist not in tox_config["tox"]["envlist"].splitlines():
        errors += fail("Expected envlist item not found: %s" % expected_envlist)

    # Check that conditional dependencies are up to date
    for component in ["django", "cryptography", "idna"]:
        # First, check if there are any left over conditional settings for this component
        errors += simple_diff(
            f"{component} conditional dependencies present",
            [e for e in tox_env_reqs if e.startswith(component)],
            [f"{component}{major}" for major in CONFIG[f"{component}-map"]],
        )

        for major, minor in CONFIG[f"{component}-map"].items():
            name = f"{component}{major}"
            actual = tox_env_reqs[name]
            expected = f"{CANONICAL_PYPI_NAMES[component]}=={minor}"
            if name not in tox_env_reqs:
                continue  # handled in simple-diff above

            if actual != expected:
                errors += fail(f"conditional dependency for {name}: Have {actual}, expected {expected}.")

    return errors


def check_setup_cfg():
    check_path("setup.cfg")
    errors = 0

    setup_config = configparser.ConfigParser()
    setup_config.read(os.path.join(ROOT_DIR, "setup.cfg"))

    # parse data from setup.cfg
    classifiers = setup_config["metadata"]["classifiers"].strip().splitlines()
    install_requires = setup_config["options"]["install_requires"].strip().splitlines()

    # validate that we have the proper language/django classifiers
    for pyver in CONFIG["python-map"]:
        if f"Programming Language :: Python :: {pyver}" not in classifiers:
            errors += fail(f"Python {pyver} classifier not found.")
    for djver in CONFIG["django-map"]:
        if f"Framework :: Django :: {djver}" not in classifiers:
            errors += fail(f"Django {djver} classifier not found.")

    expected_py_req = ">=%s" % CONFIG["python-major"][0]
    actual_py_req = setup_config["options"]["python_requires"]
    if actual_py_req != expected_py_req:
        errors += fail(f"python_requires: Have {actual_py_req}, expected {expected_py_req}")

    expected_django_req = "Django>=%s" % CONFIG["django-major"][0]
    if expected_django_req not in install_requires:
        errors += fail(f"{expected_django_req}: Expected Django requirement not found.")

    expected_cg_req = "cryptography>=%s" % CONFIG["cryptography-major"][0]
    if expected_cg_req not in install_requires:
        errors += fail(f"{expected_cg_req}: Expected cryptography requirement not found.")

    expected_idna_req = "idna>=%s" % CONFIG["idna-major"][0]
    if expected_idna_req not in install_requires:
        errors += fail(f"{expected_idna_req}: Expected idna requirement not found.")

    return errors


def check_test_settings():
    relpath = os.path.join("ca", "ca", "test_settings.py")
    fullpath = os.path.join(ROOT_DIR, relpath)
    check_path(relpath)
    errors = 0

    test_settings = import_mod("test_settings", fullpath)
    for component in ["python", "django", "cryptography"]:
        config_key = f"{component}-map"
        setting = f"NEWEST_{component.upper()}_VERSION"
        value = getattr(test_settings, setting)
        expected = tuple(int(e) for e in list(CONFIG[config_key])[-1].split("."))
        if value == expected:
            ok(f"{setting} = {value}")
        else:
            errors += fail(f"{setting}: Have {value}, expected {expected}")

    return errors


total_errors = check(check_travis)
total_errors += check(check_github_actions_tests)
total_errors += check(check_tox)
total_errors += check(check_setup_cfg)
total_errors += check(check_test_settings)

if total_errors != 0:
    print(colored("A total of %s error(s) found!" % total_errors, "red", attrs=["bold"]))
    sys.exit(1)
else:
    print(colored("Congratulations. All clean.", "green"))

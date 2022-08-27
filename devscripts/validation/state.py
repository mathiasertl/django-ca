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
import importlib.util
import os
import re
import sys
from pathlib import Path

import yaml
from setuptools.config.setupcfg import read_configuration
from termcolor import colored

from devscripts import config
from devscripts.out import err
from devscripts.out import ok

# pylint: enable=no-name-in-module

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

CANONICAL_PYPI_NAMES = {
    "acme": "acme",
    "cryptography": "cryptography",
    "django": "Django",
    "josepy": "josepy",
}


def get_expected_version_line(project_config):
    """Get expected string for README and intro.rst."""
    min_pyver = project_config["python-major"][0]
    min_djver = project_config["django-major"][0]
    min_cgver = project_config["cryptography-major"][0]
    return f"Written in Python {min_pyver}+, Django {min_djver}+ and cryptography {min_cgver}+."


def check_path(path):
    """Output the path to check."""
    print(f"* Checking {colored(path, attrs=['bold'])}")


def import_mod(name, path):
    """Import the module from the given path."""
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def simple_diff(what, actual, expected) -> int:
    """Simply compare two values and output any difference."""
    if expected == actual:
        return ok(what)
    return err(f"{what}: Have {actual}, expected {expected}.")


def check(func, *args, **kwargs):
    """Run a given check."""
    errors = func(*args, **kwargs)
    if errors == 1:
        print(colored(f"{errors} error found.", "red", attrs=["bold"]))
    elif errors:
        print(colored(f"{errors} errors found.", "red", attrs=["bold"]))
    else:
        print(colored("No errors found.", "green"))
    print()  # to get a delimiter line to next check or summary
    return errors


def check_github_actions_tests(project_config):
    """Check github actions."""
    relpath = os.path.join(".github", "workflows", "tests.yml")
    full_path = os.path.join(config.ROOT_DIR, relpath)
    check_path(relpath)
    with open(full_path, encoding="utf-8") as stream:
        action_config = yaml.load(stream, Loader=Loader)
    matrix = action_config["jobs"]["tests"]["strategy"]["matrix"]

    errors = simple_diff("Python versions", matrix["python-version"], list(project_config["python-map"]))
    errors += simple_diff("Django versions", matrix["django-version"], project_config["django"])
    errors += simple_diff(
        "cryptography versions", matrix["cryptography-version"], project_config["cryptography"]
    )
    return errors


def check_tox(project_config):
    """Check tox.ini."""
    errors = 0
    check_path("tox.ini")
    tox_config = configparser.ConfigParser()
    tox_config.read(os.path.join(config.ROOT_DIR, "tox.ini"))

    # Mapping of additional testenv specific requirements
    tox_deps = tox_config["testenv"]["deps"].splitlines()
    tox_env_reqs = dict([line.split(": ", 1) for line in tox_deps if ": " in line])

    # Check that there is a testenv listing all versions
    # pylint: disable=consider-using-f-string  # this line is just ugly otherwise
    # expected_envlist = "py{%s}-django{%s}-cryptography{%s}-acme{%s}-idna{%s}" % (
    #    ",".join([pyver.replace(".", "") for pyver in CONFIG["python-map"]]),
    #    ",".join(CONFIG["django-map"]),
    #    ",".join(CONFIG["cryptography-map"]),
    #    ",".join(CONFIG["acme-map"]),
    #    ",".join(CONFIG["idna-map"]),
    # )

    # pylint: enable=consider-using-f-string
    # Check disabled as long as different Django versions support different Python versions
    # if expected_envlist not in tox_config["tox"]["envlist"].splitlines():
    #    errors += err(f"Expected envlist item not found: {expected_envlist}")

    # Check that conditional dependencies are up to date
    for component in ["django", "cryptography", "acme", "josepy"]:
        # First, check if there are any left over conditional settings for this component
        errors += simple_diff(
            f"{component} conditional dependencies present",
            [e for e in tox_env_reqs if e.startswith(component)],
            [f"{component}{major}" for major in project_config[f"{component}-map"]],
        )

        for major, minor in project_config[f"{component}-map"].items():
            name = f"{component}{major}"
            try:
                actual = tox_env_reqs[name]
            except KeyError:
                errors += err(f"{name}: Conditional dependency not found.")
                continue

            expected = f"{CANONICAL_PYPI_NAMES[component]}=={minor}"
            if name not in tox_env_reqs:
                continue  # handled in simple-diff above

            if actual != expected:
                errors += err(f"conditional dependency for {name}: Have {actual}, expected {expected}.")

    return errors


def check_setup_cfg(project_config):
    """Check setup.cfg"""
    check_path("setup.cfg")
    errors = 0

    setup_config = read_configuration(os.path.join(config.ROOT_DIR, "setup.cfg"))

    # parse data from setup.cfg
    classifiers = setup_config["metadata"]["classifiers"]
    install_requires = setup_config["options"]["install_requires"]

    # validate that we have the proper language/django classifiers
    pyver_cfs = [
        m.groups(0)[0] for m in filter(None, [re.search(r"Python :: (3\.[0-9]+)$", cf) for cf in classifiers])
    ]
    if pyver_cfs != project_config["python-major"]:
        errors += err(f'Wrong python classifiers: Have {pyver_cfs}, wanted {project_config["python-major"]}')

    djver_cfs = [
        m.groups(0)[0]
        for m in filter(None, [re.search(r"Django :: ([0-9]\.[0-9]+)$", cf) for cf in classifiers])
    ]
    if djver_cfs != project_config["django-major"]:
        errors += err(f'Wrong python classifiers: Have {djver_cfs}, wanted {project_config["django-major"]}')

    for djver in project_config["django-map"]:
        if f"Framework :: Django :: {djver}" not in classifiers:
            errors += err(f"Django {djver} classifier not found.")

    expected_py_req = f">={project_config['python-major'][0]}"
    actual_py_req = setup_config["options"]["python_requires"]
    if actual_py_req != expected_py_req:
        errors += err(f"python_requires: Have {actual_py_req}, expected {expected_py_req}")

    expected_django_req = f"Django>={project_config['django-major'][0]}"
    if expected_django_req not in install_requires:
        errors += err(f"{expected_django_req}: Expected Django requirement not found.")

    expected_cg_req = f"cryptography>={project_config['cryptography-major'][0]}"
    if expected_cg_req not in install_requires:
        errors += err(f"{expected_cg_req}: Expected cryptography requirement not found.")

    # Do not check setup.cfg minimum dependency, as actually any version works fine right now
    # expected_idna_req = f"idna>={project_config['idna-major'][0]}"
    # if expected_idna_req not in install_requires:
    #    errors += err(f"{expected_idna_req}: Expected idna requirement not found.")

    return errors


def check_test_settings(project_config):
    """Check test_settings.py"""
    relpath = Path("ca/ca/test_settings.py")
    fullpath = config.ROOT_DIR / relpath
    check_path(relpath)
    errors = 0

    test_settings = import_mod("test_settings", fullpath)
    for component in ["python", "django", "cryptography"]:
        config_key = f"{component}-map"
        setting = f"NEWEST_{component.upper()}_VERSION"
        value = getattr(test_settings, setting)
        expected = tuple(int(e) for e in list(project_config[config_key])[-1].split("."))
        if value == expected:
            ok(f"{setting} = {value}")
        else:
            errors += err(f"{setting}: Have {value}, expected {expected}")

    return errors


def check_intro(project_config):
    """Check intro.rst (reused in a couple of places)."""
    errors = 0
    intro_path = os.path.join("docs", "source", "intro.rst")
    intro_fullpath = os.path.join(config.ROOT_DIR, intro_path)
    check_path(intro_path)
    with open(intro_fullpath, encoding="utf-8") as stream:
        intro = stream.read()

    exp_version_line = get_expected_version_line(project_config)
    if f"#. {exp_version_line}" not in intro.splitlines():
        errors += err('Does not contain correct version line ("Written in ...").')
    return errors


def check_readme(project_config):
    """Check contents of README.md."""
    errors = 0
    check_path("README.md")
    readme_fullpath = os.path.join(config.ROOT_DIR, "README.md")
    with open(readme_fullpath, encoding="utf-8") as stream:
        readme = stream.read()

    exp_version_line = get_expected_version_line(project_config)
    if f"{exp_version_line}" not in readme:
        errors += err('Does not contain correct version line ("Written in ...").')

    return errors


def validate():
    """Main function."""
    project_config = config.get_project_config()

    total_errors = check(check_github_actions_tests, project_config)
    total_errors += check(check_tox, project_config)
    total_errors += check(check_setup_cfg, project_config)
    total_errors += check(check_test_settings, project_config)
    total_errors += check(check_intro, project_config)
    total_errors += check(check_readme, project_config)
    if total_errors:
        print(colored(f"A total of {total_errors} error(s) found!", "red", attrs=["bold"]))
        sys.exit(1)
    else:
        print(colored("Congratulations. All clean.", "green"))

# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU General
# Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca. If not, see
# <http://www.gnu.org/licenses/>.

"""Script to make sure that the source code is in a consistent state."""
import argparse
import configparser
import importlib.util
import os
import re
import types
import typing
from pathlib import Path
from typing import Any, Dict, Union

import yaml
from setuptools.config.pyprojecttoml import read_configuration
from termcolor import colored

from devscripts import config
from devscripts.commands import CommandError, DevCommand
from devscripts.out import err, info, ok

if typing.TYPE_CHECKING:  # pragma: only py<3.10  # remove TYPE_CHECKING check once support for 3.9 is dropped
    # protected by TYPE_CHECKING as ParamSpec is new in Python 3.10.
    CheckFuncSpec = typing.ParamSpec("CheckFuncSpec")

# pylint: enable=no-name-in-module

CANONICAL_PYPI_NAMES = {
    "acme": "acme",
    "cryptography": "cryptography",
    "django": "Django",
}

TOX_ENV_SHORT_NAMES = {
    "cryptography": "cg",
    "django": "dj",
}


def get_expected_version_line() -> str:
    """Get expected string for README and intro.rst."""
    min_pyver = config.PYTHON_RELEASES[0]
    min_django_version = config.DJANGO[0]
    min_cryptography_version = config.CRYPTOGRAPHY[0]
    return (
        f"Written in Python {min_pyver}+, Django {min_django_version}+ and cryptography "
        f"{min_cryptography_version}+."
    )


def check_path(path: Union[str, "os.PathLike[str]"]) -> None:
    """Output the path to check."""
    print(f"* Checking {colored(str(path), attrs=['bold'])}")


def import_mod(name: str, path: Union[str, "os.PathLike[str]"]) -> types.ModuleType:
    """Import the module from the given path."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None:
        raise ValueError(f"Cannot load spec from file: {path}.{name}.")
    if spec.loader is None:
        raise ValueError(f"Spec has no loader: {path}.{name}")

    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def simple_diff(what: str, actual: Any, expected: Any) -> int:
    """Simply compare two values and output any difference."""
    if expected == actual:
        return ok(what)
    return err(f"{what}: Have {actual}, expected {expected}.")


# pragma: only py<3.10: Quoting for CheckFuncSpec, as ParamSpec was added in Python 3.10.
def check(
    func: "typing.Callable[CheckFuncSpec, int]", *args: "CheckFuncSpec.args", **kwargs: "CheckFuncSpec.kwargs"
) -> int:
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


def check_github_action_versions(job: Dict[str, Any]) -> int:
    """Check versions of/in GitHub actions."""
    errors = 0
    expected_action_versions = config.GITHUB_CONFIG["actions"]
    for step_config in job["steps"]:
        if step_uses := step_config.get("uses"):
            action, action_version = step_uses.split("@", 1)

            if expected_action_version := expected_action_versions.get(action):
                if expected_action_version != action_version:
                    errors += err(f"{action}: Have {action_version}, expected {expected_action_version}")
            else:
                info(f"{action}: action version not configured")

            if action == "actions/setup-python":
                py_version = step_config["with"]["python-version"]
                if py_version not in ("${{ matrix.python-version }}", config.PYTHON_RELEASES[-1]):
                    errors += err(f"Outdated Python version: {py_version}")
    return errors


def check_github_actions_tests() -> int:
    """Check GitHub actions."""
    errors = 0
    for workflow in Path(".github", "workflows").glob("*.yml"):
        check_path(workflow)
        with open(config.ROOT_DIR / workflow, encoding="utf-8") as stream:
            action_config = yaml.safe_load(stream)

        for job_name, job in action_config["jobs"].items():
            check_github_action_versions(job)

            if workflow.name == "tests.yml":
                matrix = job["strategy"]["matrix"]
                errors += simple_diff(
                    "Python versions", tuple(matrix["python-version"]), config.PYTHON_RELEASES
                )
                errors += simple_diff("Django versions", tuple(matrix["django-version"]), config.DJANGO)
                errors += simple_diff(
                    "cryptography versions", tuple(matrix["cryptography-version"]), config.CRYPTOGRAPHY
                )

    return errors


def check_tox() -> int:
    """Check tox.ini."""
    errors = 0
    check_path("tox.ini")
    tox_config = configparser.ConfigParser()
    tox_config.read(config.ROOT_DIR / "tox.ini")

    # Mapping of additional testenv specific requirements
    tox_deps = tox_config["testenv"]["deps"].splitlines()
    tox_env_reqs = dict([line.split(": ", 1) for line in tox_deps if ": " in line])

    # Check that there is a testenv listing all versions
    # pylint: disable-next=useless-suppression  # not useless, want to enable line eventually
    # pylint: disable=consider-using-f-string  # this line is just ugly otherwise
    expected_env_list = "py{%s}-dj{%s}-cg{%s}-acme{%s}" % (
        ",".join([pyver.replace(".", "") for pyver in config.PYTHON_RELEASES]),
        ",".join(config.DJANGO),
        ",".join(config.CRYPTOGRAPHY),
        ",".join(config.ACME),
    )

    # pylint: enable=consider-using-f-string
    # Check disabled as long as different Django versions support different Python versions
    if expected_env_list not in tox_config["tox"]["envlist"].splitlines():
        info(f"(disabled) Expected envlist item not found: {expected_env_list}")

    # Check that conditional dependencies are up-to-date
    for component in ["django", "cryptography", "acme"]:
        # First, check if there are any leftover conditional settings for this component
        short_name = TOX_ENV_SHORT_NAMES.get(component, component)
        errors += simple_diff(
            f"{component} conditional dependencies present",
            [e for e in tox_env_reqs if e.startswith(short_name)],
            [f"{short_name}{major}" for major in getattr(config, component.upper())],
        )

        for major in getattr(config, component.upper()):
            name = f"{short_name}{major}"
            try:
                actual = tox_env_reqs[name]
            except KeyError:
                errors += err(f"{name}: Conditional dependency not found.")
                continue

            expected = f"{CANONICAL_PYPI_NAMES[component]}~={major}"
            if name not in tox_env_reqs:
                continue  # handled in simple-diff above

            if actual != expected:
                errors += err(f"conditional dependency for {name}: Have {actual}, expected {expected}.")

    return errors


def check_pyproject_toml() -> int:
    """Check pyproject.toml."""
    check_path("pyproject.toml")
    errors = 0

    project_configuration = read_configuration(config.ROOT_DIR / "pyproject.toml")

    # Get data from pyproject.toml
    classifiers = project_configuration["project"]["classifiers"]

    # Get requirements - split everything after the first comma, to allow excluding single versions
    install_requires = [s.split(",")[0] for s in project_configuration["project"]["dependencies"]]

    # validate that we have the proper language/django classifiers
    pyver_cfs = tuple(
        m.groups(0)[0] for m in filter(None, [re.search(r"Python :: (3\.[0-9]+)$", cf) for cf in classifiers])
    )
    if pyver_cfs != config.PYTHON_RELEASES:
        errors += err(f"Wrong python classifiers: Have {pyver_cfs}, wanted {config.PYTHON_RELEASES}")

    djver_cfs = tuple(
        m.groups(0)[0]
        for m in filter(None, [re.search(r"Django :: ([0-9]\.[0-9]+)$", cf) for cf in classifiers])
    )
    if djver_cfs != config.DJANGO:
        errors += err(f"Wrong python classifiers: Have {djver_cfs}, wanted {config.DJANGO}")

    for djver in config.DJANGO:
        if f"Framework :: Django :: {djver}" not in classifiers:
            errors += err(f"Django {djver} classifier not found.")

    expected_py_req = f">={config.PYTHON_RELEASES[0]}"
    actual_py_req = project_configuration["project"]["requires-python"]
    if actual_py_req != expected_py_req:
        errors += err(f"python_requires: Have {actual_py_req}, expected {expected_py_req}")

    expected_django_req = f"Django>={config.DJANGO[0]}"
    if expected_django_req not in install_requires:
        errors += err(f"{expected_django_req}: Expected Django requirement not found.")

    expected_cg_req = f"cryptography>={config.CRYPTOGRAPHY[0]}"
    if expected_cg_req not in install_requires:
        errors += err(f"{expected_cg_req}: Expected cryptography requirement not found.")

    expected_acme_req = f"acme>={config.ACME[0]}"
    if expected_acme_req not in install_requires:
        errors += err(f"{expected_acme_req}: Expected acme requirement not found.")

    return errors


def check_intro() -> int:
    """Check intro.rst (reused in a couple of places)."""
    errors = 0
    intro_path = Path("docs", "source", "intro.rst")
    check_path(intro_path)
    with open(config.ROOT_DIR / intro_path, encoding="utf-8") as stream:
        intro = stream.read()

    exp_version_line = get_expected_version_line()
    if f"#. {exp_version_line}" not in intro.splitlines():
        errors += err('Does not contain correct version line ("Written in ...").')
    return errors


def check_readme() -> int:
    """Check contents of README.md."""
    errors = 0
    check_path("README.md")
    with open(config.ROOT_DIR / "README.md", encoding="utf-8") as stream:
        readme = stream.read()

    exp_version_line = get_expected_version_line()
    if f"{exp_version_line}" not in readme:
        errors += err('Does not contain correct version line ("Written in ...").')

    return errors


class Command(DevCommand):
    """Class implementing the ``dev.py validate state`` command."""

    help_text = "Validate state of various configuration and documentation files."

    def handle(self, args: argparse.Namespace) -> None:
        total_errors = check(check_github_actions_tests)
        total_errors += check(check_tox)
        total_errors += check(check_pyproject_toml)
        total_errors += check(check_intro)
        total_errors += check(check_readme)

        if total_errors != 0:
            raise CommandError(f"A total of {total_errors} error(s) found!")

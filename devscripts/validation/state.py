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
from collections.abc import Callable
from pathlib import Path
from typing import Any, ParamSpec

import yaml
from termcolor import colored

from devscripts import config
from devscripts.commands import CommandError, DevCommand
from devscripts.out import disabled, err, info

CheckFuncSpec = ParamSpec("CheckFuncSpec")

# pylint: enable=no-name-in-module

CANONICAL_PYPI_NAMES = {
    "acme": "acme",
    "cryptography": "cryptography",
    "django": "Django",
    "pydantic": "pydantic",
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


def check_path(path: str | os.PathLike[str]) -> None:
    """Output the path to check."""
    print(f"* Checking {colored(str(path), attrs=['bold'])}")


def import_mod(name: str, path: str | os.PathLike[str]) -> types.ModuleType:
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
        return 0
    return err(f"{what}: Have {actual}, expected {expected}.")


def check(
    func: Callable[CheckFuncSpec, int], *args: CheckFuncSpec.args, **kwargs: CheckFuncSpec.kwargs
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


def check_github_action_versions(job: dict[str, Any]) -> int:
    """Check versions of/in GitHub actions."""
    errors = 0
    expected_action_versions = config.GITHUB_CONFIG["actions"]
    for step_config in job["steps"]:
        if step_uses := step_config.get("uses"):
            if step_uses.startswith("./.github/actions/"):
                continue  # local step
            if "@" not in step_uses:
                errors += err(f"{step_uses} does not have a version.")
                continue
            action, action_version = step_uses.split("@", 1)

            if expected_action_version := expected_action_versions.get(action):
                if expected_action_version != action_version:
                    errors += err(f"{action}: Have {action_version}, expected {expected_action_version}")
            else:
                info(f"{action}: action version not configured")

            if action == "actions/setup-python":
                py_version = str(step_config["with"]["python-version"])
                if py_version not in ("${{ matrix.python-version }}", config.NEWEST_PYTHON):
                    errors += err(f"Outdated Python version: {py_version} (newest: {config.NEWEST_PYTHON})")
    return errors


def check_github_actions_tests(release_branch: bool) -> int:  # noqa: PLR0912
    """Check GitHub actions."""
    errors = 0

    django_versions = tuple(f"{version}" for version in config.DJANGO)
    cg_versions = tuple(f"{version}" for version in config.CRYPTOGRAPHY)
    pydantic_versions = tuple(f"{version}" for version in config.PYDANTIC)

    for action_path in Path(".github", "actions").glob("*/action.yaml"):
        check_path(action_path)
        with open(config.ROOT_DIR / action_path, encoding="utf-8") as stream:
            action = yaml.safe_load(stream)
        check_github_action_versions(action["runs"])

    if release_branch:
        expected_python: tuple[str, ...] = (config.PYTHON_RELEASES[-1],)
    else:
        expected_python = config.PYTHON_RELEASES

    for workflow in Path(".github", "workflows").glob("*.yml"):
        check_path(workflow)
        with open(config.ROOT_DIR / workflow, encoding="utf-8") as stream:
            action_config = yaml.safe_load(stream)

        for _job_name, job in action_config["jobs"].items():
            errors += check_github_action_versions(job)

            if matrix := job.get("strategy", {}).get("matrix"):
                for key, values in matrix.items():
                    if key == "python-version":
                        errors += simple_diff("Python versions", tuple(values), expected_python)
                    elif key == "django-version":
                        errors += simple_diff("Django versions", tuple(values), django_versions)
                    elif key == "cryptography-version":
                        errors += simple_diff("cryptography versions", tuple(values), cg_versions)
                    elif key == "pydantic-version":
                        errors += simple_diff("Pydantic versions", tuple(values), pydantic_versions)
                    elif key == "debian-version":
                        errors += simple_diff("Debian versions", tuple(values), config.DEBIAN_RELEASES)
                    elif key == "alpine-version":
                        errors += simple_diff("Alpine versions", tuple(values), config.ALPINE_RELEASES)
                    elif key == "extra":
                        errors += simple_diff("Extras", tuple(values), tuple(config.EXTRAS))
                    elif key == "postgres-version":
                        errors += simple_diff(
                            "PostgreSQL versions", tuple(values), tuple(config.RELEASE["postgres"])
                        )
                    elif key == "mariadb-image":
                        expected = tuple(f"mysql:{version}" for version in config.RELEASE["mysql"]) + tuple(
                            f"mariadb:{version}" for version in config.RELEASE["mariadb"]
                        )
                        errors += simple_diff("MariaDB", tuple(values), expected)
                    elif key in ("os", "language", "exclude"):  # keys are ignored
                        continue
                    else:
                        info(f"{key}: Unknown matrix element with values {values}.")

            # Check any NEWEST_* environment variables
            for key, value in action_config.get("env", {}).items():
                if key == "NEWEST_PYTHON" and value != config.PYTHON_RELEASES[-1]:
                    errors += err(f"    env.NEWEST_PYTHON is {value}.")
                if key == "NEWEST_CRYPTOGRAPHY" and value != cg_versions[-1]:
                    errors += err(f"    env.NEWEST_CRYPTOGRAPHY is {value}.")
                if key == "NEWEST_PYDANTIC" and value != pydantic_versions[-1]:
                    errors += err(f"    env.NEWEST_PYDANTIC is {value}.")

    return errors


def check_tox() -> int:
    """Check tox.ini."""
    errors = 0
    check_path("tox.ini")
    tox_config = configparser.ConfigParser()
    tox_config.read(config.ROOT_DIR / "tox.ini")

    # Mapping of additional testenv specific requirements
    tox_deps = tox_config["testenv"]["dependency_groups"].splitlines()
    tox_dep_groups = dict([line.split(": ", 1) for line in tox_deps if ": " in line])

    # Check that there is a testenv listing all versions
    # pylint: disable-next=useless-suppression  # not useless, want to enable line eventually
    # pylint: disable=consider-using-f-string  # this line is just ugly otherwise
    expected_env_list = "py{{{}}}-dj{{{}}}-cg{{{}}}-acme{{{}}}-pydantic{{{}}}".format(
        ",".join([pyver.replace(".", "") for pyver in config.PYTHON_RELEASES]),
        ",".join(config.DJANGO),
        ",".join(config.CRYPTOGRAPHY),
        ",".join(config.ACME),
        ",".join(config.PYDANTIC),
    )

    # pylint: enable=consider-using-f-string
    # Check disabled as long as different Django versions support different Python versions
    if expected_env_list not in tox_config["tox"]["envlist"].splitlines():
        errors += disabled(f"Expected envlist item not found: {expected_env_list}")

    # Check that conditional dependencies are up-to-date
    for component in ["django", "cryptography", "acme", "pydantic"]:
        # First, check if there are any leftover conditional settings for this component
        short_name = TOX_ENV_SHORT_NAMES.get(component, component)
        errors += simple_diff(
            f"{component} conditional dependencies present",
            [e for e in tox_dep_groups if e.startswith(short_name)],
            [f"{short_name}{major}" for major in getattr(config, component.upper())],
        )

        for major in getattr(config, component.upper()):
            name = f"{short_name}{major}"
            try:
                actual = tox_dep_groups[name]
            except KeyError:
                errors += err(f"{name}: Conditional dependency not found.")
                continue

            expected = f"{CANONICAL_PYPI_NAMES[component]}{major}"
            if name not in tox_dep_groups:
                continue  # handled in simple-diff above

            if actual != expected:
                errors += err(f"conditional dependency for {name}: Have {actual}, expected {expected}.")

    return errors


def check_pyproject_toml(release_branch: bool) -> int:  # pylint: disable=too-many-locals
    """Check pyproject.toml."""
    check_path("pyproject.toml")
    errors = 0

    # project_configuration = config.read_configuration(config.ROOT_DIR / "pyproject.toml")
    data = config.PYPROJECT_TOML

    newest_uv = data["django-ca"]["release"]["uv"]
    if newest_uv != data["tool"]["uv"]["required-version"]:
        errors += err(f"tool.uv: Outdated uv version ({data['tool']['uv']['required-version']}).")

    # Get data from pyproject.toml
    classifiers = config.PYPROJECT_TOML["project"]["classifiers"]

    # Get requirements - split everything after the first comma, to allow excluding single versions
    install_requires = [s.split(",")[0] for s in config.PYPROJECT_TOML["project"]["dependencies"]]

    # validate that we have the proper language/django classifiers
    pyver_cfs = tuple(
        m.groups(0)[0] for m in filter(None, [re.search(r"Python :: (3\.[0-9]+)$", cf) for cf in classifiers])
    )
    if pyver_cfs != config.PYTHON_RELEASES and not release_branch:
        errors += err(f"Wrong python classifiers: Have {pyver_cfs}, wanted {config.PYTHON_RELEASES}")

    djver_cfs = tuple(
        m.groups(0)[0]
        for m in filter(None, [re.search(r"Django :: ([0-9]\.[0-9]+)$", cf) for cf in classifiers])
    )
    if djver_cfs != config.DJANGO:
        errors += err(f"Wrong Django classifiers: Have {djver_cfs}, wanted {config.DJANGO}")

    for djver in config.DJANGO:
        if f"Framework :: Django :: {djver}" not in classifiers:
            errors += err(f"Django {djver} classifier not found.")

    expected_py_req = f">={config.PYTHON_RELEASES[0]}"
    if bound := config.UPPER_BOUNDS.get("python"):
        expected_py_req += f",<{bound}"

    actual_py_req = config.PYPROJECT_TOML["project"]["requires-python"]
    if actual_py_req != expected_py_req and not release_branch:
        errors += err(f"python_requires: Have {actual_py_req}, expected {expected_py_req}")

    # Check project dependencies
    expected_django_req = f"Django>={config.DJANGO[0]}"
    if bound := config.UPPER_BOUNDS.get("django"):
        expected_py_req += f",<{bound}"

    if expected_django_req not in install_requires:
        # Check currently disabled due to python version specific qualifiers
        errors += disabled(f"{expected_django_req}: Expected Django requirement not found.")

    expected_cg_req = f"cryptography>={config.CRYPTOGRAPHY[0]}"
    if bound := config.UPPER_BOUNDS.get("cryptography"):
        expected_py_req += f",<{bound}"
    if expected_cg_req not in install_requires:
        errors += err(f"{expected_cg_req}: Expected cryptography requirement not found.")

    expected_acme_req = f"acme>={config.ACME[0]}"
    if expected_acme_req not in install_requires:
        errors += err(f"{expected_acme_req}: Expected acme requirement not found.")
    if bound := config.UPPER_BOUNDS.get("acme"):
        expected_py_req += f",<{bound}"

    # Check dependency groups used in  tox and GitHub Actions.
    for sw, versions in {
        "Django": config.DJANGO,
        "cryptography": config.CRYPTOGRAPHY,
        "acme": config.ACME,
        "pydantic": config.PYDANTIC,
    }.items():
        actual_groups = [g for g in config.PYPROJECT_TOML["dependency-groups"] if g.startswith(sw)]
        expected_groups = [f"{sw}{version}" for version in versions]
        if sw == "Django":
            expected_groups.append("DjangoLTS")

        if sorted(actual_groups) != sorted(expected_groups):
            errors += err(
                f"{sw}: Unexpected dependency groups. Got: {actual_groups}, expected: {expected_groups}"
            )
            continue

        dependency_groups = config.PYPROJECT_TOML["dependency-groups"]
        for version in versions:
            expected_group_key = f"{sw}{version}"
            expected_group = [f"{sw}~={version}.0"]
            dependency_group = dependency_groups[expected_group_key]
            if actual_group := [group.split(";")[0].strip() for group in dependency_group]:
                if actual_group != expected_group:
                    errors += err(f"{expected_group_key}: Depends on {actual_group}.")
            else:
                errors += err(f"{expected_group_key}: Dependency group not found.")

    return errors


def check_intro(release_branch: bool) -> int:
    """Check intro.rst (reused in a couple of places)."""
    errors = 0
    intro_path = Path("docs", "source", "intro.rst")
    check_path(intro_path)
    if release_branch:
        return errors

    with open(config.ROOT_DIR / intro_path, encoding="utf-8") as stream:
        intro = stream.read()

    exp_version_line = get_expected_version_line()
    if f"#. {exp_version_line}" not in intro.splitlines():
        errors += err('Does not contain correct version line ("Written in ...").')
    return errors


def check_readme(release_branch: bool) -> int:
    """Check contents of README.md."""
    errors = 0
    check_path("README.md")
    if release_branch:
        return errors

    with open(config.ROOT_DIR / "README.md", encoding="utf-8") as stream:
        readme = stream.read()

    exp_version_line = get_expected_version_line()
    if f"{exp_version_line}" not in readme:
        errors += err('Does not contain correct version line ("Written in ...").')

    return errors


def check_dockerfile(path: str, distro: str) -> int:
    """Check the main Dockerfile for consistency."""
    errors = 0
    check_path(path)

    with open(path, encoding="utf-8") as stream:
        dockerfile = stream.read().splitlines()

    arg_lines = [line for line in dockerfile if line.lower().startswith("arg ")]
    for arg_line in arg_lines:
        match = re.match("ARG ([A-Z_]+)(=(.*))?", arg_line, re.IGNORECASE)
        if match is None:
            continue
        arg_key, _, arg_value = match.groups()

        # Validate we use the newest python and distro
        if arg_key == "IMAGE":
            if distro == "debian":
                expected_image = f"python:{config.NEWEST_PYTHON}-slim-{config.DEBIAN_RELEASES[-1]}"
                if arg_value != expected_image:
                    errors += err(f"{arg_value}: Unexpected image found (should be {expected_image}).")
            elif distro == "alpine":
                expected_image = f"python:{config.NEWEST_PYTHON}-alpine{config.ALPINE_RELEASES[-1]}"
                if arg_value != expected_image:
                    errors += err(f"{arg_value}: Unexpected image found (should be {expected_image}).")
            else:
                errors += err(f"{distro}: Unknown distro found.")

        # Validate we use the newest UV
        elif arg_key == "UV" and arg_value != config.UV:
            errors += err(f"UV build arg does not reference newest UV version ({arg_value} vs. {config.UV}).")

    return errors


def check_readthedocs() -> int:
    """Check .readthedocs.yaml."""
    errors = 0
    check_path(".readthedocs.yaml")
    with open(config.ROOT_DIR / ".readthedocs.yaml", encoding="utf-8") as stream:
        rtd_config = yaml.safe_load(stream)

    # Check Python version
    pyver = rtd_config["build"]["tools"]["python"]
    if pyver != config.NEWEST_PYTHON:
        errors += err(f"{pyver}: Old python version.")

    # check UV version
    for command in rtd_config["build"]["jobs"]["create_environment"]:
        if match := re.search(" uv (.*)", command):
            uv_version = match.groups(1)[0]
            if uv_version != config.UV:
                errors += err(f"{uv_version}: Unexpected UV version.")
    return errors


class Command(DevCommand):
    """Class implementing the ``dev.py validate state`` command."""

    help_text = "Validate state of various configuration and documentation files."

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--release-branch", action="store_true", default=False)

    def handle(self, args: argparse.Namespace) -> None:
        release_branch = args.release_branch or os.environ.get("GITHUB_REF_NAME", "").startswith("release/")

        total_errors = check(check_github_actions_tests, release_branch)
        total_errors += check(check_tox)
        total_errors += check(check_pyproject_toml, release_branch)
        total_errors += check(check_intro, release_branch)
        total_errors += check(check_readme, release_branch)
        total_errors += check(check_dockerfile, "Dockerfile", "debian")
        total_errors += check(check_dockerfile, "Dockerfile.alpine", "alpine")
        total_errors += check(check_readthedocs)

        if total_errors != 0:
            raise CommandError(f"A total of {total_errors} error(s) found!")

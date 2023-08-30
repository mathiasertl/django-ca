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

"""pytest configuration."""

import os
import sys
import typing
from typing import Any, List, Tuple

import coverage
import packaging
import pkg_resources
from _pytest.config.argparsing import Parser

import cryptography

import django
from django.conf import settings

import pytest
from pytest_cov.plugin import CovPlugin

if typing.TYPE_CHECKING:
    from _pytest.config import Config as PytestConfig


def exclude_versions(
    cov: coverage.Coverage,
    software: str,
    current_version: Tuple[int, int],
    pragma_version: Tuple[int, int],
    version_str: str,
) -> None:
    """
    Parameters
    ----------
    cov : coverage object
    software : str
    current_version
        The currently used version.
    pragma_version
        The version to add pragmas for.
    version_str:
        Same as `version` but as ``str``.
    """

    if current_version == pragma_version:
        cov.exclude(f"pragma: only {software}>{version_str}")
        cov.exclude(f"pragma: only {software}<{version_str}")

        cov.exclude(f"pragma: {software}<{version_str} branch")
        cov.exclude(f"pragma: {software}!={version_str}")

        # branches
        cov.exclude(f"pragma: {software}>={version_str}", which="partial")
        cov.exclude(f"pragma: {software}<={version_str}", which="partial")

        # completely exclude pragma branches that just don't match.
        # For example, when running python 3.9:
        #
        # if sys.version_info[:2] > (3, 9):  # pragma: py>3.9 branch
        #     print("Only python 3.10 or later")
        #
        # --> just completely exclude the block, as it is never executed
        cov.exclude(f"pragma: {software}>{version_str} branch")
        cov.exclude(f"pragma: {software}<{version_str} branch")
    else:
        cov.exclude(f"pragma: only {software}=={version_str}")
        cov.exclude(f"pragma: {software}!={version_str}", which="partial")

        if current_version < pragma_version:
            cov.exclude(f"pragma: only {software}>={version_str}")
            cov.exclude(f"pragma: only {software}>{version_str}")

            # Branches that run in the current version
            cov.exclude(f"pragma: {software}<{version_str} branch", which="partial")
            cov.exclude(f"pragma: {software}<={version_str} branch", which="partial")

            # Completely exclude branches only used in *newer* versions. For example, if you use Python 3.8:
            #
            # if sys.version_info[:2] > (3, 9):  # pragma: py>3.9 branch
            #     print("Only python 3.9 or later")
            #
            # --> The branch is never executed on Python 3.8.
            cov.exclude(f"pragma: {software}>{version_str} branch")
            cov.exclude(f"pragma: {software}>={version_str} branch")

        if current_version > pragma_version:
            cov.exclude(f"pragma: only {software}<={version_str}")
            cov.exclude(f"pragma: only {software}<{version_str}")

            # Branches that run in the current version
            cov.exclude(f"pragma: {software}>{version_str} branch", which="partial")
            cov.exclude(f"pragma: {software}>={version_str} branch", which="partial")

            # Completely exclude branches only used in *older* versions. For example, if you use Python 3.9:
            #
            # if sys.version_info[:2] < (3, 9):  # pragma: py<3.9 branch
            #     print("Only before Python 3.9")
            #
            # --> The branch is never executed on Python 3.9.
            cov.exclude(f"pragma: {software}<{version_str} branch")
            cov.exclude(f"pragma: {software}<={version_str} branch")


def setup_pragmas(cov: coverage.Coverage) -> None:
    """Setup pragmas to allow coverage exclusion based on Python/django/cryptography version."""

    # exclude python version specific code
    py_versions = [(3, 7), (3, 8), (3, 9), (3, 10), (3, 11), (3, 12), (3, 13), (3, 14)]
    for version in py_versions:
        version_str = ".".join([str(v) for v in version])
        exclude_versions(cov, "py", sys.version_info[:2], version, version_str)

    # exclude django-version specific code
    django_versions = [(3, 2), (4, 1), (4, 2), (5, 0), (5, 1)]
    for version in django_versions:
        version_str = ".".join([str(v) for v in version])
        exclude_versions(cov, "django", django.VERSION[:2], version, version_str)

    # exclude cryptography-version specific code
    this_version = typing.cast(Tuple[int, int], packaging.version.parse(cryptography.__version__).release[:2])
    cryptography_versions = [(37, 0), (38, 0), (39, 0), (40, 0), (41, 0), (42, 0), (43, 0), (44, 0)]
    for ver in cryptography_versions:
        version_str = ".".join([str(v) for v in ver])
        exclude_versions(cov, "cryptography", this_version, ver, version_str)


def pytest_addoption(parser: Parser) -> None:
    """Add some pytest options."""
    parser.addoption("--no-selenium", action="store_true", default=False, help="Do not run selenium tests.")
    parser.addoption(
        "--no-virtual-display",
        action="store_true",
        default=False,
        help="Do not run tests in virtual display.",
    )


def pytest_configure(config: "PytestConfig") -> None:
    """Output libraries, configure coverage pragmas."""
    cov_plugin: CovPlugin = config.pluginmanager.get_plugin("_cov")
    cov: coverage.Coverage = cov_plugin.cov_controller.combining_cov
    setup_pragmas(cov)

    config.addinivalue_line("markers", "selenium: mark tests that use selenium")

    skip_selenium = config.getoption("--no-selenium") or not settings.RUN_SELENIUM_TESTS

    if config.getoption("--no-virtual-display"):  # pragma: no cover
        os.environ["VIRTUAL_DISPLAY"] = "n"

    # Add a header to log important software versions
    print("Testing with:")
    print("* Python: ", sys.version.replace("\n", ""))
    # pylint: disable-next=not-an-iterable  # false positive
    installed_versions = {p.project_name: p.version for p in pkg_resources.working_set}
    for pkg in sorted(["Django", "acme", "cryptography", "celery", "idna", "josepy"]):
        print(f"* {pkg}: {installed_versions[pkg]}")
    print(f"* Selenium tests: {not skip_selenium}")

    if not os.path.exists(settings.GECKODRIVER_PATH) and not skip_selenium:  # pragma: no cover
        raise pytest.UsageError(
            f"{settings.GECKODRIVER_PATH}: Please download geckodriver to {settings.GECKODRIVER_PATH}: "
            "https://selenium-python.readthedocs.io/installation.html#drivers"
        )


def pytest_collection_modifyitems(config: "PytestConfig", items: List[Any]) -> None:  # pragma: no cover
    """Mark Selenium tests as skipped if appropriate."""
    if config.getoption("--no-selenium") or not settings.RUN_SELENIUM_TESTS:
        if config.getoption("--no-selenium"):
            reason = "--no-selenium was passed"
        else:
            reason = "Not using the newest Python/cryptography/acme."

        skip_selenium = pytest.mark.skip(reason=reason)
        for item in items:
            if "selenium" in item.keywords:
                item.add_marker(skip_selenium)

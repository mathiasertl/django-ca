import sys
import typing
from typing import Tuple

import coverage
import packaging
import pytest
from pytest_cov.plugin import CovPlugin

import cryptography

import django


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


def pytest_configure(config):
    cov_plugin: CovPlugin = config.pluginmanager.get_plugin("_cov")
    cov: coverage.Coverage = cov_plugin.cov_controller.combining_cov
    setup_pragmas(cov)

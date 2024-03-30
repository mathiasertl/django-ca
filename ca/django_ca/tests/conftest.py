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

# pylint: disable=redefined-outer-name  # requested pytest fixtures show up this way.

import importlib.metadata
import os
import sys
from collections.abc import Iterator
from typing import Any

import coverage

from django.test import Client

import pytest
from _pytest.config import Config as PytestConfig
from _pytest.config.argparsing import Parser
from _pytest.python import Metafunc
from pytest_cov.plugin import CovPlugin

from ca import settings_utils  # noqa: F401  # to get rid of pytest warnings for untested modules
from django_ca.tests.base.conftest_helpers import (
    generate_ca_fixture,
    generate_cert_fixture,
    generate_pub_fixture,
    generate_usable_ca_fixture,
    interesting_certificate_names,
    setup_pragmas,
    unusable_cert_names,
    usable_ca_names,
    usable_cert_names,
)
from django_ca.tests.base.constants import GECKODRIVER_PATH, RUN_SELENIUM_TESTS
from django_ca.tests.base.typehints import User

# NOTE: Assertion rewrites are in __init__.py

# Load fixtures from local "plugin":
pytest_plugins = ["django_ca.tests.base.fixtures"]


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

    skip_selenium = config.getoption("--no-selenium") or not RUN_SELENIUM_TESTS

    if config.getoption("--no-virtual-display"):  # pragma: no cover
        os.environ["VIRTUAL_DISPLAY"] = "n"

    # Add a header to log important software versions
    print("Testing with:")
    print("* Python: ", sys.version.replace("\n", ""))
    # pragma: only py<3.10  # p.name is available as a shortcut to p.metadata["Name"] in Python 3.10
    installed_versions = {p.metadata["Name"]: p.version for p in importlib.metadata.distributions()}
    for pkg in sorted(["Django", "acme", "cryptography", "celery", "idna", "josepy", "pydantic"]):
        print(f"* {pkg}: {installed_versions[pkg]}")
    print(f"* Selenium tests: {not skip_selenium}")
    if not skip_selenium:  # pragma: no cover
        print(f"    geckodriver at {GECKODRIVER_PATH}")

    if not os.path.exists(GECKODRIVER_PATH) and not skip_selenium:  # pragma: no cover
        raise pytest.UsageError(
            f"{GECKODRIVER_PATH}: Please download geckodriver to {GECKODRIVER_PATH}: "
            "https://selenium-python.readthedocs.io/installation.html#drivers"
        )


def pytest_collection_modifyitems(config: "PytestConfig", items: list[Any]) -> None:  # pragma: no cover
    """Mark Selenium tests as skipped if appropriate."""
    if config.getoption("--no-selenium") or not RUN_SELENIUM_TESTS:
        if config.getoption("--no-selenium"):
            reason = "--no-selenium was passed"
        else:
            reason = "Not using the newest Python/cryptography/acme."

        skip_selenium = pytest.mark.skip(reason=reason)
        for item in items:
            if "selenium" in item.keywords:
                item.add_marker(skip_selenium)


def pytest_generate_tests(metafunc: "Metafunc") -> None:
    """Pytest hook used for parametrizing fixtures."""
    if "interesting_cert" in metafunc.fixturenames:
        metafunc.parametrize("interesting_cert", interesting_certificate_names, indirect=True)


@pytest.fixture()
def user(
    # PYLINT NOTE: usefixtures() does not (yet?) work with fixtures as of pytest==7.4.3
    #   https://docs.pytest.org/en/7.4.x/how-to/fixtures.html
    #   https://github.com/pytest-dev/pytest/issues/3664
    db: None,  # pylint: disable=unused-argument
    django_user_model: type["User"],
) -> "User":
    """Fixture for a basic Django user with no extra permissions."""
    username = "user"

    try:
        user = django_user_model.objects.get_by_natural_key(username)
    except django_user_model.DoesNotExist:
        user = django_user_model.objects.create_user(username=username, password="password")
    return user


@pytest.fixture()
def user_client(user: "User", client: Client) -> Iterator[Client]:
    """A Django test client logged in as a normal user."""
    client.force_login(user)
    yield client


# Dynamically inject repetitive fixtures:
#   https://github.com/pytest-dev/pytest/issues/2424
for _ca_name in usable_ca_names:
    globals()[_ca_name] = generate_ca_fixture(_ca_name)
    globals()[f"usable_{_ca_name}"] = generate_usable_ca_fixture(_ca_name)
for _ca_name in usable_ca_names + usable_cert_names + unusable_cert_names:
    globals()[f"{_ca_name.replace('-', '_')}_pub"] = generate_pub_fixture(_ca_name)
for cert_name in usable_cert_names:
    globals()[cert_name.replace("-", "_")] = generate_cert_fixture(cert_name)

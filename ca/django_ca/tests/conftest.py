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
from typing import Any, Iterator, List

import coverage
import pkg_resources

from django.conf import settings

import pytest
from _pytest.config.argparsing import Parser
from pytest_cov.plugin import CovPlugin

from django_ca.models import Certificate
from django_ca.tests.base.conftest_helpers import (
    fixture_data,
    generate_ca_fixture,
    generate_cert_fixture,
    generate_csr_fixture,
    generate_pub_fixture,
    setup_pragmas,
)

if typing.TYPE_CHECKING:
    from _pytest.config import Config as PytestConfig
    from _pytest.fixtures import SubRequest
    from _pytest.python import Metafunc


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


def pytest_generate_tests(metafunc: "Metafunc") -> None:
    """Pytest hook used for parametrizing fixtures."""
    if "interesting_cert" in metafunc.fixturenames:
        metafunc.parametrize("interesting_cert", interesting_certificate_names, indirect=True)


@pytest.fixture()
def interesting_cert(request: "SubRequest") -> Iterator[Certificate]:
    """Parametrized fixture for "interesting" certificates.

    A function using this fixture will be called once for each interesting certificate.
    """
    yield request.getfixturevalue(request.param.replace("-", "_"))


# CAs that can be used for signing certificates
usable_ca_names = [
    name for name, conf in fixture_data["certs"].items() if conf["type"] == "ca" and conf.get("key_filename")
]
unusable_ca_names = [
    name
    for name, conf in fixture_data["certs"].items()
    if conf["type"] == "ca" and name not in usable_ca_names
]
all_ca_names = usable_ca_names + unusable_ca_names

usable_cert_names = [
    name
    for name, conf in fixture_data["certs"].items()
    if conf["type"] == "cert" and conf["cat"] == "generated"
]
unusable_cert_names = [
    name
    for name, conf in fixture_data["certs"].items()
    if conf["type"] == "cert" and name not in usable_ca_names
]
interesting_certificate_names = ["child-cert", "all-extensions", "alt-extensions", "no-extensions"]
all_cert_names = usable_cert_names + unusable_cert_names

# Dynamically inject repetitive fixtures:
#   https://github.com/pytest-dev/pytest/issues/2424
for name in usable_ca_names:
    globals()[name] = generate_ca_fixture(name)
for name in usable_ca_names + usable_cert_names:
    globals()[f"{name.replace('-', '_')}_pub"] = generate_pub_fixture(name)
for name in usable_cert_names:
    globals()[f"{name.replace('-', '_')}_csr"] = generate_csr_fixture(name)
    globals()[name.replace("-", "_")] = generate_cert_fixture(name)

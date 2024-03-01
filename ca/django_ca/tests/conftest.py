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

# pylint: disable=redefined-outer-name  # requested pytest fixtures show up this way.

"""pytest configuration."""
import copy
import importlib.metadata
import os
import sys
from pathlib import Path
from typing import Any, Iterator, List, Type

import coverage

from cryptography import x509
from cryptography.x509.oid import CertificatePoliciesOID, ExtensionOID, NameOID

from django.core.files.storage import storages
from django.test import Client

import pytest
from _pytest.config import Config as PytestConfig
from _pytest.config.argparsing import Parser
from _pytest.fixtures import SubRequest
from _pytest.python import Metafunc
from pytest_cov.plugin import CovPlugin
from pytest_django.fixtures import SettingsWrapper

from ca import settings_utils  # noqa: F401  # to get rid of pytest warnings
from django_ca import ca_settings
from django_ca.backends import key_backends
from django_ca.backends.storages import StoragesBackend
from django_ca.models import Certificate
from django_ca.profiles import profiles
from django_ca.tests.base.conftest_helpers import (
    all_cert_names,
    generate_ca_fixture,
    generate_cert_fixture,
    generate_pub_fixture,
    generate_usable_ca_fixture,
    interesting_certificate_names,
    precertificate_signed_certificate_timestamps_cert_names,
    setup_pragmas,
    signed_certificate_timestamp_cert_names,
    signed_certificate_timestamps_cert_names,
    unusable_cert_names,
    usable_ca_names,
    usable_cert_names,
)
from django_ca.tests.base.constants import GECKODRIVER_PATH, RUN_SELENIUM_TESTS
from django_ca.tests.base.typehints import User

# NOTE: Assertion rewrites are in __init__.py


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


def pytest_collection_modifyitems(config: "PytestConfig", items: List[Any]) -> None:  # pragma: no cover
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
def ca_name(request: "SubRequest") -> Iterator[str]:
    """Fixture for a name suitable for a CA."""
    yield request.node.name


@pytest.fixture()
def hostname(ca_name: str) -> Iterator[str]:
    """Fixture for a hostname.

    The value is unique for each test, and it includes the CA name, which includes the test name.
    """
    yield f"{ca_name.replace('_', '-')}.example.com"


@pytest.fixture()
def key_backend(request: "SubRequest") -> StoragesBackend:
    """Return a :py:class:`~django_ca.backends.storages.StoragesBackend` suitable for creating a new CA."""
    request.getfixturevalue("tmpcadir")
    yield key_backends[ca_settings.CA_DEFAULT_KEY_BACKEND]


@pytest.fixture()
def rfc4514_subject(subject: x509.Name) -> Iterator[str]:
    """Fixture for an RFC 4514 formatted name to use for a subject.

    The common name is based on :py:func:`~django_ca.tests.conftest.hostname` and identical to
    :py:func:`~django_ca.tests.conftest.subject`.
    """
    return x509.Name(reversed(list(subject))).rfc4514_string()


@pytest.fixture()
def subject(hostname: str) -> Iterator[x509.Name]:
    """Fixture for a :py:class:`~cg:cryptography.x509.Name` to use for a subject.

    The common name is based on :py:func:`~django_ca.tests.conftest.hostname` and identical to
    :py:func:`~django_ca.tests.conftest.rfc4514_subject`.
    """
    yield x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "AT"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Vienna"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Vienna"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Django CA"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Django CA Testsuite"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"subject.{hostname}"),
        ]
    )


@pytest.fixture()
def interesting_cert(request: "SubRequest") -> Iterator[Certificate]:
    """Parametrized fixture for "interesting" certificates.

    A function using this fixture will be called once for each interesting certificate.
    """
    yield request.getfixturevalue(request.param.replace("-", "_"))


@pytest.fixture(params=all_cert_names)
def any_cert(request: "SubRequest") -> Iterator[Certificate]:
    """Parametrized fixture for absolutely *any* certificate name."""
    yield request.param


@pytest.fixture()
def user(
    # PYLINT NOTE: usefixtures() does not (yet?) work with fixtures as of pytest==7.4.3
    #   https://docs.pytest.org/en/7.4.x/how-to/fixtures.html
    #   https://github.com/pytest-dev/pytest/issues/3664
    db: None,  # pylint: disable=unused-argument
    django_user_model: Type["User"],
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


@pytest.fixture()
def tmpcadir(tmp_path: Path, settings: SettingsWrapper) -> Iterator[SettingsWrapper]:
    """Fixture to create a temporary directory for storing files using the storages backend."""
    settings.CA_DIR = str(tmp_path)

    # Set the full setting and do **not** update the setting in place. This *somehow* makes a difference.
    orig_storages = copy.deepcopy(settings.STORAGES)
    updated_storages = copy.deepcopy(settings.STORAGES)
    updated_storages["django-ca"]["OPTIONS"]["location"] = str(tmp_path)
    settings.STORAGES = updated_storages

    # Reset profiles, so that they are loaded again on first access
    profiles._reset()  # pylint: disable=protected-access

    try:
        yield settings
    finally:
        profiles._reset()  # pylint: disable=protected-access

        # Reset storages, otherwise the path lives into the next test in some cases
        # pylint: disable-next=protected-access  # only way to reset this
        storages._storages = {}  # type: ignore[attr-defined]  # not defined in django-stubs
        settings.STORAGES = orig_storages


# CAs that can be used for signing certificates

# Dynamically inject repetitive fixtures:
#   https://github.com/pytest-dev/pytest/issues/2424
for _ca_name in usable_ca_names:
    globals()[_ca_name] = generate_ca_fixture(_ca_name)
    globals()[f"usable_{_ca_name}"] = generate_usable_ca_fixture(_ca_name)
for _ca_name in usable_ca_names + usable_cert_names + unusable_cert_names:
    globals()[f"{_ca_name.replace('-', '_')}_pub"] = generate_pub_fixture(_ca_name)
for cert_name in usable_cert_names:
    globals()[cert_name.replace("-", "_")] = generate_cert_fixture(cert_name)


@pytest.fixture(params=signed_certificate_timestamp_cert_names)
def signed_certificate_timestamp_pub(request: "SubRequest") -> Iterator[x509.Certificate]:
    """Parametrized fixture for certificates that have any SCT extension."""
    name = request.param.replace("-", "_")

    yield request.getfixturevalue(f"{name}_pub")


@pytest.fixture(params=signed_certificate_timestamps_cert_names)
def signed_certificate_timestamps_pub(
    request: "SubRequest",
) -> Iterator[x509.Certificate]:  # pragma: no cover
    """Parametrized fixture for certificates that have a SignedCertificateTimestamps extension.

    .. NOTE:: There are no certificates with this extension right now, so this fixture is in fact never run.
    """
    name = request.param.replace("-", "_")

    yield request.getfixturevalue(f"{name}_pub")


@pytest.fixture(params=precertificate_signed_certificate_timestamps_cert_names)
def precertificate_signed_certificate_timestamps_pub(request: "SubRequest") -> Iterator[x509.Certificate]:
    """Parametrized fixture for certificates that have a PrecertSignedCertificateTimestamps extension."""
    name = request.param.replace("-", "_")

    yield request.getfixturevalue(f"{name}_pub")


@pytest.fixture(
    params=(
        [x509.PolicyInformation(policy_identifier=CertificatePoliciesOID.ANY_POLICY, policy_qualifiers=None)],
        [
            x509.PolicyInformation(
                policy_identifier=CertificatePoliciesOID.ANY_POLICY, policy_qualifiers=["example"]
            )
        ],
        [
            x509.PolicyInformation(
                policy_identifier=CertificatePoliciesOID.ANY_POLICY,
                policy_qualifiers=[x509.UserNotice(notice_reference=None, explicit_text=None)],
            )
        ],
        [
            x509.PolicyInformation(
                policy_identifier=CertificatePoliciesOID.ANY_POLICY,
                policy_qualifiers=[x509.UserNotice(notice_reference=None, explicit_text="explicit text")],
            )
        ],
        [
            x509.PolicyInformation(
                policy_identifier=CertificatePoliciesOID.ANY_POLICY,
                policy_qualifiers=[
                    x509.UserNotice(
                        notice_reference=x509.NoticeReference(organization=None, notice_numbers=[]),
                        explicit_text="explicit",
                    )
                ],
            )
        ],
        [  # notice reference with org, but still empty notice numbers
            x509.PolicyInformation(
                policy_identifier=CertificatePoliciesOID.ANY_POLICY,
                policy_qualifiers=[
                    x509.UserNotice(
                        notice_reference=x509.NoticeReference(organization="MyOrg", notice_numbers=[]),
                        explicit_text="explicit",
                    )
                ],
            )
        ],
        [
            x509.PolicyInformation(
                policy_identifier=CertificatePoliciesOID.ANY_POLICY,
                policy_qualifiers=[
                    x509.UserNotice(
                        notice_reference=x509.NoticeReference(organization="MyOrg", notice_numbers=[1, 2, 3]),
                        explicit_text="explicit",
                    )
                ],
            )
        ],
        [  # test multiple qualifiers
            x509.PolicyInformation(
                policy_identifier=CertificatePoliciesOID.ANY_POLICY,
                policy_qualifiers=["simple qualifier 1", "simple_qualifier 2"],
            )
        ],
        [  # test multiple complex qualifiers
            x509.PolicyInformation(
                policy_identifier=CertificatePoliciesOID.ANY_POLICY,
                policy_qualifiers=[
                    "simple qualifier 1",
                    x509.UserNotice(
                        notice_reference=x509.NoticeReference(organization="MyOrg 2", notice_numbers=[2, 4]),
                        explicit_text="explicit 2",
                    ),
                    "simple qualifier 3",
                    x509.UserNotice(
                        notice_reference=x509.NoticeReference(organization="MyOrg 4", notice_numbers=[]),
                        explicit_text="explicit 4",
                    ),
                ],
            )
        ],
        [  # test multiple policy information
            x509.PolicyInformation(
                policy_identifier=CertificatePoliciesOID.ANY_POLICY,
                policy_qualifiers=["simple qualifier 1", "simple_qualifier 2"],
            ),
            x509.PolicyInformation(
                policy_identifier=CertificatePoliciesOID.ANY_POLICY,
                policy_qualifiers=[
                    "simple qualifier 1",
                    x509.UserNotice(
                        notice_reference=x509.NoticeReference(organization="MyOrg 2", notice_numbers=[2, 4]),
                        explicit_text="explicit 2",
                    ),
                ],
            ),
        ],
    )
)
def certificate_policies_value(request: "SubRequest") -> Iterator[x509.CertificatePolicies]:
    """Parametrized fixture with many different x509.CertificatePolicies objects."""
    yield x509.CertificatePolicies(policies=request.param)


@pytest.fixture(params=(True, False))
def certificate_policies(
    request: "SubRequest", certificate_policies_value: x509.CertificatePolicies
) -> Iterator[x509.Extension[x509.CertificatePolicies]]:
    """Parametrized fixture yielding different x509.Extension[x509.CertificatePolicies] objects."""
    yield x509.Extension(
        critical=request.param, oid=ExtensionOID.CERTIFICATE_POLICIES, value=certificate_policies_value
    )

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

"""Helpers for pytest conftest."""
import json
import os
import shutil
import sys
import typing
from typing import Any, Iterator, Optional, Tuple

import coverage
import packaging

import cryptography
from cryptography import x509
from cryptography.hazmat.primitives import serialization

import django
from django.conf import settings
from django.urls import reverse

import pytest
from _pytest.fixtures import SubRequest
from freezegun import freeze_time
from pytest_django.fixtures import SettingsWrapper

from django_ca.models import Certificate, CertificateAuthority
from django_ca.tests.base import timestamps
from django_ca.utils import int_to_hex


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


def generate_pub_fixture(name: str) -> typing.Callable[[], Iterator[x509.Certificate]]:
    """Generate fixture for a loaded public key (root_pub, root_cert_pub, ...)."""

    @pytest.fixture(scope="session")
    def fixture() -> Iterator[x509.Certificate]:
        yield load_pub(name)

    return fixture


def generate_csr_fixture(name: str) -> typing.Callable[[], Iterator[x509.CertificateSigningRequest]]:
    """Generate fixture for a loaded CSR (root_cert_csr, ...)."""

    @pytest.fixture(scope="session")
    def fixture() -> Iterator[x509.CertificateSigningRequest]:
        yield load_csr(name)

    return fixture


def generate_csr_pem_fixture(name: str) -> typing.Callable[["SubRequest"], Iterator[str]]:
    """Generate fixture for a loaded CSR (root_cert_csr, ...)."""

    @pytest.fixture(scope="session")
    def fixture(request: "SubRequest") -> Iterator[str]:
        sanitized_name = name.replace("-", "_")
        csr = request.getfixturevalue(f"{sanitized_name}_csr")
        yield csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    return fixture


def generate_ca_fixture(name: str) -> typing.Callable[["SubRequest", Any], Iterator[CertificateAuthority]]:
    """Function to generate CA fixtures (root, child, ...)."""

    @pytest.fixture()
    def fixture(
        request: "SubRequest",
        db: Any,  # pylint: disable=unused-argument,invalid-name  # usefixtures does not work for fixtures
    ) -> Iterator[CertificateAuthority]:
        data = fixture_data["certs"][name]
        pub = request.getfixturevalue(f"{name}_pub")

        # Load any parent
        parent = None
        if parent_name := data.get("parent"):
            parent = request.getfixturevalue(parent_name)

        with freeze_time(timestamps["everything_valid"]):
            ca = load_ca(name, pub, parent)

        yield ca  # NOTE: Yield must be outside the freeze-time block, or durations are wrong

    return fixture


def generate_usable_ca_fixture(
    name: str,
) -> typing.Callable[["SubRequest", SettingsWrapper], Iterator[CertificateAuthority]]:
    """Function to generate CA fixtures (root, child, ...)."""

    @pytest.fixture()
    def fixture(request: "SubRequest", tmpcadir: SettingsWrapper) -> Iterator[CertificateAuthority]:
        ca = request.getfixturevalue(name)  # load the CA into the database
        data = fixture_data["certs"][name]
        shutil.copy(os.path.join(settings.FIXTURES_DIR, data["key_filename"]), tmpcadir.CA_DIR)

        yield ca

    return fixture


def generate_cert_fixture(name: str) -> typing.Callable[["SubRequest"], Iterator[Certificate]]:
    """Function to generate cert fixtures (root_cert, all_extensions, no_extensions, ...)."""

    @pytest.fixture()
    def fixture(request: "SubRequest") -> Iterator[Certificate]:
        sanitized_name = name.replace("-", "_")
        data = fixture_data["certs"][name]
        ca = request.getfixturevalue(data["ca"])
        csr = request.getfixturevalue(f"{sanitized_name}_csr")
        pub = request.getfixturevalue(f"{sanitized_name}_pub")

        with freeze_time(timestamps["everything_valid"]):
            cert = load_cert(ca, csr, pub, data.get("profile", ""))

        yield cert  # NOTE: Yield must be outside the freeze-time block, or durations are wrong

    return fixture


def load_pub(name: str) -> x509.Certificate:
    """Load a public key from file."""
    with open(os.path.join(settings.FIXTURES_DIR, f"{name}.pub.der"), "rb") as stream:
        return x509.load_der_x509_certificate(stream.read())


def load_csr(name: str) -> x509.CertificateSigningRequest:
    """Load a CSR from file."""
    with open(os.path.join(settings.FIXTURES_DIR, f"{name}.csr"), "rb") as stream:
        return x509.load_pem_x509_csr(stream.read())


def load_ca(
    name: str, pub: x509.Certificate, parent: Optional[CertificateAuthority], **kwargs: Any
) -> CertificateAuthority:
    """Load a CA."""
    # Set default URLs
    serial = int_to_hex(pub.serial_number)
    hostname = settings.CA_DEFAULT_HOSTNAME

    crl_path = reverse("django_ca:crl", kwargs={"serial": serial})
    ocsp_path = reverse("django_ca:ocsp-cert-post", kwargs={"serial": serial})
    issuer_path = reverse("django_ca:issuer", kwargs={"serial": serial})

    kwargs.setdefault("crl_url", f"http://{hostname}{crl_path}")
    kwargs.setdefault("issuer_url", f"http://{hostname}{issuer_path}")
    kwargs.setdefault("ocsp_url", f"http://{hostname}{ocsp_path}")

    ca = CertificateAuthority(name=name, private_key_path=f"{name}.key", parent=parent, **kwargs)
    ca.update_certificate(pub)  # calculates serial etc
    ca.save()
    return ca


def load_cert(
    ca: CertificateAuthority, csr: x509.CertificateSigningRequest, pub: x509.Certificate, profile: str = ""
) -> Certificate:
    """Load a certificate from with the given CA/CSR and public key."""
    cert = Certificate(ca=ca, csr=csr, profile=profile)
    cert.update_certificate(pub)  # calculates serial etc
    cert.save()
    return cert


with open(os.path.join(settings.FIXTURES_DIR, "cert-data.json"), encoding="utf-8") as cert_data_stream:
    fixture_data = json.load(cert_data_stream)
certs = fixture_data["certs"]

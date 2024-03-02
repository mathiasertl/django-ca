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
import os
import shutil
import sys
import typing
from typing import Any, Iterator, Optional, Tuple

import coverage
import packaging

import cryptography
from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

import django
from django.conf import settings
from django.urls import reverse

import pytest
from _pytest.fixtures import SubRequest
from pytest_django.fixtures import SettingsWrapper

from django_ca import ca_settings, constants
from django_ca.models import Certificate, CertificateAuthority
from django_ca.tests.base.constants import CERT_DATA, FIXTURES_DIR
from django_ca.tests.base.utils import crl_distribution_points, distribution_point, uri
from django_ca.utils import int_to_hex


def exclude_versions(
    cov: coverage.Coverage,
    software: str,
    current_version: Tuple[int, int],
    pragma_version: Tuple[int, int],
    version_str: str,
) -> None:
    """Add pragmas to exclude lines of code if specific versions of `software` are *not* installed.

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


def generate_ca_fixture(name: str) -> typing.Callable[["SubRequest", Any], Iterator[CertificateAuthority]]:
    """Function to generate CA fixtures (root, child, ...)."""

    @pytest.fixture()
    def fixture(
        request: "SubRequest",
        db: Any,  # pylint: disable=unused-argument  # usefixtures does not work for fixtures
    ) -> Iterator[CertificateAuthority]:
        data = CERT_DATA[name]
        pub = request.getfixturevalue(f"{name}_pub")

        # Load any parent
        parent = None
        if parent_name := data.get("parent"):
            parent = request.getfixturevalue(parent_name)

        kwargs = {
            "sign_crl_distribution_points": data["sign_crl_distribution_points"],
            "sign_authority_information_access": data["sign_authority_information_access"],
        }

        ca = load_ca(name, pub, parent, **kwargs)

        yield ca  # NOTE: Yield must be outside the freeze-time block, or durations are wrong

    return fixture


def generate_usable_ca_fixture(
    name: str,
) -> typing.Callable[["SubRequest", SettingsWrapper], Iterator[CertificateAuthority]]:
    """Function to generate CA fixtures (root, child, ...)."""

    @pytest.fixture()
    def fixture(request: "SubRequest", tmpcadir: SettingsWrapper) -> Iterator[CertificateAuthority]:
        ca = request.getfixturevalue(name)  # load the CA into the database
        data = CERT_DATA[name]
        shutil.copy(os.path.join(FIXTURES_DIR, data["key_filename"]), tmpcadir.CA_DIR)

        yield ca

    return fixture


def generate_cert_fixture(name: str) -> typing.Callable[["SubRequest"], Iterator[Certificate]]:
    """Function to generate cert fixtures (root_cert, all_extensions, no_extensions, ...)."""

    @pytest.fixture()
    def fixture(request: "SubRequest") -> Iterator[Certificate]:
        sanitized_name = name.replace("-", "_")
        data = CERT_DATA[name]
        ca = request.getfixturevalue(data["ca"])
        pub = request.getfixturevalue(f"{sanitized_name}_pub")
        cert = load_cert(ca, None, pub, data.get("profile", ""))

        yield cert  # NOTE: Yield must be outside the freeze-time block, or durations are wrong

    return fixture


def load_pub(name: str) -> x509.Certificate:
    """Load a public key from file."""
    conf = CERT_DATA[name]
    if conf["cat"] == "sphinx-contrib":
        with open(conf["pub_path"], "rb") as stream:
            return x509.load_pem_x509_certificate(stream.read())
    else:
        with open(os.path.join(FIXTURES_DIR, f"{name}.pub"), "rb") as stream:
            return x509.load_der_x509_certificate(stream.read())


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

    kwargs.setdefault(
        "sign_crl_distribution_points",
        crl_distribution_points(distribution_point([uri(f"http://{hostname}{crl_path}")])),
    )
    access_descriptions = [
        x509.AccessDescription(
            access_method=AuthorityInformationAccessOID.OCSP,
            access_location=uri(f"http://{hostname}{ocsp_path}"),
        ),
        x509.AccessDescription(
            access_method=AuthorityInformationAccessOID.CA_ISSUERS,
            access_location=uri(f"http://{hostname}{issuer_path}"),
        ),
    ]

    kwargs.setdefault(
        "sign_authority_information_access",
        x509.Extension(
            oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
            critical=constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.AUTHORITY_INFORMATION_ACCESS],
            value=x509.AuthorityInformationAccess(access_descriptions),
        ),
    )

    ca = CertificateAuthority(
        name=name,
        key_backend_alias=ca_settings.CA_DEFAULT_KEY_BACKEND,
        key_backend_options={"path": f"{name}.key"},
        parent=parent,
        **kwargs,
    )
    ca.update_certificate(pub)  # calculates serial etc
    ca.full_clean()
    ca.save()
    return ca


def load_cert(
    ca: CertificateAuthority,
    csr: Optional[x509.CertificateSigningRequest],
    pub: x509.Certificate,
    profile: str = "",
) -> Certificate:
    """Load a certificate from with the given CA/CSR and public key."""
    cert = Certificate(ca=ca, csr=csr, profile=profile)
    cert.update_certificate(pub)  # calculates serial etc
    cert.save()
    return cert


# Define various classes of certificates
usable_ca_names = [
    name for name, conf in CERT_DATA.items() if conf["type"] == "ca" and conf.get("key_filename")
]
unusable_ca_names = [
    name for name, conf in CERT_DATA.items() if conf["type"] == "ca" and name not in usable_ca_names
]
all_ca_names = usable_ca_names + unusable_ca_names

usable_cert_names = [
    name for name, conf in CERT_DATA.items() if conf["type"] == "cert" and conf["cat"] == "generated"
]
unusable_cert_names = [
    name for name, conf in CERT_DATA.items() if conf["type"] == "cert" and name not in usable_ca_names
]
interesting_certificate_names = ["child-cert", "all-extensions", "alt-extensions", "no-extensions"]

signed_certificate_timestamp_cert_names = [
    name
    for name, conf in CERT_DATA.items()
    if "precertificate_signed_certificate_timestamps" in conf or "signed_certificate_timestamps" in conf
]
precertificate_signed_certificate_timestamps_cert_names = [
    name for name, conf in CERT_DATA.items() if "precertificate_signed_certificate_timestamps" in conf
]
signed_certificate_timestamps_cert_names = [
    name for name, conf in CERT_DATA.items() if "signed_certificate_timestamps" in conf
]

all_cert_names = usable_cert_names + unusable_cert_names

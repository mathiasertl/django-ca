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
from pathlib import Path
from typing import Any, cast

import coverage

from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

import django
from django.conf import settings
from django.urls import reverse

import pytest
from _pytest.fixtures import SubRequest

from django_ca import constants
from django_ca.conf import model_settings
from django_ca.models import Certificate, CertificateAuthority
from django_ca.tests.base.constants import (
    CERT_DATA,
    CRYPTOGRAPHY_VERSION,
    CRYPTOGRAPHY_VERSIONS,
    DJANGO_VERSIONS,
    FIXTURES_DIR,
    JOSEPY_VERSION,
    JOSEPY_VERSIONS,
    PYTHON_VERSIONS,
)
from django_ca.tests.base.utils import crl_distribution_points, distribution_point, uri
from django_ca.utils import int_to_hex


def exclude_versions(
    cov: coverage.Coverage,
    software: str,
    current_version: tuple[int] | tuple[int, int],
    pragma_version: tuple[int] | tuple[int, int],
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
        # For example, when running python 3.13:
        #
        # if sys.version_info[:2] > (3, 13):  # pragma: py>3.13 branch
        #     print("Only python 3.14 or later")
        #
        # --> just completely exclude the block, as it is never executed
        cov.exclude(f"pragma: {software}>{version_str} branch")
        cov.exclude(f"pragma: {software}<{version_str} branch")
    else:  # pragma: no cover  # depending on the installed versions, this might or might not happen
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
            # if sys.version_info[:2] > (3, 13):  # pragma: py>3.13 branch
            #     print("Only python 3.14 or later")
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
            # if sys.version_info[:2] < (3, 13):  # pragma: py<3.13 branch
            #     print("Only before Python 3.13")
            #
            # --> The branch is never executed on Python 3.9.
            cov.exclude(f"pragma: {software}<{version_str} branch")
            cov.exclude(f"pragma: {software}<={version_str} branch")


def setup_pragmas(cov: coverage.Coverage) -> None:
    """Setup pragmas to allow coverage exclusion based on Python/django/cryptography version."""
    # exclude python version specific code
    for version in PYTHON_VERSIONS:
        version_str = ".".join([str(v) for v in version])
        exclude_versions(cov, "py", sys.version_info[:2], version, version_str)

    # exclude django-version specific code
    for version in DJANGO_VERSIONS:
        version_str = ".".join([str(v) for v in version])
        exclude_versions(cov, "django", django.VERSION[:2], version, version_str)

    # exclude cryptography-version specific code
    for ver in CRYPTOGRAPHY_VERSIONS:
        version_str = ".".join([str(v) for v in ver])
        cg_version = cast(tuple[int], CRYPTOGRAPHY_VERSION[:1])
        exclude_versions(cov, "cryptography", cg_version, ver, version_str)

    # exclude josepy-version specific code
    for josepy_version in JOSEPY_VERSIONS:
        version_str = ".".join([str(v) for v in josepy_version])
        exclude_versions(cov, "josepy", JOSEPY_VERSION[:2], josepy_version, version_str)  # type: ignore[arg-type]


def generate_pub_fixture(name: str) -> typing.Callable[[], x509.Certificate]:
    """Generate fixture for a loaded public key (root_pub, root_cert_pub, ...)."""

    @pytest.fixture(scope="session")
    def fixture() -> x509.Certificate:
        return load_pub(name)

    return fixture


def generate_ca_fixture(name: str) -> typing.Callable[["SubRequest", Any], CertificateAuthority]:
    """Function to generate CA fixtures (root, child, ...)."""

    @pytest.fixture
    def fixture(
        request: "SubRequest",
        db: Any,  # pylint: disable=unused-argument  # usefixtures does not work for fixtures
    ) -> CertificateAuthority:
        data = CERT_DATA[name]
        ca_fixture_name = f"{name}_pub"
        if data["cat"] == "sphinx-contrib":
            ca_fixture_name = f"contrib_{ca_fixture_name}"
        pub = request.getfixturevalue(ca_fixture_name)

        # Load any parent
        parent = None
        if parent_name := data.get("parent"):
            parent = request.getfixturevalue(parent_name)

        kwargs = {
            "sign_crl_distribution_points": data.get("sign_crl_distribution_points"),
            "sign_authority_information_access": data.get("sign_authority_information_access"),
        }

        ca = load_ca(name, pub, parent, acme_enabled=True, **kwargs)

        return ca  # NOTE: Yield must be outside the freeze-time block, or durations are wrong

    return fixture


def generate_usable_ca_fixture(name: str) -> typing.Callable[["SubRequest", Path], CertificateAuthority]:
    """Function to generate CA fixtures (root, child, ...)."""

    @pytest.fixture
    def fixture(request: "SubRequest", tmpcadir: Path) -> CertificateAuthority:
        ca = request.getfixturevalue(name)  # load the CA into the database
        data = CERT_DATA[name]
        shutil.copy(os.path.join(FIXTURES_DIR, data["key_filename"]), tmpcadir)

        return ca  # type: ignore[no-any-return]

    return fixture


def generate_cert_fixture(name: str) -> typing.Callable[["SubRequest"], Certificate]:
    """Function to generate cert fixtures (root_cert, all_extensions, no_extensions, ...)."""

    @pytest.fixture
    def fixture(request: "SubRequest") -> Certificate:
        sanitized_name = name.replace("-", "_")
        data = CERT_DATA[name]

        ca_fixture_name = data["ca"]
        if data["cat"] == "sphinx-contrib":
            ca_fixture_name = f"contrib_{ca_fixture_name}"
        ca = request.getfixturevalue(ca_fixture_name)

        pub_fixture_name = f"{sanitized_name}_pub"
        if data["cat"] in ("contrib", "sphinx-contrib"):
            pub_fixture_name = f"contrib_{pub_fixture_name}"
        pub = request.getfixturevalue(pub_fixture_name)
        csr = None
        if "csr" in data:
            csr = data["csr"]["parsed"]
        cert = load_cert(ca, csr, pub, data.get("profile", ""))

        return cert  # NOTE: Yield must be outside the freeze-time block, or durations are wrong

    return fixture


def load_pub(name: str) -> x509.Certificate:
    """Load a public key from file."""
    conf = CERT_DATA[name]
    if conf["cat"] == "sphinx-contrib":
        with open(conf["pub_path"], "rb") as stream:
            return x509.load_pem_x509_certificate(stream.read())
    if conf["cat"] == "contrib":
        with open(FIXTURES_DIR / "contrib" / f"{name}.pub", "rb") as stream:
            return x509.load_der_x509_certificate(stream.read())
    else:
        with open(FIXTURES_DIR / f"{name}.pub", "rb") as stream:
            return x509.load_der_x509_certificate(stream.read())


def load_ca(
    name: str, pub: x509.Certificate, parent: CertificateAuthority | None, **kwargs: Any
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
        key_backend_alias=model_settings.CA_DEFAULT_KEY_BACKEND,
        key_backend_options={"path": f"{name}.key"},
        ocsp_key_backend_alias="default",
        parent=parent,
        **kwargs,
    )
    ca.update_certificate(pub)  # calculates serial etc
    ca.full_clean()
    ca.save()
    return ca


def load_cert(
    ca: CertificateAuthority,
    csr: x509.CertificateSigningRequest | None,
    pub: x509.Certificate,
    profile: str = "",
) -> Certificate:
    """Load a certificate from with the given CA/CSR and public key."""
    # TYPEHINT NOTE: django-stubs 5.0.0 no longer detects csr as optional field
    cert = Certificate(ca=ca, csr=csr, profile=profile)  # type: ignore[misc]
    cert.update_certificate(pub)  # calculates serial etc
    cert.save()
    return cert


# Define various classes of certificates
usable_ca_names = [
    name for name, conf in CERT_DATA.items() if conf["type"] == "ca" and conf.get("key_filename")
]
usable_ca_names_by_type = ["dsa", "root", "ed448", "ed25519", "ec"]
contrib_ca_names = [
    name for name, conf in CERT_DATA.items() if conf["type"] == "ca" and conf["cat"] == "sphinx-contrib"
]
unusable_ca_names = [
    name for name, conf in CERT_DATA.items() if conf["type"] == "ca" and name not in usable_ca_names
]
all_ca_names = usable_ca_names + unusable_ca_names

# names for certificates that are signed by CAs (e.g. root-cert, ...)
ca_cert_names = [
    f"{name}-cert" for name, conf in CERT_DATA.items() if conf["type"] == "ca" and conf.get("key_filename")
]
usable_cert_names = [
    name for name, conf in CERT_DATA.items() if conf["type"] == "cert" and conf["cat"] == "generated"
]
contrib_cert_names = [
    name
    for name, conf in CERT_DATA.items()
    if conf["type"] == "cert" and conf["cat"] in ("contrib", "sphinx-contrib")
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

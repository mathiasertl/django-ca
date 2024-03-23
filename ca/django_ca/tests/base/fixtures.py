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

"""Pytest fixtures used throughout the code base."""

# pylint: disable=redefined-outer-name  # requested pytest fixtures show up this way.

import copy
import os
from pathlib import Path
from typing import Iterator, List

from cryptography import x509
from cryptography.x509.oid import CertificatePoliciesOID, ExtensionOID, NameOID

from django.core.files.storage import storages

import pytest
from _pytest.fixtures import SubRequest
from pytest_django.fixtures import SettingsWrapper

from django_ca import ca_settings
from django_ca.key_backends import key_backends
from django_ca.key_backends.storages import StoragesBackend
from django_ca.models import Certificate, CertificateAuthority
from django_ca.tests.base.conftest_helpers import (
    all_cert_names,
    ca_cert_names,
    precertificate_signed_certificate_timestamps_cert_names,
    signed_certificate_timestamp_cert_names,
    signed_certificate_timestamps_cert_names,
    usable_ca_names,
)


@pytest.fixture(params=all_cert_names)
def any_cert(request: "SubRequest") -> Iterator[Certificate]:
    """Parametrized fixture for absolutely *any* certificate name."""
    yield request.param


@pytest.fixture()
def ca_name(request: "SubRequest") -> Iterator[str]:
    """Fixture for a name suitable for a CA."""
    yield request.node.name


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
    """Parametrized fixture with different :py:class:`~cg:cryptography.x509.CertificatePolicies` objects."""
    yield x509.CertificatePolicies(policies=request.param)


@pytest.fixture(params=(True, False))
def certificate_policies(
    request: "SubRequest", certificate_policies_value: x509.CertificatePolicies
) -> Iterator[x509.Extension[x509.CertificatePolicies]]:
    """Parametrized fixture yielding different ``x509.Extension[x509.CertificatePolicies]`` objects."""
    yield x509.Extension(
        critical=request.param, oid=ExtensionOID.CERTIFICATE_POLICIES, value=certificate_policies_value
    )


@pytest.fixture(params=("ed448", "ed25519"))
def ed_ca(request: "SubRequest") -> Iterator[CertificateAuthority]:
    """Parametrized fixture for CAs with an Edwards-curve algorithm (ed448, ed25519)."""
    yield request.getfixturevalue(f"{request.param}")


@pytest.fixture()
def hostname(ca_name: str) -> Iterator[str]:
    """Fixture for a hostname.

    The value is unique for each test, and it includes the CA name, which includes the test name.
    """
    yield f"{ca_name.replace('_', '-')}.example.com"


@pytest.fixture()
def interesting_cert(request: "SubRequest") -> Iterator[Certificate]:
    """Parametrized fixture for "interesting" certificates.

    A function using this fixture will be called once for each interesting certificate.
    """
    yield request.getfixturevalue(request.param.replace("-", "_"))


@pytest.fixture()
def key_backend(request: "SubRequest") -> Iterator[StoragesBackend]:
    """Return a :py:class:`~django_ca.key_backends.storages.StoragesBackend` for creating a new CA."""
    request.getfixturevalue("tmpcadir")
    yield key_backends[ca_settings.CA_DEFAULT_KEY_BACKEND]  # type: ignore[misc]


@pytest.fixture(params=precertificate_signed_certificate_timestamps_cert_names)
def precertificate_signed_certificate_timestamps_pub(request: "SubRequest") -> Iterator[x509.Certificate]:
    """Parametrized fixture for certificates that have a PrecertSignedCertificateTimestamps extension."""
    name = request.param.replace("-", "_")

    yield request.getfixturevalue(f"{name}_pub")


@pytest.fixture()
def rfc4514_subject(subject: x509.Name) -> Iterator[str]:
    """Fixture for an RFC 4514 formatted name to use for a subject.

    The common name is based on :py:func:`~django_ca.tests.base.fixtures.hostname` and identical to
    :py:func:`~django_ca.tests.base.fixtures.subject`.
    """
    yield x509.Name(reversed(list(subject))).rfc4514_string()


@pytest.fixture()
def secondary_backend(request: "SubRequest") -> Iterator[StoragesBackend]:
    """Return a :py:class:`~django_ca.key_backends.storages.StoragesBackend` for the secondary key backend."""
    request.getfixturevalue("tmpcadir")
    yield key_backends["secondary"]  # type: ignore[misc]


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


@pytest.fixture()
def subject(hostname: str) -> Iterator[x509.Name]:
    """Fixture for a :py:class:`~cg:cryptography.x509.Name` to use for a subject.

    The common name is based on :py:func:`~django_ca.tests.base.fixtures.hostname` and identical to
    :py:func:`~django_ca.tests.base.fixtures.rfc4514_subject`.
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
def tmpcadir(tmp_path: Path, settings: SettingsWrapper) -> Iterator[Path]:
    """Fixture to create a temporary directory for storing files using the StoragesBackend."""
    primary_directory = tmp_path / "storages" / "django-ca"
    secondary_directory = tmp_path / "storages" / "secondary"
    os.makedirs(primary_directory, exist_ok=True)
    os.makedirs(secondary_directory, exist_ok=True)

    settings.CA_DIR = str(primary_directory)

    # Set the full setting and do **not** update the setting in place. This *somehow* makes a difference.
    orig_storages = copy.deepcopy(settings.STORAGES)
    updated_storages = copy.deepcopy(settings.STORAGES)
    updated_storages["django-ca"]["OPTIONS"]["location"] = str(primary_directory)
    updated_storages["secondary"]["OPTIONS"]["location"] = str(secondary_directory)
    settings.STORAGES = updated_storages

    try:
        yield primary_directory
    finally:
        # Reset storages, otherwise the path lives into the next test in some cases
        # pylint: disable-next=protected-access  # only way to reset this
        storages._storages = {}  # type: ignore[attr-defined]  # not defined in django-stubs
        settings.STORAGES = orig_storages


@pytest.fixture(params=usable_ca_names)
def usable_ca_name(request: "SubRequest") -> Iterator[CertificateAuthority]:
    """Parametrized fixture for the name of every usable CA."""
    yield request.param


@pytest.fixture(params=usable_ca_names)
def usable_ca(request: "SubRequest") -> Iterator[CertificateAuthority]:
    """Parametrized fixture for every usable CA (with usable private key)."""
    yield request.getfixturevalue(f"usable_{request.param}")


@pytest.fixture()
def usable_cas(request: "SubRequest") -> Iterator[List[CertificateAuthority]]:
    """Fixture for all usable CAs as a list."""
    cas = []
    for name in usable_ca_names:
        cas.append(request.getfixturevalue(f"usable_{name}"))
    yield cas


@pytest.fixture(params=ca_cert_names)
def usable_cert(request: "SubRequest") -> Iterator[Certificate]:
    """Parametrized fixture for every ``{ca}-cert`` certificate."""
    cert = request.getfixturevalue(request.param.replace("-", "_"))
    request.getfixturevalue(f"usable_{cert.ca.name}")
    yield cert

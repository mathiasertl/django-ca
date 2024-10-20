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
import subprocess
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast
from unittest import mock

from cryptography import x509
from cryptography.x509.oid import CertificatePoliciesOID, ExtensionOID, NameOID

from django.conf import settings
from django.core.cache import cache
from django.core.files.storage import storages
from django.utils.crypto import get_random_string

import pytest
from _pytest.fixtures import SubRequest
from pytest_django.fixtures import SettingsWrapper

from django_ca.conf import model_settings
from django_ca.key_backends import key_backends
from django_ca.key_backends.hsm import HSMBackend
from django_ca.key_backends.hsm.models import HSMCreatePrivateKeyOptions
from django_ca.key_backends.hsm.session import SessionPool
from django_ca.key_backends.storages import StoragesBackend
from django_ca.models import Certificate, CertificateAuthority, CertificateRevocationList
from django_ca.tests.base import constants
from django_ca.tests.base.conftest_helpers import (
    all_ca_names,
    all_cert_names,
    interesting_certificate_names,
    precertificate_signed_certificate_timestamps_cert_names,
    signed_certificate_timestamp_cert_names,
    signed_certificate_timestamps_cert_names,
    usable_ca_names,
    usable_cert_names,
)
from django_ca.tests.base.constants import CERT_DATA, TIMESTAMPS


@pytest.fixture(params=all_cert_names)
def any_cert(request: "SubRequest") -> Certificate:
    """Parametrized fixture for absolutely *any* certificate name."""
    return request.param  # type: ignore[no-any-return]


@pytest.fixture
def ca_name(request: "SubRequest") -> str:
    """Fixture for a name suitable for a CA."""
    return request.node.name  # type: ignore[no-any-return]


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
def certificate_policies_value(request: "SubRequest") -> x509.CertificatePolicies:
    """Parametrized fixture with different :py:class:`~cg:cryptography.x509.CertificatePolicies` objects."""
    return x509.CertificatePolicies(policies=request.param)


@pytest.fixture(params=(True, False))
def certificate_policies(
    request: "SubRequest", certificate_policies_value: x509.CertificatePolicies
) -> x509.Extension[x509.CertificatePolicies]:
    """Parametrized fixture yielding different ``x509.Extension[x509.CertificatePolicies]`` objects."""
    return x509.Extension(
        critical=request.param, oid=ExtensionOID.CERTIFICATE_POLICIES, value=certificate_policies_value
    )


@pytest.fixture
def clear_cache() -> Iterator[None]:
    """Fixture to clear the cache after the test."""
    yield
    cache.clear()


@pytest.fixture(params=("ed448", "ed25519"))
def ed_ca(request: "SubRequest") -> CertificateAuthority:
    """Parametrized fixture for CAs with an Edwards-curve algorithm (ed448, ed25519)."""
    return request.getfixturevalue(f"{request.param}")  # type: ignore[no-any-return]


@pytest.fixture
def hostname(ca_name: str) -> str:
    """Fixture for a hostname.

    The value is unique for each test, and it includes the CA name, which includes the test name.
    """
    return f"{ca_name.replace('_', '-')}.example.com"[-64:].lstrip("-.")


@pytest.fixture(params=interesting_certificate_names)
def interesting_cert(request: "SubRequest") -> Certificate:
    """Parametrized fixture for "interesting" certificates.

    A function using this fixture will be called once for each certificate with unusual extensions.
    """
    return request.getfixturevalue(request.param.replace("-", "_"))  # type: ignore[no-any-return]


@pytest.fixture
def key_backend(request: "SubRequest") -> StoragesBackend:
    """Return a :py:class:`~django_ca.key_backends.storages.StoragesBackend` for creating a new CA."""
    request.getfixturevalue("tmpcadir")
    return key_backends[model_settings.CA_DEFAULT_KEY_BACKEND]  # type: ignore[return-value]


@pytest.fixture(params=precertificate_signed_certificate_timestamps_cert_names)
def precertificate_signed_certificate_timestamps_pub(request: "SubRequest") -> x509.Certificate:
    """Parametrized fixture for certificates that have a PrecertSignedCertificateTimestamps extension."""
    name = request.param.replace("-", "_")
    return request.getfixturevalue(f"contrib_{name}_pub")  # type: ignore[no-any-return]


@pytest.fixture
def rfc4514_subject(subject: x509.Name) -> str:
    """Fixture for an RFC 4514 formatted name to use for a subject.

    The common name is based on :py:func:`~django_ca.tests.base.fixtures.hostname` and identical to
    :py:func:`~django_ca.tests.base.fixtures.subject`.
    """
    return x509.Name(reversed(list(subject))).rfc4514_string()


@pytest.fixture
def root_crl(root: CertificateAuthority) -> CertificateRevocationList:
    """Fixture for the global CRL object for the Root CA."""
    with open(constants.FIXTURES_DIR / "root.crl", "rb") as stream:
        crl_data = stream.read()
    last_update = TIMESTAMPS["everything_valid"]
    next_update = last_update + timedelta(seconds=86400)
    crl = CertificateRevocationList.objects.create(
        ca=root, number=0, last_update=last_update, next_update=next_update, data=crl_data
    )
    crl.cache()
    return crl


@pytest.fixture
def root_ca_crl(root: CertificateAuthority) -> CertificateRevocationList:
    """Fixture for the user CRL object for the Root CA."""
    with open(constants.FIXTURES_DIR / "root.ca.crl", "rb") as stream:
        crl_data = stream.read()
    last_update = TIMESTAMPS["everything_valid"]
    next_update = last_update + timedelta(seconds=86400)
    crl = CertificateRevocationList.objects.create(
        ca=root,
        number=0,
        last_update=last_update,
        next_update=next_update,
        data=crl_data,
        only_contains_ca_certs=True,
    )
    crl.cache()
    return crl


@pytest.fixture
def root_user_crl(root: CertificateAuthority) -> CertificateRevocationList:
    """Fixture for the user CRL object for the Root CA."""
    with open(constants.FIXTURES_DIR / "root.user.crl", "rb") as stream:
        crl_data = stream.read()
    last_update = TIMESTAMPS["everything_valid"]
    next_update = last_update + timedelta(seconds=86400)
    crl = CertificateRevocationList.objects.create(
        ca=root,
        number=0,
        last_update=last_update,
        next_update=next_update,
        data=crl_data,
        only_contains_user_certs=True,
    )
    crl.cache()
    return crl


@pytest.fixture
def root_attribute_crl(root: CertificateAuthority) -> CertificateRevocationList:
    """Fixture for the attribute CRL object for the Root CA."""
    with open(constants.FIXTURES_DIR / "root.attribute.crl", "rb") as stream:
        crl_data = stream.read()
    last_update = TIMESTAMPS["everything_valid"]
    next_update = last_update + timedelta(seconds=86400)
    crl = CertificateRevocationList.objects.create(
        ca=root,
        number=0,
        last_update=last_update,
        next_update=next_update,
        data=crl_data,
        only_contains_attribute_certs=True,
    )
    crl.cache()
    return crl


@pytest.fixture
def secondary_backend(request: "SubRequest") -> StoragesBackend:
    """Return a :py:class:`~django_ca.key_backends.storages.StoragesBackend` for the secondary key backend."""
    request.getfixturevalue("tmpcadir")
    return key_backends["secondary"]  # type: ignore[return-value]


@pytest.fixture(params=signed_certificate_timestamp_cert_names)
def signed_certificate_timestamp_pub(request: "SubRequest") -> x509.Certificate:
    """Parametrized fixture for certificates that have any SCT extension."""
    name = request.param.replace("-", "_")
    return request.getfixturevalue(f"contrib_{name}_pub")  # type: ignore[no-any-return]


@pytest.fixture(params=signed_certificate_timestamps_cert_names)
def signed_certificate_timestamps_pub(request: "SubRequest") -> x509.Certificate:  # pragma: no cover
    """Parametrized fixture for certificates that have a SignedCertificateTimestamps extension.

    .. NOTE:: There are no certificates with this extension right now, so this fixture is in fact never run.
    """
    name = request.param.replace("-", "_")

    return request.getfixturevalue(f"{name}_pub")  # type: ignore[no-any-return]


@pytest.fixture
def softhsm_setup(tmp_path: Path) -> Iterator[Path]:  # pragma: hsm
    """Fixture to set up a unique SoftHSM2 configuration."""
    softhsm_dir = tmp_path / "softhsm"
    token_dir = softhsm_dir / "tokens"
    os.makedirs(token_dir)

    softhsm2_conf = tmp_path / "softhsm2.conf"

    with open(softhsm2_conf, "w", encoding="utf-8") as stream:
        stream.write(f"""# SoftHSM v2 configuration file

    directories.tokendir = {token_dir}
    objectstore.backend = file

    # ERROR, WARNING, INFO, DEBUG
    log.level = DEBUG

    # If CKF_REMOVABLE_DEVICE flag should be set
    slots.removable = false

    # Enable and disable PKCS#11 mechanisms using slots.mechanisms.
    slots.mechanisms = ALL

    # If the library should reset the state on fork
    library.reset_on_fork = false""")

    with mock.patch.dict(os.environ, {"SOFTHSM2_CONF": str(softhsm2_conf)}):
        # Reinitialize library if already loaded (it might load the configuration).
        if lib := SessionPool._lib_pool.get(settings.PKCS11_PATH):  # pylint: disable=protected-access
            lib.reinitialize()

        yield softhsm_dir


@pytest.fixture
def softhsm_token(  # pragma: hsm
    request: "SubRequest",
    settings: SettingsWrapper,
) -> str:
    """Get a unique token for the current test."""
    request.getfixturevalue("softhsm_setup")
    token = settings.PKCS11_TOKEN_LABEL
    so_pin = settings.PKCS11_SO_PIN = get_random_string(8)
    pin = settings.PKCS11_USER_PIN = get_random_string(8)

    # Update key backend configuration
    key_backend_config = copy.deepcopy(settings.CA_KEY_BACKENDS)
    key_backend_config["hsm"]["OPTIONS"].update({"user_pin": pin})
    settings.CA_KEY_BACKENDS = key_backend_config
    key_backends._reset()  # pylint: disable=protected-access

    args = ("softhsm2-util", "--init-token", "--free", "--label", token, "--so-pin", so_pin, "--pin", pin)
    subprocess.run(args, check=True)

    # Reinitialize library if already loaded (tokens are only seen after (re-)initialization).
    if lib := SessionPool._lib_pool.get(settings.PKCS11_PATH):  # pylint: disable=protected-access
        lib.reinitialize()

    return token  # type: ignore[no-any-return]


@pytest.fixture
def hsm_backend(request: "SubRequest") -> Iterator[HSMBackend]:  # pragma: hsm
    """Fixture providing a HSMBackend with the current token and (randomized) passwords."""
    request.getfixturevalue("softhsm_token")
    yield cast(HSMBackend, key_backends["hsm"])
    key_backends._reset()  # pylint: disable=protected-access  # in case we manipulated the object


@pytest.fixture(params=HSMBackend.supported_key_types)
def usable_hsm_ca(  # pragma: hsm
    request: "SubRequest", ca_name: str, subject: x509.Name, hsm_backend: HSMBackend
) -> CertificateAuthority:
    """Parametrized fixture yielding a certificate authority for every key type."""
    request.getfixturevalue("db")
    key_type = request.param

    if key_type in settings.PKCS11_EXCLUDE_KEY_TYPES:  # pragma: no cover
        pytest.xfail(f"{key_type}: Algorithm not supported on this platform.")

    key_backend_options = HSMCreatePrivateKeyOptions(
        user_pin=hsm_backend.user_pin, key_label=ca_name, key_type=key_type, elliptic_curve=None
    )
    ca = CertificateAuthority.objects.init(
        name=ca_name,
        key_backend=hsm_backend,
        key_backend_options=key_backend_options,
        key_type=key_type,
        subject=subject,
        not_after=datetime.now(tz=timezone.utc) + timedelta(days=720),
    )
    assert isinstance(ca.key_backend, HSMBackend)
    return ca


@pytest.fixture
def subject(hostname: str) -> x509.Name:
    """Fixture for a :py:class:`~cg:cryptography.x509.Name` to use for a subject.

    The common name is based on :py:func:`~django_ca.tests.base.fixtures.hostname` and identical to
    :py:func:`~django_ca.tests.base.fixtures.rfc4514_subject`.
    """
    hostname = hostname[-61:].lstrip("-.")
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "AT"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Vienna"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Vienna"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Django CA"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Django CA Testsuite"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"cn.{hostname}"),
        ]
    )


@pytest.fixture
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


@pytest.fixture(params=all_ca_names)
def ca(request: "SubRequest") -> CertificateAuthority:
    """Parametrized fixture for all certificate authorities known to the test suite."""
    fixture_name = request.param
    if CERT_DATA[fixture_name]["cat"] in ("contrib", "sphinx-contrib"):
        fixture_name = f"contrib_{fixture_name}"
    return request.getfixturevalue(fixture_name)  # type: ignore[no-any-return]


@pytest.fixture(params=usable_ca_names)
def usable_ca_name(request: "SubRequest") -> CertificateAuthority:
    """Parametrized fixture for the name of every usable CA."""
    return request.param  # type: ignore[no-any-return]


@pytest.fixture(params=usable_ca_names)
def usable_ca(request: "SubRequest") -> CertificateAuthority:
    """Parametrized fixture for every usable CA (with usable private key)."""
    return request.getfixturevalue(f"usable_{request.param}")  # type: ignore[no-any-return]


@pytest.fixture
def usable_cas(request: "SubRequest") -> list[CertificateAuthority]:
    """Fixture for all usable CAs as a list."""
    cas = []
    for name in usable_ca_names:
        cas.append(request.getfixturevalue(f"usable_{name}"))
    return cas


@pytest.fixture(params=usable_cert_names)
def usable_cert(request: "SubRequest") -> Certificate:
    """Parametrized fixture for every ``{ca}-cert`` certificate.

    The name of the certificate can be retrieved from the non-standard `test_name` property of the
    certificate.
    """
    name = request.param
    cert = request.getfixturevalue(name.replace("-", "_"))
    cert.test_name = name
    request.getfixturevalue(f"usable_{cert.ca.name}")
    return cert  # type: ignore[no-any-return]

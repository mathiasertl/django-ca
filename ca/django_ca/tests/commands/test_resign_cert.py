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

"""Test the resign_cert management command."""

from datetime import datetime, timedelta, timezone as tz
from pathlib import Path
from typing import Any
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes

from django.utils import timezone

import pytest
from _pytest.fixtures import SubRequest
from pytest_django.fixtures import SettingsWrapper

from django_ca.constants import ExtensionOID
from django_ca.models import Certificate, CertificateAuthority, Watcher
from django_ca.tests.base.assertions import assert_command_error, assert_create_cert_signals
from django_ca.tests.base.constants import TIMESTAMPS
from django_ca.tests.base.utils import basic_constraints, cmd, cmd_e2e

pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])]


def resign_cert(serial: str, stderr: str = "", **kwargs: Any) -> Certificate:
    """Execute the regenerate_ocsp_keys command."""
    with assert_create_cert_signals():
        stdout, actual_stderr = cmd("resign_cert", serial, **kwargs)
    assert actual_stderr == stderr
    return Certificate.objects.get(pub=stdout)


def assert_resigned(old: Certificate, new: Certificate, new_ca: CertificateAuthority | None = None) -> None:
    """Assert that the resigned certificate matches the old cert."""
    new_ca = new_ca or old.ca
    issuer = new_ca.subject

    assert old.pk != new.pk  # make sure we're not comparing the same cert

    # assert various properties
    assert new_ca == new.ca
    assert issuer == new.issuer


def assert_equal_ext(old: Certificate, new: Certificate, new_ca: CertificateAuthority | None = None) -> None:
    """Assert that the extensions in both certs are equal."""
    new_ca = new_ca or old.ca
    assert old.subject == new.subject

    # assert extensions that should be equal
    aki = new_ca.get_authority_key_identifier_extension()
    assert aki == new.extensions[ExtensionOID.AUTHORITY_KEY_IDENTIFIER]
    for oid in [
        ExtensionOID.EXTENDED_KEY_USAGE,
        ExtensionOID.KEY_USAGE,
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
        ExtensionOID.TLS_FEATURE,
    ]:
        assert old.extensions.get(oid) == new.extensions.get(oid)

    # Test extensions that don't come from the old cert but from the signing CA
    assert new.extensions[ExtensionOID.BASIC_CONSTRAINTS] == basic_constraints()
    assert ExtensionOID.ISSUER_ALTERNATIVE_NAME not in new.extensions  # signing CA does not have this set

    # Some properties come from the ca
    if new_ca.sign_crl_distribution_points:
        assert new.extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS] == new_ca.sign_crl_distribution_points
    else:
        assert ExtensionOID.CRL_DISTRIBUTION_POINTS not in new.extensions


@pytest.mark.usefixtures("usable_root")
def test_with_rsa(root_cert: Certificate) -> None:
    """Simplest test while resigning a cert."""
    new = resign_cert(root_cert.serial)
    assert_resigned(root_cert, new)
    assert_equal_ext(root_cert, new)
    assert isinstance(new.algorithm, type(root_cert.algorithm))


@pytest.mark.usefixtures("usable_dsa")
def test_with_dsa(dsa_cert: Certificate) -> None:
    """Resign a certificate from a DSA CA."""
    new = resign_cert(dsa_cert.serial)
    assert_resigned(dsa_cert, new)
    assert_equal_ext(dsa_cert, new)
    assert isinstance(new.algorithm, hashes.SHA256)


@pytest.mark.usefixtures("usable_child")
def test_all_extensions_certificate(all_extensions: Certificate) -> None:
    """Test resigning the all-extensions certificate."""
    with assert_create_cert_signals():
        new = resign_cert(all_extensions.serial)

    assert_resigned(all_extensions, new)
    assert isinstance(new.algorithm, hashes.SHA256)

    expected = all_extensions.extensions
    actual = new.extensions
    assert sorted(expected.values(), key=lambda e: e.oid.dotted_string) == sorted(
        actual.values(), key=lambda e: e.oid.dotted_string
    )


@pytest.mark.usefixtures("usable_root")
def test_with_expires(root_cert: Certificate) -> None:
    """Test resigning a cert with custom expiry."""
    now = datetime.now(tz=tz.utc).replace(second=0, microsecond=0)
    new = resign_cert(root_cert.serial, expires=timedelta(days=21), stderr="")
    assert_resigned(root_cert, new)
    assert_equal_ext(root_cert, new)
    assert new.not_after == now + timedelta(days=21)


@pytest.mark.usefixtures("usable_root")
def test_overwrite(settings: SettingsWrapper, root_cert: Certificate) -> None:
    """Test overwriting extensions."""
    settings.CA_DEFAULT_SUBJECT = tuple()
    watcher = "new@example.com"

    # resign a cert, but overwrite all options
    with assert_create_cert_signals():
        stdout, stderr = cmd_e2e(["resign_cert", root_cert.serial, "--watch", watcher])
    assert stderr == ""

    new = Certificate.objects.get(pub=stdout)
    assert_resigned(root_cert, new)
    assert new.subject == root_cert.subject
    assert list(new.watchers.all()) == [Watcher.objects.get(mail=watcher)]
    assert_equal_ext(root_cert, new)


@pytest.mark.usefixtures("usable_root")
def test_cert_profile(settings: SettingsWrapper, root_cert: Certificate) -> None:
    """Test passing a profile."""
    settings.CA_PROFILES = {"server": {"expires": 200}, "webserver": {}}
    settings.CA_DEFAULT_EXPIRES = 31
    root_cert.profile = "server"
    root_cert.save()

    with assert_create_cert_signals():
        stdout, stderr = cmd_e2e(["resign_cert", root_cert.serial])
    assert stderr == ""

    new = Certificate.objects.get(pub=stdout)
    assert new.not_after.date() == timezone.now().date() + timedelta(days=200)
    assert_resigned(root_cert, new)
    assert_equal_ext(root_cert, new)


@pytest.mark.usefixtures("usable_root")
def test_to_file(tmpcadir: Path, root_cert: Certificate) -> None:
    """Test writing output to file."""
    out_path = tmpcadir / "test.pem"

    with assert_create_cert_signals():
        stdout, stderr = cmd("resign_cert", root_cert.serial, out=out_path)
    assert stdout == ""
    assert stderr == ""

    with open(out_path, encoding="ascii") as stream:
        pub = stream.read()

    new = Certificate.objects.get(pub=pub)
    assert_resigned(root_cert, new)
    assert_equal_ext(root_cert, new)


@pytest.mark.usefixtures("usable_root")
def test_error(root_cert: Certificate) -> None:
    """Test resign function throwing a random exception."""
    msg = "foobar"
    msg_re = rf"^{msg}$"
    with (
        assert_create_cert_signals(False, False),
        patch("django_ca.managers.CertificateManager.create_cert", side_effect=Exception(msg)),
        assert_command_error(msg_re),
    ):
        cmd("resign_cert", root_cert.serial)


@pytest.mark.usefixtures("usable_root")
def test_missing_cert_profile(root_cert: Certificate) -> None:
    """Test resigning a certificate with a profile that doesn't exist."""
    root_cert.profile = "profile-gone"
    root_cert.save()

    msg_re = rf'^Profile "{root_cert.profile}" for original certificate is no longer defined, please set one via the command line\.$'  # NOQA: E501
    with assert_command_error(msg_re):
        cmd("resign_cert", root_cert.serial)


@pytest.mark.hsm
def test_hsm_backend(request: "SubRequest", usable_hsm_ca: CertificateAuthority) -> None:
    """Test signing a certificate with a CA that is in an HSM."""
    if usable_hsm_ca.key_type == "RSA":
        cert = request.getfixturevalue("root_cert")
    else:
        cert = request.getfixturevalue(f"{usable_hsm_ca.key_type.lower()}_cert")
    cert.ca = usable_hsm_ca
    cert.save()

    with assert_create_cert_signals():
        stdout, stderr = cmd("resign_cert", cert.serial)
    assert stderr == ""
    new = Certificate.objects.exclude(pk=cert.pk).get()
    assert_resigned(cert, new)
    assert_equal_ext(cert, new)


@pytest.mark.freeze_time(TIMESTAMPS["everything_expired"])
def test_expired_certificate_authority(root_cert: Certificate) -> None:
    """Test resigning with a CA that has expired."""
    with assert_command_error(r"^Certificate authority has expired\.$"):
        cmd("resign_cert", root_cert.serial)


@pytest.mark.usefixtures("usable_root")
def test_disabled_certificate_authority(usable_root: CertificateAuthority, root_cert: Certificate) -> None:
    """Test resigning with a CA that is disabled."""
    assert usable_root == root_cert.ca
    usable_root.enabled = False
    usable_root.save()
    with assert_command_error(r"^Certificate authority is disabled\.$"):
        cmd("resign_cert", root_cert.serial)


@pytest.mark.usefixtures("usable_root")
def test_revoked_certificate_authority(usable_root: CertificateAuthority, root_cert: Certificate) -> None:
    """Test resigning with a CA that is revoked."""
    assert usable_root == root_cert.ca
    usable_root.revoke()
    with assert_command_error(r"^Certificate authority is revoked\.$"):
        cmd("resign_cert", root_cert.serial)


def test_unusable_private_key(root_cert: Certificate) -> None:
    """Test resigning with an unusable CA."""
    with assert_command_error(r"root.key: Private key file not found\.$"):
        cmd("resign_cert", root_cert.serial)


def test_model_validation_error(root_cert: Certificate) -> None:
    """Test model validation is tested properly.

    NOTE: This example is contrived for the default backend, as the type of the password would already be
    checked by argparse. Other backends however might have other validation mechanisms.
    """
    with assert_command_error(r"^password: Input should be a valid bytes$"):
        cmd("resign_cert", root_cert.serial, password=123)

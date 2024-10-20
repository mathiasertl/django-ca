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

"""Test the Certificate model."""

from datetime import datetime, timedelta, timezone as tz

import josepy as jose

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from django.utils import timezone

import pytest
from _pytest.logging import LogCaptureFixture
from pytest_django.fixtures import SettingsWrapper

from django_ca.constants import ReasonFlags
from django_ca.models import Certificate, CertificateAuthority
from django_ca.tests.base.assertions import assert_validation_error
from django_ca.tests.base.constants import CERT_DATA
from django_ca.tests.models.base import assert_bundle


def test_bundle_as_pem(
    root: CertificateAuthority, root_cert: Certificate, child: CertificateAuthority, child_cert: Certificate
) -> None:
    """Test bundles of various CAs."""
    assert_bundle([root_cert, root], root_cert)
    assert_bundle([child_cert, child, root], child_cert)


def test_revocation() -> None:
    """Test getting a revociation for a non-revoked certificate."""
    # Never really happens in real life, but should still be checked
    cert = Certificate(revoked=False)

    with pytest.raises(ValueError, match=r"^Certificate is not revoked\.$"):
        cert.get_revocation()


def test_root(root: CertificateAuthority, root_cert: Certificate, child_cert: Certificate) -> None:
    """Test the root property."""
    assert root_cert.root == root
    assert child_cert.root == root


def test_serial(usable_cert: Certificate) -> None:
    """Test getting the serial."""
    cert_name = usable_cert.test_name  # type: ignore[attr-defined]
    assert usable_cert.serial == CERT_DATA[cert_name].get("serial")


@pytest.mark.freeze_time("2019-02-03 15:43:12")
def test_get_revocation_time(settings: SettingsWrapper, root_cert: Certificate) -> None:
    """Test getting the revocation time."""
    assert root_cert.get_revocation_time() is None
    root_cert.revoke()

    # timestamp does not have a timezone regardless of USE_TZ
    root_cert.revoked_date = timezone.now()
    assert root_cert.get_revocation_time() == datetime(2019, 2, 3, 15, 43, 12, tzinfo=tz.utc)

    settings.USE_TZ = False
    root_cert.refresh_from_db()
    assert root_cert.get_revocation_time() == datetime(2019, 2, 3, 15, 43, 12, tzinfo=tz.utc)


@pytest.mark.freeze_time("2019-02-03 15:43:12")
def test_get_compromised_time(settings: SettingsWrapper, root_cert: Certificate) -> None:
    """Test getting the time when the certificate was compromised."""
    assert root_cert.get_compromised_time() is None
    root_cert.revoke(compromised=timezone.now())

    # timestamp does not have a timezone regardless of USE_TZ
    root_cert.compromised = timezone.now()
    assert root_cert.get_compromised_time() == datetime(2019, 2, 3, 15, 43, 12, tzinfo=tz.utc)

    settings.USE_TZ = False
    root_cert.refresh_from_db()
    assert root_cert.compromised == timezone.now()
    assert root_cert.get_compromised_time() == datetime(2019, 2, 3, 15, 43, 12, tzinfo=tz.utc)


def test_get_revocation_reason(root_cert: Certificate) -> None:
    """Test getting the revocation reason."""
    assert root_cert.get_revocation_reason() is None

    for reason in ReasonFlags:
        root_cert.revoke(reason)
        got = root_cert.get_revocation_reason()
        assert isinstance(got, x509.ReasonFlags)
        assert got.name == reason.name


def test_validate_past(root_cert: Certificate) -> None:
    """Test that model validation blocks revoked_date or revoked_invalidity in the future."""
    now = timezone.now()
    future = now + timedelta(10)
    past = now - timedelta(10)

    # Validation works if we're not revoked
    root_cert.full_clean()

    # Validation works if date is in the past
    root_cert.revoked_date = past
    root_cert.compromised = past
    root_cert.full_clean()

    root_cert.revoked_date = future
    root_cert.compromised = future
    with assert_validation_error(
        {
            "compromised": ["Date must be in the past!"],
            "revoked_date": ["Date must be in the past!"],
        }
    ):
        root_cert.full_clean()


@pytest.mark.parametrize(("name", "algorithm"), (("sha256", hashes.SHA256()), ("sha512", hashes.SHA512())))
def test_get_fingerprint(name: str, algorithm: hashes.HashAlgorithm, usable_cert: Certificate) -> None:
    """Test getting the fingerprint value."""
    cert_name = usable_cert.test_name  # type: ignore[attr-defined]
    assert usable_cert.get_fingerprint(algorithm) == CERT_DATA[cert_name][name]


def test_jwk(root_cert: Certificate, ec_cert: Certificate) -> None:
    """Test JWK property."""
    # josepy does not support loading DSA/Ed448/Ed25519 keys:
    #   https://github.com/certbot/josepy/pull/98
    assert isinstance(ec_cert.jwk, jose.jwk.JWKEC)
    assert isinstance(root_cert.jwk, jose.jwk.JWKRSA)


def test_jwk_with_unsupported_algorithm(
    dsa_cert: Certificate, ed448_cert: Certificate, ed25519_cert: Certificate
) -> None:
    """Test the ValueError raised if called with an unsupported algorithm."""
    with pytest.raises(ValueError, match="Unsupported algorithm"):
        ed448_cert.jwk  # noqa: B018
    with pytest.raises(ValueError, match="Unsupported algorithm"):
        ed25519_cert.jwk  # noqa: B018
    with pytest.raises(ValueError, match="Unsupported algorithm"):
        dsa_cert.jwk  # noqa: B018


def test_revocation_with_no_revocation_date(root_cert: Certificate) -> None:
    """Test exception when no revocation date is set."""
    root_cert.revoked = True
    root_cert.save()

    with pytest.raises(ValueError, match=r"^Certificate has no revocation date$"):
        root_cert.get_revocation()


def test_get_revocation_time_with_no_revocation_date(
    caplog: LogCaptureFixture, root_cert: Certificate
) -> None:
    """Test warning log message when there is no revocation time set but the cert is revoked."""
    root_cert.revoked = True
    root_cert.save()

    assert root_cert.get_revocation_time() is None
    assert "Inconsistent model state: revoked=True and revoked_date=None." in caplog.text

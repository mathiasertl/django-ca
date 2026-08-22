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

"""Test the acme_issue_certificate task."""

# pylint: disable=redefined-outer-name  # requested pytest fixtures show up this way.

import logging
from datetime import timedelta
from typing import Any, NoReturn
from unittest import mock

from acme import messages

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtensionOID, NameOID

from django.utils import timezone

import pytest
from _pytest.logging import LogCaptureFixture
from pytest_django.fixtures import Settings

from django_ca.celery.messages import AcmeIssueCertificateTaskArgs
from django_ca.conf import model_settings
from django_ca.models import (
    AcmeAuthorization,
    AcmeCertificate,
    AcmeOrder,
    Certificate,
    CertificateAuthority,
)
from django_ca.tasks import acme_issue_certificate
from django_ca.tests.base.constants import CERT_DATA, TIMESTAMPS
from django_ca.tests.base.utils import dns, subject_alternative_name

pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])]

#: Second hostname used for orders with more than one authorization.
HOSTNAME2 = "example.net"

#: Generic error returned to the client if signing the certificate fails.
SERVER_INTERNAL_ERROR = messages.Error.with_code(
    "serverInternal", detail="Internal error while issuing the certificate."
)


def create_csr(*names: x509.DNSName | x509.IPAddress, subject: x509.Name | None = None) -> bytes:
    """Create a CSR for the given names.

    The CSR must list exactly the names of the order, as it is validated by the task. If no name is given,
    the Subject Alternative Name extension is omitted altogether. The `subject` defaults to an empty name,
    as certbot does not set a subject at all.
    """
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject or x509.Name([]))
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    return builder.sign(CERT_DATA["root-cert"]["key"]["parsed"], hashes.SHA256()).public_bytes(Encoding.PEM)


@pytest.fixture(autouse=True)
def _log_level(caplog: LogCaptureFixture) -> None:
    """Capture log messages of the task down to the INFO level."""
    caplog.set_level(logging.INFO, logger="django_ca.tasks")


@pytest.fixture
def acme_order(acme_order: AcmeOrder) -> AcmeOrder:
    """Override the global fixture, as the task only processes orders that are being processed."""
    acme_order.status = AcmeOrder.STATUS_PROCESSING
    acme_order.save()
    return acme_order


@pytest.fixture
def acme_authorization(acme_authorization: AcmeAuthorization) -> AcmeAuthorization:
    """Override the global fixture, as the task only accepts orders with valid authorizations."""
    acme_authorization.status = AcmeAuthorization.STATUS_VALID
    acme_authorization.save()
    return acme_authorization


@pytest.fixture
def hostname(acme_authorization: AcmeAuthorization) -> str:
    """The hostname of the (only) authorization of the order."""
    return acme_authorization.value


@pytest.fixture
def csr(acme_authorization: AcmeAuthorization) -> bytes:
    """A CSR matching the authorizations of the order."""
    return create_csr(acme_authorization.general_name)


@pytest.fixture
def task_args(acme_order: AcmeOrder, csr: bytes) -> AcmeIssueCertificateTaskArgs:
    """Task arguments for the default order."""
    return AcmeIssueCertificateTaskArgs(order_pk=acme_order.pk, csr=csr)


def test_acme_disabled(
    settings: Settings, caplog: LogCaptureFixture, task_args: AcmeIssueCertificateTaskArgs
) -> None:
    """Test invoking task when ACME support is not enabled."""
    settings.CA_ENABLE_ACME = False
    acme_issue_certificate(task_args)
    assert caplog.record_tuples == [("django_ca.tasks", logging.ERROR, "ACME is not enabled.")]


def test_unknown_order(caplog: LogCaptureFixture, csr: bytes) -> None:
    """Test invoking task with an unknown order."""
    AcmeOrder.objects.all().delete()
    acme_issue_certificate(AcmeIssueCertificateTaskArgs(order_pk=999, csr=csr))
    assert caplog.record_tuples == [("django_ca.tasks", logging.ERROR, "999: ACME order not found.")]


def test_unusable_order(
    caplog: LogCaptureFixture, acme_order: AcmeOrder, task_args: AcmeIssueCertificateTaskArgs
) -> None:
    """Test invoking task where the order is not usable."""
    acme_order.status = AcmeOrder.STATUS_VALID  # usually would mean: already issued
    acme_order.save()

    acme_issue_certificate(task_args)

    message = (
        f"{acme_order}: {AcmeOrder.STATUS_VALID}: ACME order status is not {AcmeOrder.STATUS_PROCESSING}."
    )
    assert caplog.record_tuples == [("django_ca.tasks", logging.ERROR, message)]


def test_expired_order(
    caplog: LogCaptureFixture, acme_order: AcmeOrder, task_args: AcmeIssueCertificateTaskArgs
) -> None:
    """Test invoking the task with an order that has already expired."""
    acme_order.expires = timezone.now() - timedelta(seconds=1)
    acme_order.save()

    acme_issue_certificate(task_args)

    assert caplog.record_tuples == [
        (
            "django_ca.tasks",
            logging.CRITICAL,
            (
                f"{acme_order}: Received order not eligible for certificate issuance while processing "
                f"certificate: "
            ),
        )
    ]

    acme_order.refresh_from_db()
    assert acme_order.status == AcmeOrder.STATUS_INVALID

    # NOTE: Unlike the other assertions, assert_not_expired() sets its own problem document, so the client
    # is told that the order expired instead of getting the generic error.
    assert acme_order.get_error() == messages.Error.with_code(
        "orderNotReady", detail="This order has expired."
    )
    assert AcmeCertificate.objects.exists() is False


def test_invalid_authorization(
    caplog: LogCaptureFixture,
    acme_order: AcmeOrder,
    acme_authorization: AcmeAuthorization,
    task_args: AcmeIssueCertificateTaskArgs,
) -> None:
    """Test invoking the task with an authorization that is not valid."""
    acme_authorization.status = AcmeAuthorization.STATUS_PENDING
    acme_authorization.save()

    acme_issue_certificate(task_args)

    assert caplog.record_tuples == [
        (
            "django_ca.tasks",
            logging.CRITICAL,
            f"{acme_order}: Received ACME order with non-valid authorizations.",
        )
    ]

    acme_order.refresh_from_db()
    assert acme_order.status == AcmeOrder.STATUS_INVALID
    assert acme_order.get_error() == messages.Error.with_code(
        "serverInternal", detail="Internal error while issuing the certificate."
    )
    assert AcmeCertificate.objects.exists() is False


def assert_invalid_csr(caplog: LogCaptureFixture, acme_order: AcmeOrder) -> None:
    """Assert that the task rejected the CSR, marked the order as invalid and issued no certificate."""
    assert caplog.record_tuples == [
        (
            "django_ca.tasks",
            logging.CRITICAL,
            f"{acme_order}: Received invalid CSR while processing certificate.",
        )
    ]
    assert caplog.records[0].exc_info is not None  # details are only in the traceback

    acme_order.refresh_from_db()
    assert acme_order.status == AcmeOrder.STATUS_INVALID
    assert acme_order.get_error() == SERVER_INTERNAL_ERROR
    assert AcmeCertificate.objects.exists() is False
    assert Certificate.objects.exists() is False


@pytest.mark.usefixtures("usable_root")
def test_csr_with_unknown_name(caplog: LogCaptureFixture, acme_order: AcmeOrder) -> None:
    """Test a CSR listing a name that is not part of the order."""
    csr = create_csr(dns(HOSTNAME2))

    acme_issue_certificate(AcmeIssueCertificateTaskArgs(order_pk=acme_order.pk, csr=csr))

    assert_invalid_csr(caplog, acme_order)


@pytest.mark.usefixtures("usable_root")
def test_csr_without_subject_alternative_name(caplog: LogCaptureFixture, acme_order: AcmeOrder) -> None:
    """Test a CSR that has no Subject Alternative Name extension at all."""
    csr = create_csr()

    acme_issue_certificate(AcmeIssueCertificateTaskArgs(order_pk=acme_order.pk, csr=csr))

    assert_invalid_csr(caplog, acme_order)


@pytest.mark.usefixtures("usable_root")
def test_csr_with_unknown_common_name(
    caplog: LogCaptureFixture, acme_order: AcmeOrder, acme_authorization: AcmeAuthorization
) -> None:
    """Test a CSR where the names match, but the CommonName is not part of the order."""
    csr = create_csr(
        acme_authorization.general_name,
        subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOSTNAME2)]),
    )

    acme_issue_certificate(AcmeIssueCertificateTaskArgs(order_pk=acme_order.pk, csr=csr))

    assert_invalid_csr(caplog, acme_order)


@pytest.mark.parametrize("use_tz", (True, False))
@pytest.mark.usefixtures("usable_root")
def test_basic(
    settings: Settings,
    caplog: LogCaptureFixture,
    acme_order: AcmeOrder,
    hostname: str,
    task_args: AcmeIssueCertificateTaskArgs,
    use_tz: bool,
) -> None:
    """Test basic certificate issuance."""
    settings.USE_TZ = use_tz

    acme_issue_certificate(task_args)

    assert caplog.record_tuples == [
        ("django_ca.tasks", logging.INFO, f"{acme_order}: Issuing certificate for DNS:{hostname}")
    ]

    acme_order.refresh_from_db()
    assert acme_order.status == AcmeOrder.STATUS_VALID
    assert acme_order.get_error() is None  # no error is set for a successful order

    acme_cert = acme_order.acmecertificate
    assert acme_cert.cert is not None, "Check to make mypy happy"
    assert acme_cert.cert.extensions[ExtensionOID.SUBJECT_ALTERNATIVE_NAME] == subject_alternative_name(
        dns(hostname)
    )
    assert acme_cert.cert.not_after == timezone.now() + model_settings.CA_ACME_DEFAULT_CERT_VALIDITY
    assert acme_cert.cert.cn == hostname
    assert acme_cert.cert.profile == model_settings.CA_DEFAULT_PROFILE


@pytest.mark.usefixtures("usable_root")
def test_two_hostnames(acme_order: AcmeOrder, acme_authorization: AcmeAuthorization, hostname: str) -> None:
    """Test setting two hostnames."""
    AcmeAuthorization.objects.create(order=acme_order, value=HOSTNAME2, status=AcmeAuthorization.STATUS_VALID)
    csr = create_csr(acme_authorization.general_name, dns(HOSTNAME2))

    # NOTE: not testing log output here, because order of hostnames might not be stable
    acme_issue_certificate(AcmeIssueCertificateTaskArgs(order_pk=acme_order.pk, csr=csr))

    acme_order.refresh_from_db()
    assert acme_order.status == AcmeOrder.STATUS_VALID

    acme_cert = acme_order.acmecertificate
    assert acme_cert.cert is not None, "Check to make mypy happy"

    # NOTE: not comparing the extension directly, as the order of names is not stable.
    san_extension = acme_cert.cert.pub.loaded.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert san_extension.critical is False
    assert set(san_extension.value) == {dns(hostname), dns(HOSTNAME2)}

    assert acme_cert.cert.not_after == timezone.now() + model_settings.CA_ACME_DEFAULT_CERT_VALIDITY
    assert acme_cert.cert.cn in [hostname, HOSTNAME2]


@pytest.mark.parametrize("use_tz", (True, False))
@pytest.mark.usefixtures("usable_root")
def test_not_after(
    settings: Settings,
    caplog: LogCaptureFixture,
    acme_order: AcmeOrder,
    hostname: str,
    task_args: AcmeIssueCertificateTaskArgs,
    use_tz: bool,
) -> None:
    """Test certificate issuance with the not_after attribute set in the order."""
    settings.USE_TZ = use_tz
    acme_order.refresh_from_db()  # convert timestamps, as saving would fail in SQLite otherwise

    not_after = timezone.now() + timedelta(days=20)
    acme_order.not_after = not_after
    acme_order.save()

    acme_issue_certificate(task_args)

    assert caplog.record_tuples == [
        ("django_ca.tasks", logging.INFO, f"{acme_order}: Issuing certificate for DNS:{hostname}")
    ]

    acme_order.refresh_from_db()
    assert acme_order.status == AcmeOrder.STATUS_VALID

    acme_cert = acme_order.acmecertificate
    assert acme_cert.cert is not None, "Check to make mypy happy"
    assert acme_cert.cert.extensions[ExtensionOID.SUBJECT_ALTERNATIVE_NAME] == subject_alternative_name(
        dns(hostname)
    )
    assert acme_cert.cert.not_after == not_after
    assert acme_cert.cert.cn == hostname


def test_profile(
    caplog: LogCaptureFixture,
    usable_root: CertificateAuthority,
    acme_order: AcmeOrder,
    hostname: str,
    task_args: AcmeIssueCertificateTaskArgs,
) -> None:
    """Test that setting a different profile also returns the appropriate certificate."""
    usable_root.acme_profile = "client"
    usable_root.save()

    acme_issue_certificate(task_args)

    assert caplog.record_tuples == [
        ("django_ca.tasks", logging.INFO, f"{acme_order}: Issuing certificate for DNS:{hostname}")
    ]

    acme_order.refresh_from_db()
    assert acme_order.status == AcmeOrder.STATUS_VALID

    acme_cert = acme_order.acmecertificate
    assert acme_cert.cert is not None, "Check to make mypy happy"
    assert acme_cert.cert.extensions[ExtensionOID.SUBJECT_ALTERNATIVE_NAME] == subject_alternative_name(
        dns(hostname)
    )
    assert acme_cert.cert.not_after == timezone.now() + model_settings.CA_ACME_DEFAULT_CERT_VALIDITY
    assert acme_cert.cert.cn == hostname
    assert acme_cert.cert.profile == "client"


@pytest.mark.usefixtures("usable_root")
def test_signing_error(
    caplog: LogCaptureFixture,
    acme_order: AcmeOrder,
    hostname: str,
    task_args: AcmeIssueCertificateTaskArgs,
) -> None:
    """Test that the order is marked as invalid if signing the certificate fails."""
    message = "Signing the certificate went wrong."

    with mock.patch(
        "django_ca.managers.CertificateManager.create_cert", side_effect=Exception(message)
    ) as create_cert_mock:
        acme_issue_certificate(task_args)

    create_cert_mock.assert_called_once()

    assert len(caplog.records) == 2
    assert caplog.record_tuples[0] == (
        "django_ca.tasks",
        logging.INFO,
        f"{acme_order}: Issuing certificate for DNS:{hostname}",
    )
    assert caplog.record_tuples[1] == ("django_ca.tasks", logging.ERROR, "Error issuing certificate.")
    assert caplog.records[1].exc_info is not None
    assert str(caplog.records[1].exc_info[1]) == message

    # No certificate was issued and the order is marked as invalid (RFC 8555, section 7.1.6).
    acme_order.refresh_from_db()
    assert acme_order.status == AcmeOrder.STATUS_INVALID
    assert AcmeCertificate.objects.filter(order=acme_order).exists() is False

    # The order stores a generic error, so that the exception is not leaked to the client.
    assert acme_order.get_error() == SERVER_INTERNAL_ERROR
    assert message not in str(acme_order.error)


@pytest.mark.usefixtures("usable_root")
def test_error_after_signing(
    caplog: LogCaptureFixture, acme_order: AcmeOrder, task_args: AcmeIssueCertificateTaskArgs
) -> None:
    """Test that an already stored certificate is rolled back if a later statement fails."""
    message = "Storing the certificate went wrong."
    original_create_cert = Certificate.objects.create_cert

    # Create the certificate as usual, but raise right afterwards, so that the certificate is already
    # stored in the database when the exception handler is invoked.
    def create_cert(*args: Any, **kwargs: Any) -> NoReturn:
        original_create_cert(*args, **kwargs)
        raise RuntimeError(message)

    with mock.patch("django_ca.managers.CertificateManager.create_cert", side_effect=create_cert):
        acme_issue_certificate(task_args)

    assert caplog.records[1].exc_info is not None
    assert str(caplog.records[1].exc_info[1]) == message

    # The certificate was signed, but must not be stored in the database, as the order is invalid.
    assert Certificate.objects.count() == 0
    assert AcmeCertificate.objects.count() == 0
    acme_order.refresh_from_db()
    assert acme_order.status == AcmeOrder.STATUS_INVALID
    assert hasattr(acme_order, "acmecertificate") is False

    # The error is stored even though the certificate was rolled back.
    assert acme_order.get_error() == SERVER_INTERNAL_ERROR


def test_with_acme_certificate_exists(
    caplog: LogCaptureFixture,
    acme_order: AcmeOrder,
    csr: bytes,
    task_args: AcmeIssueCertificateTaskArgs,
) -> None:
    """Test error when an ACME certificate already exists."""
    AcmeCertificate.objects.create(order=acme_order, csr=csr.decode())

    acme_issue_certificate(task_args)

    assert caplog.record_tuples == [
        ("django_ca.models", logging.CRITICAL, f"{acme_order}: ACME order already has a certificate."),
        (
            "django_ca.tasks",
            logging.CRITICAL,
            (
                f"{acme_order}: Received order not eligible for certificate issuance while processing "
                f"certificate: "
            ),
        ),
    ]

    acme_order.refresh_from_db()
    assert acme_order.status == AcmeOrder.STATUS_INVALID
    assert acme_order.get_error() == SERVER_INTERNAL_ERROR

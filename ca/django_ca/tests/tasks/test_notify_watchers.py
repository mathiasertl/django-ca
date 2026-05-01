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

"""Tests for the notify_watchers task."""

# pylint: disable=redefined-outer-name,use-implicit-booleaness-not-comparison

from django.core import mail

import pytest
from pytest_django.fixtures import SettingsWrapper

from django_ca.models import Certificate, CertificateExpiryNotification, Watcher
from django_ca.tasks import notify_watchers
from django_ca.tests.base.constants import TIMESTAMPS

# Freeze at 3 days before root-cert expires: CA_NOTIFICATION_DAYS default includes 3, so
# root_cert is exactly at a notification boundary.
pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["ca_certs_expiring"])]


@pytest.fixture
def watcher() -> Watcher:
    """A watcher with a known email address."""
    return Watcher.from_addr("Watcher One <watcher@example.com>")


@pytest.mark.usefixtures("root_cert")
def test_no_notification_days(settings: SettingsWrapper) -> None:
    """When CA_NOTIFICATION_DAYS is empty the task exits immediately without sending anything."""
    settings.CA_NOTIFICATION_DAYS = []
    notify_watchers()
    assert mail.outbox == []
    assert CertificateExpiryNotification.objects.count() == 0


@pytest.mark.usefixtures("root_cert")
def test_no_watchers() -> None:
    """Certificates without watchers are skipped — no email sent, no notification recorded."""
    notify_watchers()
    assert mail.outbox == []
    assert CertificateExpiryNotification.objects.count() == 0


def test_sends_notification(
    root_cert: Certificate,
    watcher: Watcher,
    settings: SettingsWrapper,
) -> None:
    """A notification email is sent and a CertificateExpiryNotification is created."""
    settings.CA_NOTIFICATION_DAYS = [3]
    root_cert.watchers.add(watcher)

    notify_watchers()

    assert len(mail.outbox) == 1
    assert CertificateExpiryNotification.objects.filter(certificate=root_cert, days=3).exists()


def test_notification_content(
    root_cert: Certificate,
    watcher: Watcher,
    settings: SettingsWrapper,
) -> None:
    """The email has the correct subject, body and recipient."""
    settings.CA_NOTIFICATION_DAYS = [3]
    root_cert.watchers.add(watcher)

    notify_watchers()

    assert len(mail.outbox) == 1
    msg = mail.outbox[0]
    timestamp = root_cert.not_after.strftime("%Y-%m-%d")
    assert msg.subject == f"Certificate expiration for {root_cert.cn} on {timestamp}"
    assert msg.body == f"The certificate for {root_cert.cn} will expire on {timestamp}."
    assert msg.to == [watcher.mail]


def test_no_duplicate_notifications(
    root_cert: Certificate,
    watcher: Watcher,
    settings: SettingsWrapper,
) -> None:
    """Running the task twice does not send a second notification for the same cert+day."""
    settings.CA_NOTIFICATION_DAYS = [3]
    root_cert.watchers.add(watcher)

    notify_watchers()
    notify_watchers()

    assert len(mail.outbox) == 1
    assert CertificateExpiryNotification.objects.filter(certificate=root_cert, days=3).count() == 1


def test_cert_outside_notification_window(
    root_cert: Certificate,
    watcher: Watcher,
    settings: SettingsWrapper,
) -> None:
    """No notification is sent when the cert is not at a configured notification boundary."""
    # root_cert has 3 days left, but only 7 and 14 are configured — no match.
    settings.CA_NOTIFICATION_DAYS = [7, 14]
    root_cert.watchers.add(watcher)

    notify_watchers()

    assert mail.outbox == []
    assert CertificateExpiryNotification.objects.count() == 0


def test_revoked_cert_excluded(
    root_cert: Certificate,
    watcher: Watcher,
    settings: SettingsWrapper,
) -> None:
    """Revoked certificates are excluded from notifications."""
    settings.CA_NOTIFICATION_DAYS = [3]
    root_cert.watchers.add(watcher)
    root_cert.revoked = True
    root_cert.save()

    notify_watchers()

    assert mail.outbox == []
    assert CertificateExpiryNotification.objects.count() == 0


def test_multiple_watchers(
    root_cert: Certificate,
    settings: SettingsWrapper,
) -> None:
    """All watchers are combined into the single notification email for a certificate."""
    settings.CA_NOTIFICATION_DAYS = [3]
    w1 = Watcher.from_addr("Alice <alice@example.com>")
    w2 = Watcher.from_addr("Bob <bob@example.com>")
    root_cert.watchers.add(w1, w2)

    notify_watchers()

    assert len(mail.outbox) == 1
    assert sorted(mail.outbox[0].to) == ["alice@example.com", "bob@example.com"]
    assert CertificateExpiryNotification.objects.filter(certificate=root_cert, days=3).count() == 1


def test_existing_notification_prevents_send(
    root_cert: Certificate,
    watcher: Watcher,
    settings: SettingsWrapper,
) -> None:
    """A pre-existing CertificateExpiryNotification suppresses the email."""
    settings.CA_NOTIFICATION_DAYS = [3]
    root_cert.watchers.add(watcher)
    CertificateExpiryNotification.objects.create(certificate=root_cert, days=3)

    notify_watchers()

    assert mail.outbox == []
    assert CertificateExpiryNotification.objects.filter(certificate=root_cert, days=3).count() == 1


def test_multiple_notification_days(
    root_cert: Certificate,
    watcher: Watcher,
    settings: SettingsWrapper,
) -> None:
    """Only the matching day triggers a notification even when multiple days are configured."""
    # root_cert has 3 days left; only the 3-day boundary should fire.
    settings.CA_NOTIFICATION_DAYS = [3, 7, 14]
    root_cert.watchers.add(watcher)

    notify_watchers()

    assert len(mail.outbox) == 1
    assert CertificateExpiryNotification.objects.filter(certificate=root_cert, days=3).exists()
    assert not CertificateExpiryNotification.objects.filter(certificate=root_cert, days=7).exists()
    assert not CertificateExpiryNotification.objects.filter(certificate=root_cert, days=14).exists()


@pytest.mark.freeze_time(TIMESTAMPS["ca_certs_expired"])
def test_expired_cert_excluded(
    root_cert: Certificate,
    watcher: Watcher,
    settings: SettingsWrapper,
) -> None:
    """Already-expired certificates are not notified."""
    settings.CA_NOTIFICATION_DAYS = [3]
    root_cert.watchers.add(watcher)

    notify_watchers()

    assert mail.outbox == []
    assert CertificateExpiryNotification.objects.count() == 0


def test_notifications_for_different_days_are_independent(
    root_cert: Certificate,
    watcher: Watcher,
    settings: SettingsWrapper,
) -> None:
    """A notification for day N does not block a future notification for day M."""
    settings.CA_NOTIFICATION_DAYS = [3, 7]
    root_cert.watchers.add(watcher)
    # Simulate that the 7-day notification was already sent previously.
    CertificateExpiryNotification.objects.create(certificate=root_cert, days=7)

    notify_watchers()

    # The 3-day notification should still be sent.
    assert len(mail.outbox) == 1
    assert CertificateExpiryNotification.objects.filter(certificate=root_cert, days=3).exists()

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

"""Management command to revoke a certificate.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-management-commands/
"""

from datetime import datetime, timezone as tz
from typing import Any, Optional

from django.conf import settings
from django.core.management.base import CommandError, CommandParser
from django.utils import timezone

from django_ca.constants import ReasonFlags
from django_ca.management.actions import ReasonAction
from django_ca.management.base import BaseCommand
from django_ca.management.mixins import CertCommandMixin
from django_ca.models import Certificate


class Command(CertCommandMixin, BaseCommand):
    """Implement the :command:`manage.py revoke_cert` command."""

    allow_revoked = True
    help = "Revoke a certificate."

    def add_arguments(self, parser: CommandParser) -> None:
        super().add_arguments(parser)

        # Get a good example timestamp in for the help text
        example = datetime.now(tz=tz.utc).replace(microsecond=0, second=0).isoformat()

        group = parser.add_argument_group("Revocation information")
        group.add_argument("--reason", action=ReasonAction, help="An optional reason for revocation.")
        group.add_argument(
            "--compromised",
            metavar="TIMESTAMP",
            type=datetime.fromisoformat,
            help=f"When the certificate was compromised, as an ISO 8601 timestamp (example: {example}).",
        )

    def handle(
        self, cert: Certificate, reason: ReasonFlags, compromised: Optional[datetime], **options: Any
    ) -> None:
        if cert.revoked:
            raise CommandError(f"{cert.serial}: Certificate is already revoked.")

        # Make sure that the timestamp is tz-aware (makes processing easier)
        if compromised is not None and timezone.is_naive(compromised):
            raise CommandError(f"{compromised.isoformat()}: Timestamp requires a timezone.")

        # Make sure that the certificate was compromised in the past
        if compromised is not None and compromised > datetime.now(tz=tz.utc):
            raise CommandError(f"{compromised.isoformat()}: Timestamp must be in the past.")

        # If compromised is passed and USE_TZ=False, convert the timestamp to a tz-naive timestamp
        if compromised is not None and settings.USE_TZ is False:
            compromised = timezone.make_naive(compromised)

        cert.revoke(reason=reason, compromised=compromised)

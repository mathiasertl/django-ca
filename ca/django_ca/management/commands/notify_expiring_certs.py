# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca.  If not,
# see <http://www.gnu.org/licenses/>.

"""Management command to notify watchers about expiring certificates.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-management-commands/
"""

import typing
from datetime import timedelta

from django.conf import settings
from django.core.mail import send_mail
from django.core.management.base import BaseCommand, CommandParser
from django.utils import timezone

from ... import ca_settings
from ...models import Certificate


class Command(BaseCommand):  # pylint: disable=missing-class-docstring
    help = "Send notifications about expiring certificates to watchers."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--days", type=int, default=14, help="Warn DAYS days ahead of time (default: %(default)s)."
        )

    def handle(self, **options: typing.Any) -> None:
        now = timezone.now()
        expires = now + timedelta(days=options["days"] + 1)  # add a day to avoid one-of errors

        qs = Certificate.objects.valid().filter(expires__lt=expires)
        for cert in qs:
            days = (cert.expires - now).days

            if days not in ca_settings.CA_NOTIFICATION_DAYS:
                continue

            timestamp = cert.expires.strftime("%Y-%m-%d")
            subj = f"Certificate expiration for {cert.cn} on {timestamp}"
            msg = f"The certificate for {cert.cn} will expire on {timestamp}."
            recipient = list(cert.watchers.values_list("mail", flat=True))
            send_mail(subj, msg, settings.DEFAULT_FROM_EMAIL, recipient)

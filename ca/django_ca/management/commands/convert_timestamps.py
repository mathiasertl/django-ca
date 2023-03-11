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

"""convert_timestamps management command."""

import datetime
from datetime import timezone as tz
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from django_ca.models import AcmeAccount, AcmeChallenge, AcmeOrder, Certificate, CertificateAuthority


class Command(BaseCommand):  # pylint: disable=missing-class-docstring
    help = """Convert naive timestamps in local time to timezone aware timestamps.

    WARNING: This command cannot tell if it has been invoked already and will change timestamps again.
    Multiple invocations will cause wrong timestamps being stored in the database.
    """

    def convert(self, timestamp: datetime.datetime) -> datetime.datetime:
        """Convert a naive timestamp without timezone that now wrongly uses UTC to the correct value."""
        current_timezone = timezone.get_current_timezone()
        return timestamp.replace(tzinfo=current_timezone).astimezone(tz.utc).replace(microsecond=0)

    def handle(self, **options: Any) -> None:
        if settings.USE_TZ is False:
            raise CommandError("This command requires that you have configured USE_TZ=True.")

        self.stdout.write(
            self.style.ERROR(
                "WARNING: This command cannot be undone. Multiple invocations WILL cause corrupt timestamps."
            )
        )
        confirm = input('Type "YES" to continue: ')
        if confirm != "YES":
            self.stdout.write("Aborting.")
            return
        self.stdout.write("Converting timestamps...")

        for ca in CertificateAuthority.objects.all():
            ca.created = self.convert(ca.created)
            if ca.revoked_date is not None:
                ca.revoked_date = self.convert(ca.revoked_date)
            if ca.compromised is not None:
                ca.compromised = self.convert(ca.compromised)
            ca.save()

        for cert in Certificate.objects.all():
            cert.created = self.convert(cert.created)
            if cert.revoked_date is not None:
                cert.revoked_date = self.convert(cert.revoked_date)
            if cert.compromised is not None:
                cert.compromised = self.convert(cert.compromised)
            cert.save()

        for acme_account in AcmeAccount.objects.all():
            acme_account.created = self.convert(acme_account.created)
            acme_account.save()

        for acme_order in AcmeOrder.objects.all():
            acme_order.expires = self.convert(acme_order.expires)
            if acme_order.not_before is not None:
                acme_order.not_before = self.convert(acme_order.not_before)
            if acme_order.not_after is not None:
                acme_order.not_after = self.convert(acme_order.not_after)
            acme_order.save()

        for acme_challenge in AcmeChallenge.objects.filter(validated__isnull=False):
            # TYPE NOTE: mypy doesn't know that the field cannot be null due to the filter above
            acme_challenge.validated = self.convert(acme_challenge.validated)  # type: ignore[arg-type]
            acme_challenge.save()

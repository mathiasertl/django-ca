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
"""Management command to notify watchers about expiring certificates.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-management-commands/
"""

from typing import Any

from django.core.management.base import BaseCommand, CommandParser

from django_ca.celery import run_task
from django_ca.tasks import notify_watchers


class Command(BaseCommand):
    """Implement the :command:`manage.py notify_expiring_certs` command."""

    help = "Send notifications about expiring certificates to watchers."
    _warning = "no longer has any effect and will be removed in django-ca==3.3.0."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--days", type=int, help=f"DEPRECATED: This setting {self._warning}")

    def handle(self, **options: Any) -> None:
        if options["days"] is not None:
            self.stdout.write(self.style.WARNING(f"The --days option {self._warning}"))
        run_task(notify_watchers)

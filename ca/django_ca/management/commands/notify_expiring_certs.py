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

from django.core.management.base import BaseCommand

from django_ca.celery import run_task
from django_ca.tasks import notify_watchers


class Command(BaseCommand):
    """Implement the :command:`manage.py notify_expiring_certs` command."""

    help = "Send notifications about expiring certificates to watchers."

    def handle(self, **options: Any) -> None:
        run_task(notify_watchers)

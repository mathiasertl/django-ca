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

"""Management command to cache CRLs.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-management-commands/
"""

import argparse
from typing import Any

from django_ca.management.base import BaseCommand
from django_ca.tasks import cache_crls, run_task


class Command(BaseCommand):
    """Implement the :command:`manage.py cache_crls` command."""

    help = "Cache CRLs"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "serial",
            nargs="*",
            help="Generate CRLs for the given CAs. If omitted, generate CRLs for all CAs.",
        )

    def handle(self, serial: list[str], **options: Any) -> None:
        run_task(cache_crls, serial)

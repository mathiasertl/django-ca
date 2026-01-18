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

"""Management command to generate CRLs.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-management-commands/
"""

import argparse
from typing import Any

from django_ca.celery import run_task
from django_ca.celery.messages import UseCertificateAuthoritiesTaskArgs
from django_ca.management.base import BaseCommand
from django_ca.tasks import generate_crls


class Command(BaseCommand):
    """Implement the :command:`manage.py generate_crls` command."""

    help = "Generate Certificate Revocation Lists (CRLs)."

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "serial",
            dest="serials",
            nargs="*",
            help="Generate CRLs for the given CAs. If omitted, generate CRLs for all CAs.",
        )

    def handle(self, serials: list[str], **options: Any) -> None:
        data = UseCertificateAuthoritiesTaskArgs(serials=serials)
        run_task(generate_crls, data)

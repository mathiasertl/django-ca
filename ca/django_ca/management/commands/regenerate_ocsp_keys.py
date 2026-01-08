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

"""Management command to regenerate keys used for OCSP signing.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-management-commands/
"""

from collections.abc import Iterable
from typing import Any

from pydantic import ValidationError

from django.core.management.base import CommandError, CommandParser

from django_ca.celery import run_task
from django_ca.celery.messages import GenerateOCSPKeyTaskArgs
from django_ca.conf import model_settings
from django_ca.management.base import BaseCommand
from django_ca.management.mixins import UsePrivateKeyMixin
from django_ca.models import CertificateAuthority
from django_ca.tasks import generate_ocsp_key
from django_ca.utils import add_colons


class Command(UsePrivateKeyMixin, BaseCommand):
    """Implement the :command:`manage.py regenerate_ocsp_keys` command."""

    help = "Regenerate OCSP keys."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "serials",
            metavar="serial",
            nargs="*",
            help="Generate OCSP keys only for the given CA. If omitted, generate keys for all CAs.",
        )

        parser.add_argument(
            "--force",
            action="store_true",
            default=False,
            help="Force regeneration of OCSP responder certificates.",
        )
        parser.add_argument("--quiet", action="store_true", default=False, help="Do not output warnings.")
        self.add_use_private_key_arguments(parser)

    def handle(
        self,
        serials: Iterable[str],
        quiet: bool,
        force: bool,
        **options: Any,
    ) -> None:
        if not serials:
            serials = CertificateAuthority.objects.all().order_by("serial").values_list("serial", flat=True)

        if "ocsp" not in model_settings.CA_PROFILES:
            raise CommandError("ocsp: Undefined profile.")

        errors = 0
        for serial in serials:
            serial = serial.replace(":", "").strip().upper()
            hr_serial = add_colons(serial)
            try:
                ca: CertificateAuthority = CertificateAuthority.objects.get(serial=serial)
            except CertificateAuthority.DoesNotExist:
                self.stderr.write(self.style.ERROR(f"{hr_serial}: Unknown CA."))
                continue

            try:
                key_backend_options = ca.key_backend.get_use_private_key_options(ca, options)
            except ValidationError as ex:
                self.validation_error_to_command_error(ex)
            except Exception as ex:  # pragma: no cover  # pylint: disable=broad-exception-caught
                if quiet is False:
                    self.stderr.write(self.style.WARNING(f"{hr_serial}: {ex}"))
                continue

            try:
                message = GenerateOCSPKeyTaskArgs(
                    serial=serial,
                    key_backend_options=key_backend_options.model_dump(mode="json", exclude_unset=True),
                    force=force,
                )
                run_task(generate_ocsp_key, message)
            except Exception as ex:  # pylint: disable=broad-exception-caught
                self.stderr.write(f"{serial}: {ex}")
                errors += 1

        if errors:
            raise CommandError(f"Regeneration of {errors} OCSP key(s) failed.")

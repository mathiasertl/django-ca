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
from datetime import timedelta
from typing import Any

from pydantic import ValidationError

from cryptography.hazmat.primitives.asymmetric import ec

from django.core.management.base import CommandError, CommandParser

from django_ca.conf import model_settings
from django_ca.management.actions import ExpiresAction
from django_ca.management.base import BaseCommand, add_elliptic_curve, add_key_size
from django_ca.management.mixins import UsePrivateKeyMixin
from django_ca.models import CertificateAuthority
from django_ca.pydantic.messages import GenerateOCSPKeyMessage
from django_ca.tasks import generate_ocsp_key, run_task
from django_ca.typehints import AllowedHashTypes, ParsableKeyType
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
            "--expires",
            default=None,
            action=ExpiresAction,
            help="Sign the certificate for DAYS days (default: %(default)s)",
        )
        parser.add_argument(
            "--force",
            action="store_true",
            default=False,
            help="Force regeneration of OCSP responder certificates.",
        )
        parser.add_argument("--quiet", action="store_true", default=False, help="Do not output warnings.")

        self.add_algorithm(parser)
        private_key_group = parser.add_argument_group("Private key parameters")
        self.add_key_type(
            private_key_group, default=None, default_text="key type of the certificate authority"
        )
        add_key_size(private_key_group)
        add_elliptic_curve(private_key_group)

        self.add_use_private_key_arguments(parser)

        self.add_profile(
            parser, 'Override the profile used for generating the certificate. By default, "ocsp" is used.'
        )

    def handle(
        self,
        serials: Iterable[str],
        profile: str | None,
        expires: timedelta | None,
        algorithm: AllowedHashTypes | None,
        key_type: ParsableKeyType | None,
        key_size: int | None,
        elliptic_curve: ec.EllipticCurve | None,
        quiet: bool,
        force: bool,
        **options: Any,
    ) -> None:
        parameter_dict: dict[str, Any] = {"force": force}
        if profile is not None:
            self.stderr.write("WARNING: --profile is deprecated and will be removed on django-ca 2.4.0.")
            parameter_dict["profile"] = profile
        if expires is not None:
            self.stderr.write("WARNING: --expires is deprecated and will be removed on django-ca 2.4.0.")
            parameter_dict["not_after"] = expires
        if algorithm is not None:
            self.stderr.write("WARNING: --algorithm is deprecated and will be removed on django-ca 2.4.0.")
        if key_type is not None:
            self.stderr.write("WARNING: --key-type is deprecated and will be removed on django-ca 2.4.0.")
        if key_size is not None:
            self.stderr.write("WARNING: --key-size is deprecated and will be removed on django-ca 2.4.0.")
        if elliptic_curve is not None:
            self.stderr.write(
                "WARNING: --elliptic-curve is deprecated and will be removed on django-ca 2.4.0."
            )

        profile = profile or "ocsp"

        # Check if the profile exists. Note that this shouldn't really happen, since valid parameters match
        # existing profiles. The only case is when the user removes the "ocsp" profile, which is the
        # default.
        if profile not in model_settings.CA_PROFILES:
            raise CommandError(f"{profile}: Undefined profile.")

        if not serials:
            serials = CertificateAuthority.objects.all().order_by("serial").values_list("serial", flat=True)

        for serial in serials:
            serial = serial.replace(":", "").strip().upper()
            hr_serial = add_colons(serial)
            try:
                ca: CertificateAuthority = CertificateAuthority.objects.get(serial=serial)
            except CertificateAuthority.DoesNotExist:
                self.stderr.write(self.style.ERROR(f"{hr_serial}: Unknown CA."))
                continue

            per_ca_parameter_dict = {**parameter_dict, "serial": ca.serial}

            try:
                key_backend_options = ca.key_backend.get_use_private_key_options(ca, options)

                # Make sure that the selected signature hash algorithm works for the CAs backend.
                if algorithm is not None:
                    per_ca_parameter_dict["algorithm"] = ca.key_backend.validate_signature_hash_algorithm(
                        ca.key_type, algorithm, default=ca.algorithm
                    )
            except ValidationError as ex:
                self.validation_error_to_command_error(ex)
            except Exception as ex:  # pragma: no cover  # pylint: disable=broad-exception-caught
                if quiet is False:
                    self.stderr.write(self.style.WARNING(f"{hr_serial}: {ex}"))
                continue

            # Get private key parameters for this particular private key
            if key_type is not None:
                per_ca_parameter_dict["key_type"] = key_type

            if ca.key_type in ("RSA", "DSA") and key_size is not None:
                per_ca_parameter_dict["key_size"] = key_size

            if ca.key_type == "EC" and elliptic_curve is not None:
                per_ca_parameter_dict["elliptic_curve"] = elliptic_curve

            parameters = GenerateOCSPKeyMessage.model_validate(per_ca_parameter_dict)

            try:
                run_task(
                    generate_ocsp_key,
                    key_backend_options=key_backend_options.model_dump(mode="json", exclude_unset=True),
                    **parameters.model_dump(mode="json", exclude_unset=True),
                )
            except Exception as ex:
                raise CommandError(ex) from ex

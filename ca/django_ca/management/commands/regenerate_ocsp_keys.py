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

from datetime import timedelta
from typing import Any, Iterable, Optional

from cryptography.hazmat.primitives.asymmetric import ec

from django.core.management.base import CommandError, CommandParser

from django_ca import ca_settings, constants
from django_ca.management.actions import ExpiresAction
from django_ca.management.base import BaseCommand
from django_ca.models import CertificateAuthority
from django_ca.tasks import generate_ocsp_key, run_task
from django_ca.typehints import AllowedHashTypes, ParsableKeyType
from django_ca.utils import add_colons, validate_private_key_parameters


class Command(BaseCommand):  # pylint: disable=missing-class-docstring
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
            default=timedelta(days=2),
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
        self.add_key_size(private_key_group)
        self.add_elliptic_curve(private_key_group)
        self.add_password(parser)

        self.add_profile(
            parser, 'Override the profile used for generating the certificate. By default, "ocsp" is used.'
        )

    def handle(  # pylint: disable=too-many-arguments
        self,
        serials: Iterable[str],
        profile: Optional[str],
        expires: timedelta,
        algorithm: Optional[AllowedHashTypes],
        key_type: Optional[ParsableKeyType],
        key_size: Optional[int],
        elliptic_curve: Optional[ec.EllipticCurve],
        password: Optional[bytes],
        quiet: bool,
        force: bool,
        **options: Any,
    ) -> None:
        profile = profile or "ocsp"

        # Check if the profile exists. Note that this shouldn't really happen, since valid parameters match
        # existing profiles. The only case is when the user removes the "ocsp" profile, which is the
        # default.
        if profile not in ca_settings.CA_PROFILES:
            raise CommandError(f"{profile}: Undefined profile.")

        if not serials:
            serials = CertificateAuthority.objects.all().order_by("serial").values_list("serial", flat=True)

        for serial in serials:
            serial = serial.replace(":", "").strip().upper()
            hr_serial = add_colons(serial)
            try:
                ca = CertificateAuthority.objects.get(serial=serial)
            except CertificateAuthority.DoesNotExist:
                self.stderr.write(self.style.ERROR(f"{hr_serial}: Unknown CA."))
                continue

            if not ca.key_exists:
                if quiet is False:  # pragma: no branch
                    # NOTE: coverage falsely identifies the above condition to always be false.
                    self.stderr.write(self.style.WARNING(f"{hr_serial}: CA has no private key."))

                continue

            # Get private key parameters for this particular private key
            ca_key_type = key_type
            if ca_key_type is None:
                ca_key_type = ca.key_type

            ca_key_size: Optional[int] = None
            if ca_key_type in ("RSA", "DSA") and key_size is not None:
                ca_key_size = key_size

            ca_elliptic_curve: Optional[ec.EllipticCurve] = None
            if ca_key_type == "EC" and elliptic_curve is not None:
                ca_elliptic_curve = elliptic_curve

            validate_private_key_parameters(ca_key_type, ca_key_size, ca_elliptic_curve)

            algorithm_name: Optional[str] = None
            if algorithm is not None:
                algorithm_name = constants.HASH_ALGORITHM_NAMES[type(algorithm)]

            elliptic_curve_name: Optional[str] = None
            if ca_elliptic_curve is not None:
                elliptic_curve_name = ca_elliptic_curve.name

            run_task(
                generate_ocsp_key,
                ca.serial,
                profile=profile,
                expires=expires.total_seconds(),
                algorithm=algorithm_name,
                key_size=ca_key_size,
                key_type=ca_key_type,
                elliptic_curve=elliptic_curve_name,
                password=password,
                force=force,
            )

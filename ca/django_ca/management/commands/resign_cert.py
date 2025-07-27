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

"""Management command to resign an existing certificate.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-management-commands/
"""

from datetime import timedelta
from typing import Any

from cryptography import x509

from django.core.management.base import CommandError, CommandParser

from django_ca import constants
from django_ca.conf import model_settings
from django_ca.constants import ExtensionOID
from django_ca.management import actions
from django_ca.management.actions import CertificateAction
from django_ca.management.base import BaseSignCertCommand
from django_ca.models import Certificate, Watcher
from django_ca.profiles import Profile, profiles


class Command(BaseSignCertCommand):
    """Implement the :command:`manage.py resign_cert` command."""

    help = f"""Sign a CSR and output signed certificate. The defaults depend on the configured
default profile, currently {model_settings.CA_DEFAULT_PROFILE}."""

    add_extensions_help = "Override certificate extensions."
    subject_help = "Override subject for new certificate."

    def add_arguments(self, parser: CommandParser) -> None:
        self.add_use_private_key_arguments(parser)
        parser.add_argument(
            "--expires",
            action=actions.ExpiresAction,
            help=f"Sign the certificate for DAYS days (default: {model_settings.CA_DEFAULT_EXPIRES})",
        )
        parser.add_argument(
            "--watch",
            metavar="EMAIL",
            action="append",
            default=[],
            help="Email EMAIL when this certificate expires (may be given multiple times)",
        )
        parser.add_argument(
            "--out", metavar="FILE", help="Save signed certificate to FILE. If omitted, print to stdout."
        )
        parser.add_argument(
            "cert", action=CertificateAction, allow_revoked=True, help="The certificate to resign."
        )

    def get_profile(self, cert: Certificate) -> Profile:
        """Get requested profile based on command line and given certificate."""
        if cert.profile == "":
            return profiles[None]  # return default profile

        try:
            return profiles[cert.profile]
        except KeyError:
            # Occurs if the certificate specifies a profile which has since been removed from settings
            raise CommandError(  # noqa: B904
                f'Profile "{cert.profile}" for original certificate is no longer defined, please set one via the command line.'  # NOQA: E501
            )

    def handle(
        self,
        cert: Certificate,
        expires: timedelta | None,
        watch: list[str],
        **options: Any,
    ) -> None:
        profile_obj = self.get_profile(cert)
        self.verify_certificate_authority(ca=cert.ca, expires=expires, profile=profile_obj)

        # Get key backend options
        # Get key backend options and validate backend-specific options
        key_backend_options, algorithm = self.get_signing_options(cert.ca, cert.algorithm, options)

        # get list of watchers
        if watch:
            watchers = [Watcher.from_addr(addr) for addr in watch]
        else:
            watchers = list(cert.watchers.all())

        # Process any extensions given via the command-line
        extensions: list[x509.Extension[x509.ExtensionType]] = []

        # Copy over extensions from the original certificate (if not passed via the command-line)
        for oid, extension in cert.extensions.items():
            # These extensions are handled by the manager itself based on the CA:
            if oid in (
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
                ExtensionOID.CRL_DISTRIBUTION_POINTS,
                ExtensionOID.ISSUER_ALTERNATIVE_NAME,
                ExtensionOID.FRESHEST_CRL,
            ):
                continue

            # Extensions that are not configurable cannot be copied, as they would be rejected by the
            # profile.
            if (
                not isinstance(extension.value, x509.UnrecognizedExtension)
                and oid not in constants.CONFIGURABLE_EXTENSION_KEYS
            ):
                continue

            extensions.append(extension)

        try:
            cert = Certificate.objects.create_cert(
                ca=cert.ca,
                key_backend_options=key_backend_options,
                csr=cert.csr.loaded,
                profile=profile_obj,
                not_after=expires,
                subject=cert.subject,
                algorithm=algorithm,
                extensions=extensions,  # type: ignore[arg-type]
            )
        except Exception as ex:
            raise CommandError(ex) from ex

        cert.watchers.add(*watchers)

        if options["out"]:
            with open(options["out"], "w", encoding="ascii") as stream:
                stream.write(cert.pub.pem)
        else:
            self.stdout.write(cert.pub.pem)

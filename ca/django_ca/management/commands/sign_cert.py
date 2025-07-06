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

"""Management command to sign a new certificate.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-management-commands/
"""

import sys
from datetime import timedelta
from typing import Any

from cryptography import x509
from cryptography.x509.oid import NameOID

from django.core.management.base import CommandError, CommandParser

from django_ca.conf import model_settings
from django_ca.management.base import BaseSignCertCommand
from django_ca.models import Certificate, CertificateAuthority, Watcher
from django_ca.profiles import profiles
from django_ca.typehints import AllowedHashTypes, ConfigurableExtension


class Command(BaseSignCertCommand):
    """Implement the :command:`manage.py sign_cert` command."""

    help = f"""Sign a CSR and output signed certificate. The defaults depend on the configured
default profile, currently {model_settings.CA_DEFAULT_PROFILE}."""

    add_extensions_help = """Values for more complex x509 extensions. This is for advanced usage only, the
profiles already set the correct values for the most common use cases. See
https://django-ca.readthedocs.io/en/latest/extensions.html for more information."""
    subject_help = """The certificate subject of the CSR is not used. The default subject is configured
            with the CA_DEFAULT_SUBJECT setting and may be overwritten by a profile named with
            --profile. The --subject option allows you to name a CommonName (which is not usually
            in the defaults) and override any default values."""

    def add_arguments(self, parser: CommandParser) -> None:
        general_group = self.add_base_args(parser)

        general_group.add_argument(
            "--csr",
            dest="csr_path",
            default="-",
            metavar="FILE",
            help="The path to the certificate to sign, if omitted, you will be be prompted.",
        )
        general_group.add_argument(
            "-b", "--bundle", default=False, action="store_true", help="Output the whole certificate bundle."
        )

        self.add_profile(
            parser,
            """Sign certificate based on the given profile. A profile only sets the the
                         default values, options like --key-usage still override the profile.""",
        )

    def handle(  # pylint: disable=too-many-locals
        self,
        ca: CertificateAuthority,
        subject: x509.Name | None,
        expires: timedelta | None,
        watch: list[str],
        csr_path: str,
        bundle: bool,
        profile: str | None,
        out: str | None,
        algorithm: AllowedHashTypes | None,
        # Subject Alternative Name extension - used in the function directly
        subject_alternative_name: x509.SubjectAlternativeName | None,
        **options: Any,
    ) -> None:
        # Validate parameters early so that we can return better feedback to the user.
        profile_obj = profiles[profile]
        self.verify_certificate_authority(ca=ca, expires=expires, profile=profile_obj)

        # Get key backend options and validate backend-specific options
        key_backend_options, algorithm = self.get_signing_options(ca, algorithm, options)

        # get a list of watchers
        watchers = [Watcher.from_addr(addr) for addr in watch]

        # Process any extensions given via the command-line
        extensions: list[ConfigurableExtension] = self.get_end_entity_extensions(
            subject_alternative_name=subject_alternative_name, **options
        )

        cname = None
        if subject is not None:
            cname = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not cname and subject_alternative_name is None:
            raise CommandError(
                "Must give at least a Common Name in --subject or one or more "
                "--subject-alternative-name/--name arguments."
            )

        # Read the CSR
        if csr_path == "-":
            self.stdout.write("Please paste the CSR:")
            csr_bytes = b""
            while True:
                csr_bytes += sys.stdin.buffer.read(1)
                # COVERAGE NOTE: mock function always returns the full string, so we always break right away
                if csr_bytes.strip().endswith(b"-----END CERTIFICATE REQUEST-----"):  # pragma: no branch
                    break
        else:
            with open(csr_path, "rb") as csr_stream:
                csr_bytes = csr_stream.read()

        if csr_bytes.startswith(b"-----BEGIN CERTIFICATE REQUEST-----"):
            csr = x509.load_pem_x509_csr(csr_bytes)
        else:
            csr = x509.load_der_x509_csr(csr_bytes)

        try:
            cert = Certificate.objects.create_cert(
                ca,
                key_backend_options,
                csr,
                profile=profile_obj,
                not_after=expires,
                extensions=extensions,
                subject=subject,
                algorithm=algorithm,
            )
        except Exception as ex:
            raise CommandError(ex) from ex

        cert.watchers.add(*watchers)

        if bundle is True:
            output = cert.bundle_as_pem
        else:
            output = cert.pub.pem

        if out:
            with open(out, "w", encoding="ascii") as stream:
                stream.write(output)
        else:
            self.stdout.write(output)

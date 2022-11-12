# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca.  If not,
# see <http://www.gnu.org/licenses/>.

"""Management command to view details for a certificate.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-management-commands/
"""

import typing
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

from django.core.management.base import CommandParser

from ...models import Certificate
from ..base import BinaryCommand
from ..mixins import CertCommandMixin


class Command(CertCommandMixin, BinaryCommand):
    """Implement :command:`manage.py view_cert`."""

    allow_revoked = True
    help = 'View a certificate. The "list_certs" command lists all known certificates.'

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "-n",
            "--no-pem",
            default=False,
            action="store_true",
            help="Do not output public certificate in PEM format.",
        )
        parser.add_argument(
            "-e",
            "--extensions",
            default=False,
            action="store_true",
            help="Show all extensions, not just subjectAltName.",
        )
        self.add_format(parser)
        super().add_arguments(parser)

    def handle(self, cert: Certificate, encoding: Encoding, **options: typing.Any) -> None:
        self.stdout.write(f"Common Name: {cert.cn}")

        # self.stdout.write notBefore/notAfter
        self.stdout.write(f"Valid from: {cert.not_before.strftime('%Y-%m-%d %H:%M')}")
        self.stdout.write(f"Valid until: {cert.not_after.strftime('%Y-%m-%d %H:%M')}")

        # self.stdout.write status
        now = datetime.utcnow()
        if cert.revoked:
            self.stdout.write("Status: Revoked")
        elif cert.not_after < now:
            self.stdout.write("Status: Expired")
        elif cert.not_before > now:
            self.stdout.write("Status: Not yet valid")
        else:
            self.stdout.write("Status: Valid")

        # self.stdout.write extensions
        if options["extensions"]:
            self.print_extensions(cert)
        else:
            try:
                san = cert.pub.loaded.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                self.print_extension(san)
            except x509.ExtensionNotFound:
                pass

        self.stdout.write("Watchers:")
        for watcher in cert.watchers.all():
            self.stdout.write(f"* {watcher}")

        self.stdout.write("Digest:")
        for algorithm in [hashes.SHA256(), hashes.SHA512()]:
            self.stdout.write(f"    {algorithm.name}: {cert.get_fingerprint(algorithm)}")

        self.stdout.write(f"HPKP pin: {cert.hpkp_pin}")

        if not options["no_pem"]:
            self.stdout.write("")
            self.stdout.write(cert.pub.encode(encoding))

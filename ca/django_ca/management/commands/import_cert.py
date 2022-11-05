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

"""Management command to import a certificate.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-management-commands/
"""

import argparse
import typing

from cryptography import x509

from django.core.management.base import CommandError, CommandParser

from ...models import Certificate, CertificateAuthority
from ..base import BaseCommand


class Command(BaseCommand):  # pylint: disable=missing-class-docstring
    help = """Import an existing certificate.

The authority that that signed the certificate must exist in the database."""

    def add_arguments(self, parser: CommandParser) -> None:
        self.add_ca(parser, allow_disabled=False)
        parser.add_argument(
            "pub", help="Path to the public key (PEM or DER format).", type=argparse.FileType("rb")
        )

    def handle(self, pub: typing.BinaryIO, ca: CertificateAuthority, **options: typing.Any) -> None:
        pub_data = pub.read()

        # close reader objects (otherwise we get a ResourceWarning)
        pub.close()

        # load public key
        try:
            pub_loaded = x509.load_pem_x509_certificate(pub_data)
        except Exception:  # pylint: disable=broad-except
            try:
                pub_loaded = x509.load_der_x509_certificate(pub_data)
            except Exception as ex:
                raise CommandError("Unable to load public key.") from ex

        cert = Certificate(ca=ca)
        cert.update_certificate(pub_loaded)
        cert.save()

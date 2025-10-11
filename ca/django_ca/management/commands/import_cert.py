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

"""Management command to import a certificate.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-management-commands/
"""

from typing import Any

from cryptography import x509

from django.core.management.base import CommandError, CommandParser

from django_ca.management.base import BaseCommand
from django_ca.models import Certificate, CertificateAuthority


class Command(BaseCommand):
    """Implement the :command:`manage.py import_cert` command."""

    help = """Import an existing certificate.

The authority that that signed the certificate must exist in the database."""

    def add_arguments(self, parser: CommandParser) -> None:
        self.add_ca(parser, allow_disabled=False)
        parser.add_argument("pub", help="Path to the public key (PEM or DER format).")

    def handle(self, pub: str, ca: CertificateAuthority, **options: Any) -> None:
        with open(pub, "rb") as stream:
            pub_data = stream.read()

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

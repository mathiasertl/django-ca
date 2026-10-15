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

"""Management command to view details for a certificate authority.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-management-commands/
"""

from django.core.management.base import CommandParser

from django_ca.management.base import BaseCommand
from django_ca.management.mixins import OutputCertificateAuthorityMixin
from django_ca.models import CertificateAuthority


class Command(OutputCertificateAuthorityMixin, BaseCommand):
    """Implement the :command:`manage.py view_ca` command."""

    help = "View details of a certificate authority."

    def add_arguments(self, parser: CommandParser) -> None:
        self.add_ca(parser, arg="ca", allow_disabled=True)
        self.add_output_certificate_arguments(parser, default_format="text")

    def handle(
        self,
        ca: CertificateAuthority,
        output_format: str,
        serial_format: str,
        json_indent: int,
        pem: bool,
        bundle: bool,
        extensions: bool,
        wrap: bool,
        **options: object,
    ) -> None:
        self.output_certificate(
            ca,
            output_format=output_format,
            serial_format=serial_format,
            json_indent=json_indent,
            pem=pem,
            bundle=bundle,
            extensions=extensions,
            wrap=wrap,
        )

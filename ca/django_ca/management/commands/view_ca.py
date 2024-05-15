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

from typing import Any

from django.core.management.base import CommandParser

from django_ca.conf import model_settings
from django_ca.management.base import BaseViewCommand
from django_ca.models import CertificateAuthority
from django_ca.utils import add_colons


class Command(BaseViewCommand):
    """Implement the :command:`manage.py view_ca` command."""

    help = "View details of a certificate authority."

    def add_arguments(self, parser: CommandParser) -> None:
        self.add_ca(parser, arg="ca", allow_disabled=True)
        super().add_arguments(parser)

    def output_ca_information(self, ca: CertificateAuthority) -> None:
        """Output information specific to a CA."""
        self.stdout.write("\nCertificate Authority information:")
        if ca.parent:
            self.stdout.write(f"* Parent: {ca.parent.name} ({add_colons(ca.parent.serial)})")
        else:
            self.stdout.write("* Certificate authority is a root CA.")

        children = ca.children.all()
        if children:
            self.stdout.write("* Children:")
            for child in children:
                self.stdout.write(f"  * {child.name} ({add_colons(child.serial)})")
        else:
            self.stdout.write("* Certificate authority has no children.")

        if ca.max_path_length is None:
            path_length = "unlimited"
        else:
            path_length = str(ca.max_path_length)

        self.stdout.write(f"* Maximum levels of sub-CAs (path length): {path_length}")

        self.stdout.write("")
        self.stdout.write("Key storage options:")
        self.stdout.write(f"* backend: {ca.key_backend_alias}")
        if ca.key_backend_options:
            for key, value in ca.key_backend_options.items():
                self.stdout.write(f"* {key}: {value}")
        else:
            self.stdout.write("* No information available.")

        if ca.website:
            self.stdout.write(f"* Website: {ca.website}")
        if ca.terms_of_service:
            self.stdout.write(f"* Terms of service: {ca.terms_of_service}")
        if ca.caa_identity:
            self.stdout.write(f"* CAA identity: {ca.caa_identity}")

    def handle(
        self, ca: CertificateAuthority, pem: bool, extensions: bool, wrap: bool = True, **options: Any
    ) -> None:
        self.stdout.write(f"* Name: {ca.name}")
        self.stdout.write(f"* Enabled: {'Yes' if ca.enabled else 'No'}")
        self.output_header(ca)
        self.output_ca_information(ca)

        if model_settings.CA_ENABLE_ACME:
            self.stdout.write("")
            self.stdout.write("ACMEv2 support:")
            self.stdout.write(f"* Enabled: {ca.acme_enabled}")
            if ca.acme_enabled:
                self.stdout.write(f"* Requires contact: {ca.acme_requires_contact}")

        if extensions is True:
            self.stdout.write("\nCertificate extensions:")
            self.print_extensions(ca)

        if (
            ca.sign_authority_information_access
            or ca.sign_certificate_policies
            or ca.sign_crl_distribution_points
            or ca.sign_issuer_alternative_name
        ):
            self.stdout.write("\nCertificate extensions for signed certificates:")
            if ca.sign_authority_information_access:
                self.print_extension(ca.sign_authority_information_access)
            if ca.sign_certificate_policies:
                self.print_extension(ca.sign_certificate_policies)
            if ca.sign_crl_distribution_points:
                self.print_extension(ca.sign_crl_distribution_points)
            if ca.sign_issuer_alternative_name:
                self.print_extension(ca.sign_issuer_alternative_name)
        else:
            self.stdout.write("\nNo certificate extensions for signed certificates.")

        self.output_footer(ca, pem=pem, wrap=wrap)

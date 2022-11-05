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

"""Management command to view details for a certificate authority.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-management-commands/
"""

import typing

from django.core.management.base import CommandParser

from ... import ca_settings
from ...models import CertificateAuthority
from ...utils import add_colons, ca_storage
from ..base import BaseCommand


class Command(BaseCommand):  # pylint: disable=missing-class-docstring
    help = "View details of a certificate authority."

    def add_arguments(self, parser: CommandParser) -> None:
        self.add_ca(parser, arg="ca", allow_disabled=True, allow_unusable=True)

    def handle(self, ca: CertificateAuthority, **options: typing.Any) -> None:
        try:
            path = ca_storage.path(ca.private_key_path)
        except NotImplementedError:
            # Will raise NotImplementedError if storage backend does not support path(), in which case we use
            # the relative path from the database.
            # https://docs.djangoproject.com/en/dev/ref/files/storage/#django.core.files.storage.Storage.path
            path = ca.private_key_path

        self.stdout.write(f"{ca.name} (%s):" % ("enabled" if ca.enabled else "disabled"))
        self.stdout.write(f"* Serial: {add_colons(ca.serial)}")

        if ca_storage.exists(ca.private_key_path):
            self.stdout.write(f"* Path to private key:\n  {path}")
        else:
            self.stdout.write("* Private key not available locally.")

        if ca.parent:
            self.stdout.write(f"* Parent: {ca.parent.name} ({ca.parent.serial})")
        else:
            self.stdout.write("* Is a root CA.")

        children = ca.children.all()
        if children:
            self.stdout.write("* Children:")
            for child in children:
                self.stdout.write(f"  * {child.name} ({child.serial})")
        else:
            self.stdout.write("* Has no children.")

        if ca.pathlen is None:
            pathlen = "unlimited"
        else:
            pathlen = str(ca.pathlen)

        self.stdout.write(f"* Distinguished Name: {ca.distinguished_name}")
        self.stdout.write(f"* Maximum levels of sub-CAs (pathlen): {pathlen}")
        self.stdout.write(f"* HPKP pin: {ca.hpkp_pin}")

        if ca.website:
            self.stdout.write(f"* Website: {ca.website}")
        if ca.terms_of_service:
            self.stdout.write(f"* Terms of service: {ca.terms_of_service}")
        if ca.caa_identity:
            self.stdout.write(f"* CAA identity: {ca.caa_identity}")

        if ca_settings.CA_ENABLE_ACME:
            self.stdout.write("")
            self.stdout.write("ACMEv2 support:")
            self.stdout.write(f"* Enabled: {ca.acme_enabled}")
            if ca.acme_enabled:
                self.stdout.write(f"* Requires contact: {ca.acme_requires_contact}")

        self.stdout.write("")
        self.stdout.write("X509 v3 certificate extensions for CA:")

        self.print_extensions(ca)

        self.stdout.write("")
        self.stdout.write("X509 v3 certificate extensions for signed certificates:")
        self.stdout.write(f"* Certificate Revokation List (CRL): {ca.crl_url or None}")
        self.stdout.write(f"* Issuer URL: {ca.issuer_url or None}")
        self.stdout.write(f"* OCSP URL: {ca.ocsp_url or None}")
        self.stdout.write(f"* Issuer Alternative Name: {ca.issuer_alt_name or None}")
        self.stdout.write(f"\n{ca.pub.pem}")

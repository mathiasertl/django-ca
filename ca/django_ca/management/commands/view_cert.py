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

"""Management command to view details for a certificate.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-management-commands/
"""

from typing import Any

from django_ca.management.base import BaseViewCommand
from django_ca.management.mixins import CertCommandMixin
from django_ca.models import Certificate


class Command(CertCommandMixin, BaseViewCommand):
    """Implement :command:`manage.py view_cert`."""

    allow_revoked = True
    help = 'View a certificate. The "list_certs" command lists all known certificates.'

    def handle(self, cert: Certificate, pem: bool, extensions: bool, wrap: bool, **options: Any) -> None:
        self.output_header(cert)

        watchers = cert.watchers.all()
        if watchers:
            self.stdout.write("* Watchers:")
            for watcher in watchers:
                self.stdout.write(f"  * {watcher}")
        else:
            self.stdout.write("* No watchers")

        # self.stdout.write extensions
        if extensions:
            self.stdout.write("\nCertificate extensions:")
            self.print_extensions(cert)

        self.output_footer(cert, pem=pem, wrap=wrap)

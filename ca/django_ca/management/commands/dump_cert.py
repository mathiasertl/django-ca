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

"""Management command to write a certificates public key to stdout or a file.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-management-commands/
"""

import typing

from cryptography.hazmat.primitives.serialization import Encoding

from django.core.management.base import CommandError, CommandParser

from ...models import Certificate
from ..base import BinaryCommand
from ..mixins import CertCommandMixin


class Command(CertCommandMixin, BinaryCommand):
    """Implement the :command:`manage.py dump_cert` command."""

    allow_revoked = True
    help = "Dump a certificate to a file."

    def add_arguments(self, parser: CommandParser) -> None:
        super().add_arguments(parser)
        self.add_format(parser)
        parser.add_argument(
            "-b", "--bundle", default=False, action="store_true", help="Dump the whole certificate bundle."
        )
        parser.add_argument(
            "path", nargs="?", default="-", help='Path where to dump the certificate. Use "-" for stdout.'
        )

    def handle(
        self, cert: Certificate, bundle: bool, encoding: Encoding, path: str, **options: typing.Any
    ) -> None:
        if bundle and encoding == Encoding.DER:
            raise CommandError("Cannot dump bundle when using DER format.")

        if bundle:
            self.dump(path, cert.bundle_as_pem.encode())
        else:
            self.dump(path, cert.pub.encode(encoding))

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

"""Management command to write a CRL to stdout or a file.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-management-commands/
"""

import typing

from cryptography.hazmat.primitives.serialization import Encoding

from django.core.management.base import CommandError, CommandParser

from ...models import CertificateAuthority
from ...typehints import Literal
from ..base import BinaryCommand


class Command(BinaryCommand):
    """Implement :command:`manage.py dump_crl`."""

    help = "Write the certificate revocation list (CRL)."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "-e",
            "--expires",
            type=int,
            default=86400,
            metavar="SECONDS",
            help="Seconds until a new CRL will be available (default: %(default)s).",
        )
        parser.add_argument(
            "path", nargs="?", default="-", help='Path for the output file. Use "-" for stdout.'
        )
        parser.add_argument(
            "-s",
            "--scope",
            choices=["ca", "user", "attribute"],
            help="Limit the scope for the CRL (default: %(default)s).",
        )

        include_idp_group = parser.add_mutually_exclusive_group()
        include_idp_group.add_argument(
            "--include-issuing-distribution-point",
            action="store_true",
            default=None,
            help="Force inclusion of an IssuingDistributionPoint extension.",
        )
        include_idp_group.add_argument(
            "--exclude-issuing-distribution-point",
            action="store_false",
            dest="include_issuing_distribution_point",
            help="Force exclusion of an IssuingDistributionPoint extension.",
        )
        self.add_algorithm(parser)
        self.add_format(parser)
        self.add_ca(parser, allow_disabled=True)
        self.add_password(parser)
        super().add_arguments(parser)

    def handle(
        self,
        path: str,
        ca: CertificateAuthority,
        encoding: Encoding,
        scope: typing.Optional[Literal["ca", "user", "attribute"]],
        include_issuing_distribution_point: typing.Optional[bool],
        **options: typing.Any
    ) -> None:
        # Catch this case early so that we can give a better error message.
        if include_issuing_distribution_point is True and ca.parent is None and scope is None:
            raise CommandError(
                "Cannot add IssuingDistributionPoint extension to CRLs with no scope for root CAs."
            )

        kwargs = {
            "expires": options["expires"],
            "algorithm": options["algorithm"],
            "password": options["password"],
        }

        # See if we can work with the private key
        self.test_private_key(ca, options["password"])

        try:
            crl = ca.get_crl(
                include_issuing_distribution_point=include_issuing_distribution_point, scope=scope, **kwargs
            ).public_bytes(encoding)
        except Exception as ex:
            # Note: all parameters are already sanitized by parser actions
            raise CommandError(ex) from ex

        if path == "-":
            self.stdout.write(crl, ending=b"")
        else:
            try:
                with open(path, "wb") as stream:
                    stream.write(crl)
            except IOError as ex:
                raise CommandError(ex) from ex

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

"""Management command to write a CRL to stdout or a file.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-management-commands/
"""

from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from django.core.management.base import CommandError, CommandParser

from django_ca.management.actions import ExpiresAction
from django_ca.management.base import BinaryCommand
from django_ca.management.mixins import UsePrivateKeyMixin
from django_ca.models import CertificateAuthority, CertificateRevocationList


class Command(UsePrivateKeyMixin, BinaryCommand):
    """Implement :command:`manage.py dump_crl`."""

    help = "Write the certificate revocation list (CRL)."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "-e",
            "--expires",
            action=ExpiresAction,
            default=timedelta(days=1),
            metavar="SECONDS",
            help="Seconds until a new CRL will be available (default: %(default)s).",
        )
        parser.add_argument(
            "path", nargs="?", default="-", help='Path for the output file. Use "-" for stdout.'
        )

        scope_group = parser.add_argument_group("Scope", "Options that affect the scope of the CRL.")
        only_certs_group = scope_group.add_mutually_exclusive_group()
        only_certs_group.add_argument(
            "--only-contains-ca-certs",
            action="store_true",
            default=False,
            help="Only include CA certificates in the CRL.",
        )
        only_certs_group.add_argument(
            "--only-contains-user-certs",
            action="store_true",
            default=False,
            help="Only include end-entity certificates in the CRL.",
        )
        only_certs_group.add_argument(
            "--only-contains-attribute-certs",
            action="store_true",
            default=False,
            help="Only include attribute certificates in the CRL (NOTE: Attribute certificates are not "
            "supported, and the CRL will always be empty).",
        )
        scope_group.add_argument(
            "--only-some-reasons",
            dest="reasons",
            action="append",
            choices=[
                reason.name
                for reason in x509.ReasonFlags
                if reason not in (x509.ReasonFlags.unspecified, x509.ReasonFlags.remove_from_crl)
            ],
            help="Only include certificates revoked for the given reason. Can be given multiple "
            "times to include multiple reasons.",
        )

        self.add_format(parser)
        self.add_ca(parser, allow_disabled=True)
        self.add_use_private_key_arguments(parser)
        super().add_arguments(parser)

    def handle(
        self,
        path: str,
        ca: CertificateAuthority,
        encoding: Encoding,
        only_contains_ca_certs: bool,
        only_contains_user_certs: bool,
        only_contains_attribute_certs: bool,
        expires: timedelta,
        reasons: list[str] | None,
        **options: Any,
    ) -> None:
        key_backend_options, _algorithm = self.get_signing_options(ca, ca.algorithm, options)

        next_update = datetime.now(tz=UTC) + expires
        only_some_reasons = None
        if reasons is not None:
            only_some_reasons = frozenset([x509.ReasonFlags[reason] for reason in reasons])

        # Actually create the CRL
        try:
            crl = CertificateRevocationList.objects.create_certificate_revocation_list(
                ca=ca,
                key_backend_options=key_backend_options,
                next_update=next_update,
                only_contains_ca_certs=only_contains_ca_certs,
                only_contains_user_certs=only_contains_user_certs,
                only_contains_attribute_certs=only_contains_attribute_certs,
                only_some_reasons=only_some_reasons,
            )
            if encoding == Encoding.PEM:
                data = crl.pem
            else:
                if crl.data is None:  # pragma: no cover  # just to make mypy happy
                    raise CommandError("CRL was not generated.")
                data = bytes(crl.data)
        except Exception as ex:
            # Note: all parameters are already sanitized by parser actions
            raise CommandError(ex) from ex

        if path == "-":
            self.stdout.write(data, ending=b"")
        else:
            try:
                with open(path, "wb") as stream:
                    stream.write(data)
            except OSError as ex:
                raise CommandError(ex) from ex

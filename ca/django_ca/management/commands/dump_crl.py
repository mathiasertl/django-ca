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

import typing
import warnings
from datetime import datetime, timedelta, timezone as tz
from typing import Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from django.core.management.base import CommandError, CommandParser

from django_ca.deprecation import RemovedInDjangoCA230Warning
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
            "-s",
            "--scope",
            choices=["ca", "user", "attribute"],
            help="Limit the scope for the CRL (default: %(default)s).",
        )
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
        self.add_use_private_key_arguments(parser)
        super().add_arguments(parser)

    def handle(
        self,
        path: str,
        ca: CertificateAuthority,
        encoding: Encoding,
        scope: Optional[typing.Literal["ca", "user", "attribute"]],
        only_contains_ca_certs: bool,
        only_contains_user_certs: bool,
        only_contains_attribute_certs: bool,
        include_issuing_distribution_point: Optional[bool],
        expires: timedelta,
        reasons: Optional[list[str]],
        **options: Any,
    ) -> None:
        key_backend_options, _algorithm = self.get_signing_options(ca, ca.algorithm, options)

        if include_issuing_distribution_point is not None:
            warnings.warn(
                "--include-issuing-distribution-point and --exclude-issuing-distribution-point no longer "
                "have any effect and will be removed in django-ca 2.3.0.",
                RemovedInDjangoCA230Warning,
                stacklevel=1,
            )
        if options.get("algorithm"):
            warnings.warn(
                "--algorithm no longer has any effect and will be removed in django-ca 2.3.0.",
                RemovedInDjangoCA230Warning,
                stacklevel=1,
            )
        if scope is not None:
            warnings.warn(
                "--scope is deprecated and will be removed in django-ca 2.3.0. Use "
                "--only-contains-{ca,user,attribute}-certs instead.",
                RemovedInDjangoCA230Warning,
                stacklevel=1,
            )

        # Handle deprecated scope parameter.
        if scope == "user":
            only_contains_user_certs = True
        elif scope == "ca":
            only_contains_ca_certs = True
        elif scope == "attribute":
            only_contains_attribute_certs = True

        next_update = datetime.now(tz=tz.utc) + expires
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

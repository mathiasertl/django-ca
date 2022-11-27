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

"""Management command to edit a certificate authority.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-management-commands/
"""

import typing

from cryptography import x509

from django.core.management.base import CommandParser

from ... import ca_settings
from ...constants import EXTENSION_KEYS
from ...models import CertificateAuthority
from ...utils import format_general_name
from ..base import BaseCommand
from ..mixins import CertificateAuthorityDetailMixin


class Command(CertificateAuthorityDetailMixin, BaseCommand):
    """Implement :command:`manage.py edit_ca`."""

    help = "Edit a certificate authority."

    def add_arguments(self, parser: CommandParser) -> None:
        self.add_general_args(parser, default=None)
        self.add_ca(parser, "ca", allow_disabled=True)
        self.add_acme_group(parser)
        self.add_ca_args(parser)

        group = parser.add_mutually_exclusive_group()
        group.add_argument(
            "--enable",
            action="store_true",
            dest="enabled",
            default=None,
            help="Enable the certificate authority.",
        )
        group.add_argument(
            "--disable", action="store_false", dest="enabled", help="Disable the certificate authority."
        )

    def handle(self, ca: CertificateAuthority, **options: typing.Any) -> None:
        if options["issuer_url"] is not None:
            ca.issuer_url = options["issuer_url"]
        if options[EXTENSION_KEYS[x509.IssuerAlternativeName.oid]]:
            ian = options[EXTENSION_KEYS[x509.IssuerAlternativeName.oid]]
            ca.issuer_alt_name = ",".join([format_general_name(name) for name in ian.value])
        if options["ocsp_url"] is not None:
            ca.ocsp_url = options["ocsp_url"]
        if options["crl_url"] is not None:
            ca.crl_url = "\n".join(options["crl_url"])

        if options["enabled"] is not None:
            ca.enabled = options["enabled"]

        if options["caa"] is not None:
            ca.caa_identity = options["caa"]
        if options["website"] is not None:
            ca.website = options["website"]
        if options["tos"] is not None:
            ca.terms_of_service = options["tos"]

        # set options where argparse dest matches Django model field name
        if ca_settings.CA_ENABLE_ACME:  # pragma: no branch; never False because parser throws error already
            for param in ["acme_enabled", "acme_requires_contact"]:
                if options[param] is not None:
                    setattr(ca, param, options[param])

        ca.save()

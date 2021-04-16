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

"""Mixins for :py:class:`~django:django.core.management.BaseCommand` classes."""

import typing

from django.core.management.base import CommandParser

from .. import ca_settings
from ..extensions import IssuerAlternativeName
from ..typehints import Protocol
from . import actions


class CommandProtocol(Protocol):
    """Protocol for mixin classes, so that mypy can detect any issues."""

    def add_arguments(self, parser: CommandParser) -> None:
        """Entry point for subclassed commands to add custom arguments."""


class CertCommandMixin(CommandProtocol):
    """Mixin for commands that operate on a single certificate."""

    allow_revoked = False

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "cert",
            action=actions.CertificateAction,
            allow_revoked=self.allow_revoked,
            help="""Certificate by CommonName or serial. If you give a CommonName (which is not by
                definition unique) there must be only one valid certificate with the given
                CommonName.""",
        )
        super().add_arguments(parser)


class CertificateAuthorityDetailMixin(CommandProtocol):
    """Mixin to add common arguments to commands that create or update a certificate authority."""

    def add_general_args(self, parser: CommandParser, default: typing.Optional[str] = "") -> None:
        """Add some general arguments.

        Parameters
        ----------

        parser : CommandParser
        default : str, optional
            Default value for arguments. Pass ``None`` if you want to be able to know if the value was passed
            or not.
        """

        group = parser.add_argument_group("General", "General information about the CA.")
        group.add_argument("--caa", default=default, metavar="NAME", help="CAA record for this CA.")
        group.add_argument(
            "--website",
            default=default,
            metavar="URL",
            action=actions.URLAction,
            help="Browsable URL for the CA.",
        )
        group.add_argument(
            "--tos",
            default=default,
            metavar="URL",
            action=actions.URLAction,
            help="Terms of service URL for the CA.",
        )

    def add_acme_group(self, parser: CommandParser) -> None:
        """Add arguments for ACMEv2."""

        if not ca_settings.CA_ENABLE_ACME:
            return

        group = parser.add_argument_group("ACMEv2", "ACMEv2 configuration.")

        enable_group = group.add_mutually_exclusive_group()
        enable_group.add_argument(
            "--acme-enable",
            dest="acme_enabled",
            action="store_true",
            default=None,
            help="Enable ACMEv2 support.",
        )
        enable_group.add_argument(
            "--acme-disable", dest="acme_enabled", action="store_false", help="Disable ACMEv2 support."
        )

        disable_group = group.add_mutually_exclusive_group()
        disable_group.add_argument(
            "--acme-contact-optional",
            dest="acme_requires_contact",
            action="store_false",
            default=None,
            help="Do not require email address during ACME account registration.",
        )

        disable_group.add_argument(
            "--acme-contact-required",
            dest="acme_requires_contact",
            action="store_true",
            help="Require email address during ACME account registration.",
        )

    def add_ca_args(self, parser: CommandParser) -> None:
        """Add CA arguments."""

        group = parser.add_argument_group(
            "X509 v3 certificate extensions for signed certificates",
            "Extensions added when signing certificates.",
        )
        group.add_argument(
            "--issuer-url",
            metavar="URL",
            action=actions.URLAction,
            help="URL to the certificate of your CA (in DER format).",
        )
        group.add_argument(
            "--issuer-alt-name",
            metavar="URL",
            action=actions.AlternativeNameAction,
            extension=IssuerAlternativeName,
            help="URL to the homepage of your CA.",
        )
        group.add_argument(
            "--crl-url",
            action=actions.MultipleURLAction,
            help="URL to a certificate revokation list. Can be given multiple times.",
        )
        group.add_argument(
            "--ocsp-url", metavar="URL", action=actions.URLAction, help="URL of an OCSP responder."
        )

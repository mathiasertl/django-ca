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

import abc
import typing
from textwrap import indent

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from django.core.exceptions import ImproperlyConfigured
from django.core.management.base import BaseCommand, CommandError, CommandParser

from .. import ca_settings
from ..extensions import extension_as_text, get_extension_name
from ..models import CertificateAuthority, X509CertMixin
from ..utils import add_colons
from . import actions

if typing.TYPE_CHECKING:
    # When type checking, mixins use BaseCommand as base class for all mixins.
    # This way, mypy does not complain about missing attributes.
    _Base = BaseCommand
else:
    _Base = object


class ArgumentsMixin(_Base, metaclass=abc.ABCMeta):
    """Mixin that adds some common functions to BaseCommand subclasses."""

    def add_algorithm(self, parser: CommandParser) -> None:
        """Add the --algorithm option."""

        parser.add_argument(
            "--algorithm",
            metavar="{sha512,sha256,...}",
            default=ca_settings.CA_DIGEST_ALGORITHM,
            action=actions.AlgorithmAction,
            help="The HashAlgorithm that will be used to generate the signature (default: {default}).",
        )

    def add_ca(
        self,
        parser: CommandParser,
        arg: str = "--ca",
        help_text: str = "Certificate authority to use (default: %(default)s).",
        allow_disabled: bool = False,
        no_default: bool = False,
        allow_unusable: bool = False,
    ) -> None:
        """Add the ``--ca`` action.

        Parameters
        ----------

        parser
        arg : str, optional
        help : str, optional
        allow_disabled : bool, optional
        no_default : bool, optional
        allow_unusable : bool, optional
        """
        if no_default is True:
            default = None
        else:
            try:
                default = CertificateAuthority.objects.default()
            except ImproperlyConfigured:
                default = None

        help_text = help_text % {"default": add_colons(default.serial) if default else None}
        parser.add_argument(
            arg,
            metavar="SERIAL",
            help=help_text,
            default=default,
            allow_disabled=allow_disabled,
            allow_unusable=allow_unusable,
            action=actions.CertificateAuthorityAction,
        )

    def add_format(self, parser: CommandParser) -> None:
        """Add the -f/--format option."""

        parser.add_argument(
            "-f",
            "--format",
            metavar="{PEM,ASN1,DER}",
            default=Encoding.PEM,
            action=actions.FormatAction,
            dest="encoding",
            help=f'The format to use ("ASN1" is an alias for "DER", default: {Encoding.PEM.name}).',
        )

    def add_password(self, parser: CommandParser, help_text: str = "") -> None:
        """Add password option."""
        if not help_text:
            help_text = "Password used for accessing the private key of the CA."
        parser.add_argument("-p", "--password", nargs="?", action=actions.PasswordAction, help=help_text)

    def print_extension(self, ext: x509.Extension[x509.ExtensionType]) -> None:
        """Print extension to stdout."""

        ext_name = get_extension_name(ext.oid)
        if ext.critical:
            self.stdout.write(f"{ext_name} (critical):")
        else:
            self.stdout.write(f"{ext_name}:")
        self.stdout.write(indent(extension_as_text(ext.value), "    "))

    def print_extensions(self, cert: X509CertMixin) -> None:
        """Print all extensions for the given certificate."""
        for ext in cert.sorted_extensions:
            self.print_extension(ext)

    def test_private_key(self, ca: CertificateAuthority, password: typing.Optional[bytes]) -> None:
        """Test that we can load the private key of a CA."""
        try:
            ca.key(password)
        except Exception as ex:
            raise CommandError(str(ex)) from ex


class CertCommandMixin(_Base, metaclass=abc.ABCMeta):
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


class CertificateAuthorityDetailMixin(_Base, metaclass=abc.ABCMeta):
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
            extension_type=x509.IssuerAlternativeName,
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

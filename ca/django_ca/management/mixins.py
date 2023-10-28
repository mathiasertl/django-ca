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

"""Mixins for :py:class:`~django:django.core.management.BaseCommand` classes."""

import abc
import typing
from textwrap import indent
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding

from django.core.exceptions import ImproperlyConfigured
from django.core.management.base import BaseCommand, CommandError, CommandParser

from django_ca import ca_settings
from django_ca.extensions import extension_as_text, get_extension_name
from django_ca.management import actions
from django_ca.management.actions import IntegerRangeAction
from django_ca.models import CertificateAuthority, X509CertMixin
from django_ca.typehints import ActionsContainer, AllowedHashTypes, ParsableKeyType
from django_ca.utils import add_colons, validate_public_key_parameters

if typing.TYPE_CHECKING:
    # When type checking, mixins use BaseCommand as base class for all mixins.
    # This way, mypy does not complain about missing attributes.
    _Base = BaseCommand
else:
    _Base = object


class ArgumentsMixin(_Base, metaclass=abc.ABCMeta):
    """Mixin that adds some common functions to BaseCommand subclasses."""

    def add_algorithm(
        self, parser: ActionsContainer, default_text: str = "algorithm of the signing CA"
    ) -> None:
        """Add the --algorithm option."""
        # Do NOT add an argparse-level default here, as the default depends on what the command does
        parser.add_argument(
            "--algorithm",
            action=actions.AlgorithmAction,
            help=f"Hash algorithm used to generate the signature (default: {default_text}).",
        )

    def add_ca(
        self,
        parser: ActionsContainer,
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
        help_text : str, optional
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

    def add_password(self, parser: ActionsContainer, help_text: str = "") -> None:
        """Add password option."""
        if not help_text:
            help_text = "Password used for accessing the private key of the CA."
        parser.add_argument("-p", "--password", nargs="?", action=actions.PasswordAction, help=help_text)

    def get_hash_algorithm(
        self,
        key_type: ParsableKeyType,
        algorithm: Optional[AllowedHashTypes],
        default_algorithm: Optional[AllowedHashTypes] = None,
    ) -> Optional[AllowedHashTypes]:
        """Get the hash algorithm based on the options on the command line."""
        # Use default if no hash algorithm was specified
        if algorithm is None and default_algorithm is not None:
            algorithm = default_algorithm

        # Validate public key parameters early so that we can return better feedback to the user.
        try:
            return validate_public_key_parameters(key_type, algorithm)
        except ValueError as ex:
            raise CommandError(*ex.args) from ex

    def print_extension(self, ext: x509.Extension[x509.ExtensionType]) -> None:
        """Print extension to stdout."""
        ext_name = get_extension_name(ext.oid)
        if ext.critical:
            self.stdout.write(f"* {ext_name} (critical):")
        else:
            self.stdout.write(f"* {ext_name}:")
        self.stdout.write(indent(extension_as_text(ext.value), "  "))

    def print_extensions(self, cert: X509CertMixin) -> None:
        """Print all extensions for the given certificate."""
        for ext in cert.sorted_extensions:
            self.print_extension(ext)

    def test_private_key(
        self, ca: CertificateAuthority, password: Optional[bytes]
    ) -> CertificateIssuerPrivateKeyTypes:
        """Test that we can load the private key of a CA."""
        try:
            return ca.key(password)
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

    def add_general_args(self, parser: CommandParser, default: Optional[str] = "") -> ActionsContainer:
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
        return group

    def add_acme_group(self, parser: CommandParser) -> None:
        """Add arguments for ACMEv2 (if enabled)."""
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

        registration_group = group.add_mutually_exclusive_group()
        registration_group.add_argument(
            "--acme-enable-account-registration",
            dest="acme_registration",
            action="store_true",
            default=None,
            help="Enable registration of new accounts for ACME clients.",
        )
        registration_group.add_argument(
            "--acme-disable-account-registration",
            dest="acme_registration",
            action="store_false",
            help="Disable registration of new accounts for ACME clients.",
        )

        group.add_argument(
            "--acme-profile",
            metavar="PROFILE",
            choices=list(ca_settings.CA_PROFILES),
            help="Profile used when issuing certificates.",
        )

        contact_group = group.add_mutually_exclusive_group()
        contact_group.add_argument(
            "--acme-contact-optional",
            dest="acme_requires_contact",
            action="store_false",
            default=None,
            help="Do not require email address during ACME account registration.",
        )

        contact_group.add_argument(
            "--acme-contact-required",
            dest="acme_requires_contact",
            action="store_true",
            help="Require email address during ACME account registration.",
        )

    def add_ocsp_group(self, parser: CommandParser) -> None:
        """Add arguments for automatic OCSP configuration."""
        group = parser.add_argument_group(
            "OCSP responder configuration",
            "Options for how the automatically configured OCSP responder behaves.",
        )
        group.add_argument(
            "--ocsp-responder-key-validity",
            action=IntegerRangeAction,
            min=1,
            metavar="DAYS",
            help="How long (*in days*) automatically generated OCSP responder certificates are valid.",
        )
        group.add_argument(
            "--ocsp-response-validity",
            action=IntegerRangeAction,
            min=600,
            metavar="SECONDS",
            help="How long (*in seconds*) OCSP responses are valid (default: 86400).",
        )

    def add_rest_api_group(self, parser: CommandParser) -> None:
        """Add arguments for the REST API (if enabled)."""
        if not ca_settings.CA_ENABLE_REST_API:
            return

        group = parser.add_argument_group("API Access")
        enable_group = group.add_mutually_exclusive_group()
        enable_group.add_argument(
            "--api-enable",
            dest="api_enabled",
            action="store_true",
            default=None,
            help="Enable API support.",
        )
        enable_group.add_argument(
            "--api-disable", dest="api_enabled", action="store_false", help="Disable API support."
        )

    def add_ca_args(self, parser: ActionsContainer) -> None:
        """Add CA arguments."""
        group = parser.add_argument_group(
            "X509 v3 certificate extensions for signed certificates",
            "Extensions added when signing certificates.",
        )
        group.add_argument(
            "--sign-ca-issuer",
            metavar="NAME",
            action=actions.URLAction,
            default="",
            help="URL to the certificate of your CA (in DER format).",
        )
        group.add_argument(
            "--sign-issuer-alternative-name",
            metavar="NAME",
            action=actions.AlternativeNameLegacyAction,
            extension_type=x509.IssuerAlternativeName,
            help="URL to the homepage of your CA.",
        )
        group.add_argument(
            "--sign-crl-full-name",
            action=actions.MultipleURLAction,
            metavar="NAME",
            help="URL to a certificate revocation list.",
        )
        group.add_argument(
            "--sign-ocsp-responder",
            metavar="NAME",
            default="",
            action=actions.URLAction,
            help="URL of an OCSP responder.",
        )
        self.add_certificate_policies_group(  # type: ignore[attr-defined]  # defined in BaseCommand
            group, "foo", dest="sign_certificate_policies", allow_any_policy=True, prefix="sign-"
        )

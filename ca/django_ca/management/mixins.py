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
import json
import shutil
import sys
import textwrap
import typing
from datetime import UTC, datetime
from typing import Any, Generic, NoReturn

from pydantic import BaseModel, ValidationError

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.management.base import BaseCommand, CommandError, CommandParser

from django_ca.conf import model_settings
from django_ca.constants import DEFAULT_KEY_BACKEND_KEY, SIGNATURE_HASH_ALGORITHM_NAMES
from django_ca.extensions import extension_as_text, get_extension_name
from django_ca.key_backends import key_backends
from django_ca.management import actions
from django_ca.management.actions import IntegerRangeAction, KeyBackendAction
from django_ca.models import Certificate, CertificateAuthority, X509CertMixin
from django_ca.pydantic.certificate import DjangoCertificateAuthorityModel, DjangoCertificateModel
from django_ca.typehints import (
    ActionsContainer,
    ArgumentGroup,
    CertificateExtension,
    SignatureHashAlgorithm,
    X509CertMixinTypeVar,
)
from django_ca.utils import add_colons, hex_to_int, name_for_display

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
    ) -> None:
        """Add the ``--ca`` action.

        Parameters
        ----------
        parser
        arg : str, optional
        help_text : str, optional
        allow_disabled : bool, optional
        no_default : bool, optional
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

    def add_general_args(self, parser: CommandParser, default: str | None = "") -> ActionsContainer:
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
        if not model_settings.CA_ENABLE_ACME:
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
            choices=list(model_settings.CA_PROFILES),
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

    def add_ocsp_group(self, parser: CommandParser, default_ocsp_key_backend: str | None = None) -> None:
        """Add arguments for automatic OCSP configuration."""
        group = parser.add_argument_group(
            "OCSP responder configuration",
            "Options for how the automatically configured OCSP responder behaves.",
        )
        group.add_argument(
            "--ocsp-key-backend",
            choices=list(model_settings.CA_OCSP_KEY_BACKENDS),
            default=default_ocsp_key_backend,
            help="The backend used for storing private keys for OCSP responder delegate certificates. "
            "Depending on the backend, you have to choose different options below for private keys. "
            "(default: %(default)s).",
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
        if not model_settings.CA_ENABLE_REST_API:
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


class OutputCertificateMixinBase(Generic[X509CertMixinTypeVar], _Base, metaclass=abc.ABCMeta):
    """Mixin base class providing arguments and functions for outputting details on the command line."""

    def add_output_certificate_arguments(self, parser: CommandParser, default_format: str = "serial") -> None:
        """Add options for outputting certificates to the command parser."""
        group = parser.add_argument_group("Output options")
        group.add_argument(
            "--serial-format",
            choices=("int", "hex", "dotted-hex"),
            default="dotted-hex",
            help="Format used for serial numbers.",
        )
        group.add_argument(
            "--output-format",
            default=default_format,
            type=lambda v: v.lower(),
            choices=("pem", "der", "serial", "text", "json", "none"),
        )
        group.add_argument(
            "-b",
            "--bundle",
            default=False,
            action="store_true",
            help="With --output-format=pem, output the whole certificate bundle.",
        )
        group.add_argument(
            "-n",
            "--no-pem",
            default=True,
            dest="pem",
            action="store_false",
            help="With --output-format=text, do not output public certificate in PEM format.",
        )
        group.add_argument(
            "--no-extensions",
            default=True,
            dest="extensions",
            action="store_false",
            help="With --output-format=text, show all extensions, not just subjectAltName.",
        )
        group.add_argument(
            "--no-wrap",
            default=True,
            dest="wrap",
            action="store_false",
            help="With --output-format=text, do not wrap long lines to terminal width.",
        )
        group.add_argument(
            "--json-indent", metavar="INDENT", type=int, help="Indent JSON (default: %(default)s)."
        )

    def convert_serial(self, serial: str, serial_format: str) -> int | str:
        """Shared function to convert a serial."""
        if serial_format == "int":
            return str(hex_to_int(serial))
        if serial_format == "hex":
            return serial
        if serial_format == "dotted-hex":
            return add_colons(serial)
        raise ValueError("Unknown serial format.")  # pragma: no cover  # we support all formats.

    def wrap_digest(self, algorithm: str, text: str) -> str:
        """Wrap digest in a way that colons align nicely in multiple lines."""
        initial_indent = "  "

        # We subtract three (length of ":XY"), just to be on the safe side
        # NOTE: 111 is enough to (just) fit an SHA3/256 hash
        text_width = min(111, shutil.get_terminal_size(fallback=(111, 100)).columns) - 3

        # Index where the fingerprint data starts
        start = len(initial_indent) + len(algorithm) + len(": ")

        # Round text width down to ensure that digest line consistently ends with a ":"
        # (text_width - start) == the width available for the digest
        text_width -= (text_width - start) % 3

        subsequent_indent = " " * (len(algorithm) + 4)  # 4 == initial indent + ": "
        lines = textwrap.wrap(
            text, text_width, initial_indent=initial_indent, subsequent_indent=subsequent_indent
        )
        text = "\n".join(lines).replace(f"{algorithm}:\n{subsequent_indent}", f"{algorithm}: ")
        return text

    def print_extension(self, ext: CertificateExtension) -> None:
        """Print extension to stdout."""
        ext_name = get_extension_name(ext.oid)
        if ext.critical:
            self.stdout.write(f"* {ext_name} (critical):")
        else:
            self.stdout.write(f"* {ext_name}:")
        self.stdout.write(textwrap.indent(extension_as_text(ext.value), "  "))

    def print_extensions(self, cert: X509CertMixin) -> None:
        """Print all extensions for the given certificate."""
        for ext in cert.sorted_extensions:
            self.print_extension(ext)

    def output_status(self, cert: X509CertMixin) -> None:
        """Output certificate status."""
        now = datetime.now(UTC)
        if cert.revoked:
            self.stdout.write("* Status: Revoked")
        elif cert.pub.loaded.not_valid_after_utc < now:
            self.stdout.write("* Status: Expired")
        elif cert.pub.loaded.not_valid_before_utc > now:
            self.stdout.write("* Status: Not yet valid")
        else:
            self.stdout.write("* Status: Valid")

    def output_name(self, name: x509.Name, indent: str = "  ") -> None:
        """Output a name as a list."""
        for key, value in name_for_display(name):
            self.stdout.write(f"{indent}* {key}: {value}")

    def output_header(self, cert: X509CertMixin) -> None:
        """Output basic certificate information."""
        if cert.subject:
            self.stdout.write("* Subject:")
            self.output_name(cert.subject)
        else:
            self.stdout.write("* Subject: (empty)")

        self.stdout.write(f"* Serial: {add_colons(cert.serial)}")
        if cert.issuer:
            self.stdout.write("* Issuer:")
            self.output_name(cert.issuer)
        else:
            self.stdout.write("* Issuer: (empty)")

        if settings.USE_TZ:
            # If USE_TZ is True, database (and thus output) fields will use locally configured timezone
            not_before = cert.not_before
            not_after = cert.not_after
        else:
            # If USE_TZ is False, still display UTC timestamps.
            not_before = cert.pub.loaded.not_valid_before_utc
            not_after = cert.pub.loaded.not_valid_after_utc

        self.stdout.write(f"* Not valid before: {not_before.isoformat(' ')}")
        self.stdout.write(f"* Not valid after: {not_after.isoformat(' ')}")

        self.output_status(cert)

    def output_footer(self, cert: X509CertMixinTypeVar, pem: bool, wrap: bool = True) -> None:
        """Output digest and PEM in footer."""
        self.stdout.write("\nDigest:")
        for algorithm_type, algorithm_name in SIGNATURE_HASH_ALGORITHM_NAMES.items():
            fingerprint = cert.get_fingerprint(algorithm_type())
            text = f"{algorithm_name}: {fingerprint}"

            if wrap is True:
                text = self.wrap_digest(algorithm_name, text)
            else:
                text = f"  {text}"

            self.stdout.write(text)

        if pem is True:
            self.stdout.write("")
            self.stdout.write(cert.pub.pem)

    @abc.abstractmethod
    def output_as_text(
        self,
        value: X509CertMixinTypeVar,
        *,
        pem: bool,
        extensions: bool,
        wrap: bool,
    ) -> None:
        """Output certificate as Text."""

    @abc.abstractmethod
    def output_as_json(self, value: X509CertMixinTypeVar, indent: int | None, serial_format: str) -> None:
        """Output certificate as JSON."""

    def output_certificate(  # pylint: disable=unused-argument
        self,
        value: X509CertMixinTypeVar,
        output_format: str,
        serial_format: str,
        json_indent: int | None,
        pem: bool,
        bundle: bool,
        extensions: bool,
        wrap: bool,
        **options: Any,
    ) -> None:
        """Main function for outputting a CA/Certificate."""
        if output_format == "serial":
            self.stdout.write(str(self.convert_serial(value.serial, serial_format)))
        elif output_format == "pem":
            if bundle:
                self.stdout.write(value.bundle_as_pem.strip())  # strip b/c write() adds a newline anyway
            else:
                self.stdout.write(value.pub.pem.strip())  # strip b/c write() adds a newline anyway
        elif output_format == "der":
            # NOTE: we circumvent self.stdout, as it is impossible to write bytes to it.
            sys.stdout.buffer.write(value.pub.der)
        elif output_format == "text":
            self.output_as_text(value, extensions=extensions, pem=pem, wrap=wrap)
        elif output_format == "json":
            self.output_as_json(value, indent=json_indent, serial_format=serial_format)


class OutputCertificateAuthorityMixin(
    OutputCertificateMixinBase[CertificateAuthority], metaclass=abc.ABCMeta
):
    """Mixin providing arguments and functions for outputting Certificate Authority details."""

    def output_as_json(self, value: CertificateAuthority, indent: int | None, serial_format: str) -> None:
        fingerprint_hashes = tuple(cls() for cls in SIGNATURE_HASH_ALGORITHM_NAMES)
        model = DjangoCertificateAuthorityModel.model_validate(
            value, context={"hash_algorithms": fingerprint_hashes}
        )
        data = model.model_dump(mode="json")
        data["certificate"]["serial_number"] = self.convert_serial(
            data["certificate"]["serial"], serial_format
        )
        self.stdout.write(json.dumps(data, indent=indent, sort_keys=True))

    def output_ca_information(self, ca: CertificateAuthority) -> None:
        """Output information specific to a CA."""
        self.stdout.write("\nCertificate Authority information:")
        if ca.parent:
            self.stdout.write(f"* Parent: {ca.parent.name} ({add_colons(ca.parent.serial)})")
        else:
            self.stdout.write("* Certificate authority is a root CA.")

        children = ca.children.all()
        if children:
            self.stdout.write("* Children:")
            for child in children:
                self.stdout.write(f"  * {child.name} ({add_colons(child.serial)})")
        else:
            self.stdout.write("* Certificate authority has no children.")

        if ca.max_path_length is None:
            path_length = "unlimited"
        else:
            path_length = str(ca.max_path_length)

        self.stdout.write(f"* Maximum levels of sub-CAs (path length): {path_length}")

        self.stdout.write("")
        self.stdout.write("Key storage options:")
        self.stdout.write(f"* backend: {ca.key_backend_alias}")
        if ca.key_backend_options:
            for key, value in ca.key_backend_options.items():
                self.stdout.write(f"* {key}: {value}")
        else:
            self.stdout.write("* No information available.")

        if ca.website:
            self.stdout.write(f"* Website: {ca.website}")
        if ca.terms_of_service:
            self.stdout.write(f"* Terms of service: {ca.terms_of_service}")
        if ca.caa_identity:
            self.stdout.write(f"* CAA identity: {ca.caa_identity}")

    def output_as_text(
        self,
        value: CertificateAuthority,
        *,
        pem: bool,
        extensions: bool,
        wrap: bool,
    ) -> None:
        self.stdout.write(f"* Name: {value.name}")
        self.stdout.write(f"* Enabled: {'Yes' if value.enabled else 'No'}")
        self.output_header(value)
        self.output_ca_information(value)

        if model_settings.CA_ENABLE_ACME:
            self.stdout.write("")
            self.stdout.write("ACMEv2 support:")
            self.stdout.write(f"* Enabled: {value.acme_enabled}")
            if value.acme_enabled:
                self.stdout.write(f"* Requires contact: {value.acme_requires_contact}")

        if extensions is True:
            self.stdout.write("\nCertificate extensions:")
            self.print_extensions(value)

        if (
            value.sign_authority_information_access
            or value.sign_certificate_policies
            or value.sign_crl_distribution_points
            or value.sign_issuer_alternative_name
        ):
            self.stdout.write("\nCertificate extensions for signed certificates:")
            if value.sign_authority_information_access:
                self.print_extension(value.sign_authority_information_access)
            if value.sign_certificate_policies:
                self.print_extension(value.sign_certificate_policies)
            if value.sign_crl_distribution_points:
                self.print_extension(value.sign_crl_distribution_points)
            if value.sign_issuer_alternative_name:
                self.print_extension(value.sign_issuer_alternative_name)
        else:
            self.stdout.write("\nNo certificate extensions for signed certificates.")

        self.output_footer(value, pem=pem, wrap=wrap)


class OutputCertificateMixin(OutputCertificateMixinBase[Certificate], metaclass=abc.ABCMeta):
    """Mixin providing arguments and functions for outputting Certificate Authority details."""

    def output_as_json(self, value: Certificate, indent: int | None, serial_format: str) -> None:
        fingerprint_hashes = tuple(cls() for cls in SIGNATURE_HASH_ALGORITHM_NAMES)
        model = DjangoCertificateModel.model_validate(value, context={"hash_algorithms": fingerprint_hashes})
        data = model.model_dump(mode="json")
        data["certificate"]["serial_number"] = self.convert_serial(
            data["certificate"]["serial"], serial_format
        )
        self.stdout.write(json.dumps(data, indent=indent, sort_keys=True))

    def output_as_text(self, value: Certificate, *, pem: bool, extensions: bool, wrap: bool) -> None:
        self.output_header(value)

        watchers = value.watchers.all()
        if watchers:
            self.stdout.write("* Watchers:")
            for watcher in watchers:
                self.stdout.write(f"  * {watcher}")
        else:
            self.stdout.write("* No watchers")

        # self.stdout.write extensions
        if extensions:
            self.stdout.write("\nCertificate extensions:")
            self.print_extensions(value)

        self.output_footer(value, pem=pem, wrap=wrap)


class PydanticModelValidationMixin:
    """Mixin providing common functions for Pydantic model handling."""

    def validation_error_to_command_error(self, ex: ValidationError) -> NoReturn:
        """Convert a Pydantic validation error into a Django Command Error."""
        # Convert Pydantic errors into a list of "nice" strings
        messages = []
        for error in ex.errors():
            if error["loc"]:
                locations = (str(loc) for loc in error["loc"])
                messages.append(f"{', '.join(locations)}: {error['msg']}")
            else:
                messages.append(error["msg"])

        if len(messages) == 1:  # pylint: disable=no-else-raise  # just makes the code clearer
            raise CommandError(messages[0]) from ex
        else:
            message = "\n".join(f"* {msg}" for msg in messages)
            raise CommandError(f"{len(messages)} errors:\n{message}") from ex


class StorePrivateKeyMixin:
    """Mixin to add options for storing a private key."""

    def add_key_backend_option(self, parser: CommandParser) -> ArgumentGroup:
        """Add argument group for the --key-backend option."""
        group = parser.add_argument_group("Private key options")
        group.add_argument(
            "--key-backend",
            action=KeyBackendAction,
            help="The key can be stored using different backends. Depending on the backend, you have to "
            f"choose different options below for private keys. (default: {DEFAULT_KEY_BACKEND_KEY}).",
        )
        return group


class UsePrivateKeyMixin:
    """Mixin to add options for using a private key."""

    def add_use_private_key_arguments(self, parser: CommandParser) -> None:
        """Add arguments for loading a parent CA via its key backend."""
        for backend in key_backends:
            group = backend.add_use_private_key_group(parser)
            if group is not None:  # pragma: no branch  # all implementations add an option group
                backend.add_use_private_key_arguments(group)

    def get_signing_options(
        self, ca: CertificateAuthority, algorithm: SignatureHashAlgorithm | None, options: dict[str, Any]
    ) -> tuple[BaseModel, SignatureHashAlgorithm | None]:
        """Get variables required for signing a certificate."""
        try:
            key_backend_options = ca.key_backend.get_use_private_key_options(ca, options)

            # Make sure that the selected signature hash algorithm works for the CAs backend.
            algorithm = ca.key_backend.validate_signature_hash_algorithm(
                ca.key_type, algorithm, default=ca.algorithm
            )

            ca.check_usable(key_backend_options)
        except ValidationError as ex:
            self.validation_error_to_command_error(ex)  # type: ignore[attr-defined]
        except Exception as ex:
            raise CommandError(str(ex)) from ex

        return key_backend_options, algorithm

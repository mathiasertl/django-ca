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

"""Command subclasses and argparse helpers for django-ca."""

import abc
import argparse
import io
import shutil
import sys
import textwrap
import typing
from datetime import datetime, timedelta
from datetime import timezone as tz
from typing import Any, Optional, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

from django.core.management.base import BaseCommand as _BaseCommand
from django.core.management.base import CommandError, CommandParser, OutputWrapper
from django.utils import timezone

from django_ca import ca_settings, constants
from django_ca.management import actions, mixins
from django_ca.models import CertificateAuthority, X509CertMixin
from django_ca.profiles import Profile
from django_ca.typehints import ActionsContainer, AllowedHashTypes, ArgumentGroup, ExtensionMapping
from django_ca.utils import add_colons, format_name


class BinaryOutputWrapper(OutputWrapper):
    """An output wrapper that allows you to write binary data."""

    ending: bytes  # type: ignore[assignment]
    _out: typing.BinaryIO

    def __init__(self, out: typing.BinaryIO, ending: bytes = b"\n") -> None:
        super().__init__(out, ending=ending)  # type: ignore[arg-type]

    def write(  # type: ignore[override]
        self,
        msg: Union[str, bytes] = b"",
        style_func: Optional[typing.Callable[..., Any]] = None,
        ending: Optional[bytes] = None,
    ) -> None:
        if ending is None:
            ending = self.ending

        if isinstance(msg, str):
            msg = msg.encode("utf-8")
        if ending and not msg.endswith(ending):
            msg += ending

        self._out.write(msg)


class BinaryCommand(mixins.ArgumentsMixin, _BaseCommand, metaclass=abc.ABCMeta):
    """A :py:class:`~django:django.core.management.BaseCommand` that supports binary output."""

    stdout: BinaryOutputWrapper
    stderr: BinaryOutputWrapper

    def __init__(
        self,
        stdout: Optional[io.BytesIO] = None,
        stderr: Optional[io.BytesIO] = None,
        no_color: bool = True,
        force_color: bool = False,
    ) -> None:
        # BaseCommand error handling is not suitable and sets stdout/stderr redundantly:
        # pylint: disable=super-init-not-called

        self.stdout = BinaryOutputWrapper(stdout or sys.stdout.buffer)
        # TODO: we set stdout below?!
        self.stderr = BinaryOutputWrapper(stdout or sys.stdout.buffer)

    def execute(self, *args: Any, **options: Any) -> None:
        if options.get("force_color"):
            raise CommandError("This command does not support color output.")

        if options.get("stdout"):  # pragma: no branch
            self.stdout = BinaryOutputWrapper(options.pop("stdout"))
        if options.get("stderr"):  # pragma: no branch
            self.stderr = BinaryOutputWrapper(options.pop("stderr"))
        options["no_color"] = True

        super().execute(*args, **options)

    def dump(self, path: str, data: bytes) -> None:
        """Dump `data` to `path` (``-`` means stdout)."""

        if path == "-":
            self.stdout.write(data, ending=b"")
        else:
            try:
                with open(path, "wb") as stream:
                    stream.write(data)
            except IOError as ex:
                raise CommandError(ex) from ex


class BaseCommand(mixins.ArgumentsMixin, _BaseCommand, metaclass=abc.ABCMeta):
    """Base class for most/all management commands."""

    @property
    def valid_subject_keys(self) -> str:
        """Return human-readable enumeration of valid subject keys (CN/...)."""
        fields = [f'"{f}"' for f in constants.NAME_OID_TYPES]
        return f"{', '.join(fields[:-1])} and {fields[-1]}"

    def add_subject(
        self,
        parser: ActionsContainer,
        arg: str = "subject",
        metavar: Optional[str] = None,
        help_text: Optional[str] = None,
    ) -> None:
        """Add subject option."""
        parser.add_argument(arg, action=actions.NameAction, metavar=metavar, help=help_text)

    def add_elliptic_curve(self, parser: ActionsContainer) -> None:
        """Add --elliptic-curve option."""
        default = ca_settings.CA_DEFAULT_ELLIPTIC_CURVE.name
        parser.add_argument(
            "--elliptic-curve",
            action=actions.EllipticCurveAction,
            help=f"Elliptic Curve used for EC keys (default: {default}).",
        )

    def add_key_size(self, parser: ActionsContainer) -> None:
        """Add --key-size option (2048, 4096, ...)."""
        parser.add_argument(
            "--key-size",
            action=actions.KeySizeAction,
            help=f"Key size for a RSA/DSA private key (default: {ca_settings.CA_DEFAULT_KEY_SIZE}).",
        )

    def add_key_type(
        self, parser: ActionsContainer, default: Optional[str] = "RSA", default_text: str = "%(default)s"
    ) -> None:
        """Add --key-type option (type of private key - RSA/DSA/EC/Ed25519/Ed448)."""
        parser.add_argument(
            "--key-type",
            choices=["RSA", "DSA", "EC", "Ed25519", "Ed448"],
            default=default,
            help=f"Key type for the private key (default: {default_text}).",
        )

    def add_profile(self, parser: CommandParser, help_text: str) -> None:
        """Add profile-related options."""
        group = parser.add_argument_group("profiles", help_text)
        group = group.add_mutually_exclusive_group()
        for name, profile in ca_settings.CA_PROFILES.items():
            group.add_argument(
                f"--{name}",
                action="store_const",
                const=name,
                dest="profile",
                help=profile.get("description", ""),
            )


class BaseSignCommand(BaseCommand, metaclass=abc.ABCMeta):
    """Base class for all commands that sign certificates (init_ca, sign_cert, resign_cert).

    This class can add options for all x509 extensions.
    """

    def _add_extension(self, extensions: ExtensionMapping, value: x509.ExtensionType, critical: bool) -> None:
        """Add an extension to the passed extension dictionary."""
        extensions[value.oid] = x509.Extension(oid=value.oid, critical=critical, value=value)

    def add_authority_information_access_group(
        self,
        parser: CommandParser,
        legacy_ocsp_args: Tuple[str, ...] = (),
        legacy_issuer_args: Tuple[str, ...] = (),
    ) -> None:
        """Add argument group for the Authority Information Access extension."""
        group = parser.add_argument_group(
            f"{constants.EXTENSION_NAMES[ExtensionOID.AUTHORITY_INFORMATION_ACCESS]} extension",
            """Information about the issuer of the CA. These options only work for intermediate CAs. Default
            values are based on the default hostname (see above) and work out of the box if a webserver is
            configured. Options can be given multiple times to add multiple values.""",
        )
        group.add_argument(
            "--ocsp-responder",
            *legacy_ocsp_args,
            dest="authority_information_access",
            action=actions.AuthorityInformationAccessAction,
            access_method=AuthorityInformationAccessOID.OCSP,
            help="URL of an OCSP responder.",
        )
        group.add_argument(
            "--ca-issuer",
            *legacy_issuer_args,
            dest="authority_information_access",
            action=actions.AuthorityInformationAccessAction,
            access_method=AuthorityInformationAccessOID.CA_ISSUERS,
            help="URL to the certificate of your CA (in DER format).",
        )

    def add_certificate_policies_group(
        self, parser: argparse.ArgumentParser, description: str, allow_any_policy: bool = False
    ) -> None:
        """Add argument group for the Certificate Policies extension."""
        ext_name = constants.EXTENSION_NAMES[ExtensionOID.CERTIFICATE_POLICIES]
        group = parser.add_argument_group(f"{ext_name} extension", description.format(ext_name=ext_name))
        group.add_argument(
            "--policy-identifier",
            action=actions.PolicyIdentifierAction,
            dest="certificate_policies",
            allow_any_policy=allow_any_policy,
            help="Add a certificate policy with the given OID. May be given multiple times to add multiple "
            "policies.",
        )
        group.add_argument(
            "--certification-practice-statement",
            action=actions.CertificationPracticeStatementAction,
            dest="certificate_policies",
            help="Add a certification practice statement (CPS) to the last policy added with"
            "--policy-identifier.",
        )
        group.add_argument(
            "--user-notice",
            action=actions.UserNoticeAction,
            dest="certificate_policies",
            help="Add a textual statement that can be displayed to the user to the last policy added with "
            "--policy-identifier.",
        )
        self.add_critical_option(
            group,
            ExtensionOID.CERTIFICATE_POLICIES,
            help_suffix="It is usually not marked as critical.",
        )

    def add_critical_option(
        self, parser: ActionsContainer, oid: x509.ObjectIdentifier, help_suffix: str = ""
    ) -> None:
        """Add a --...-(non-)critical option for the extension to the given argparse ActionContainer."""
        destination = f"{constants.EXTENSION_KEYS[oid]}_critical"
        extension_arg = constants.EXTENSION_KEYS[oid].replace("_", "-")
        default = constants.EXTENSION_DEFAULT_CRITICAL[oid]

        if default is True:
            option = f"--{extension_arg}-non-critical"
            action = "store_false"
            help_text = f"Mark the extension as non-critical. {help_suffix}".strip()
        else:
            option = f"--{extension_arg}-critical"
            action = "store_true"
            help_text = f"Mark the extension as critical. {help_suffix}".strip()

        parser.add_argument(option, dest=destination, action=action, default=default, help=help_text)

    def add_crl_distribution_points_group(
        self,
        parser: CommandParser,
        help_suffix: str,
        extra_args: Tuple[str, ...] = (),
        description_suffix: str = "",
    ) -> None:
        """Add argument group for the CRL Distribution Points extension."""
        ext_name = constants.EXTENSION_NAMES[ExtensionOID.CRL_DISTRIBUTION_POINTS]
        description = "This extension defines how a Certificate Revocation List (CRL) can be obtained."
        help_text = (
            "Add NAME (usually a URL) to the endpoints where a CRL can be retrieved. This option can be "
            f"given multiple times and replaces the default endpoint. {help_suffix}"
        )

        if description_suffix:
            description += f" {description_suffix}"

        group = parser.add_argument_group(f"{ext_name} extension", description)

        group.add_argument(
            "--crl-full-name",
            *extra_args,
            dest="crl_full_names",
            type=actions.general_name_type,
            action="append",
            metavar="NAME",
            help=help_text,
        )
        self.add_critical_option(group, ExtensionOID.CRL_DISTRIBUTION_POINTS)

    def add_extended_key_usage_group(self, parser: CommandParser) -> None:
        """Add argument group for the Extended Key Usage extension."""
        ext_name = constants.EXTENSION_NAMES[ExtensionOID.EXTENDED_KEY_USAGE]
        group = parser.add_argument_group(
            f"{ext_name} extension",
            "This extension indicates additional purposes that this certificate may be used for.",
        )
        group.add_argument(
            "--extended-key-usage",
            metavar="EXTENDED_KEY_USAGE",
            action=actions.ExtendedKeyUsageAction,
            help="Extended Key Usages to use for this certificate. %(metavar)s is either a dotted string or "
            'a known Extended Key Usage, e.g. "serverAuth" or "clientAuth". This option takes multiple '
            "values.",
        )
        self.add_critical_option(group, ExtensionOID.EXTENDED_KEY_USAGE)

    def add_issuer_alternative_name_group(self, parser: CommandParser) -> None:
        """Add argument group for the Issuer Alternative Name extension."""
        ext_name = constants.EXTENSION_NAMES[ExtensionOID.ISSUER_ALTERNATIVE_NAME]
        group = parser.add_argument_group(
            f"{ext_name} extension",
            "This extension is used to associate alternative names with the certificate issuer. It is rarely "
            "used in practice.",
        )
        group.add_argument(
            "--issuer-alternative-name",
            action=actions.AlternativeNameAction,
            extension_type=x509.IssuerAlternativeName,
            help="Alternative name for the certificate issuer. May be given multiple times.",
        )
        # OpenSSL raises an error if this extension is critical.
        # self.add_critical_option(group, ExtensionOID.ISSUER_ALTERNATIVE_NAME)

    def add_key_usage_group(self, parser: CommandParser, default: Optional[x509.KeyUsage] = None) -> None:
        """Add argument group for the Key Usage extension."""
        ext_name = constants.EXTENSION_NAMES[ExtensionOID.KEY_USAGE]
        group = parser.add_argument_group(
            f"{ext_name} extension", "This extension defines what the certificate can be used for."
        )
        group.add_argument(
            "--key-usage",
            metavar="KEY_USAGE",
            action=actions.KeyUsageAction,
            default=default,
            help='Key Usage bits for this certificate, e.g. "keyAgreement" or "keyEncipherment". '
            "This option accepts multiple values.",
        )
        self.add_critical_option(group, ExtensionOID.KEY_USAGE)

    def add_subject_alternative_name_group(
        self,
        parser: CommandParser,
        description_suffix: str = "",
        additional_option_strings: Tuple[str, ...] = tuple(),
    ) -> None:
        """Add argument group for the Subject Alternative Name extension."""

        ext_name = constants.EXTENSION_NAMES[ExtensionOID.SUBJECT_ALTERNATIVE_NAME]
        description = "This extension lists the names (usually domain names) that a certificate is valid for."
        if description_suffix:
            description += f" {description_suffix}"

        group = parser.add_argument_group(f"{ext_name} extension", description)
        group.add_argument(
            "--subject-alternative-name",
            "--name",
            *additional_option_strings,
            action=actions.AlternativeNameAction,
            extension_type=x509.SubjectAlternativeName,
            help="Add %(metavar)s to the certificate.",
        )
        self.add_critical_option(group, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)

    def add_tls_feature_group(self, parser: CommandParser) -> None:
        """Add argument group for the TLS Feature extension."""
        ext_name = constants.EXTENSION_NAMES[ExtensionOID.TLS_FEATURE]
        group = parser.add_argument_group(
            f"{ext_name} extension",
            "This extension allows specifying required TLS feature extensions.",
        )
        group.add_argument(
            "--tls-feature",
            metavar="TLS_FEATURE",
            # TODO: Set choices when old comma-separated values are removed in 1.26.0.
            # choices=tuple(constants.TLS_FEATURE_NAMES)
            action=actions.TLSFeatureAction,
            help='TLS feature flags to include. Valid values are "status_request" (also known as '
            'OCSPMustStaple) and "status_request_v2" (also known as Multiple Certificate Status Request).',
        )
        self.add_critical_option(group, ExtensionOID.TLS_FEATURE)


class BaseSignCertCommand(BaseSignCommand, metaclass=abc.ABCMeta):
    """Base class for commands signing certificates (sign_cert, resign_cert)."""

    add_extensions_help = ""  # concrete classes should set this
    subject_help: typing.ClassVar  # concrete classes should set this

    def add_base_args(self, parser: CommandParser, no_default_ca: bool = False) -> ArgumentGroup:
        """Add common arguments for signing certificates."""
        general_group = parser.add_argument_group("General")
        self.add_subject_group(parser)
        self.add_algorithm(general_group)
        self.add_ca(general_group, no_default=no_default_ca)
        self.add_password(general_group)
        self.add_authority_information_access_group(parser)
        self.add_certificate_policies_group(
            parser,
            description="In end-entity certificates, this extension indicates the policy under which the "
            "certificate was issued and the purposes for which it may be used.",
        )
        self.add_crl_distribution_points_group(
            parser, "This option will override distribution points configured by the CA."
        )
        self.add_issuer_alternative_name_group(parser)
        self.add_extended_key_usage_group(parser)
        self.add_key_usage_group(parser)
        self.add_ocsp_no_check_group(parser)
        self.add_subject_alternative_name_group(parser, additional_option_strings=("--alt",))
        self.add_tls_feature_group(parser)

        general_group.add_argument(
            "--expires",
            action=actions.ExpiresAction,
            help=f"Sign the certificate for DAYS days (default: {ca_settings.CA_DEFAULT_EXPIRES})",
        )
        general_group.add_argument(
            "--watch",
            metavar="EMAIL",
            action="append",
            default=[],
            help="Email EMAIL when this certificate expires (may be given multiple times)",
        )
        general_group.add_argument(
            "--out", metavar="FILE", help="Save signed certificate to FILE. If omitted, print to stdout."
        )
        return general_group

    def add_ocsp_no_check_group(self, parser: CommandParser) -> None:
        """Add argument group for the OCSPNoCheck extension."""
        ext_name = constants.EXTENSION_NAMES[ExtensionOID.OCSP_NO_CHECK]
        group = parser.add_argument_group(
            f"{ext_name} extension",
            f"The {ext_name} extension is used in OCSP responder certificates to indicate that it does not "
            "need to be checked via OCSP.",
        )
        group.add_argument(
            "--ocsp-no-check", default=False, action="store_true", help=f"Add the {ext_name} extension."
        )
        self.add_critical_option(group, ExtensionOID.OCSP_NO_CHECK)

    def add_subject_group(self, parser: CommandParser) -> None:
        """Add argument for a subject."""

        group = parser.add_argument_group("Certificate subject", self.subject_help)

        # NOTE: Don't set the default value here because it would mask the user not setting anything at all.
        self.add_subject(
            group,
            arg="--subject",
            metavar="/key1=value1/key2=value2/...",
            help_text=f"""Valid keys are {self.valid_subject_keys}. Pass an empty value (e.g. "/C=/ST=...")
            to remove a field from the subject.""",
        )

    def test_options(  # pylint: disable=unused-argument
        self,
        ca: CertificateAuthority,
        expires: Optional[timedelta],
        password: Optional[bytes],
        profile: Profile,
        **options: Any,
    ) -> None:
        """Additional tests for validity of some options."""

        parsed_expires = profile.get_expires(expires)

        if ca.expires < parsed_expires:
            max_days = (ca.expires - timezone.now()).days
            raise CommandError(
                f"Certificate would outlive CA, maximum expiry for this CA is {max_days} days."
            )

        # See if we can work with the private key
        self.test_private_key(ca, password)


class BaseViewCommand(BaseCommand):  # pylint: disable=abstract-method; is a base class
    """Base class for view_* commands."""

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "-n",
            "--no-pem",
            default=True,
            dest="pem",
            action="store_false",
            help="Do not output public certificate in PEM format.",
        )
        parser.add_argument(
            "--no-extensions",
            default=True,
            dest="extensions",
            action="store_false",
            help="Show all extensions, not just subjectAltName.",
        )
        parser.add_argument(
            "--no-wrap",
            default=True,
            dest="wrap",
            action="store_false",
            help="Do not wrap long lines to terminal width.",
        )
        super().add_arguments(parser)

    def wrap_digest(self, algorithm: str, text: str) -> str:
        """Wrap digest in a way that colons align nicely in multiple lines."""
        # 107 is enough to (just) fit an SHA-256 hash
        text_width = min(107, shutil.get_terminal_size(fallback=(107, 100)).columns)
        text_width -= (text_width + 1) % 3

        subsequent_indent = " " * (len(algorithm) + 4)
        lines = textwrap.wrap(text, text_width, initial_indent="  ", subsequent_indent=subsequent_indent)
        return "\n".join(lines)

    def output_status(self, cert: X509CertMixin) -> None:
        """Output certificate status"""
        now = datetime.now(tz.utc)
        if cert.revoked:
            self.stdout.write("* Status: Revoked")
        elif cert.not_after < now:
            self.stdout.write("* Status: Expired")
        elif cert.not_before > now:
            self.stdout.write("* Status: Not yet valid")
        else:
            self.stdout.write("* Status: Valid")

    def output_header(self, cert: X509CertMixin) -> None:
        """Output basic certificate information."""
        self.stdout.write(f"* Subject: {format_name(cert.subject)}")
        self.stdout.write(f"* Serial: {add_colons(cert.serial)}")
        self.stdout.write(f"* Issuer: {format_name(cert.issuer)}")
        self.stdout.write(f"* Valid from: {cert.not_before.isoformat(' ')}")
        self.stdout.write(f"* Valid until: {cert.not_after.isoformat(' ')}")
        self.output_status(cert)
        self.stdout.write(f"* HPKP pin: {cert.hpkp_pin}")

    def output_footer(self, cert: X509CertMixin, pem: bool, wrap: bool = True) -> None:
        """Output digest and PEM in footer."""
        self.stdout.write("\nDigest:")
        hash_algorithms: Tuple[AllowedHashTypes, ...] = (hashes.SHA256(), hashes.SHA512())
        for algorithm in hash_algorithms:
            algorithm_name = constants.HASH_ALGORITHM_NAMES[type(algorithm)]
            fingerprint = cert.get_fingerprint(algorithm)
            text = f"{algorithm_name}: {fingerprint}"

            if wrap is True:
                text = self.wrap_digest(algorithm_name, text)
            else:
                text = f"  {text}"

            self.stdout.write(text)

        if pem is True:
            self.stdout.write("")
            self.stdout.write(cert.pub.pem)

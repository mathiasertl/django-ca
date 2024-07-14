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
import io
import shutil
import sys
import textwrap
import typing
from datetime import datetime, timedelta, timezone as tz
from typing import Any, Optional, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

from django.core.management.base import (
    BaseCommand as _BaseCommand,
    CommandError,
    CommandParser,
    OutputWrapper,
)
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from django_ca import constants
from django_ca.conf import model_settings
from django_ca.management import actions, mixins
from django_ca.management.mixins import UsePrivateKeyMixin
from django_ca.models import CertificateAuthority, X509CertMixin
from django_ca.profiles import Profile
from django_ca.typehints import (
    ActionsContainer,
    AllowedHashTypes,
    ArgumentGroup,
    ConfigurableExtension,
    ConfigurableExtensionType,
    SubjectFormats,
)
from django_ca.utils import add_colons, format_name_rfc4514, name_for_display, parse_name_rfc4514, x509_name

if typing.TYPE_CHECKING:
    from django_stubs_ext import StrOrPromise


def add_elliptic_curve(parser: ActionsContainer, prefix: str = "") -> None:
    """Add --elliptic-curve option."""
    default = model_settings.CA_DEFAULT_ELLIPTIC_CURVE.name
    parser.add_argument(
        f"--{prefix}elliptic-curve",
        action=actions.EllipticCurveAction,
        help=f"Elliptic Curve used for EC keys (default: {default}).",
    )


def add_key_size(parser: ActionsContainer) -> None:
    """Add --key-size option (2048, 4096, ...)."""
    parser.add_argument(
        "--key-size",
        action=actions.KeySizeAction,
        help=f"Key size for a RSA/DSA private key (default: {model_settings.CA_DEFAULT_KEY_SIZE}).",
    )


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


class BinaryCommand(
    mixins.ArgumentsMixin, mixins.PydanticModelValidationMixin, _BaseCommand, metaclass=abc.ABCMeta
):
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
            except OSError as ex:
                raise CommandError(ex) from ex


class BaseCommand(
    mixins.ArgumentsMixin, mixins.PydanticModelValidationMixin, _BaseCommand, metaclass=abc.ABCMeta
):
    """Base class for most/all management commands."""

    def add_authority_information_access_group(
        self,
        parser: CommandParser,
        description: "StrOrPromise" = "",
        name: str = f"{constants.EXTENSION_NAMES[ExtensionOID.AUTHORITY_INFORMATION_ACCESS]} extension",
        prefix: str = "",
    ) -> None:
        """Add argument group for the Authority Information Access extension."""
        dest_prefix = prefix.replace("-", "_")
        if not description:
            description = _(
                "Information about the issuer of the CA. These options only work for intermediate CAs. "
                "Default values are based on the default hostname (see above) and work out of the box if a "
                "webserver is configured. Options can be given multiple times to add multiple values."
            )
        group = parser.add_argument_group(name, str(description))
        group.add_argument(
            f"--{prefix}ocsp-responder",
            dest=f"{dest_prefix}authority_information_access",
            action=actions.AuthorityInformationAccessAction,
            access_method=AuthorityInformationAccessOID.OCSP,
            help="URL of an OCSP responder.",
        )
        group.add_argument(
            f"--{prefix}ca-issuer",
            dest=f"{dest_prefix}authority_information_access",
            action=actions.AuthorityInformationAccessAction,
            access_method=AuthorityInformationAccessOID.CA_ISSUERS,
            help="URL to the certificate of your CA (in DER format).",
        )

    def add_certificate_policies_group(
        self,
        parser: CommandParser,
        description: str,
        name: str = f"{constants.EXTENSION_NAMES[ExtensionOID.CERTIFICATE_POLICIES]} extension",
        allow_any_policy: bool = False,
        dest: str = "certificate_policies",
        prefix: str = "",
    ) -> None:
        """Add argument group for the Certificate Policies extension."""
        ext_name = constants.EXTENSION_NAMES[ExtensionOID.CERTIFICATE_POLICIES]
        group = parser.add_argument_group(name, description.format(ext_name=ext_name))

        group.add_argument(
            f"--{prefix}policy-identifier",
            action=actions.PolicyIdentifierAction,
            dest=dest,
            allow_any_policy=allow_any_policy,
            help="Add a certificate policy with the given OID. May be given multiple times to add multiple "
            "policies.",
        )
        group.add_argument(
            f"--{prefix}certification-practice-statement",
            action=actions.CertificationPracticeStatementAction,
            dest=dest,
            help="Add a certification practice statement (CPS) to the last policy added with "
            "--policy-identifier.",
        )
        group.add_argument(
            f"--{prefix}user-notice",
            action=actions.UserNoticeAction,
            dest=dest,
            help="Add a textual statement that can be displayed to the user to the last policy added with "
            "--policy-identifier.",
        )
        self.add_critical_option(
            group,
            ExtensionOID.CERTIFICATE_POLICIES,
            prefix=prefix,
            help_suffix="It is usually not marked as critical.",
        )

    def add_crl_distribution_points_group(
        self,
        parser: CommandParser,
        description: "StrOrPromise" = "",
        name: str = f"{constants.EXTENSION_NAMES[ExtensionOID.CRL_DISTRIBUTION_POINTS]} extension",
        prefix: str = "",
    ) -> None:
        """Add argument group for the CRL Distribution Points extension."""
        help_text = (
            "Add NAME (usually a URL) to the endpoints where a CRL can be retrieved. This option can be "
            "given multiple times and replaces the default endpoint."
        )

        group = parser.add_argument_group(name, str(description))

        group.add_argument(
            f"--{prefix}crl-full-name",
            dest=f"{prefix.replace('-', '_')}crl_full_names",
            type=actions.general_name_type,
            action="append",
            metavar="NAME",
            help=help_text,
        )
        self.add_critical_option(group, ExtensionOID.CRL_DISTRIBUTION_POINTS, prefix=prefix)

    def add_certificate_authority_sign_extension_groups(self, parser: CommandParser) -> None:
        """Add CA arguments."""
        # Empty section to add an extra header for this section:
        parser.add_argument_group(
            "X509 v3 certificate extensions for signed certificates",
            "Extensions added when signing certificates.",
        )

        # Common help text for extensions that are usually configured automatically.
        default_hostname_suffix: StrOrPromise = ""
        if model_settings.CA_DEFAULT_HOSTNAME:  # pragma: no branch
            default_hostname_suffix = _(
                " This extension is configured automatically using the CA_DEFAULT_HOSTNAME if not overridden "
                "by options in this section."
            )

        # Add Authority Information Access extension
        ext_name = constants.EXTENSION_NAMES[ExtensionOID.AUTHORITY_INFORMATION_ACCESS]
        self.add_authority_information_access_group(
            parser,
            f"{ext_name} extension added to a certificate when signing it.{default_hostname_suffix}",
            name=f"{ext_name} extension in certificates",
            prefix="sign-",
        )

        # Add Certificate Policies extension
        ext_name = constants.EXTENSION_NAMES[ExtensionOID.CERTIFICATE_POLICIES]
        self.add_certificate_policies_group(
            parser,
            f"{ext_name} extension added to a certificate when signing it.",
            name=f"{ext_name} extension in certificates",
            dest="sign_certificate_policies",
            allow_any_policy=True,
            prefix="sign-",
        )

        # Add CRL Distribution Points extension
        ext_name = constants.EXTENSION_NAMES[ExtensionOID.CRL_DISTRIBUTION_POINTS]
        self.add_crl_distribution_points_group(
            parser,
            description=(
                f"{ext_name} extension added to a certificate when signing it.{default_hostname_suffix}"
            ),
            name=f"{ext_name} extension in certificates",
            prefix="sign-",
        )

        # Add Issuer Alternative Name extension
        ext_name = constants.EXTENSION_NAMES[ExtensionOID.ISSUER_ALTERNATIVE_NAME]
        self.add_issuer_alternative_name_group(
            parser,
            f"{ext_name} extension added to a certificate when signing it. Rarely used in practice.",
            name=f"{ext_name} extension in certificates",
            prefix="sign-",
        )

    def add_critical_option(
        self, parser: ActionsContainer, oid: x509.ObjectIdentifier, help_suffix: str = "", prefix: str = ""
    ) -> None:
        """Add a --...-(non-)critical option for the extension to the given argparse ActionContainer."""
        destination = f"{prefix.replace('-', '_')}{constants.EXTENSION_KEYS[oid]}_critical"
        extension_arg = constants.EXTENSION_KEYS[oid].replace("_", "-")
        default = constants.EXTENSION_DEFAULT_CRITICAL[oid]

        if default is True:
            option = f"--{prefix}{extension_arg}-non-critical"
            action = "store_false"
            help_text = f"Mark the extension as non-critical. {help_suffix}".strip()
        else:
            option = f"--{prefix}{extension_arg}-critical"
            action = "store_true"
            help_text = f"Mark the extension as critical. {help_suffix}".strip()

        parser.add_argument(option, dest=destination, action=action, default=default, help=help_text)

    def add_issuer_alternative_name_group(
        self,
        parser: CommandParser,
        description: "StrOrPromise" = "",
        name: str = f"{constants.EXTENSION_NAMES[ExtensionOID.ISSUER_ALTERNATIVE_NAME]} extension",
        dest: Optional[str] = None,
        prefix: str = "",
    ) -> None:
        """Add argument group for the Issuer Alternative Name extension."""
        if not description:
            description = constants.EXTENSION_DESCRIPTIONS[ExtensionOID.ISSUER_ALTERNATIVE_NAME]

        group = parser.add_argument_group(name, str(description))
        group.add_argument(
            f"--{prefix}issuer-alternative-name",
            action=actions.AlternativeNameAction,
            dest=dest,
            extension_type=x509.IssuerAlternativeName,
            help="Alternative name for the certificate issuer. May be given multiple times.",
        )
        # OpenSSL raises an error if this extension is critical.
        # self.add_critical_option(group, ExtensionOID.ISSUER_ALTERNATIVE_NAME)

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

    def add_key_type(
        self, parser: ActionsContainer, default: Optional[str], default_text: str = "%(default)s"
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
        for name, profile in model_settings.CA_PROFILES.items():
            group.add_argument(
                f"--{name}", action="store_const", const=name, dest="profile", help=str(profile.description)
            )


class BaseSignCommand(BaseCommand, metaclass=abc.ABCMeta):
    """Base class for all commands that sign certificates (init_ca, sign_cert, resign_cert).

    This class can add options for all x509 extensions.
    """

    def add_extension(
        self,
        extensions: list[ConfigurableExtension],
        value: ConfigurableExtensionType,
        critical: bool,
    ) -> None:
        """Shortcut for adding the given extension value to the list of extensions."""
        extensions.append(
            # TYPEHINT NOTE: list has Extension[A] | Extension[B], but value has Extension[A | B].
            x509.Extension(oid=value.oid, critical=critical, value=value)  # type: ignore[arg-type]
        )

    def add_subject_format_option(self, parser: ActionsContainer) -> None:
        """Add the --subject-format option."""
        parser.add_argument(
            "--subject-format",
            choices=("openssl", "rfc4514"),
            default="rfc4514",
            help='Format for parsing the subject. Use "openssl" (the default before django-ca 2.0) to pass '
            'slash-separated subjects (e.g. "/C=AT/O=Org/CN=example.com") and "rfc4514" to pass RFC 4514 '
            'conforming strings (e.g. "C=AT,O=Org,CN=example.com"). The default is %(default)s, support for '
            "openssl-style strings will be removed in django-ca 2.2.",
        )

    def parse_x509_name(self, value: str, name_format: SubjectFormats) -> x509.Name:
        """Parse a `name` in the given `format`."""
        if name_format == "openssl":
            name = x509_name(value)
            self.stderr.write(
                f"WARNING: {value}: openssl-style format is deprecated, use --subject-format=rfc4514 "
                "and pass an RFC 4514 compatible subject string instead. It will become default in "
                "django-ca 2.0, and support for the old format will be removed in django-ca 2.2. "
                f"The given subject looks like this in RFC4514:\n\n    {format_name_rfc4514(name)}"
            )
            return name
        if name_format == "rfc4514":
            try:
                return parse_name_rfc4514(value)
            except ValueError as ex:  # pragma: only cryptography>=43.0
                raise CommandError(ex) from ex
        # COVERAGE NOTE: Already covered by argparse
        raise ValueError(f"{name_format}: Unknown subject format.")  # pragma: no cover

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
        additional_option_strings: tuple[str, ...] = tuple(),
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


class BaseSignCertCommand(UsePrivateKeyMixin, BaseSignCommand, metaclass=abc.ABCMeta):
    """Base class for commands signing certificates (sign_cert, resign_cert)."""

    add_extensions_help = ""  # concrete classes should set this
    subject_help: typing.ClassVar  # concrete classes should set this

    def add_base_args(self, parser: CommandParser, no_default_ca: bool = False) -> ArgumentGroup:
        """Add common arguments for signing certificates."""
        general_group = parser.add_argument_group("General")
        self.add_subject_group(parser)
        self.add_algorithm(general_group)
        self.add_ca(general_group, no_default=no_default_ca)
        self.add_use_private_key_arguments(parser)
        self.add_authority_information_access_group(parser)
        self.add_certificate_policies_group(
            parser,
            description="In end-entity certificates, this extension indicates the policy under which the "
            "certificate was issued and the purposes for which it may be used.",
        )
        self.add_crl_distribution_points_group(
            parser,
            _(
                "This extension defines how a Certificate Revocation List (CRL) can be obtained. This option "
                "will override distribution points configured by the CA."
            ),
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
            help=f"Sign the certificate for DAYS days (default: {model_settings.CA_DEFAULT_EXPIRES})",
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

        # Add the --subject-format option
        self.add_subject_format_option(group)

        # NOTE: Don't set the default value here because it would mask the user not setting anything at all.
        self.add_subject(
            group,
            arg="--subject",
            metavar="/key1=value1/key2=value2/...",
            help_text=f"""Valid keys are {self.valid_subject_keys}. Pass an empty value (e.g. "/C=/ST=...")
            to remove a field from the subject.""",
        )

    def verify_certificate_authority(
        self, ca: CertificateAuthority, expires: Optional[timedelta], profile: Profile
    ) -> None:
        """Verify that the certificate authority can be used for signing."""
        if ca.expires < timezone.now():
            raise CommandError("Certificate authority has expired.")
        if ca.revoked:
            raise CommandError("Certificate authority is revoked.")
        if not ca.enabled:
            raise CommandError("Certificate authority is disabled.")

        if expires is None:
            expires = profile.expires
        parsed_expires = datetime.now(tz=tz.utc).replace(second=0, microsecond=0) + expires

        if ca.expires < parsed_expires:
            max_days = (ca.expires - timezone.now()).days
            raise CommandError(
                f"Certificate would outlive CA, maximum expiry for this CA is {max_days} days."
            )


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
        """Output certificate status."""
        now = datetime.now(tz.utc)
        if cert.revoked:
            self.stdout.write("* Status: Revoked")
        elif cert.not_after < now:
            self.stdout.write("* Status: Expired")
        elif cert.not_before > now:
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
        self.stdout.write(f"* Valid from: {cert.not_before.isoformat(' ')}")
        self.stdout.write(f"* Valid until: {cert.not_after.isoformat(' ')}")
        self.output_status(cert)

    def output_footer(self, cert: X509CertMixin, pem: bool, wrap: bool = True) -> None:
        """Output digest and PEM in footer."""
        self.stdout.write("\nDigest:")
        hash_algorithms: tuple[AllowedHashTypes, ...] = (hashes.SHA256(), hashes.SHA512())
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

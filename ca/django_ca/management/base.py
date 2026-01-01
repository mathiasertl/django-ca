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
import sys
import typing
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID

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
from django_ca.constants import ExtensionOID
from django_ca.management import actions, mixins
from django_ca.management.actions import DatetimeAction
from django_ca.management.mixins import UsePrivateKeyMixin
from django_ca.models import CertificateAuthority
from django_ca.profiles import Profile
from django_ca.typehints import (
    ActionsContainer,
    ArgumentGroup,
    ConfigurableExtension,
    ConfigurableExtensionType,
)

if typing.TYPE_CHECKING:
    from django_stubs_ext import StrOrPromise


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
        msg: str | bytes = b"",
        style_func: typing.Callable[..., Any] | None = None,
        ending: bytes | None = None,
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
        stdout: io.BytesIO | None = None,
        stderr: io.BytesIO | None = None,
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
        dest: str | None = None,
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
        metavar: str | None = None,
        help_text: str | None = None,
    ) -> None:
        """Add subject option."""
        parser.add_argument(arg, action=actions.NameAction, metavar=metavar, help=help_text)

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

    def add_key_usage_group(self, parser: CommandParser, default: x509.KeyUsage | None = None) -> None:
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
    subject_help: typing.ClassVar[str]  # concrete classes should set this

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
        self.add_private_key_usage_period_group(parser)
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
        return general_group

    def add_ocsp_no_check_group(self, parser: CommandParser) -> None:
        """Add arguments for the OCSPNoCheck extension."""
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

    def add_private_key_usage_period_group(self, parser: CommandParser) -> None:
        """Add arguments for the PrivateKeyUsagePeriod extension."""
        ext_name = constants.EXTENSION_NAMES[ExtensionOID.PRIVATE_KEY_USAGE_PERIOD]
        group = parser.add_argument_group(
            f"{ext_name} extension",
            f"The {ext_name}  extension indicates the period of use for the private key.",
        )
        group.add_argument(
            "--private-key-usage-period-not-before",
            action=DatetimeAction,
            precision="s",
            help="Earliest possible usage of the private key.",
        )
        group.add_argument(
            "--private-key-usage-period-not-after",
            action=DatetimeAction,
            precision="s",
            help="Latest possible usage of the private key.",
        )

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

    def verify_certificate_authority(
        self, ca: CertificateAuthority, expires: timedelta | None, profile: Profile
    ) -> None:
        """Verify that the certificate authority can be used for signing."""
        if ca.not_after < timezone.now():
            raise CommandError("Certificate authority has expired.")
        if ca.revoked:
            raise CommandError("Certificate authority is revoked.")
        if not ca.enabled:
            raise CommandError("Certificate authority is disabled.")

        if expires is None:
            expires = profile.expires
        parsed_expires = datetime.now(tz=UTC).replace(second=0, microsecond=0) + expires

        if ca.not_after < parsed_expires:
            max_days = (ca.not_after - timezone.now()).days
            raise CommandError(
                f"Certificate would outlive CA, maximum expiry for this CA is {max_days} days."
            )

    def add_private_key_usage_period(
        self, extensions: list[ConfigurableExtension], not_before: datetime | None, not_after: datetime | None
    ) -> None:
        """Get the PrivateKeyUsagePeriod, if set."""
        if not_before is None and not_after is None:  # exit early if neither value is set
            return

        if not_before and not_after and not_before > not_after:
            # Later validation will also catch this, but raise CommandError here for better error messages
            raise CommandError("PrivateKeyUsagePeriod: not_after must be after not_before.")

        value = x509.PrivateKeyUsagePeriod(not_before=not_before, not_after=not_after)
        self.add_extension(extensions, value, critical=False)

    def get_end_entity_extensions(  # pylint: disable=too-many-locals # noqa: PLR0913
        self,  # pylint: disable=unused-argument
        # Authority Information Access extension
        authority_information_access: x509.AuthorityInformationAccess | None,
        # Certificate Policies extension
        certificate_policies: x509.CertificatePolicies | None,
        certificate_policies_critical: bool,
        # CRL Distribution Points extension
        crl_full_names: list[x509.GeneralName] | None,
        crl_distribution_points_critical: bool,
        # Extended Key Usage extension
        extended_key_usage: x509.ExtendedKeyUsage | None,
        extended_key_usage_critical: bool,
        # Issuer Alternative Name extension:
        issuer_alternative_name: x509.IssuerAlternativeName | None,
        # Key Usage extension
        key_usage: x509.KeyUsage | None,
        key_usage_critical: bool,
        # OCSP No Check extension
        ocsp_no_check: bool,
        ocsp_no_check_critical: bool,
        # PrivateKeyUsagePeriod extension
        private_key_usage_period_not_before: datetime | None,
        private_key_usage_period_not_after: datetime | None,
        # Subject Alternative Name extension
        subject_alternative_name: x509.SubjectAlternativeName | None,
        subject_alternative_name_critical: bool,
        # TLSFeature extension
        tls_feature: x509.TLSFeature | None,
        tls_feature_critical: bool,
        **options: Any,
    ) -> list[ConfigurableExtension]:
        """Get extensions for end-entity certificates from the command line."""
        extensions: list[ConfigurableExtension] = []

        if authority_information_access is not None:
            self.add_extension(
                extensions,
                authority_information_access,
                constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.AUTHORITY_INFORMATION_ACCESS],
            )
        if certificate_policies is not None:
            self.add_extension(extensions, certificate_policies, certificate_policies_critical)
        if crl_full_names is not None:
            distribution_point = x509.DistributionPoint(
                full_name=crl_full_names, relative_name=None, crl_issuer=None, reasons=None
            )
            self.add_extension(
                extensions, x509.CRLDistributionPoints([distribution_point]), crl_distribution_points_critical
            )
        if extended_key_usage is not None:
            self.add_extension(extensions, extended_key_usage, extended_key_usage_critical)
        if issuer_alternative_name is not None:
            self.add_extension(
                extensions,
                issuer_alternative_name,
                constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.ISSUER_ALTERNATIVE_NAME],
            )
        if key_usage is not None:
            self.add_extension(extensions, key_usage, key_usage_critical)
        if ocsp_no_check is True:
            self.add_extension(extensions, x509.OCSPNoCheck(), ocsp_no_check_critical)
        self.add_private_key_usage_period(
            extensions, private_key_usage_period_not_before, private_key_usage_period_not_after
        )

        if subject_alternative_name is not None:
            self.add_extension(extensions, subject_alternative_name, subject_alternative_name_critical)
        if tls_feature is not None:
            self.add_extension(extensions, tls_feature, tls_feature_critical)

        return extensions

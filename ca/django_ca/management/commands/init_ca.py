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

"""Management command to create a certificate authority.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-management-commands/
"""

from collections.abc import Iterable
from datetime import datetime, timedelta, timezone as tz
from typing import Any, Optional

from pydantic import BaseModel, ValidationError

from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID

from django.core.management.base import CommandError, CommandParser
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from django_ca import constants
from django_ca.conf import model_settings
from django_ca.key_backends import KeyBackend, key_backends
from django_ca.management.actions import ExpiresAction, IntegerRangeAction, NameAction
from django_ca.management.base import BaseSignCommand, add_key_size
from django_ca.management.mixins import CertificateAuthorityDetailMixin, StorePrivateKeyMixin
from django_ca.models import CertificateAuthority
from django_ca.pydantic.messages import GenerateOCSPKeyMessage
from django_ca.tasks import cache_crl, generate_ocsp_key, run_task
from django_ca.typehints import (
    AllowedHashTypes,
    ArgumentGroup,
    CertificateExtension,
    CertificateExtensionType,
    ParsableKeyType,
    SubjectFormats,
)
from django_ca.utils import format_general_name, parse_general_name


class Command(StorePrivateKeyMixin, CertificateAuthorityDetailMixin, BaseSignCommand):
    """Implement :command:`manage.py init_ca`."""

    help = "Create a certificate authority."

    def add_basic_constraints_group(self, parser: CommandParser) -> None:
        """Add argument group for the Basic Constraints extension."""
        ext_name = constants.EXTENSION_NAMES[ExtensionOID.BASIC_CONSTRAINTS]
        group = parser.add_argument_group(
            f"{ext_name} extension",
            "This extension allows you to specify the number of CAs that can appear below this one. A path "
            "length of zero (the default) means it can only be used to sign end-entity certificates and not "
            "further CAs.",
        )
        group = group.add_mutually_exclusive_group()
        group.add_argument(
            "--path-length",
            default=0,
            type=int,
            help="Maximum number of intermediate CAs (default: %(default)s).",
        )
        group.add_argument(
            "--no-path-length",
            action="store_const",
            const=None,
            dest="path_length",
            help="Do not add a path length attribute.",
        )

    def add_inhibit_any_policy_group(self, parser: CommandParser) -> None:
        """Add argument group for the Inhibit anyPolicy extension."""
        ext_name = constants.EXTENSION_NAMES[ExtensionOID.INHIBIT_ANY_POLICY]
        cert_policies_name = constants.EXTENSION_NAMES[ExtensionOID.CERTIFICATE_POLICIES]
        group = parser.add_argument_group(
            f"{ext_name} extension",
            "This extension indicates that the special anyPolicy is not considered a match when it appears "
            f"in the {cert_policies_name} extension after the given number of certificates in the validation "
            "path.",
        )
        group.add_argument(
            "--inhibit-any-policy",
            action=IntegerRangeAction,
            min=0,
            help="Number of certificates in the validation path where the anyPolicy is still permitted. "
            "Must be an integer >= 0.",
        )

    def add_name_constraints_group(self, parser: CommandParser) -> ArgumentGroup:
        """Add an argument group for the NameConstraints extension."""
        ext_name = constants.EXTENSION_NAMES[ExtensionOID.NAME_CONSTRAINTS]
        group = parser.add_argument_group(
            f"{ext_name} extension",
            "This extension limits the names a signed certificate can contain.",
        )
        group.add_argument(
            "--permit-name",
            metavar="NAME",
            action="append",
            type=parse_general_name,
            help="Add NAME to the permitted-subtree.",
        )
        group.add_argument(
            "--exclude-name",
            metavar="NAME",
            action="append",
            type=parse_general_name,
            help="Add NAME to the excluded-subtree.",
        )
        return group

    def add_policy_constraints_group(self, parser: CommandParser) -> None:
        """Add argument group for the Policy Constraints extension."""
        ext_name = constants.EXTENSION_NAMES[ExtensionOID.POLICY_CONSTRAINTS]
        group = parser.add_argument_group(
            f"{ext_name} extension",
            "This extension can be used to require an explicit policy and/or prohibit policy mapping.",
        )
        group.add_argument(
            "--inhibit-policy-mapping",
            action=IntegerRangeAction,
            min=0,
            help="Number of certificates in the validation path until policy mapping is no longer permitted.",
        )
        group.add_argument(
            "--require-explicit-policy",
            action=IntegerRangeAction,
            min=0,
            help="Number of certificates in the validation path until an explicit policy for the entire path "
            "is required.",
        )

    def add_create_private_key_arguments(self, parser: CommandParser) -> None:
        """Add general arguments for private keys."""
        key_types: set[str] = set()
        elliptic_curves: set[str] = set()

        # Calculate all key types supported by any configured backend.
        for backend in key_backends:
            key_types |= set(backend.supported_key_types)
            elliptic_curves |= set(backend.supported_elliptic_curves)

        parser.add_argument(
            "--key-type",
            choices=key_types,
            default=model_settings.CA_DEFAULT_PRIVATE_KEY_TYPE,
            help="Key type for the private key (default: %(default)s).",
        )
        add_key_size(parser)
        default_elliptic_curve = model_settings.CA_DEFAULT_ELLIPTIC_CURVE
        parser.add_argument(
            "--elliptic-curve",
            choices=sorted(elliptic_curves),
            help=f"Elliptic Curve used for EC keys (default: {default_elliptic_curve.name}).",
        )

        # Add argument groups for backend-specific options.
        for backend in key_backends:
            group = backend.add_create_private_key_group(parser)
            if group is not None:  # pragma: no branch  # all current backends add a group.
                backend.add_create_private_key_arguments(group)

    def add_parent_private_key_storage_arguments(self, group: ArgumentGroup) -> None:
        """Add arguments for loading a parent CA via its key backend."""
        for backend in key_backends:
            backend.add_use_parent_private_key_arguments(group)

    def add_arguments(self, parser: CommandParser) -> None:
        # Load all supported key backend classes so that they can add command-line arguments.
        default = constants.HASH_ALGORITHM_NAMES[type(model_settings.CA_DEFAULT_SIGNATURE_HASH_ALGORITHM)]
        dsa_default = constants.HASH_ALGORITHM_NAMES[
            type(model_settings.CA_DEFAULT_DSA_SIGNATURE_HASH_ALGORITHM)
        ]

        general_group = self.add_general_args(parser)
        general_group.add_argument(
            "--expires",
            metavar="DAYS",
            action=ExpiresAction,
            default=timedelta(365 * 10),
            help="CA certificate expires in DAYS days (default: %(default)s).",
        )
        self.add_subject_format_option(general_group)
        self.add_algorithm(
            general_group, default_text=f"{default} for RSA/EC keys, {dsa_default} for DSA keys"
        )

        self.add_key_backend_option(parser)
        self.add_create_private_key_arguments(parser)

        intermediate_group = parser.add_argument_group(
            "Intermediate certificate authority", "Options to create an intermediate certificate authority."
        )
        self.add_ca(
            intermediate_group,
            "--parent",
            no_default=True,
            help_text="Make the CA an intermediate CA of the named CA. By default, this is a new root CA.",
        )
        self.add_parent_private_key_storage_arguments(intermediate_group)

        parser.add_argument("name", help="Human-readable name of the CA")
        parser.add_argument(
            "subject",
            action=NameAction,
            help='The subject of the CA in the format "/key1=value1/key2=value2/...", requires at least a'
            "CommonName to be present (/CN=...).",
        )

        group = parser.add_argument_group(
            "Default hostname",
            f"""The default hostname is used to compute default URLs for services like OCSP. The hostname is
            usually configured in your settings (current setting: {model_settings.CA_DEFAULT_HOSTNAME}), but
            you can override that value here. The value must be just the hostname and optionally a port,
            *without* a protocol, e.g.  "ca.example.com" or "ca.example.com:8000".""",
        )
        group = group.add_mutually_exclusive_group()
        group.add_argument(
            "--default-hostname",
            metavar="HOSTNAME",
            help="Override the the default hostname configured in your settings.",
        )
        group.add_argument(
            "--no-default-hostname",
            dest="default_hostname",
            action="store_false",
            help="Disable any default hostname configured in your settings.",
        )

        self.add_acme_group(parser)
        self.add_ocsp_group(parser)
        self.add_rest_api_group(parser)

        self.add_authority_information_access_group(parser)
        self.add_basic_constraints_group(parser)
        self.add_certificate_policies_group(
            parser,
            "In certificate authorities, this extension limits the policies that may occur in certification "
            "paths that include the certificate authority.",
            allow_any_policy=True,
        )
        self.add_crl_distribution_points_group(
            parser,
            description=_(
                "This extension defines how a Certificate Revocation List (CRL) can be obtained. "
                "Cannot be used for root certificate authorities."
            ),
        )
        self.add_extended_key_usage_group(parser)
        self.add_inhibit_any_policy_group(parser)
        self.add_issuer_alternative_name_group(parser)
        self.add_key_usage_group(parser, default=CertificateAuthority.DEFAULT_KEY_USAGE)
        self.add_name_constraints_group(parser)
        self.add_policy_constraints_group(parser)
        self.add_subject_alternative_name_group(
            parser, description_suffix="It is not commonly used in certificate authorities."
        )
        self.add_tls_feature_group(parser)

        self.add_certificate_authority_sign_extension_groups(parser)

    def add_extension(
        self,
        # TYPEHINT NOTE: extensions needs to be more general here as we also add CA-only extensions
        extensions: list[CertificateExtension],  # type: ignore[override]
        value: CertificateExtensionType,
        critical: bool,
    ) -> None:
        """Shortcut for adding the given extension value to the list of extensions."""
        extension = x509.Extension(oid=value.oid, critical=critical, value=value)
        # TYPEHINT NOTE: list has Extension[A] | Extension[B], but value has Extension[A | B].
        extensions.append(extension)  # type: ignore[arg-type]

    def handle(  # pylint: disable=too-many-locals  # noqa: PLR0912,PLR0913,PLR0915
        self,
        name: str,
        subject: str,
        parent: Optional[CertificateAuthority],
        expires: timedelta,
        # private key storage options
        key_backend: KeyBackend[BaseModel, BaseModel, BaseModel],
        key_type: ParsableKeyType,
        key_size: Optional[int],
        elliptic_curve: Optional[str],
        algorithm: Optional[AllowedHashTypes],
        # Authority Information Access extension (MUST be non-critical)
        authority_information_access: Optional[x509.AuthorityInformationAccess],
        # Basic Constraints extension
        path_length: Optional[int],
        # Certificate Policies extension
        certificate_policies: Optional[x509.CertificatePolicies],
        certificate_policies_critical: bool,
        # CRL Distribution Points extension
        crl_full_names: Optional[list[x509.GeneralName]],
        crl_distribution_points_critical: bool,
        # Extended Key Usage extension
        extended_key_usage: Optional[x509.ExtendedKeyUsage],
        extended_key_usage_critical: bool,
        # Inhibit anyPolicy extension:
        inhibit_any_policy: Optional[int],
        # Issuer Alternative Name extension:
        issuer_alternative_name: Optional[x509.IssuerAlternativeName],
        # Key Usage extension:
        key_usage: x509.KeyUsage,
        key_usage_critical: bool,
        # Name Constraints extension:
        permit_name: Optional[Iterable[x509.GeneralName]],
        exclude_name: Optional[Iterable[x509.GeneralName]],
        # Policy Constraints extension:
        require_explicit_policy: Optional[int],
        inhibit_policy_mapping: Optional[int],
        # Subject Alternative Name extension
        subject_alternative_name: Optional[x509.SubjectAlternativeName],
        subject_alternative_name_critical: bool,
        # ACMEv2 related options
        caa: str,
        website: str,
        tos: str,
        # Authority Information Access extension  for certificates (MUST be non-critical)
        sign_authority_information_access: Optional[x509.AuthorityInformationAccess],
        # Certificate Policies extension  for certificates
        sign_certificate_policies: Optional[x509.CertificatePolicies],
        sign_certificate_policies_critical: bool,
        # CRL Distribution Points extension for certificates
        sign_crl_full_names: Optional[list[x509.GeneralName]],
        sign_crl_distribution_points_critical: bool,
        # Issuer Alternative Name extension  for certificates
        sign_issuer_alternative_name: Optional[x509.IssuerAlternativeName],
        # OCSP responder configuration
        ocsp_responder_key_validity: Optional[int],
        ocsp_response_validity: Optional[int],
        # subject_format will be removed in django-ca 2.2
        subject_format: SubjectFormats,
        **options: Any,
    ) -> None:
        # Make sure that selected private key options are supported by the selected key backend
        if key_type not in key_backend.supported_key_types:
            raise CommandError(f"{key_type}: Key type not supported by {key_backend.alias} key backend.")
        if (
            key_type == "EC"
            and elliptic_curve is not None
            and elliptic_curve not in key_backend.supported_elliptic_curves
        ):
            raise CommandError(
                f"{elliptic_curve}: Elliptic curve not supported by {key_backend.alias} key backend."
            )

        try:
            key_backend_options = key_backend.get_create_private_key_options(
                key_type, key_size, elliptic_curve=elliptic_curve, options=options
            )

            # Make sure that the selected signature hash algorithm works for the selected backend.
            algorithm = key_backend.validate_signature_hash_algorithm(key_type, algorithm)

            # If there is a parent CA, test if we can use it (here) to sign certificates. The most common case
            # where this happens is if the key is stored on the filesystem, but only accessible to the Celery
            # worker and the current process is on the webserver side.
            signer_key_backend_options = None
            if parent is not None:
                signer_key_backend_options = parent.key_backend.get_use_parent_private_key_options(
                    parent, options
                )

                # Check if the parent key is usable
                parent.check_usable(signer_key_backend_options)
        except ValidationError as ex:
            self.validation_error_to_command_error(ex)
        except CommandError:  # reraise to give backends the opportunity to set the return code.
            raise
        except Exception as ex:
            raise CommandError(str(ex)) from ex

        # In case of CAs, we silently set the expiry date to that of the parent CA if the user specified a
        # number of days that would make the CA expire after the parent CA.
        #
        # The reasoning is simple: When issuing the child CA, the default is automatically after that of the
        # parent if it wasn't issued on the same day.
        if parent and timezone.now() + expires > parent.expires:
            expires_datetime = parent.expires

            # Make sure expires_datetime is tz-aware, even if USE_TZ=False.
            if timezone.is_naive(expires_datetime):
                expires_datetime = timezone.make_aware(expires_datetime)
        else:
            expires_datetime = datetime.now(tz=tz.utc) + expires

        if parent and not parent.allows_intermediate_ca:
            raise CommandError("Parent CA cannot create intermediate CA due to path length restrictions.")
        if not parent and crl_full_names:
            raise CommandError("CRLs cannot be used to revoke root CAs.")
        if not parent and authority_information_access:
            if ocsp_responder := next(
                (
                    ad
                    for ad in authority_information_access
                    if ad.access_method == AuthorityInformationAccessOID.OCSP
                ),
                None,
            ):
                responder_value = format_general_name(ocsp_responder.access_location)
                raise CommandError(f"{responder_value}: OCSP responder cannot be added to root CAs.")

            # No if check necessary here, authority_information_access contains either ocsp or ca_issuer
            # COVERAGE NOTE: next() will always return, so it's not a branch
            ca_issuer = next(  # pragma: no branch
                ad
                for ad in authority_information_access
                if ad.access_method == AuthorityInformationAccessOID.CA_ISSUERS
            )
            responder_value = format_general_name(ca_issuer.access_location)
            raise CommandError(f"{responder_value}: CA issuer cannot be added to root CAs.")

        # Parse the subject
        parsed_subject = self.parse_x509_name(subject, subject_format)

        # We require a valid common name
        common_name = next((attr.value for attr in parsed_subject if attr.oid == NameOID.COMMON_NAME), False)
        if not common_name:
            raise CommandError("Subject must contain a common name (CN=...).")

        extensions: list[CertificateExtension] = [
            x509.Extension(oid=ExtensionOID.KEY_USAGE, critical=key_usage_critical, value=key_usage)
        ]

        # Add the Authority Information Access extension
        if authority_information_access is not None:
            self.add_extension(
                extensions,
                authority_information_access,
                constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.AUTHORITY_INFORMATION_ACCESS],
            )
        # Add the Certificate Policies extension
        if certificate_policies is not None:
            self.add_extension(extensions, certificate_policies, certificate_policies_critical)
        # Add the CRL Distribution Points extension
        if crl_full_names is not None:
            distribution_point = x509.DistributionPoint(
                full_name=crl_full_names, relative_name=None, crl_issuer=None, reasons=None
            )
            self.add_extension(
                extensions, x509.CRLDistributionPoints([distribution_point]), crl_distribution_points_critical
            )
        # Add the Extended Key Usage extension
        if extended_key_usage is not None:
            self.add_extension(extensions, extended_key_usage, extended_key_usage_critical)
        # Add the inhibitAnyPolicy extension
        if inhibit_any_policy is not None:
            self.add_extension(
                extensions,
                x509.InhibitAnyPolicy(skip_certs=inhibit_any_policy),
                constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.INHIBIT_ANY_POLICY],
            )
        # Add the Issuer Alternative Name extension
        if issuer_alternative_name is not None:
            self.add_extension(
                extensions,
                issuer_alternative_name,
                constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.ISSUER_ALTERNATIVE_NAME],
            )
        # Add the NameConstraints extension
        if permit_name or exclude_name:
            self.add_extension(
                extensions,
                x509.NameConstraints(excluded_subtrees=exclude_name, permitted_subtrees=permit_name),
                constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.NAME_CONSTRAINTS],
            )
        # Add the Policy Constraints extension
        if require_explicit_policy is not None or inhibit_policy_mapping is not None:
            self.add_extension(
                extensions,
                x509.PolicyConstraints(
                    require_explicit_policy=require_explicit_policy,
                    inhibit_policy_mapping=inhibit_policy_mapping,
                ),
                constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.POLICY_CONSTRAINTS],
            )
        # Add the Subject Alternative Name extension
        if subject_alternative_name is not None:
            self.add_extension(
                extensions,
                subject_alternative_name,
                subject_alternative_name_critical,
            )

        # Add extensions for signing new certificates
        sign_authority_information_access_ext = None
        if sign_authority_information_access is not None:
            sign_authority_information_access_ext = x509.Extension(
                oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
                critical=constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.AUTHORITY_INFORMATION_ACCESS],
                value=sign_authority_information_access,
            )
        sign_certificate_policies_ext = None
        if sign_certificate_policies is not None:
            sign_certificate_policies_ext = x509.Extension(
                oid=ExtensionOID.CERTIFICATE_POLICIES,
                critical=sign_certificate_policies_critical,
                value=sign_certificate_policies,
            )
        sign_crl_distribution_points_ext = None
        if sign_crl_full_names:
            distribution_point = x509.DistributionPoint(
                full_name=sign_crl_full_names, relative_name=None, crl_issuer=None, reasons=None
            )
            sign_crl_distribution_points_ext = x509.Extension(
                oid=ExtensionOID.CRL_DISTRIBUTION_POINTS,
                critical=sign_crl_distribution_points_critical,
                value=x509.CRLDistributionPoints([distribution_point]),
            )
        sign_issuer_alternative_name_ext = None
        if sign_issuer_alternative_name is not None:
            sign_issuer_alternative_name_ext = x509.Extension(
                oid=ExtensionOID.ISSUER_ALTERNATIVE_NAME, critical=False, value=sign_issuer_alternative_name
            )

        kwargs = {}
        if options["default_hostname"] is not None:
            kwargs["default_hostname"] = options["default_hostname"]

        if model_settings.CA_ENABLE_ACME:  # pragma: no branch; parser throws error already
            # These settings are only there if ACME is enabled
            for opt in ["acme_enabled", "acme_registration", "acme_requires_contact"]:
                if options[opt] is not None:
                    kwargs[opt] = options[opt]

            if acme_profile := options["acme_profile"]:
                if acme_profile not in model_settings.CA_PROFILES:
                    raise CommandError(f"{acme_profile}: Profile is not defined.")
                kwargs["acme_profile"] = acme_profile

        if model_settings.CA_ENABLE_REST_API:  # pragma: no branch; parser throws error already
            if (api_enabled := options.get("api_enabled")) is not None:
                kwargs["api_enabled"] = api_enabled

        try:
            ca = CertificateAuthority.objects.init(
                name=name,
                key_backend=key_backend,
                key_backend_options=key_backend_options,
                subject=parsed_subject,
                expires=expires_datetime,
                algorithm=algorithm,
                parent=parent,
                use_parent_private_key_options=signer_key_backend_options,
                path_length=path_length,
                key_type=key_type,
                extensions=extensions,
                caa=caa,
                website=website,
                terms_of_service=tos,
                sign_authority_information_access=sign_authority_information_access_ext,
                sign_certificate_policies=sign_certificate_policies_ext,
                sign_crl_distribution_points=sign_crl_distribution_points_ext,
                sign_issuer_alternative_name=sign_issuer_alternative_name_ext,
                ocsp_response_validity=ocsp_response_validity,
                ocsp_responder_key_validity=ocsp_responder_key_validity,
                **kwargs,
            )

            load_key_backend_options = key_backend.get_use_private_key_options(ca, options)
        except ValidationError as ex:  # pragma: no cover
            # COVERAGE NOTE: There is currently no way to trigger this via get_use_private_key_options(), as
            #   all currently implemented backends would have raised an error earlier already. At the same
            #   time, validation errors are hard to mock. Nonetheless, this is theoretically possible, so we
            #   handle it here.
            self.validation_error_to_command_error(ex)
        except CommandError:  # reraise to give backends the opportunity to set the return code.
            raise
        except Exception as ex:
            raise CommandError(ex) from ex

        # Generate OCSP keys and cache CRLs
        serialized_key_backend_options = load_key_backend_options.model_dump(mode="json")

        generate_csp_key_message = GenerateOCSPKeyMessage(serial=ca.serial)
        run_task(
            generate_ocsp_key,
            key_backend_options=serialized_key_backend_options,
            **generate_csp_key_message.model_dump(mode="json", exclude_unset=True),
        )

        run_task(cache_crl, serial=ca.serial, key_backend_options=serialized_key_backend_options)

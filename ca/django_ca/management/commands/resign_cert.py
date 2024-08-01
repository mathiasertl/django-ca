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

"""Management command to resign an existing certificate.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-management-commands/
"""

from datetime import timedelta
from typing import Any, Optional

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from django.core.management.base import CommandError, CommandParser

from django_ca import constants
from django_ca.conf import model_settings
from django_ca.management.actions import CertificateAction
from django_ca.management.base import BaseSignCertCommand
from django_ca.models import Certificate, CertificateAuthority, Watcher
from django_ca.profiles import Profile, profiles
from django_ca.typehints import AllowedHashTypes, ConfigurableExtension, SubjectFormats


class Command(BaseSignCertCommand):
    """Implement the :command:`manage.py resign_cert` command."""

    help = f"""Sign a CSR and output signed certificate. The defaults depend on the configured
default profile, currently {model_settings.CA_DEFAULT_PROFILE}."""

    add_extensions_help = "Override certificate extensions."
    subject_help = "Override subject for new certificate."

    def add_arguments(self, parser: CommandParser) -> None:
        self.add_base_args(parser, no_default_ca=True)
        self.add_profile(parser, """Use given profile to determine certificate expiry.""")
        parser.add_argument(
            "cert", action=CertificateAction, allow_revoked=True, help="The certificate to resign."
        )

    def get_profile(self, profile: Optional[str], cert: Certificate) -> Profile:
        """Get requested profile based on command line and given certificate."""
        if profile is not None:
            return profiles[profile]
        if cert.profile == "":
            return profiles[None]

        try:
            return profiles[cert.profile]
        except KeyError:
            # Occurs if the certificate specifies a profile which has since been removed from settings
            raise CommandError(  # noqa: B904
                f'Profile "{cert.profile}" for original certificate is no longer defined, please set one via the command line.'  # NOQA: E501
            )

    def handle(  # pylint: disable=too-many-locals  # noqa: PLR0912, PLR0913
        self,
        cert: Certificate,
        ca: Optional[CertificateAuthority],
        subject: Optional[str],
        expires: Optional[timedelta],
        watch: list[str],
        profile: Optional[str],
        algorithm: Optional[AllowedHashTypes],
        # Authority Information Access extension
        authority_information_access: x509.AuthorityInformationAccess,
        # Certificate Policies extension
        certificate_policies: Optional[x509.CertificatePolicies],
        certificate_policies_critical: bool,
        # CRL Distribution Points extension
        crl_full_names: Optional[list[x509.GeneralName]],
        crl_distribution_points_critical: bool,
        # Extended Key Usage extension
        extended_key_usage: Optional[x509.ExtendedKeyUsage],
        extended_key_usage_critical: bool,
        # Issuer Alternative Name extension:
        issuer_alternative_name: Optional[x509.IssuerAlternativeName],
        # Key Usage extension
        key_usage: Optional[x509.KeyUsage],
        key_usage_critical: bool,
        # OCSP No Check extension
        ocsp_no_check: bool,
        ocsp_no_check_critical: bool,
        # Subject Alternative Name extension
        subject_alternative_name: Optional[x509.SubjectAlternativeName],
        subject_alternative_name_critical: bool,
        # TLSFeature extension
        tls_feature: Optional[x509.TLSFeature],
        tls_feature_critical: bool,
        # subject_format will be removed in django-ca 2.2
        subject_format: SubjectFormats,
        **options: Any,
    ) -> None:
        if ca is None:
            ca = cert.ca

        profile_obj = self.get_profile(profile, cert)
        self.verify_certificate_authority(ca=ca, expires=expires, profile=profile_obj)

        # Get key backend options
        # Get key backend options and validate backend-specific options
        key_backend_options, algorithm = self.get_signing_options(ca, algorithm, options)

        # get list of watchers
        if watch:
            watchers = [Watcher.from_addr(addr) for addr in watch]
        else:
            watchers = list(cert.watchers.all())

        if subject is None:
            parsed_subject = cert.subject
        else:
            parsed_subject = self.parse_x509_name(subject, subject_format)

        # Process any extensions given via the command-line
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
        if subject_alternative_name is not None:
            self.add_extension(extensions, subject_alternative_name, subject_alternative_name_critical)
        if tls_feature is not None:
            self.add_extension(extensions, tls_feature, tls_feature_critical)

        # Copy over extensions from the original certificate (if not passed via the command-line)
        for oid, extension in cert.extensions.items():
            # These extensions are handled by the manager itself based on the CA:
            if oid in (ExtensionOID.AUTHORITY_INFORMATION_ACCESS, ExtensionOID.CRL_DISTRIBUTION_POINTS):
                continue

            # Extensions that are not configurable cannot be copied, as they would be rejected by the
            # profile.
            if oid not in constants.CONFIGURABLE_EXTENSION_KEYS:
                continue

            # Add extensions not already added via the command line
            if next((ext for ext in extensions if ext.oid == oid), None) is None:
                # TYPEHINT NOTE: Extensions from the original certificate may in fact be any extension, as
                # an imported certificate could add custom ones.
                extensions.append(extension)  # type: ignore[arg-type]

        # Verify that we have either a Common Name in the subject or a Subject Alternative Name extension
        # NOTE: This can only happen here in two edge cases:
        #   * Pass a subject without common name AND a certificate does *not* have a subject alternative name.
        #   * An imported certificate that has neither Common Name nor subject alternative name.
        common_names = parsed_subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        has_subject_alternative_name = next(
            (ext for ext in extensions if ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME), None
        )
        if not common_names and has_subject_alternative_name is None:
            raise CommandError(
                "Must give at least a Common Name in --subject or one or more "
                "--subject-alternative-name/--name arguments."
            )

        try:
            cert = Certificate.objects.create_cert(
                ca=ca,
                key_backend_options=key_backend_options,
                csr=cert.csr.loaded,
                profile=profile_obj,
                expires=expires,
                subject=parsed_subject,
                algorithm=algorithm,
                extensions=extensions,
            )
        except Exception as ex:
            raise CommandError(ex) from ex

        cert.watchers.add(*watchers)

        if options["out"]:
            with open(options["out"], "w", encoding="ascii") as stream:
                stream.write(cert.pub.pem)
        else:
            self.stdout.write(cert.pub.pem)

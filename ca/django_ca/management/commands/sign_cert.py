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

"""Management command to sign a new certificate.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-management-commands/
"""

import sys
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID

from django.core.management.base import CommandError, CommandParser

from django_ca.conf import model_settings
from django_ca.management.base import BaseSignCertCommand
from django_ca.management.mixins import OutputCertificateMixin
from django_ca.models import Certificate, CertificateAuthority, Watcher
from django_ca.profiles import profiles
from django_ca.typehints import ConfigurableExtension, SignatureHashAlgorithm


class Command(OutputCertificateMixin, BaseSignCertCommand):
    """Implement the :command:`manage.py sign_cert` command."""

    help = f"""Sign a CSR and output signed certificate. The defaults depend on the configured
default profile, currently {model_settings.CA_DEFAULT_PROFILE}."""

    add_extensions_help = """Values for more complex x509 extensions. This is for advanced usage only, the
profiles already set the correct values for the most common use cases. See
https://django-ca.readthedocs.io/en/latest/extensions.html for more information."""
    subject_help = """The certificate subject of the CSR is not used. The default subject is configured
            with the CA_DEFAULT_SUBJECT setting and may be overwritten by a profile named with
            --profile. The --subject option allows you to name a CommonName (which is not usually
            in the defaults) and override any default values."""

    def add_arguments(self, parser: CommandParser) -> None:
        general_group = self.add_base_args(parser)

        general_group.add_argument(
            "--csr",
            dest="csr_path",
            default="-",
            metavar="FILE",
            help="The path to the certificate to sign, if omitted, you will be be prompted.",
        )

        self.add_output_certificate_arguments(parser, default_format="pem")

        self.add_profile(
            parser,
            """Sign certificate based on the given profile. A profile only sets the the
                         default values, options like --key-usage still override the profile.""",
        )

    def handle(  # noqa: PLR0913, PLR0917  # pylint: disable=too-many-locals
        self,
        ca: CertificateAuthority,
        subject: x509.Name | None,
        expires: timedelta | None,
        watch: list[str],
        csr_path: str,
        profile: str | None,
        algorithm: SignatureHashAlgorithm | None,
        # output certificate group
        output_format: str,
        serial_format: str,
        json_indent: int,
        pem: bool,
        bundle: bool,
        extensions: bool,
        wrap: bool,
        # Authority Information Access extension (MUST be non-critical)
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
        # Key Usage extension:
        key_usage: x509.KeyUsage | None,
        key_usage_critical: bool,
        # OCSP No Check extension
        ocsp_no_check: bool,
        ocsp_no_check_critical: bool,
        # PrivateKeyUsagePeriod extension:
        private_key_usage_period_not_before: datetime | None,
        private_key_usage_period_not_after: datetime | None,
        # Subject Alternative Name extension:
        subject_alternative_name: x509.SubjectAlternativeName | None,
        subject_alternative_name_critical: bool,
        # TLSFeature extension:
        tls_feature: x509.TLSFeature | None,
        tls_feature_critical: bool,
        **options: object,
    ) -> None:
        # Validate parameters early so that we can return better feedback to the user.
        profile_obj = profiles[profile]
        self.verify_certificate_authority(ca=ca, expires=expires, profile=profile_obj)

        # Get key backend options and validate backend-specific options
        key_backend_options, algorithm = self.get_signing_options(ca, algorithm, options)

        # get a list of watchers
        watchers = [Watcher.from_addr(addr) for addr in watch]

        # Process any extensions given via the command-line
        cert_extensions: list[ConfigurableExtension] = self.get_end_entity_extensions(
            authority_information_access=authority_information_access,
            certificate_policies=certificate_policies,
            certificate_policies_critical=certificate_policies_critical,
            crl_full_names=crl_full_names,
            crl_distribution_points_critical=crl_distribution_points_critical,
            extended_key_usage=extended_key_usage,
            extended_key_usage_critical=extended_key_usage_critical,
            issuer_alternative_name=issuer_alternative_name,
            key_usage=key_usage,
            key_usage_critical=key_usage_critical,
            ocsp_no_check=ocsp_no_check,
            ocsp_no_check_critical=ocsp_no_check_critical,
            private_key_usage_period_not_before=private_key_usage_period_not_before,
            private_key_usage_period_not_after=private_key_usage_period_not_after,
            subject_alternative_name=subject_alternative_name,
            subject_alternative_name_critical=subject_alternative_name_critical,
            tls_feature=tls_feature,
            tls_feature_critical=tls_feature_critical,
        )

        cname = None
        if subject is not None:
            cname = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not cname and subject_alternative_name is None:
            raise CommandError(
                "Must give at least a Common Name in --subject or one or more "
                "--subject-alternative-name/--name arguments."
            )

        # Read the CSR
        if csr_path == "-":
            self.stdout.write("Please paste the CSR:")
            csr_bytes = b""
            while True:
                csr_bytes += sys.stdin.buffer.read(1)
                # COVERAGE NOTE: mock function always returns the full string, so we always break right away
                if csr_bytes.strip().endswith(b"-----END CERTIFICATE REQUEST-----"):  # pragma: no branch
                    break
        else:
            with open(csr_path, "rb") as csr_stream:
                csr_bytes = csr_stream.read()

        if csr_bytes.startswith(b"-----BEGIN CERTIFICATE REQUEST-----"):
            csr = x509.load_pem_x509_csr(csr_bytes)
        else:
            csr = x509.load_der_x509_csr(csr_bytes)

        try:
            cert = Certificate.objects.create_cert(
                ca,
                key_backend_options,
                csr,
                profile=profile_obj,
                not_after=expires,
                extensions=cert_extensions,
                subject=subject,
                algorithm=algorithm,
            )
        except Exception as ex:
            raise CommandError(ex) from ex

        cert.watchers.add(*watchers)

        self.output_certificate(
            cert,
            output_format=output_format,
            serial_format=serial_format,
            json_indent=json_indent,
            pem=pem,
            bundle=bundle,
            extensions=extensions,
            wrap=wrap,
        )

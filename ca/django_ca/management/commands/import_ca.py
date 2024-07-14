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

"""Management command to import a certificate authority.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-management-commands/
"""

import argparse
import typing
from typing import Any, Optional

from pydantic import BaseModel, ValidationError

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.x509.oid import ExtensionOID

from django.core.management.base import CommandError, CommandParser

from django_ca import constants
from django_ca.conf import model_settings
from django_ca.constants import PRIVATE_KEY_TYPES, PUBLIC_KEY_TYPES
from django_ca.key_backends import KeyBackend, key_backends
from django_ca.management.actions import PasswordAction
from django_ca.management.base import BaseCommand
from django_ca.management.mixins import CertificateAuthorityDetailMixin, StorePrivateKeyMixin
from django_ca.models import CertificateAuthority
from django_ca.utils import get_private_key_type


class Command(StorePrivateKeyMixin, CertificateAuthorityDetailMixin, BaseCommand):
    """Implement :command:`manage.py import_ca`."""

    help = """Import an existing certificate authority.

Note that the private key will be copied to the directory configured by the CA_DIR setting."""

    def add_store_private_key_arguments(self, parser: CommandParser) -> None:
        """Add general arguments for private keys."""
        for backend in key_backends:
            group = backend.add_store_private_key_group(parser)
            if group is not None:  # pragma: no branch  # all current backends add a group.
                backend.add_store_private_key_arguments(group)

    def add_arguments(self, parser: CommandParser) -> None:
        self.add_ca(
            parser,
            "--parent",
            help_text="Make the CA an intermediate CA of the named CA. By default, this is a new root CA.",
            no_default=True,
        )
        self.add_key_backend_option(parser)
        self.add_store_private_key_arguments(parser)
        parser.add_argument(
            "--import-password",
            nargs="?",
            action=PasswordAction,
            metavar="PASSWORD",
            prompt="Password to import CA: ",
            help="Password for the private key.",
        )

        self.add_acme_group(parser)
        self.add_ocsp_group(parser)
        self.add_rest_api_group(parser)
        self.add_certificate_authority_sign_extension_groups(parser)

        parser.add_argument("name", help="Human-readable name of the CA")
        parser.add_argument(
            "key", help="Path to the private key (PEM or DER format).", type=argparse.FileType("rb")
        )
        parser.add_argument(
            "pem", help="Path to the public key (PEM or DER format).", type=argparse.FileType("rb")
        )

    def handle(  # pylint: disable=too-many-locals  # noqa: PLR0913,PLR0912,PLR0915
        self,
        name: str,
        key: typing.BinaryIO,
        pem: typing.BinaryIO,
        key_backend: KeyBackend[BaseModel, BaseModel, BaseModel],
        parent: Optional[CertificateAuthority],
        import_password: Optional[bytes],
        # Authority Information Access extension  for certificates (MUST be non-critical)
        sign_authority_information_access: Optional[x509.AuthorityInformationAccess],
        # Certificate Policies extension
        sign_certificate_policies: Optional[x509.CertificatePolicies],
        sign_certificate_policies_critical: bool,
        # Issuer Alternative Name extension  for certificates
        sign_issuer_alternative_name: Optional[x509.IssuerAlternativeName],
        # CRL Distribution Points extension for certificates
        sign_crl_full_names: Optional[list[x509.GeneralName]],
        sign_crl_distribution_points_critical: bool,
        # OCSP responder configuration
        ocsp_responder_key_validity: Optional[int],
        ocsp_response_validity: Optional[int],
        **options: Any,
    ) -> None:
        key_data = key.read()
        certificate_data = pem.read()

        # close reader objects (otherwise we get a ResourceWarning)
        key.close()
        pem.close()

        # load private key
        try:
            key_loaded = serialization.load_pem_private_key(key_data, import_password)
        except Exception:  # pylint: disable=broad-except
            try:
                key_loaded = serialization.load_der_private_key(key_data, import_password)
            except Exception as ex:
                raise CommandError("Unable to load private key.") from ex

        # Ensure correct private key type
        if not isinstance(key_loaded, PRIVATE_KEY_TYPES):
            raise CommandError(f"{key_loaded.__class__.__name__}: Invalid private key type.")
        key_loaded = typing.cast(CertificateIssuerPrivateKeyTypes, key_loaded)

        # Make sure that the private key type is supported by the backend
        key_type = get_private_key_type(key_loaded)
        if key_type not in key_backend.supported_key_types:
            raise CommandError(f"{key_type}: Not supported by the {key_backend.alias} key backend.")

        # load certificate
        try:
            loaded_certificate = x509.load_pem_x509_certificate(certificate_data)
        except Exception:  # pylint: disable=broad-except
            try:
                loaded_certificate = x509.load_der_x509_certificate(certificate_data)
            except Exception as ex:
                raise CommandError("Unable to load public key.") from ex

        # Ensure correct certificate type
        # COVERAGE NOTE: All public key types that can be encoded as PEM/DER work (x448/x255129 cannot be
        #   encoded as PEM or DER).
        if not isinstance(loaded_certificate.public_key(), PUBLIC_KEY_TYPES):  # pragma: no cover
            raise CommandError(f"{loaded_certificate.__class__.__name__}: Invalid certificate type.")

        try:
            key_backend_options = key_backend.get_store_private_key_options(options)
        except ValidationError as ex:
            self.validation_error_to_command_error(ex)
        except CommandError:  # reraise to give backends the opportunity to set the return code.
            raise
        except Exception as ex:
            raise CommandError(ex) from ex

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
        if sign_crl_full_names is not None:
            sign_crl_distribution_points_ext = x509.Extension(
                oid=ExtensionOID.CRL_DISTRIBUTION_POINTS,
                critical=sign_crl_distribution_points_critical,
                value=x509.CRLDistributionPoints(
                    [
                        x509.DistributionPoint(
                            full_name=sign_crl_full_names, relative_name=None, crl_issuer=None, reasons=None
                        )
                    ]
                ),
            )
        sign_issuer_alternative_name_ext = None
        if sign_issuer_alternative_name is not None:
            sign_issuer_alternative_name_ext = x509.Extension(
                oid=ExtensionOID.ISSUER_ALTERNATIVE_NAME, critical=False, value=sign_issuer_alternative_name
            )

        ca = CertificateAuthority(
            name=name,
            key_backend_alias=key_backend.alias,
            parent=parent,
            sign_authority_information_access=sign_authority_information_access_ext,
            sign_certificate_policies=sign_certificate_policies_ext,
            sign_crl_distribution_points=sign_crl_distribution_points_ext,
            sign_issuer_alternative_name=sign_issuer_alternative_name_ext,
        )

        # Set OCSP responder options
        if ocsp_responder_key_validity is not None:
            ca.ocsp_responder_key_validity = ocsp_responder_key_validity
        if ocsp_response_validity is not None:
            ca.ocsp_response_validity = ocsp_response_validity

        # Set ACME options
        if model_settings.CA_ENABLE_ACME:  # pragma: no branch; parser throws error already
            for param in ["acme_enabled", "acme_registration", "acme_requires_contact"]:
                if options[param] is not None:
                    setattr(ca, param, options[param])

            if acme_profile := options["acme_profile"]:
                ca.acme_profile = acme_profile

        # Set API options
        if model_settings.CA_ENABLE_REST_API:  # pragma: no branch; parser throws error already
            if (api_enabled := options.get("api_enabled")) is not None:
                ca.api_enabled = api_enabled

        # Store certificate and derived fields in database
        ca.update_certificate(loaded_certificate)

        # Store the private key
        try:
            key_backend.store_private_key(ca, key_loaded, loaded_certificate, key_backend_options)
        except Exception as ex:
            raise CommandError(ex) from ex

        # Only save CA to database if we loaded all data and copied private key
        ca.save()

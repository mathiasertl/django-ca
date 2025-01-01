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

"""Django model managers."""

import typing
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone as tz
from typing import TYPE_CHECKING, Any, Generic, Optional, TypeVar, Union

from asgiref.sync import sync_to_async
from pydantic import BaseModel

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

import django
from django.conf import settings
from django.db import models, transaction
from django.db.models.functions import Coalesce
from django.urls import reverse
from django.utils import timezone

from django_ca import constants
from django_ca.conf import model_settings
from django_ca.deprecation import RemovedInDjangoCA230Warning, deprecate_argument
from django_ca.extensions.utils import format_extensions, get_formatting_context
from django_ca.key_backends.base import KeyBackend
from django_ca.modelfields import LazyCertificateSigningRequest
from django_ca.openssh import SshHostCaExtension, SshUserCaExtension
from django_ca.profiles import Profile, profiles
from django_ca.pydantic.validators import crl_scope_validator
from django_ca.querysets import AcmeCertificateQuerySet
from django_ca.signals import post_create_ca, post_issue_cert, pre_create_ca
from django_ca.typehints import (
    AllowedHashTypes,
    CertificateExtension,
    CertificateExtensionDict,
    ConfigurableExtension,
    ParsableKeyType,
    X509CertMixinTypeVar,
)
from django_ca.utils import int_to_hex, validate_hostname, validate_public_key_parameters

# https://mypy.readthedocs.io/en/latest/runtime_troubles.html
if typing.TYPE_CHECKING:
    from django_ca.models import (
        AcmeAccount,
        AcmeAuthorization,
        AcmeCertificate,
        AcmeChallenge,
        AcmeOrder,
        Certificate,
        CertificateAuthority,
        CertificateRevocationList,
    )
    from django_ca.querysets import (
        AcmeAccountQuerySet,
        AcmeAuthorizationQuerySet,
        AcmeOrderQuerySet,
        CertificateAuthorityQuerySet,
        CertificateQuerySet,
        CertificateRevocationListQuerySet,
    )

    CertificateAuthorityManagerBase = models.Manager[CertificateAuthority]
    CertificateManagerBase = models.Manager[Certificate]
    CertificateRevocationListManagerBase = models.Manager[CertificateRevocationList]
    AcmeAccountManagerBase = models.Manager[AcmeAccount]
    AcmeAuthorizationManagerBase = models.Manager[AcmeAuthorization]
    AcmeCertificateManagerBase = models.Manager[AcmeCertificate]
    AcmeChallengeManagerBase = models.Manager[AcmeChallenge]
    AcmeOrderManagerBase = models.Manager[AcmeOrder]

    QuerySetTypeVar = TypeVar("QuerySetTypeVar", CertificateAuthorityQuerySet, CertificateQuerySet)
else:
    CertificateAuthorityManagerBase = CertificateManagerBase = models.Manager
    CertificateRevocationListManagerBase = models.Manager
    AcmeAccountManagerBase = AcmeAuthorizationManagerBase = AcmeCertificateManagerBase = (
        AcmeChallengeManagerBase
    ) = AcmeOrderManagerBase = models.Manager
    QuerySetTypeVar = TypeVar("QuerySetTypeVar")


class CertificateManagerMixin(Generic[X509CertMixinTypeVar, QuerySetTypeVar]):
    """Mixin for model managers."""

    if typing.TYPE_CHECKING:
        # django-stubs (mypy plugin for Django) currently typehints queryset methods as returning a manager,
        # and does not know about queryset methods coming from the queryset. We typehint basic queryset
        # methods here, so that mypy knows that returned objects are querysets.
        #
        # The type overrides are because of the return type, as mypy thinks they should return a manager.
        #
        # pylint: disable=missing-function-docstring,unused-argument; just defining stubs here

        def all(self) -> QuerySetTypeVar: ...

        def get_queryset(self) -> QuerySetTypeVar: ...

        def filter(self, *args: Any, **kwargs: Any) -> QuerySetTypeVar: ...

        def exclude(self, *args: Any, **kwargs: Any) -> QuerySetTypeVar: ...

        def order_by(self, *fields: str) -> QuerySetTypeVar: ...

        def for_certificate_revocation_list(
            self,
            reasons: Optional[Iterable[x509.ReasonFlags]] = None,
            now: Optional[datetime] = None,
            grace_timedelta: timedelta = timedelta(minutes=10),
        ) -> "CertificateQuerySet": ...

        def get_by_serial_or_cn(self, identifier: str) -> X509CertMixinTypeVar: ...

        async def aget_by_serial_or_cn(self, identifier: str) -> X509CertMixinTypeVar: ...

        def valid(self) -> QuerySetTypeVar: ...


class CertificateAuthorityManager(
    CertificateManagerMixin["CertificateAuthority", "CertificateAuthorityQuerySet"],
    CertificateAuthorityManagerBase,
):
    """Model manager for the CertificateAuthority model."""

    if typing.TYPE_CHECKING:
        # See CertificateManagerMixin for description on this branch
        #
        # pylint: disable=missing-function-docstring; just defining stubs here

        def acme(self) -> "CertificateAuthorityQuerySet": ...

        def disabled(self) -> "CertificateAuthorityQuerySet": ...

        def enabled(self) -> "CertificateAuthorityQuerySet": ...

        def invalid(self) -> "CertificateAuthorityQuerySet": ...

        def usable(self) -> "CertificateAuthorityQuerySet": ...

    def _get_formatting_context(self, serial: int, signer_serial: int) -> dict[str, Union[int, str]]:
        context = get_formatting_context(serial, signer_serial)
        kwargs = {"serial": context["SIGNER_SERIAL_HEX"]}
        context["OCSP_PATH"] = reverse("django_ca:ocsp-ca-post", kwargs=kwargs).lstrip("/")
        context["CRL_PATH"] = reverse("django_ca:ca-crl", kwargs=kwargs).lstrip("/")
        return context

    def _handle_authority_information_access(
        self,
        hostname: Optional[str],
        extensions: CertificateExtensionDict,
    ) -> None:
        """Add an Authority Information Access extension with a URI based on `hostname` to `extensions`.

        If the extension is already present, OCSP/CA Issuers access description are only added if the
        extension does not contain any access descriptions of the respective type.
        """
        oid = ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        access_descriptions: list[x509.AccessDescription] = []
        if oid in extensions:
            extension = typing.cast(x509.AuthorityInformationAccess, extensions[oid].value)
            access_descriptions = list(extension)

        has_ocsp = any(ad.access_method == AuthorityInformationAccessOID.OCSP for ad in access_descriptions)
        has_issuer = any(
            ad.access_method == AuthorityInformationAccessOID.CA_ISSUERS for ad in access_descriptions
        )

        # Fields are only added if not already present, so if both are present, we have nothing to do
        if has_ocsp and has_issuer:
            return

        if has_issuer is False:
            access_descriptions.append(
                x509.AccessDescription(
                    access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                    access_location=x509.UniformResourceIdentifier(f"http://{hostname}/{{CA_ISSUER_PATH}}"),
                )
            )
        if has_ocsp is False:
            access_descriptions.append(
                x509.AccessDescription(
                    access_method=AuthorityInformationAccessOID.OCSP,
                    access_location=x509.UniformResourceIdentifier(f"http://{hostname}/{{OCSP_PATH}}"),
                )
            )

        # Finally sort by OID so that we have more predictable behavior
        access_descriptions = sorted(access_descriptions, key=lambda ad: ad.access_method.dotted_string)

        extensions[oid] = x509.Extension(
            oid=oid,
            critical=constants.EXTENSION_DEFAULT_CRITICAL[oid],
            value=x509.AuthorityInformationAccess(access_descriptions),
        )

    def _handle_crl_distribution_point(
        self, hostname: Optional[str], extensions: CertificateExtensionDict
    ) -> None:
        """Add CRL Distribution Point extension with a URI based on `hostname` to `extensions`.

        The extension is only added if it is not already set in `extensions`.
        """
        oid = ExtensionOID.CRL_DISTRIBUTION_POINTS
        if oid in extensions:
            return

        uri = x509.UniformResourceIdentifier(f"http://{hostname}/{{CRL_PATH}}")
        extensions[oid] = x509.Extension(
            oid=oid,
            critical=constants.EXTENSION_DEFAULT_CRITICAL[oid],
            value=x509.CRLDistributionPoints(
                [x509.DistributionPoint(full_name=[uri], relative_name=None, reasons=None, crl_issuer=None)]
            ),
        )

    # PYLINT NOTE: documented in queryset
    def default(self) -> "CertificateAuthority":  # pylint: disable=missing-function-docstring
        # Needs to be here because the async_to_sync version in the queryset does not get mirrored here.
        return self.all().default()

    @deprecate_argument("expires", RemovedInDjangoCA230Warning, replacement="not_after")
    def init(  # noqa: PLR0912,PLR0913,PLR0915
        self,
        name: str,
        # If BaseModel is used, you can no longer pass subclasses without a mypy warning (-> variance)
        key_backend: KeyBackend[Any, Any, Any],
        key_backend_options: BaseModel,
        subject: x509.Name,
        not_after: Optional[datetime] = None,
        expires: Optional[datetime] = None,
        algorithm: Optional[AllowedHashTypes] = None,
        parent: Optional["CertificateAuthority"] = None,
        use_parent_private_key_options: Optional[BaseModel] = None,
        default_hostname: Optional[Union[bool, str]] = None,
        path_length: Optional[int] = None,
        key_type: ParsableKeyType = "RSA",
        extensions: Optional[Iterable[CertificateExtension]] = None,
        caa: str = "",
        website: str = "",
        terms_of_service: str = "",
        acme_enabled: bool = False,
        acme_registration: bool = True,
        acme_requires_contact: bool = True,
        acme_profile: Optional[str] = None,
        openssh_ca: bool = False,
        sign_authority_information_access: Optional[x509.Extension[x509.AuthorityInformationAccess]] = None,
        sign_certificate_policies: Optional[x509.Extension[x509.CertificatePolicies]] = None,
        sign_crl_distribution_points: Optional[x509.Extension[x509.CRLDistributionPoints]] = None,
        sign_issuer_alternative_name: Optional[x509.Extension[x509.IssuerAlternativeName]] = None,
        ocsp_key_backend_alias: str = "default",
        ocsp_responder_key_validity: Optional[int] = None,
        ocsp_response_validity: Optional[int] = None,
        api_enabled: Optional[bool] = None,
    ) -> "CertificateAuthority":
        """Create a new certificate authority.

        .. deprecated:: 2.1.0

           The ``expires`` parameter is deprecated and will be removed in django-ca 2.3.0. use ``not_after``
           instead.

        .. versionchanged:: 2.0.0

           * Support for passing an ``int`` or ``timedelta`` for `expires` has been deprecated and will be
             removed in django-ca 2.0.

        .. versionchanged:: 1.29.0

           * The `expires` parameter is now mandatory, passing ``None`` will raise ``ValueError``.

        .. versionchanged:: 1.28.0

           * The `key_backend` and `key_backend_options` parameters where added.
           * The `path`, `password`, `key_size` and `elliptic_curve` parameters where removed, they are now
             part of `key_backend`.
           * The `parent_password` parameter was removed, it is now part of the backend loaded for the parent.
           * The `issuer_alt_name` parameter was renamed to `sign_issuer_alternative_name`.
           * The `crl_url` option was removed in favor of `sign_crl_distribution_points`.
           * The `issuer_url` and `ocsp_url` options where removed in favor of
             `sign_authority_information_access`.

        .. versionchanged:: 1.26.0

           * The `permitted_subtrees` and `excluded_subtrees` subtrees where removed. Pass a
             :py:class:`~cg:cryptography.x509.NameConstraints` extension in `extensions` instead.
           * Added the `acme_registration` option.

        Parameters
        ----------
        name : str
            The name of the CA. This is a human-readable string and is used for administrative purposes only.
        key_backend : :py:class:`~django_ca.key_backends.base.KeyBackend`
            A subclass of :py:class:`~django_ca.key_backends.base.KeyBackend` to use for storing the private
            key.
        key_backend_options : BaseModel
            Parameters required for creating the private key using `key_backend`.
        subject : :py:class:`cg:cryptography.x509.Name`
           The desired subject for the certificate.
        not_after : datetime
            When this certificate authority will expire.
        algorithm : :py:class:`~cg:cryptography.hazmat.primitives.hashes.HashAlgorithm`, optional
            Hash algorithm used when signing the certificate, defaults to
            :ref:`settings-ca-default-signature-hash-algorithm` for RSA/EC keys, and
            :ref:`settings-ca-default-dsa-signature-hash-algorithm` for DSA keys. Passing an algorithm for
            Ed448/Ed25519 keys is an error.
        parent : :py:class:`~django_ca.models.CertificateAuthority`, optional
            Parent certificate authority for the new CA. Passing this value makes the CA an intermediate
            authority. Let unset if this CA will be used for OpenSSH.
        use_parent_private_key_options : BaseModel, optional
            Transient parameters required for signing certificates with `parent` (e.g. a password). This
            argument is required if `parent` is given.
        default_hostname : str, optional
            Override the URL configured with :ref:`CA_DEFAULT_HOSTNAME <settings-ca-default-hostname>` with a
            different hostname. Set to ``False`` to disable the hostname.
        path_length : int, optional
            Value of the path length attribute for the Basic Constraints extension.
        key_type: str, optional
            The type of private key to generate, must be one of ``"RSA"``, ``"DSA"``, ``"EC"``, or
            ``"Ed25519"`` , with ``"RSA"`` being the default.
        extensions : list of :py:class:`cg:cryptography.x509.Extension`
            An optional list of additional extensions to add to the certificate.
        caa : str, optional
            CAA identity. Note that this field is not yet currently used.
        website : str, optional
            URL to a human-readable website.
        terms_of_service : str, optional
            URL to the terms of service for the CA.
        acme_enabled : bool, optional
            Set to ``True`` to enable ACMEv2 support for this CA.
        acme_registration : bool, optional
            Whether to allow ACMEv2 clients to register new ACMEv2 accounts (if support is enabled in the
            first place). By default, account registration is enabled.
        acme_profile : str, optional
            The profile to use when issuing certificates via ACMEv2. Defaults to the CA_DEFAULT_PROFILE.
        acme_requires_contact : bool, optional
            Set to ``False`` if you do not want to force clients to register with an email address.
        openssh_ca : bool, optional
            Set to ``True`` if you want to use this to use this CA for signing OpenSSH certs.
        sign_authority_information_access : :py:class:`~cg:cryptography.x509.Extension`, optional
            Add the given Authority Information Access extension when signing certificates.
        sign_certificate_policies : :py:class:`~cg:cryptography.x509.Extension`, optional
            Add the given Certificate Policies extension when signing certificates.
        sign_crl_distribution_points : :py:class:`~cg:cryptography.x509.Extension`, optional
            Add the given CRL Distribution Points extension when signing certificates.
        sign_issuer_alternative_name : :py:class:`~cg:cryptography.x509.Extension`, optional
            Add the given Issuer Alternative Name extension when signing certificates.
        ocsp_key_backend_alias : str, optional
            The OCSP key backend to use, defaults to "default".
        ocsp_responder_key_validity : int, optional
            How long (in days) OCSP responder keys should be valid.
        ocsp_response_validity : int, optional
            How long (in seconds) OCSP responses should be valid.
        api_enabled : bool, optional
            If the REST API shall be enabled.

        Raises
        ------
        ValueError
            For various cases of wrong input data (e.g. extensions of invalid type).
        """
        # pylint: disable=too-many-locals
        if expires is not None and not_after is not None:
            raise ValueError("`not_before` and `expires` cannot both be set.")
        if not_after is None:
            not_after = expires
        if not_after is None:  # pragma: only django-ca<2.3.0  # can only happen while we still have expires
            raise TypeError("Missing required argument: 'not_after'")

        if parent is not None and use_parent_private_key_options is None:
            raise ValueError("use_parent_private_key_options is required when parent is passed.")
        if openssh_ca and parent:
            raise ValueError("OpenSSH does not support intermediate authorities")
        if extensions is None:
            extensions = []
        else:
            extensions = list(extensions)  # cast extensions to list if set (so that we can extend later)

            # check type of values to provide better errors
            for extension in extensions:
                if isinstance(extension, x509.Extension) is False:
                    raise ValueError(f"Cannot add extension of type {type(extension).__name__}")

        # NOTE: Already verified by the caller, so this is only for when the Python API is used directly.
        algorithm = validate_public_key_parameters(key_type, algorithm)

        if not isinstance(not_after, datetime):
            raise TypeError(f"{not_after}: not_after must be a datetime.")
        if not_after.utcoffset() is None:
            raise ValueError("not_after must not be a naive datetime.")

        # Append OpenSSH extensions if an OpenSSH CA was requested
        if openssh_ca:
            extensions.extend([SshHostCaExtension(), SshUserCaExtension()])

        extensions_dict: CertificateExtensionDict = {ext.oid: ext for ext in extensions}

        if ExtensionOID.KEY_USAGE not in extensions_dict:
            extensions_dict[ExtensionOID.KEY_USAGE] = x509.Extension(
                oid=ExtensionOID.KEY_USAGE,
                critical=constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.KEY_USAGE],
                value=self.model.DEFAULT_KEY_USAGE,
            )

        serial = x509.random_serial_number()

        if default_hostname is None:
            default_hostname = model_settings.CA_DEFAULT_HOSTNAME

        if acme_profile is None:
            acme_profile = model_settings.CA_DEFAULT_PROFILE
        elif acme_profile not in model_settings.CA_PROFILES:
            raise ValueError(f"{acme_profile}: Profile is not defined.")

        if parent:
            signer_serial = parent.pub.loaded.serial_number
        else:
            signer_serial = serial

        context = self._get_formatting_context(serial, signer_serial)

        # If there is a default hostname, use it to compute some URLs from that
        if isinstance(default_hostname, str) and default_hostname:
            default_hostname = validate_hostname(default_hostname, allow_port=True)

            if sign_authority_information_access is None:
                # Calculate OCSP access description
                ocsp_path = reverse("django_ca:ocsp-cert-post", kwargs={"serial": context["SERIAL_HEX"]})
                ocsp_url = f"http://{default_hostname}{ocsp_path}"
                ocsp_access_description = x509.AccessDescription(
                    access_method=AuthorityInformationAccessOID.OCSP,
                    access_location=x509.UniformResourceIdentifier(ocsp_url),
                )

                # Calculate CA Issuers access description
                issuer_url = f"http://{default_hostname}/{context['CA_ISSUER_PATH']}"
                ca_issuers_access_description = x509.AccessDescription(
                    access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                    access_location=x509.UniformResourceIdentifier(issuer_url),
                )

                # Finally create the Authority Information Access extension
                sign_authority_information_access = x509.Extension(
                    oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
                    critical=constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.AUTHORITY_INFORMATION_ACCESS],
                    value=x509.AuthorityInformationAccess(
                        # NOTE: OCSP comes first because it has the lexicographically lower dotted string.
                        #   Parts of the test-suite depend on stable order of access descriptions.
                        [ocsp_access_description, ca_issuers_access_description]
                    ),
                )

            if sign_crl_distribution_points is None:
                crl_path = reverse("django_ca:crl", kwargs={"serial": context["SERIAL_HEX"]})
                dpoint = x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(f"http://{default_hostname}{crl_path}")],
                    relative_name=None,
                    crl_issuer=None,
                    reasons=None,
                )
                sign_crl_distribution_points = x509.Extension(
                    oid=ExtensionOID.CRL_DISTRIBUTION_POINTS,
                    critical=constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.CRL_DISTRIBUTION_POINTS],
                    value=x509.CRLDistributionPoints([dpoint]),
                )

            # Add extensions that make sense only for intermediate CAs
            if parent:
                self._handle_authority_information_access(default_hostname, extensions_dict)
                self._handle_crl_distribution_point(default_hostname, extensions_dict)

        # Format extension values
        format_extensions(extensions_dict, context)

        # Cast extensions_dict back to list, so that signal handler receives the same type as the method
        # itself. This has the added bonus of signal handlers being able to influence the extension order.
        extensions = list(extensions_dict.values())

        # Initialize the CA model (has to be passed to key_backend.create_private_key()).
        ca: CertificateAuthority = self.model(
            name=name,
            parent=parent,
            serial=int_to_hex(serial),
            caa_identity=caa,
            website=website,
            terms_of_service=terms_of_service,
            acme_enabled=acme_enabled,
            acme_registration=acme_registration,
            acme_profile=acme_profile,
            acme_requires_contact=acme_requires_contact,
            sign_authority_information_access=sign_authority_information_access,
            sign_certificate_policies=sign_certificate_policies,
            sign_crl_distribution_points=sign_crl_distribution_points,
            sign_issuer_alternative_name=sign_issuer_alternative_name,
            key_backend_alias=key_backend.alias,
            ocsp_key_backend_alias=ocsp_key_backend_alias,
        )

        # Set fields with a default value
        if ocsp_responder_key_validity is not None:
            ca.ocsp_responder_key_validity = ocsp_responder_key_validity
        if ocsp_response_validity is not None:
            ca.ocsp_response_validity = ocsp_response_validity
        if api_enabled is not None:
            ca.api_enabled = api_enabled

        pre_create_ca.send(
            sender=self.model,
            name=name,
            key_type=key_type,
            algorithm=algorithm,
            not_after=not_after,
            parent=parent,
            subject=subject,
            path_length=path_length,
            extensions=extensions,
            caa=caa,
            website=website,
            terms_of_service=terms_of_service,
            acme_enabled=acme_enabled,
            acme_registration=acme_registration,
            acme_profile=acme_profile,
            acme_requires_contact=acme_requires_contact,
            sign_authority_information_access=sign_authority_information_access,
            sign_certificate_policies=sign_certificate_policies,
            sign_crl_distribution_points=sign_crl_distribution_points,
            sign_issuer_alternative_name=sign_issuer_alternative_name,
            ocsp_responder_key_validity=ocsp_responder_key_validity,
            ocsp_response_validity=ocsp_response_validity,
            api_enabled=api_enabled,
        )

        # Actually generate the private key and set ca.key_backend_options.
        public_key, use_private_key_options = key_backend.create_private_key(
            ca, key_type, key_backend_options
        )

        # Add Basic Constraints extension
        extensions.append(
            x509.Extension(
                oid=ExtensionOID.BASIC_CONSTRAINTS,
                critical=True,
                value=x509.BasicConstraints(ca=True, path_length=path_length),
            )
        )

        # Add Subject Key Identifier extension
        extensions.append(
            x509.Extension(
                oid=ExtensionOID.SUBJECT_KEY_IDENTIFIER,
                critical=False,
                value=x509.SubjectKeyIdentifier.from_public_key(public_key),
            )
        )

        # Add Authority Key Identifier extension (and design on backend for signing)
        if parent is None:
            signer_ca = ca
            signer_backend = key_backend
            aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key)
            issuer = subject
        else:
            signer_ca = parent
            signer_backend = parent.key_backend
            use_private_key_options = use_parent_private_key_options
            aki = parent.get_authority_key_identifier()
            issuer = parent.subject

        extensions.append(
            x509.Extension(oid=ExtensionOID.AUTHORITY_KEY_IDENTIFIER, critical=False, value=aki)
        )

        # Sign the certificate
        certificate = signer_backend.sign_certificate(
            signer_ca,
            use_private_key_options,
            public_key,
            serial=serial,
            algorithm=algorithm,
            issuer=issuer,
            subject=subject,
            not_after=not_after,
            extensions=extensions,
        )

        ca.update_certificate(certificate)
        ca.save()

        post_create_ca.send(sender=self.model, ca=ca)
        return ca


class CertificateManager(
    CertificateManagerMixin["Certificate", "CertificateQuerySet"], CertificateManagerBase
):
    """Model manager for the Certificate model."""

    if typing.TYPE_CHECKING:
        # See CertificateManagerMixin for description on this branch
        #
        # pylint: disable=missing-function-docstring; just defining stubs here
        def currently_valid(self) -> "CertificateQuerySet": ...

        def expired(self) -> "CertificateQuerySet": ...

        def not_yet_valid(self) -> "CertificateQuerySet": ...

        def preferred_order(self) -> "CertificateQuerySet": ...

        def revoked(self) -> "CertificateQuerySet": ...

    @deprecate_argument("expires", RemovedInDjangoCA230Warning, replacement="not_after")
    def create_cert(  # noqa: PLR0913
        self,
        ca: "CertificateAuthority",
        key_backend_options: BaseModel,
        csr: x509.CertificateSigningRequest,
        profile: Optional[Profile] = None,
        autogenerated: Optional[bool] = None,
        subject: Optional[x509.Name] = None,
        expires: Optional[Union[datetime, timedelta]] = None,
        not_after: Optional[Union[datetime, timedelta]] = None,
        algorithm: Optional[AllowedHashTypes] = None,
        extensions: Optional[Iterable[ConfigurableExtension]] = None,
        add_crl_url: Optional[bool] = None,
        add_ocsp_url: Optional[bool] = None,
        add_issuer_url: Optional[bool] = None,
        add_issuer_alternative_name: Optional[bool] = None,
    ) -> "Certificate":
        """Create and sign a new certificate based on the given profile.

        .. deprecated:: 2.1.0

           The ``expires`` parameter is deprecated and will be removed in django-ca 2.3.0. use ``not_after``
           instead.

        Parameters
        ----------
        ca : :py:class:`~django_ca.models.CertificateAuthority`
            The certificate authority to sign the certificate with.
        key_backend_options : BaseModel
            Transient parameters required for signing certificates with `ca` (e.g. a password).
        csr : :py:class:`~cg:cryptography.x509.CertificateSigningRequest`
            The certificate signing request to use when signing a certificate. Passing a ``str`` or ``bytes``
            is deprecated and will be removed in django-ca 1.20.0.
        profile : :py:class:`~django_ca.profiles.Profile`, optional
            The name of a profile or a manually created :py:class:`~django_ca.profiles.Profile` instance. If
            not given, the profile configured by :ref:`CA_DEFAULT_PROFILE <settings-ca-default-profile>` is
            used.
        autogenerated : bool, optional
            Override the profiles ``autogenerated`` flag.
        subject : :py:class:`~cg:cryptography.x509.Name`, optional
            Passed to :py:func:`Profiles.create_cert() <django_ca.profiles.Profile.create_cert>`.
        not_after : datetime or timedelta, optional
            Passed to :py:func:`Profiles.create_cert() <django_ca.profiles.Profile.create_cert>`.
        algorithm : :py:class:`~cg:cryptography.hazmat.primitives.hashes.HashAlgorithm`, optional
            Passed to :py:func:`Profiles.create_cert() <django_ca.profiles.Profile.create_cert>`.
        extensions : list or of :py:class:`~cg:cryptography.x509.Extension`
            Passed to :py:func:`Profiles.create_cert() <django_ca.profiles.Profile.create_cert>`.
        add_crl_url : bool, optional
            Passed to :py:func:`Profiles.create_cert() <django_ca.profiles.Profile.create_cert>`.
        add_ocsp_url : bool, optional
            Passed to :py:func:`Profiles.create_cert() <django_ca.profiles.Profile.create_cert>`.
        add_issuer_url : bool, optional
            Passed to :py:func:`Profiles.create_cert() <django_ca.profiles.Profile.create_cert>`.
        add_issuer_alternative_name : bool, optional
            Passed to :py:func:`Profiles.create_cert() <django_ca.profiles.Profile.create_cert>`.
        """
        # Get the profile object if none was passed
        if profile is None:
            profile = profiles[None]
        elif not isinstance(profile, Profile):
            raise TypeError("profile must be of type django_ca.profiles.Profile.")
        if not_after is not None and expires is not None:
            raise ValueError("`not_before` and `expires` cannot both be set.")
        if expires is not None:
            not_after = expires

        cert = profile.create_cert(
            ca,
            key_backend_options,
            csr,
            subject=subject,
            not_after=not_after,
            algorithm=algorithm,
            extensions=extensions,
            add_crl_url=add_crl_url,
            add_ocsp_url=add_ocsp_url,
            add_issuer_url=add_issuer_url,
            add_issuer_alternative_name=add_issuer_alternative_name,
        )

        obj = self.model(ca=ca, csr=LazyCertificateSigningRequest(csr), profile=profile.name)
        obj.update_certificate(cert)
        if autogenerated is None:
            obj.autogenerated = profile.autogenerated
        else:
            obj.autogenerated = autogenerated
        obj.save()

        post_issue_cert.send(sender=self.model, cert=obj)

        return obj


class CertificateRevocationListManager(CertificateRevocationListManagerBase):
    """The model manager for :py:class:`~django_ca.models.CertificateRevocationList`.

    .. versionadded:: 2.1.0
    """

    if typing.TYPE_CHECKING:
        # See CertificateManagerMixin for description on this branch
        #
        # pylint: disable=missing-function-docstring,unused-argument; just defining stubs here

        def reasons(
            self, only_some_reasons: Optional[frozenset[x509.ReasonFlags]]
        ) -> "CertificateRevocationListQuerySet": ...

        def scope(
            self,
            serial: str,
            only_contains_ca_certs: bool = False,
            only_contains_user_certs: bool = False,
            only_contains_attribute_certs: bool = False,
            only_some_reasons: Optional[frozenset[x509.ReasonFlags]] = None,
        ) -> "CertificateRevocationListQuerySet": ...

    def _add_issuing_distribution_point_extension(
        self,
        builder: x509.CertificateRevocationListBuilder,
        *,
        only_contains_ca_certs: bool,
        only_contains_user_certs: bool,
        only_contains_attribute_certs: bool,
        only_some_reasons: Optional[frozenset[x509.ReasonFlags]],
    ) -> x509.CertificateRevocationListBuilder:
        # We can only add the IDP extension if one of these properties is set, see RFC 5280, 5.2.5.
        if (
            only_contains_user_certs
            or only_contains_ca_certs
            or only_contains_attribute_certs
            or only_some_reasons
        ):
            return builder.add_extension(
                x509.IssuingDistributionPoint(
                    full_name=None,
                    relative_name=None,
                    indirect_crl=False,
                    only_contains_ca_certs=only_contains_ca_certs,
                    only_contains_user_certs=only_contains_user_certs,
                    only_contains_attribute_certs=only_contains_attribute_certs,
                    only_some_reasons=only_some_reasons,
                ),
                critical=True,  # "is a critical CRL extension"  - RFC 5280, section 5.2.5
            )

        return builder

    def _add_revoked_certificates(
        self,
        builder: x509.CertificateRevocationListBuilder,
        ca: "CertificateAuthority",
        now: datetime,
        *,
        only_contains_ca_certs: bool,
        only_contains_user_certs: bool,
        only_contains_attribute_certs: bool,  # pylint: disable=unused-argument
        only_some_reasons: Optional[frozenset[x509.ReasonFlags]],
    ) -> x509.CertificateRevocationListBuilder:
        # Add certificate authorities if applicable
        if only_contains_ca_certs is True or only_contains_user_certs is False:
            for child_ca in ca.children.for_certificate_revocation_list(now=now, reasons=only_some_reasons):
                builder = builder.add_revoked_certificate(child_ca.get_revocation())

        # Add certificates if applicable
        if only_contains_user_certs is True or only_contains_ca_certs is False:
            certs = ca.certificate_set.for_certificate_revocation_list(now=now, reasons=only_some_reasons)
            for cert in certs:
                builder = builder.add_revoked_certificate(cert.get_revocation())

        return builder

    @transaction.atomic
    def create_certificate_revocation_list(
        self,
        ca: "CertificateAuthority",
        key_backend_options: BaseModel,
        *,
        next_update: Optional[datetime] = None,
        only_contains_ca_certs: bool = False,
        only_contains_user_certs: bool = False,
        only_contains_attribute_certs: bool = False,
        only_some_reasons: Optional[frozenset[x509.ReasonFlags]] = None,
    ) -> "CertificateRevocationList":
        """Create or update a certificate revocation list.

        Apart from `ca` and `key_backend_options`, all arguments are optional and must be passed as keyword
        arguments.

        Parameters
        ----------
        ca : :py:class:`~django_ca.models.CertificateAuthority`
            The certificate authority to generate the CRL for.
        key_backend_options : BaseModel
            Key backend options for using the private key.
        next_update : datetime, optional
            When the CRL will be updated again, defaults to one day.
        only_contains_ca_certs : bool, optional
            Set to ``True`` to generate a CRL that contains only CA certificates.
        only_contains_user_certs : bool, optional
            Set to ``True`` to generate a CRL that contains only end-entity certificates.
        only_contains_attribute_certs : bool, optional
            Set to ``True`` to generate a CRL that contains only attribute certificates. Note that this is not
            supported and will always return an empty CRL.
        only_some_reasons : frozenset[:py:class:`~cg:cryptography.x509.ReasonFlags`], optional
            Pass a set of :py:class:`~cg:cryptography.x509.ReasonFlags` to limit the CRL to certificates that
            have been revoked for that reason.
        """
        # Parameter validation
        crl_scope_validator(
            only_contains_ca_certs, only_contains_user_certs, only_contains_attribute_certs, only_some_reasons
        )

        # Compute last_update/next_update timestamps
        last_update = datetime.now(tz=tz.utc).replace(microsecond=0)
        if next_update is None:
            next_update = last_update + timedelta(days=1)
        else:
            next_update = next_update.replace(microsecond=0)

        if settings.USE_TZ is False:
            last_update = timezone.make_naive(last_update, timezone=tz.utc)

            if timezone.is_aware(next_update):
                next_update = timezone.make_naive(next_update, timezone=tz.utc)

        # Initialize builder
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(ca.pub.loaded.subject)
        builder = builder.last_update(last_update)
        builder = builder.next_update(next_update)

        # Add AuthorityKeyIdentifier extension from the certificate authority
        builder = builder.add_extension(ca.get_authority_key_identifier(), critical=False)

        # Add the IssuingDistributionPoint extension
        builder = self._add_issuing_distribution_point_extension(
            builder,
            only_contains_ca_certs=only_contains_ca_certs,
            only_contains_user_certs=only_contains_user_certs,
            only_contains_attribute_certs=only_contains_attribute_certs,
            only_some_reasons=only_some_reasons,
        )

        builder = self._add_revoked_certificates(
            builder,
            ca,
            now=last_update,
            only_contains_ca_certs=only_contains_ca_certs,
            only_contains_user_certs=only_contains_user_certs,
            only_contains_attribute_certs=only_contains_attribute_certs,
            only_some_reasons=only_some_reasons,
        )

        # Create subquery for the current CRL number with the given scope.
        number_subquery = (
            self.scope(
                serial=ca.serial,
                only_contains_ca_certs=only_contains_ca_certs,
                only_contains_user_certs=only_contains_user_certs,
                only_contains_attribute_certs=only_contains_attribute_certs,
                only_some_reasons=only_some_reasons,
            )
            .order_by("-number")
            .values(new_number=models.F("number") + 1)[:1]
        )

        # Create database object (as late as possible so any exception above would not hit the database)
        obj: CertificateRevocationList = self.create(
            ca=ca,
            number=Coalesce(models.Subquery(number_subquery, default=1), 0),
            only_contains_ca_certs=only_contains_ca_certs,
            only_contains_user_certs=only_contains_user_certs,
            only_contains_attribute_certs=only_contains_attribute_certs,
            only_some_reasons=only_some_reasons,
            last_update=last_update,
            next_update=next_update,
        )

        # Refresh the object from the database, since we need to access the number. See:
        # https://docs.djangoproject.com/en/5.1/ref/models/expressions/#f-assignments-persist-after-model-save
        if django.VERSION >= (5, 0):  # pragma: django>=5.1 branch
            # Assure that ``ca`` is loaded already
            fields = ("ca", "number")  # only fetch required fields to optimize query
            obj.refresh_from_db(from_queryset=self.model.objects.select_related("ca"), fields=fields)
        else:  # pragma: django<5.1 branch
            # The `from_queryset` argument was added in Django 5.0.
            obj = self.model.objects.select_related("ca").get(pk=obj.pk)

        # Add the CRL Number extension
        builder = builder.add_extension(x509.CRLNumber(crl_number=obj.number), critical=False)

        # Create the signed CRL
        crl = ca.key_backend.sign_certificate_revocation_list(
            ca=ca, use_private_key_options=key_backend_options, builder=builder, algorithm=ca.algorithm
        )

        # Store CRL in the database
        obj.data = crl.public_bytes(Encoding.DER)
        obj.save(update_fields=("data",))  # only update single field to optimize query

        return obj

    acreate_certificate_revocation_list = sync_to_async(create_certificate_revocation_list)


class AcmeAccountManager(AcmeAccountManagerBase):
    """Model manager for :py:class:`~django_ca.models.AcmeAccount`."""

    if typing.TYPE_CHECKING:
        # See CertificateManagerMixin for description on this branch
        #
        # pylint: disable=missing-function-docstring; just defining stubs here

        def url(self) -> "AcmeAccountQuerySet": ...

        def viewable(self) -> "AcmeAccountQuerySet": ...


class AcmeOrderManager(AcmeOrderManagerBase):
    """Model manager for :py:class:`~django_ca.models.AcmeOrder`."""

    if TYPE_CHECKING:
        # See CertificateManagerMixin for description on this branch
        #
        # pylint: disable=missing-function-docstring,unused-argument; just defining stubs here

        def account(self, account: "AcmeAccount") -> "AcmeOrderQuerySet": ...

        def url(self) -> "AcmeOrderQuerySet": ...

        def viewable(self) -> "AcmeOrderQuerySet": ...


class AcmeAuthorizationManager(AcmeAuthorizationManagerBase):
    """Model manager for :py:class:`~django_ca.models.AcmeAuthorization`."""

    if typing.TYPE_CHECKING:
        # See CertificateManagerMixin for description on this branch
        #
        # pylint: disable=missing-function-docstring,unused-argument; just defining stubs here

        def account(self, account: "AcmeAccount") -> "AcmeAuthorizationQuerySet": ...

        def dns(self) -> "AcmeAuthorizationQuerySet": ...

        def names(self) -> list[str]: ...

        def url(self) -> "AcmeAuthorizationQuerySet": ...

        def viewable(self) -> "AcmeAuthorizationQuerySet": ...


class AcmeChallengeManager(AcmeChallengeManagerBase):
    """Model manager for :py:class:`~django_ca.models.AcmeChallenge`."""


class AcmeCertificateManager(AcmeCertificateManagerBase):
    """Model manager for :py:class:`~django_ca.models.AcmeCertificate`."""

    if typing.TYPE_CHECKING:
        # See CertificateManagerMixin for description on this branch
        #
        # pylint: disable=missing-function-docstring; just defining stubs here
        def account(self) -> "AcmeCertificateQuerySet": ...

        def url(self) -> "AcmeCertificateQuerySet": ...

        def viewalbe(self) -> "AcmeCertificateQuerySet": ...

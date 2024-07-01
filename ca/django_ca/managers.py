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
from datetime import datetime, timedelta
from typing import Any, Generic, Optional, TypeVar, Union

from pydantic import BaseModel

from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

from django.db import models
from django.urls import reverse

from django_ca import constants
from django_ca.conf import model_settings
from django_ca.extensions.utils import format_extensions, get_formatting_context
from django_ca.key_backends.base import KeyBackend
from django_ca.modelfields import LazyCertificateSigningRequest
from django_ca.openssh import SshHostCaExtension, SshUserCaExtension
from django_ca.profiles import Profile, profiles
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
    )
    from django_ca.querysets import (
        AcmeAccountQuerySet,
        AcmeAuthorizationQuerySet,
        CertificateAuthorityQuerySet,
        CertificateQuerySet,
    )

    AcmeAccountManagerBase = models.Manager[AcmeAccount]
    AcmeAuthorizationManagerBase = models.Manager[AcmeAuthorization]
    AcmeCertificateManagerBase = models.Manager[AcmeCertificate]
    AcmeChallengeManagerBase = models.Manager[AcmeChallenge]
    AcmeOrderManagerBase = models.Manager[AcmeOrder]
    CertificateAuthorityManagerBase = models.Manager[CertificateAuthority]
    CertificateManagerBase = models.Manager[Certificate]

    QuerySetTypeVar = TypeVar("QuerySetTypeVar", CertificateAuthorityQuerySet, CertificateQuerySet)
else:
    AcmeAccountManagerBase = AcmeAuthorizationManagerBase = AcmeCertificateManagerBase = (
        AcmeChallengeManagerBase
    ) = AcmeOrderManagerBase = CertificateAuthorityManagerBase = CertificateManagerBase = models.Manager
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

        def get_by_serial_or_cn(self, identifier: str) -> X509CertMixinTypeVar: ...

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

        def default(self) -> "CertificateAuthority": ...

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

    def init(  # noqa: PLR0912,PLR0913,PLR0915
        self,
        name: str,
        # If BaseModel is used, you can no longer pass subclasses without a mypy warning (-> variance)
        key_backend: KeyBackend[Any, Any, Any],
        key_backend_options: BaseModel,
        subject: x509.Name,
        expires: datetime,
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
        ocsp_responder_key_validity: Optional[int] = None,
        ocsp_response_validity: Optional[int] = None,
        api_enabled: Optional[bool] = None,
    ) -> "CertificateAuthority":
        """Create a new certificate authority.

        .. versionchanged:: 1.29.0

           * The `expires` parameter is now mandatory, passing ``None`` will raise ``ValueError``.

        .. deprecated:: 1.29.0

           * Support for passing an ``int`` or ``timedelta`` for `expires` has been deprecated and will be
             removed in django-ca 2.0.

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
        expires : datetime
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

        if not isinstance(expires, datetime):
            raise TypeError(f"{expires}: expires must be a datetime.")
        if expires.utcoffset() is None:
            raise ValueError("expires must not be a naive datetime.")

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
            expires=expires,
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
            serial,
            algorithm,
            issuer,
            subject,
            expires,
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

    def create_cert(  # noqa: PLR0913
        self,
        ca: "CertificateAuthority",
        key_backend_options: BaseModel,
        csr: x509.CertificateSigningRequest,
        profile: Optional[Profile] = None,
        autogenerated: Optional[bool] = None,
        subject: Optional[x509.Name] = None,
        expires: Optional[Union[datetime, timedelta]] = None,
        algorithm: Optional[AllowedHashTypes] = None,
        extensions: Optional[Iterable[ConfigurableExtension]] = None,
        add_crl_url: Optional[bool] = None,
        add_ocsp_url: Optional[bool] = None,
        add_issuer_url: Optional[bool] = None,
        add_issuer_alternative_name: Optional[bool] = None,
    ) -> "Certificate":
        """Create and sign a new certificate based on the given profile.

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
        expires : datetime or timedelta, optional
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

        cert = profile.create_cert(
            ca,
            key_backend_options,
            csr,
            subject=subject,
            expires=expires,
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


class AcmeAccountManager(AcmeAccountManagerBase):
    """Model manager for :py:class:`~django_ca.models.AcmeAccount`."""

    if typing.TYPE_CHECKING:
        # See CertificateManagerMixin for description on this branch
        #
        # pylint: disable=missing-function-docstring; just defining stubs here

        def viewable(self) -> "AcmeAccountQuerySet": ...


class AcmeOrderManager(AcmeOrderManagerBase):
    """Model manager for :py:class:`~django_ca.models.AcmeOrder`."""


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

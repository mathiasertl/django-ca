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


import pathlib
import typing
import warnings
from typing import Any, Dict, Generic, Iterable, List, Optional, Sequence, Tuple, TypeVar, Union

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

from django.core.files.base import ContentFile
from django.db import models
from django.urls import reverse

from django_ca import ca_settings, constants
from django_ca.deprecation import RemovedInDjangoCA126Warning, deprecate_argument, deprecate_type
from django_ca.extensions.utils import format_extensions, get_formatting_context
from django_ca.modelfields import LazyCertificateSigningRequest
from django_ca.openssh import SshHostCaExtension, SshUserCaExtension
from django_ca.profiles import Profile, profiles
from django_ca.signals import post_create_ca, post_issue_cert, pre_create_ca
from django_ca.typehints import (
    AllowedHashTypes,
    Expires,
    ExtensionMapping,
    ParsableKeyType,
    X509CertMixinTypeVar,
)
from django_ca.utils import (
    add_colons,
    ca_storage,
    format_general_name,
    generate_private_key,
    get_cert_builder,
    int_to_hex,
    parse_expires,
    parse_general_name,
    validate_hostname,
    validate_private_key_parameters,
    validate_public_key_parameters,
)

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
    from django_ca.querysets import AcmeAccountQuerySet, CertificateAuthorityQuerySet, CertificateQuerySet

    AcmeAccountManagerBase = models.Manager[AcmeAccount]
    AcmeAuthorizationManagerBase = models.Manager[AcmeAuthorization]
    AcmeCertificateManagerBase = models.Manager[AcmeCertificate]
    AcmeChallengeManagerBase = models.Manager[AcmeChallenge]
    AcmeOrderManagerBase = models.Manager[AcmeOrder]
    CertificateAuthorityManagerBase = models.Manager[CertificateAuthority]
    CertificateManagerBase = models.Manager[Certificate]

    QuerySetTypeVar = TypeVar("QuerySetTypeVar", CertificateAuthorityQuerySet, CertificateQuerySet)
else:
    AcmeAccountManagerBase = (
        AcmeAuthorizationManagerBase
    ) = (
        AcmeCertificateManagerBase
    ) = (
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

        def all(self) -> QuerySetTypeVar:
            ...

        def get_queryset(self) -> QuerySetTypeVar:
            ...

        def filter(self, *args: Any, **kwargs: Any) -> QuerySetTypeVar:
            ...

        def exclude(self, *args: Any, **kwargs: Any) -> QuerySetTypeVar:
            ...

        def order_by(self, *fields: str) -> QuerySetTypeVar:
            ...

        def get_by_serial_or_cn(self, identifier: str) -> X509CertMixinTypeVar:
            ...

        def valid(self) -> QuerySetTypeVar:
            ...

    def get_common_extensions(
        self, crl_url: Optional[Iterable[str]] = None
    ) -> List[Tuple[bool, Union[x509.CRLDistributionPoints, x509.AuthorityInformationAccess]]]:
        """Add extensions potentially common to both CAs and certs."""

        extensions: List[Tuple[bool, Union[x509.CRLDistributionPoints, x509.AuthorityInformationAccess]]] = []
        if crl_url:
            urls = [x509.UniformResourceIdentifier(c) for c in crl_url]
            dps = [
                x509.DistributionPoint(full_name=[c], relative_name=None, crl_issuer=None, reasons=None)
                for c in urls
            ]
            extensions.append((False, x509.CRLDistributionPoints(dps)))

        return extensions


class CertificateAuthorityManager(
    CertificateManagerMixin["CertificateAuthority", "CertificateAuthorityQuerySet"],
    CertificateAuthorityManagerBase,
):
    """Model manager for the CertificateAuthority model."""

    if typing.TYPE_CHECKING:
        # See CertificateManagerMixin for description on this branch
        #
        # pylint: disable=missing-function-docstring; just defining stubs here

        def acme(self) -> "CertificateAuthorityQuerySet":
            ...

        def default(self) -> "CertificateAuthority":
            ...

        def disabled(self) -> "CertificateAuthorityQuerySet":
            ...

        def enabled(self) -> "CertificateAuthorityQuerySet":
            ...

        def invalid(self) -> "CertificateAuthorityQuerySet":
            ...

        def usable(self) -> "CertificateAuthorityQuerySet":
            ...

    def _get_formatting_context(self, serial: int, signer_serial: int) -> Dict[str, Union[int, str]]:
        context = get_formatting_context(serial, signer_serial)
        kwargs = {"serial": context["SIGNER_SERIAL_HEX"]}
        context["OCSP_PATH"] = reverse("django_ca:ocsp-ca-post", kwargs=kwargs).lstrip("/")
        context["CRL_PATH"] = reverse("django_ca:ca-crl", kwargs=kwargs).lstrip("/")
        return context

    def _handle_authority_information_access(
        self,
        extensions: ExtensionMapping,
        ca_issuer_url: Optional[Sequence[str]],
        ca_ocsp_url: Optional[Sequence[str]],
    ) -> None:
        access_descriptions: List[x509.AccessDescription] = []
        if ExtensionOID.AUTHORITY_INFORMATION_ACCESS in extensions:
            extension = typing.cast(
                x509.AuthorityInformationAccess, extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS].value
            )
            access_descriptions = list(extension)

        has_ocsp = any(ad.access_method == AuthorityInformationAccessOID.OCSP for ad in access_descriptions)
        has_issuer = any(
            ad.access_method == AuthorityInformationAccessOID.CA_ISSUERS for ad in access_descriptions
        )

        if ca_issuer_url and has_issuer is False:
            access_descriptions += [
                x509.AccessDescription(
                    access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                    access_location=parse_general_name(name),
                )
                for name in ca_issuer_url
            ]
        if ca_ocsp_url and has_ocsp is False:
            access_descriptions += [
                x509.AccessDescription(
                    access_method=AuthorityInformationAccessOID.OCSP, access_location=parse_general_name(name)
                )
                for name in ca_ocsp_url
            ]

        # Finally sort by OID so that we have more predictable behavior
        access_descriptions = sorted(access_descriptions, key=lambda ad: ad.access_method.dotted_string)

        if access_descriptions:
            extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS] = x509.Extension(
                oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
                critical=False,
                value=x509.AuthorityInformationAccess(access_descriptions),
            )

    @deprecate_argument("permitted_subtrees", RemovedInDjangoCA126Warning)
    @deprecate_argument("excluded_subtrees", RemovedInDjangoCA126Warning)
    @deprecate_argument("ca_issuer_url", RemovedInDjangoCA126Warning)
    @deprecate_argument("ca_crl_url", RemovedInDjangoCA126Warning)
    @deprecate_argument("ca_ocsp_url", RemovedInDjangoCA126Warning)
    @deprecate_type("ca_ocsp_url", str, RemovedInDjangoCA126Warning)
    @deprecate_type("ca_issuer_url", str, RemovedInDjangoCA126Warning)
    def init(
        self,
        name: str,
        subject: x509.Name,
        expires: Expires = None,
        algorithm: Optional[AllowedHashTypes] = None,
        parent: Optional["CertificateAuthority"] = None,
        default_hostname: Optional[Union[bool, str]] = None,
        path_length: Optional[int] = None,
        issuer_url: Optional[str] = None,
        issuer_alt_name: Optional[x509.Extension[x509.IssuerAlternativeName]] = None,
        crl_url: Optional[Iterable[str]] = None,
        ocsp_url: Optional[str] = None,
        ca_issuer_url: Optional[Sequence[str]] = None,
        ca_crl_url: Optional[Sequence[str]] = None,
        ca_ocsp_url: Optional[Sequence[str]] = None,
        permitted_subtrees: Optional[Iterable[x509.GeneralName]] = None,
        excluded_subtrees: Optional[Iterable[x509.GeneralName]] = None,
        password: Optional[Union[str, bytes]] = None,
        parent_password: Optional[Union[str, bytes]] = None,
        elliptic_curve: Optional[ec.EllipticCurve] = None,
        key_type: ParsableKeyType = "RSA",
        key_size: Optional[int] = None,
        extensions: Optional[Iterable[x509.Extension[x509.ExtensionType]]] = None,
        path: Union[pathlib.PurePath, str] = "ca",
        caa: str = "",
        website: str = "",
        terms_of_service: str = "",
        acme_enabled: bool = False,
        acme_requires_contact: bool = True,
        acme_profile: Optional[str] = None,
        openssh_ca: bool = False,
    ) -> "CertificateAuthority":
        """Create a new certificate authority.

        .. versionchanged:: 1.23.0

           * The `ecc_curve` parameter was renamed to `elliptic_curve`.
           * Passing ``key_type="EdDSA"`` is deprecated, use ``key_type="Ed25519"`` instead.
           * Passing ``key_type="ECC"`` is deprecated, use ``key_type="EC"`` instead.

        .. versionchanged:: 1.24.0

           * The `extra_extensions` parameter was renamed to `extensions`.
           * The `pathlen` parameter was renamed to `path_length`.
           * The `ca_issuer_url` and `ca_ocsp_url` parameters are now list of strings. Support for bare
             strings will be removed in ``django-ca==1.26.0``.

        .. versionchanged:: 1.25.0

           * The `permitted_subtrees` and `excluded_subtrees` subtrees are deprecated and will be removed in
             ``django-ca==1.26.0``. Pass a :py:class:`~cg:cryptography.x509.NameConstraints` extension in
             `extensions` instead.


        Parameters
        ----------

        name : str
            The name of the CA. This is a human-readable string and is used for administrative purposes only.
        subject : :py:class:`cg:cryptography.x509.Name`
           The desired subject for the certificate.
        expires : int or datetime or timedelta, optional
            When this certificate authority will expire, defaults to :ref:`CA_DEFAULT_EXPIRES
            <settings-ca-default-expires>`.
        algorithm : :py:class:`~cg:cryptography.hazmat.primitives.hashes.HashAlgorithm`, optional
            Hash algorithm used when signing the certificate, defaults to
            :ref:`settings-ca-default-signature-hash-algorithm` for RSA/EC keys, and
            :ref:`settings-ca-default-dsa-signature-hash-algorithm` for DSA keys. Passing an algorithm for
            Ed448/Ed25519 keys is an error.
        parent : :py:class:`~django_ca.models.CertificateAuthority`, optional
            Parent certificate authority for the new CA. Passing this value makes the CA an intermediate
            authority. Let unset if this CA will be used for OpenSSH.
        default_hostname : str, optional
            Override the URL configured with :ref:`CA_DEFAULT_HOSTNAME <settings-ca-default-hostname>` with a
            different hostname. Set to ``False`` to disable the hostname.
        path_length : int, optional
            Value of the path length attribute for the Basic Constraints extension.
        issuer_url : str
            URL for the DER/ASN1 formatted certificate that is signing certificates.
        issuer_alt_name : :py:class:`~cg:cryptography.x509.Extension`, optional
            IssuerAlternativeName used when signing certificates.  The value of the extension must be an
            :py:class:`~cg:cryptography.x509.IssuerAlternativeName` instance.
        crl_url : list of str, optional
            CRL URLs used for certificates signed by this CA.
        ocsp_url : str, optional
            OCSP URL used for certificates signed by this CA. The default is no value, unless
            :ref:`CA_DEFAULT_HOSTNAME <settings-ca-default-hostname>` is set.
        password : bytes or str, optional
            Password to encrypt the private key with.
        parent_password : bytes or str, optional
            Password that the private key of the parent CA is encrypted with.
        elliptic_curve : :py:class:`~cg:cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve`, optional
            An elliptic curve to use for EC keys. This parameter is ignored if ``key_type`` is not ``"EC"``.
            Defaults to the :ref:`CA_DEFAULT_ELLIPTIC_CURVE <settings-ca-default-elliptic-curve>`.
        key_type: str, optional
            The type of private key to generate, must be one of ``"RSA"``, ``"DSA"``, ``"EC"``, or
            ``"Ed25519"`` , with ``"RSA"`` being the default.
        key_size : int, optional
            Integer specifying the key size, must be a power of two (e.g. 2048, 4096, ...). Defaults to
            the :ref:`CA_DEFAULT_KEY_SIZE <settings-ca-default-key-size>`, unused if
            ``key_type="EC"`` or ``key_type="Ed25519"``.
        extensions : list of :py:class:`cg:cryptography.x509.Extension`
            An optional list of additional extensions to add to the certificate.
        path : str or pathlib.PurePath, optional
            Where to store the CA private key (default ``ca``).
        caa : str, optional
            CAA identity. Note that this field is not yet currently used.
        website : str, optional
            URL to a human-readable website.
        terms_of_service : str, optional
            URL to the terms of service for the CA.
        acme_enabled : bool, optional
            Set to ``True`` to enable ACME support for this CA.
        acme_profile : str, optional
            The profile to use when issuing certificates via ACMEv2. Defaults to the CA_DEFAULT_PROFILE.
        acme_requires_contact : bool, optional
            Set to ``False`` if you do not want to force clients to register with an email address.
        openssh_ca : bool, optional
            Set to ``True`` if you want to use this to use this CA for signing OpenSSH certs.

        Raises
        ------

        ValueError
            For various cases of wrong input data (e.g. ``key_size`` not being the power of two).
        PermissionError
            If the private key file cannot be written to disk.
        """
        # pylint: disable=too-many-arguments,too-many-locals,too-many-branches,too-many-statements
        # NOTE: Already verified by KeySizeAction, so these checks are only for when the Python API is used
        #       directly. generate_private_key() invokes this again, but we here to avoid sending a signal.

        if key_type == "ECC":  # type: ignore[comparison-overlap]  # that's a deprecated value
            warnings.warn(
                'key_type="ECC" is deprecated, use key_type="EC" instead.',
                RemovedInDjangoCA126Warning,
                stacklevel=2,
            )
            key_type = "EC"
        if key_type == "EdDSA":  # type: ignore[comparison-overlap]  # that's a deprecated value
            warnings.warn(
                'key_type="EdDSA" key_type is deprecated, use key_type="Ed25519" instead.',
                RemovedInDjangoCA126Warning,
                stacklevel=2,
            )
            key_type = "Ed25519"

        if isinstance(ca_ocsp_url, str):  # pragma: django_ca<1.26.0
            ca_ocsp_url = [ca_ocsp_url]
        if isinstance(ca_issuer_url, str):  # pragma: django_ca<1.26.0
            ca_issuer_url = [ca_issuer_url]
        if extensions is None:
            extensions = []
        else:
            extensions = list(extensions)  # cast extensions to list if set (so that we can extend later)

            # check type of values to provide better errors
            for extension in extensions:
                if isinstance(extension, x509.Extension) is False:
                    raise ValueError(f"Cannot add extension of type {type(extension).__name__}")

        key_size, elliptic_curve = validate_private_key_parameters(key_type, key_size, elliptic_curve)
        algorithm = validate_public_key_parameters(key_type, algorithm)

        expires = parse_expires(expires)

        if openssh_ca and parent:
            raise ValueError("OpenSSH does not support intermediate authorities")

        # Append OpenSSH extensions if an OpenSSH CA was requested
        if openssh_ca:
            extensions.extend([SshHostCaExtension(), SshUserCaExtension()])

        extensions_dict = {ext.oid: ext for ext in extensions}

        if ExtensionOID.KEY_USAGE not in extensions_dict:
            extensions_dict[ExtensionOID.KEY_USAGE] = x509.Extension(
                oid=ExtensionOID.KEY_USAGE,
                critical=constants.EXTENSION_DEFAULT_CRITICAL[ExtensionOID.KEY_USAGE],
                value=self.model.DEFAULT_KEY_USAGE,
            )

        if crl_url is None:
            crl_url = []

        serial = x509.random_serial_number()

        if default_hostname is None:
            default_hostname = ca_settings.CA_DEFAULT_HOSTNAME
        if acme_profile is None:
            acme_profile = ca_settings.CA_DEFAULT_PROFILE
        elif acme_profile not in ca_settings.CA_PROFILES:
            raise ValueError(f"{acme_profile}: Profile is not defined.")

        if parent:
            signer_serial = parent.pub.loaded.serial_number
        else:
            signer_serial = serial

        context = self._get_formatting_context(serial, signer_serial)

        # If there is a default hostname, use it to compute some URLs from that
        if isinstance(default_hostname, str) and default_hostname != "":
            default_hostname = validate_hostname(default_hostname, allow_port=True)

            # Set OCSP urls
            if not ocsp_url:
                ocsp_path = reverse("django_ca:ocsp-cert-post", kwargs={"serial": context["SERIAL_HEX"]})
                ocsp_url = f"http://{default_hostname}{ocsp_path}"
            if parent and not ca_ocsp_url:  # OCSP for CA only makes sense in intermediate CAs
                ca_ocsp_url = [f"http://{default_hostname}/{context['OCSP_PATH']}"]

            # Set issuer path
            if parent and not ca_issuer_url:
                ca_issuer_url = [f"http://{default_hostname}/{context['CA_ISSUER_PATH']}"]
            if not issuer_url:
                issuer_url = f"http://{default_hostname}/{context['CA_ISSUER_PATH']}"

            # Set CRL URLs
            if not crl_url:
                crl_path = reverse("django_ca:crl", kwargs={"serial": context["SERIAL_HEX"]})
                crl_url = [f"http://{default_hostname}{crl_path}"]
            if parent and not ca_crl_url:  # CRL for CA only makes sense in intermediate CAs
                ca_crl_url = [f"http://{default_hostname}/{context['CRL_PATH']}"]

        # Handle the Authority Information Access extension by adding any manually passed access descriptions
        self._handle_authority_information_access(extensions_dict, ca_issuer_url, ca_ocsp_url)

        # Format extension values
        format_extensions(extensions_dict, context)

        # Cast extensions_dict back to list, so that signal handler receives the same type as the method
        # itself. This has the added bonus of signal handlers being able to influence the extension order.
        extensions = list(extensions_dict.values())

        pre_create_ca.send(
            sender=self.model,
            name=name,
            key_size=key_size,
            key_type=key_type,
            algorithm=algorithm,
            expires=expires,
            parent=parent,
            subject=subject,
            pathlen=path_length,
            issuer_url=issuer_url,
            issuer_alt_name=issuer_alt_name,
            crl_url=crl_url,
            ocsp_url=ocsp_url,
            ca_issuer_url=ca_issuer_url,
            ca_crl_url=ca_crl_url,
            ca_ocsp_url=ca_ocsp_url,
            permitted_subtrees=permitted_subtrees,
            excluded_subtrees=excluded_subtrees,
            password=password,
            parent_password=parent_password,
            extensions=extensions,
            caa=caa,
            website=website,
            terms_of_service=terms_of_service,
            acme_enabled=acme_enabled,
            acme_profile=acme_profile,
            acme_requires_contact=acme_requires_contact,
        )

        private_key = generate_private_key(key_size, key_type, elliptic_curve)
        public_key = private_key.public_key()

        builder = get_cert_builder(expires, serial=serial)
        builder = builder.public_key(public_key)
        builder = builder.subject_name(subject)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length), critical=True
        )

        subject_key_id = x509.SubjectKeyIdentifier.from_public_key(public_key)
        builder = builder.add_extension(subject_key_id, critical=False)

        if parent is None:
            builder = builder.issuer_name(subject)
            private_sign_key = private_key
            aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key)
        else:
            builder = builder.issuer_name(parent.pub.loaded.subject)
            private_sign_key = parent.key(parent_password)
            aki = parent.get_authority_key_identifier()
        builder = builder.add_extension(aki, critical=False)

        for critical, ext in self.get_common_extensions(ca_crl_url):
            # Check if the extension was passed directly, in which case we do not add it here.
            if ext.oid not in extensions_dict:
                builder = builder.add_extension(ext, critical=critical)

        if permitted_subtrees is not None or excluded_subtrees is not None:
            builder = builder.add_extension(
                x509.NameConstraints(permitted_subtrees, excluded_subtrees), critical=True
            )

        for extra_extension in extensions:
            builder = builder.add_extension(extra_extension.value, critical=extra_extension.critical)

        certificate = builder.sign(private_key=private_sign_key, algorithm=algorithm)

        # Normalize extensions for create()
        crl_url = "\n".join(crl_url)

        # Convert arguments for database storage
        serialized_ian = ""
        if issuer_alt_name is not None:
            serialized_ian = ",".join(format_general_name(name) for name in issuer_alt_name.value)

        ca = self.model(
            name=name,
            issuer_url=issuer_url,
            issuer_alt_name=serialized_ian,
            ocsp_url=ocsp_url,
            crl_url=crl_url,
            parent=parent,
            caa_identity=caa,
            website=website,
            terms_of_service=terms_of_service,
            acme_enabled=acme_enabled,
            acme_profile=acme_profile,
            acme_requires_contact=acme_requires_contact,
        )
        ca.update_certificate(certificate)

        if password is None:
            encryption: serialization.KeySerializationEncryption = serialization.NoEncryption()
        else:
            if isinstance(password, str):
                password = password.encode("utf-8")
            encryption = serialization.BestAvailableEncryption(password)

        pem = private_key.private_bytes(
            encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=encryption
        )

        # write private key to file
        safe_serial = ca.serial.replace(":", "")
        path = path / pathlib.PurePath(f"{safe_serial}.key")
        ca.private_key_path = ca_storage.save(str(path), ContentFile(pem))
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

        def expired(self) -> "CertificateQuerySet":
            ...

        def not_yet_valid(self) -> "CertificateQuerySet":
            ...

        def revoked(self) -> "CertificateQuerySet":
            ...

    def create_cert(
        self,
        ca: "CertificateAuthority",
        csr: x509.CertificateSigningRequest,
        profile: Optional[Profile] = None,
        autogenerated: Optional[bool] = None,
        **kwargs: Any,
    ) -> "Certificate":
        """Create and sign a new certificate based on the given profile.

        Parameters
        ----------

        ca : :py:class:`~django_ca.models.CertificateAuthority`
            The certificate authority to sign the certificate with.
        csr : :py:class:`~cg:cryptography.x509.CertificateSigningRequest`
            The certificate signing request to use when signing a certificate. Passing a ``str`` or ``bytes``
            is deprecated and will be removed in django-ca 1.20.0.
        profile : :py:class:`~django_ca.profiles.Profile`, optional
            The name of a profile or a manually created :py:class:`~django_ca.profiles.Profile` instance. If
            not given, the profile configured by :ref:`CA_DEFAULT_PROFILE <settings-ca-default-profile>` is
            used.
        autogenerated : bool, optional
            Override the profiles ``autogenerated`` flag.
        **kwargs
            All other keyword arguments are passed to :py:func:`Profiles.create_cert()
            <django_ca.profiles.Profile.create_cert>`.
        """

        # Get the profile object if none was passed
        if profile is None:
            profile = profiles[None]
        elif not isinstance(profile, Profile):
            raise TypeError("profile must be of type django_ca.profiles.Profile.")

        cert = profile.create_cert(ca, csr, **kwargs)

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

        def viewable(self) -> "AcmeAccountQuerySet":
            ...


class AcmeOrderManager(AcmeOrderManagerBase):
    """Model manager for :py:class:`~django_ca.models.AcmeOrder`."""


class AcmeAuthorizationManager(AcmeAuthorizationManagerBase):
    """Model manager for :py:class:`~django_ca.models.AcmeAuthorization`."""


class AcmeChallengeManager(AcmeChallengeManagerBase):
    """Model manager for :py:class:`~django_ca.models.AcmeChallenge`."""


class AcmeCertificateManager(AcmeCertificateManagerBase):
    """Model manager for :py:class:`~django_ca.models.AcmeCertificate`."""

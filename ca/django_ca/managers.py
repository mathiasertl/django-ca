# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca. If not,
# see <http://www.gnu.org/licenses/>.

"""Django model managers."""


import pathlib
import typing
import warnings
from typing import TYPE_CHECKING, Any, Generic, Iterable, List, Optional, Sequence, Tuple, TypeVar, Union

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat
from cryptography.x509.oid import AuthorityInformationAccessOID

from django.core.files.base import ContentFile
from django.db import models
from django.urls import reverse

from . import ca_settings
from .constants import EXTENSION_DEFAULT_CRITICAL
from .deprecation import RemovedInDjangoCA123Warning, deprecate_argument, deprecate_type
from .extensions import Extension, IssuerAlternativeName, NameConstraints
from .modelfields import LazyCertificateSigningRequest
from .openssh import SshHostCaExtension, SshUserCaExtension
from .profiles import Profile, profiles
from .signals import post_create_ca, post_issue_cert, pre_create_ca
from .typehints import Expires, ParsableExtension, ParsableKeyType, X509CertMixinTypeVar
from .utils import (
    ca_storage,
    format_general_name,
    generate_private_key,
    get_cert_builder,
    int_to_hex,
    parse_expires,
    parse_general_name,
    validate_hostname,
    validate_key_parameters,
)

# https://mypy.readthedocs.io/en/latest/runtime_troubles.html
if TYPE_CHECKING:
    from .models import (
        AcmeAccount,
        AcmeAuthorization,
        AcmeCertificate,
        AcmeChallenge,
        AcmeOrder,
        Certificate,
        CertificateAuthority,
    )
    from .querysets import AcmeAccountQuerySet, CertificateAuthorityQuerySet, CertificateQuerySet

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

    if TYPE_CHECKING:
        # django-stubs (mypy plugin for Django) currently typehints queryset methods as returning a manager,
        # and does not know about queryset methods comming from the queryset. We typehint basic queryset
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
        self,
        issuer_url: Optional[str] = None,
        crl_url: Optional[Iterable[str]] = None,
        ocsp_url: Optional[str] = None,
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
        auth_info_access = []
        if ocsp_url:
            uri = x509.UniformResourceIdentifier(ocsp_url)
            auth_info_access.append(
                x509.AccessDescription(access_method=AuthorityInformationAccessOID.OCSP, access_location=uri)
            )
        if issuer_url:
            uri = x509.UniformResourceIdentifier(issuer_url)
            auth_info_access.append(
                x509.AccessDescription(
                    access_method=AuthorityInformationAccessOID.CA_ISSUERS, access_location=uri
                )
            )
        if auth_info_access:
            extensions.append((False, x509.AuthorityInformationAccess(auth_info_access)))
        return extensions

    def _extra_extensions(
        self,
        builder: x509.CertificateBuilder,
        extra_extensions: typing.List[typing.Union[x509.Extension[x509.ExtensionType]]],
    ) -> x509.CertificateBuilder:
        warn = "Passing a django_ca.extensions.Extension is deprecated and will be removed in django_ca 1.23."
        for ext in extra_extensions:
            if isinstance(ext, x509.Extension):
                builder = builder.add_extension(ext.value, critical=ext.critical)
            elif isinstance(ext, Extension):
                warnings.warn(warn, category=RemovedInDjangoCA123Warning, stacklevel=2)
                builder = builder.add_extension(*ext.for_builder())
            else:
                raise ValueError(f"Cannot add extension of type {type(ext).__name__}")
        return builder


class CertificateAuthorityManager(
    CertificateManagerMixin["CertificateAuthority", "CertificateAuthorityQuerySet"],
    CertificateAuthorityManagerBase,
):
    """Model manager for the CertificateAuthority model."""

    if TYPE_CHECKING:
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

    @deprecate_argument("name_constraints", RemovedInDjangoCA123Warning)
    @deprecate_type("issuer_alt_name", (str, IssuerAlternativeName), RemovedInDjangoCA123Warning)
    def init(
        self,
        name: str,
        subject: x509.Name,
        expires: Expires = None,
        algorithm: typing.Optional[HashAlgorithm] = None,
        parent: Optional["CertificateAuthority"] = None,
        default_hostname: Optional[Union[bool, str]] = None,
        pathlen: Optional[int] = None,
        issuer_url: Optional[str] = None,
        issuer_alt_name: typing.Optional[x509.Extension[x509.IssuerAlternativeName]] = None,
        crl_url: Optional[Iterable[str]] = None,
        ocsp_url: Optional[str] = None,
        ca_issuer_url: Optional[str] = None,
        ca_crl_url: Optional[Sequence[str]] = None,
        ca_ocsp_url: Optional[str] = None,
        name_constraints: Optional[Union[ParsableExtension, NameConstraints]] = None,
        permitted_subtrees: typing.Optional[typing.Iterable[x509.GeneralName]] = None,
        excluded_subtrees: typing.Optional[typing.Iterable[x509.GeneralName]] = None,
        password: Optional[Union[str, bytes]] = None,
        parent_password: Optional[Union[str, bytes]] = None,
        ecc_curve: Optional[ec.EllipticCurve] = None,
        key_type: ParsableKeyType = "RSA",
        key_size: Optional[int] = None,
        extra_extensions: Optional[typing.Iterable[x509.Extension[x509.ExtensionType]]] = None,
        path: Union[pathlib.PurePath, str] = "ca",
        caa: str = "",
        website: str = "",
        terms_of_service: str = "",
        acme_enabled: bool = False,
        acme_requires_contact: bool = True,
        openssh_ca: bool = False,
    ) -> "CertificateAuthority":
        """Create a new certificate authority.

        .. deprecated:: 1.21.0

           * The `name_constraints` parameter is deprecated and will be removed in ``django_ca==1.23``. Use
             the `permitted_subtrees` and `excluded_subtrees` parameter instead.
           * Passing  ``django_ca.extensions.Extension`` instance to `extra_extensions` is now deprecated. The
             feature will be removed in ``django_ca==1.23``. Pass a ``x509.Extension`` instance instead.
           * The `issuer_alt_name` now accepts a
             :py:class:`~cg:cryptography.x509.Extension` with a
             :py:class:`~cg:cryptography.x509.IssuerAlternativeName` value, passing a `str` or
             ``django_ca.extensions.IssuerAlternativeName`` is deprecated and will be removed in
             ``django_ca==1.23``.

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
            :ref:`CA_DIGEST_ALGORITHM <settings-ca-digest-algorithm>`.
        parent : :py:class:`~django_ca.models.CertificateAuthority`, optional
            Parent certificate authority for the new CA. Passing this value makes the CA an intermediate
            authority. Let unset if this CA will be used for OpenSSH.
        default_hostname : str, optional
            Override the URLconfigured with :ref:`CA_DEFAULT_HOSTNAME <settings-ca-default-hostname>` with a
            different hostname. Set to ``False`` to disable the hostname.
        pathlen : int, optional
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
        ca_issuer_url : str, optional
            URL for the DER/ASN1 formatted certificate that is signing this CA. For intermediate CAs, this
            would usually be the ``issuer_url`` of the parent CA.
        ca_crl_url : list of str, optional
            CRL URLs used for this CA. This value is only meaningful for intermediate CAs.
        ca_ocsp_url : str, optional
            OCSP URL used for this CA. This value is only meaningful for intermediate CAs. The default is
            no value, unless :ref:`CA_DEFAULT_HOSTNAME <settings-ca-default-hostname>` is set.
        permitted_subtrees : list of x509.GeneralName, optional
            List of general names to add to the permitted names of the NameConstraints extension.
        excluded_subtrees : list of x509.GeneralName, optional
            List of general names to add to the permitted names of the NameConstraints extension.
        name_constraints ``django_ca.extensions.NameConstraints``
            Deprecated in favor of `permitted_subtrees` and `excluded_subtrees`.
        password : bytes or str, optional
            Password to encrypt the private key with.
        parent_password : bytes or str, optional
            Password that the private key of the parent CA is encrypted with.
        ecc_curve : :py:class:`~cg:cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve`, optional
            An elliptic curve to use for ECC keys. This parameter is ignored if ``key_type`` is not ``"ECC"``.
            Defaults to the :ref:`CA_DEFAULT_ECC_CURVE <settings-ca-default-ecc-curve>`.
        key_type: str, optional
            The type of private key to generate, must be one of ``"RSA"``, ``"DSA"``, ``"ECC"``, or
            ``"EdDSA"`` , with ``"RSA"`` being the default.
        key_size : int, optional
            Integer specifying the key size, must be a power of two (e.g. 2048, 4096, ...). Defaults to
            the :ref:`CA_DEFAULT_KEY_SIZE <settings-ca-default-key-size>`, unused if
            ``key_type="ECC"`` or ``key_type="EdDSA"``.
        extra_extensions : list of :py:class:`cg:cryptography.x509.Extension`
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
        validate_key_parameters(key_size, key_type, ecc_curve)

        if openssh_ca:
            algorithm = None
        elif algorithm is None:
            algorithm = ca_settings.CA_DIGEST_ALGORITHM
        expires = parse_expires(expires)

        if openssh_ca and parent:
            raise ValueError("OpenSSH does not support intermediate authorities")
        if not openssh_ca and key_type == "EdDSA":
            raise ValueError("EdDSA only supported for OpenSSH authorities")

        # Cast extra_extensions to list if set (so that we can extend if necessary)
        if extra_extensions:
            extra_extensions = list(extra_extensions)
        else:
            extra_extensions = []

        # Append OpenSSH extensions if an OpenSSH CA was requested
        if openssh_ca:
            extra_extensions.extend([SshHostCaExtension(), SshUserCaExtension()])

        # Normalize extensions to django_ca.extensions.Extension subclasses
        if isinstance(issuer_alt_name, str):
            issuer_alt_name = x509.Extension(
                oid=x509.IssuerAlternativeName.oid,
                critical=EXTENSION_DEFAULT_CRITICAL[x509.IssuerAlternativeName.oid],
                value=x509.IssuerAlternativeName(general_names=[parse_general_name(issuer_alt_name)]),
            )
        elif isinstance(issuer_alt_name, IssuerAlternativeName):
            issuer_alt_name = issuer_alt_name.as_extension()

        if crl_url is None:
            crl_url = []

        serial = x509.random_serial_number()
        hex_serial = int_to_hex(serial)

        if default_hostname is None:
            default_hostname = ca_settings.CA_DEFAULT_HOSTNAME

        # If there is a default hostname, use it to compute some URLs from that
        if isinstance(default_hostname, str) and default_hostname != "":
            default_hostname = validate_hostname(default_hostname, allow_port=True)
            if parent:
                root_serial = parent.serial
            else:
                root_serial = hex_serial

            # Set OCSP urls
            if not ocsp_url:
                ocsp_path = reverse("django_ca:ocsp-cert-post", kwargs={"serial": hex_serial})
                ocsp_url = f"http://{default_hostname}{ocsp_path}"
            if parent and not ca_ocsp_url:  # OCSP for CA only makes sense in intermediate CAs
                ocsp_path = reverse("django_ca:ocsp-ca-post", kwargs={"serial": root_serial})
                ca_ocsp_url = f"http://{default_hostname}{ocsp_path}"

            # Set issuer path
            issuer_path = reverse("django_ca:issuer", kwargs={"serial": root_serial})
            if parent and not ca_issuer_url:
                ca_issuer_url = f"http://{default_hostname}{issuer_path}"
            if not issuer_url:
                issuer_url = f"http://{default_hostname}{issuer_path}"

            # Set CRL URLs
            if not crl_url:
                crl_path = reverse("django_ca:crl", kwargs={"serial": hex_serial})
                crl_url = [f"http://{default_hostname}{crl_path}"]
            if parent and not ca_crl_url:  # CRL for CA only makes sense in intermediate CAs
                ca_crl_path = reverse("django_ca:ca-crl", kwargs={"serial": root_serial})
                ca_crl_url = [f"http://{default_hostname}{ca_crl_path}"]

        pre_create_ca.send(
            sender=self.model,
            name=name,
            key_size=key_size,
            key_type=key_type,
            algorithm=algorithm,
            expires=expires,
            parent=parent,
            subject=subject,
            pathlen=pathlen,
            issuer_url=issuer_url,
            issuer_alt_name=issuer_alt_name,
            crl_url=crl_url,
            ocsp_url=ocsp_url,
            ca_issuer_url=ca_issuer_url,
            ca_crl_url=ca_crl_url,
            ca_ocsp_url=ca_ocsp_url,
            name_constraints=name_constraints,
            permitted_subtrees=permitted_subtrees,
            excluded_subtrees=excluded_subtrees,
            password=password,
            parent_password=parent_password,
            extra_extensions=extra_extensions,
            caa=caa,
            website=website,
            terms_of_service=terms_of_service,
            acme_enabled=acme_enabled,
            acme_requires_contact=acme_requires_contact,
        )

        private_key = generate_private_key(key_size, key_type, ecc_curve)
        public_key = private_key.public_key()

        builder = get_cert_builder(expires, serial=serial)
        builder = builder.public_key(public_key)
        builder = builder.subject_name(subject)
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=pathlen), critical=True)
        builder = builder.add_extension(
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
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

        for critical, ext in self.get_common_extensions(ca_issuer_url, ca_crl_url, ca_ocsp_url):
            builder = builder.add_extension(ext, critical=critical)

        if permitted_subtrees is not None or excluded_subtrees is not None:
            builder = builder.add_extension(
                x509.NameConstraints(permitted_subtrees, excluded_subtrees), critical=True
            )
        elif name_constraints:
            if not isinstance(name_constraints, NameConstraints):
                name_constraints = NameConstraints(name_constraints)

            builder = builder.add_extension(*name_constraints.for_builder())

        if extra_extensions:
            builder = self._extra_extensions(builder, extra_extensions)

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

    if TYPE_CHECKING:
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

    if TYPE_CHECKING:
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

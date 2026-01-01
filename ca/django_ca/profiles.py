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

"""Module for handling certificate profiles."""

from collections.abc import Iterable, Iterator
from datetime import UTC, datetime, timedelta
from threading import local
from typing import TYPE_CHECKING, Annotated, Any, cast

from pydantic import BaseModel, Field

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPublicKeyTypes
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID

from django.urls import reverse

from django_ca import constants
from django_ca.conf import model_settings
from django_ca.constants import CERTIFICATE_EXTENSION_KEY_OIDS
from django_ca.extensions.utils import format_extensions, get_formatting_context
from django_ca.pydantic.name import NameModel
from django_ca.pydantic.profile import ProfileConfigurationModel
from django_ca.pydantic.type_aliases import DayValidator, PositiveTimedelta
from django_ca.signals import pre_sign_cert
from django_ca.typehints import ConfigurableExtension, ConfigurableExtensionDict, SignatureHashAlgorithm
from django_ca.utils import merge_x509_names

if TYPE_CHECKING:
    from django_ca.models import CertificateAuthority


class Profile(ProfileConfigurationModel):
    """A certificate profile defining properties and extensions of a certificate.

    Instances of this class usually represent profiles defined in :ref:`CA_PROFILES <settings-ca-profiles>`,
    but you can also create your own profile to create a different type of certificate. An instance of this
    class can be used to create a signed certificate based on the given CA::

        >>> from cryptography import x509
        >>> from cryptography.x509.oid import NameOID
        >>> Profile(  # doctest: +ELLIPSIS
        ...     name="example",
        ...     subject=x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "AT")]),
        ...     extensions={"ocsp_no_check": {}}
        ... )
        Profile(...)
    """

    name: str

    # Overwritten to provide the noted defaults.
    subject: NameModel | None = Field(default_factory=lambda: model_settings.CA_DEFAULT_SUBJECT, repr=False)
    expires: Annotated[PositiveTimedelta, DayValidator] = Field(
        default_factory=lambda: model_settings.CA_DEFAULT_EXPIRES, repr=False
    )

    def _get_extensions(self, extensions: ConfigurableExtensionDict) -> None:
        # pylint: disable-next=no-member  # issue with pylint
        for key, ext in self.extensions.items():
            oid = CERTIFICATE_EXTENSION_KEY_OIDS[key]
            if ext is None:
                extensions.pop(oid, None)
            else:
                extensions.setdefault(oid, ext.cryptography)

    def create_cert(  # noqa: PLR0913  # pylint: disable=too-many-locals
        self,
        ca: "CertificateAuthority",
        key_backend_options: BaseModel,
        csr: x509.CertificateSigningRequest,
        *,
        subject: x509.Name | None = None,
        not_after: datetime | timedelta | None = None,
        algorithm: SignatureHashAlgorithm | None = None,
        extensions: Iterable[ConfigurableExtension] | None = None,
        allow_unrecognized_extensions: bool = False,
        allow_empty_subject: bool = False,
        add_crl_url: bool | None = None,
        add_ocsp_url: bool | None = None,
        add_issuer_url: bool | None = None,
        add_issuer_alternative_name: bool | None = None,
    ) -> x509.Certificate:
        """Create a x509 certificate based on this profile, the passed CA and input parameters.

        This function is the core function used to create x509 certificates. In its simplest form, you only
        need to pass a ca, private key options, a CSR and a subject to get a valid certificate::

            >>> from cryptography import x509
            >>> from cryptography.x509.oid import NameOID
            >>> from django_ca.key_backends.storages.models import StoragesUsePrivateKeyOptions
            >>> subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'example.com')])
            >>> key_backend_options = StoragesUsePrivateKeyOptions(password=None)
            >>> profile = get_profile('webserver')
            >>> profile.create_cert(ca, key_backend_options, csr, subject=subject)  # doctest: +ELLIPSIS
            <Certificate(subject=<Name(...,CN=example.com)>, ...)>

        .. versionchanged:: 2.4.0

           The `allow_empty_subject` parameter was added.

        .. versionchanged:: 2.3.0

           The `expires` parameter was renamed to `not_after`.

        .. versionchanged:: 2.2.1

           The `allow_unrecognized_extensions` parameter was added.

        The function will add CRL, OCSP, Issuer and IssuerAlternativeName URLs based on the CA if the profile
        has the *add_crl_url*, *add_ocsp_url* and *add_issuer_url* and *add_issuer_alternative_name* values
        set. Parameters to this function with the same name allow you override this behavior.

        The function allows you to override profile values using the *expires* and *algorithm* values. You can
        pass additional *extensions* as a list, which will override any extensions from the profile, but the
        CA passed will append to these extensions unless the *add_...* values are ``False``.

        Parameters
        ----------
        ca : :py:class:`~django_ca.models.CertificateAuthority`
            The CA to sign the certificate with.
        key_backend_options : BaseModel
            Options required for using the private key of the certificate authority.
        csr : :py:class:`~cg:cryptography.x509.CertificateSigningRequest`
            The CSR for the certificate.
        subject : :py:class:`~cg:cryptography.x509.Name`, optional
            Subject for the certificate. The value will be merged with the subject of the profile. If not
            given, the certificate's subject will be identical to the subject from the profile.
        not_after : datetime or timedelta, optional
            Override when this certificate will expire.
        algorithm : :py:class:`~cg:cryptography.hazmat.primitives.hashes.HashAlgorithm`, optional
            Override the hash algorithm used when signing the certificate.
        extensions : list of :py:class:`~cg:cryptography.x509.Extension`
            List of additional extensions to set for the certificate. Note that values from the CA might
            update the passed extensions: For example, if you pass an
            :py:class:`~cg:cryptography.x509.IssuerAlternativeName` extension, *add_issuer_alternative_name*
            is ``True`` and the passed CA has an IssuerAlternativeName set, that value will be appended to the
            extension you pass here.
        allow_unrecognized_extensions : bool, optional
            Set to ``True`` to allow passing unrecognized extensions. The default is ``False``. Note that when
            setting this to ``True``, it is possible to pass almost any extension value without any sanity
            check, so you have to be extremely careful.
        allow_empty_subject : bool, optional
            Allow the certificate to contain no subject or Subject Alternative Name extension at all. By
            default, this method will raise an error if there is neither a common name in the certificate's
            subject nor a Subject Alternative Name extension.
        add_crl_url : bool, optional
            Override if any CRL URLs from the CA should be added to the CA. If not passed, the value set in
            the profile is used.
        add_ocsp_url : bool, optional
            Override if any OCSP URLs from the CA should be added to the CA. If not passed, the value set in
            the profile is used.
        add_issuer_url : bool, optional
            Override if any Issuer URLs from the CA should be added to the CA. If not passed, the value set in
            the profile is used.
        add_issuer_alternative_name : bool, optional
            Override if any IssuerAlternativeNames from the CA should be added to the CA. If not passed, the
            value set in the profile is used.

        Returns
        -------
        cryptography.x509.Certificate
            The signed certificate.
        """
        # Get overrides values from profile if not passed as parameter
        if add_crl_url is None:
            add_crl_url = self.add_crl_url
        if add_ocsp_url is None:
            add_ocsp_url = self.add_ocsp_url
        if add_issuer_url is None:
            add_issuer_url = self.add_issuer_url
        if add_issuer_alternative_name is None:
            add_issuer_alternative_name = self.add_issuer_alternative_name

        if extensions is None:
            configurable_cert_extensions: ConfigurableExtensionDict = {}
        else:
            # Ensure that the function did *not* get any extension not meant to be in a certificate or that
            # should not be configurable by the user.
            for extension in extensions:
                # Allow clients to pass unrecognized extensions.
                if allow_unrecognized_extensions is True and isinstance(
                    extension.value, x509.UnrecognizedExtension
                ):
                    continue

                if extension.oid not in constants.CONFIGURABLE_EXTENSION_KEYS:
                    raise ValueError(f"{extension}: Extension cannot be set when creating a certificate.")

            configurable_cert_extensions = {ext.oid: ext for ext in extensions}

        # Get extensions from profile
        self._get_extensions(configurable_cert_extensions)

        if self.subject is not None:
            if subject is not None:
                # pylint: disable-next=no-member  # issue with pylint
                subject = merge_x509_names(self.subject.cryptography, subject)
            else:
                # pylint: disable-next=no-member  # issue with pylint
                subject = self.subject.cryptography

        # Add first DNSName/IPAddress from subjectAlternativeName as commonName if not present in the subject
        subject = self._update_cn_from_san(subject, configurable_cert_extensions)

        if subject is None:
            raise ValueError("Cannot determine subject for certificate.")

        if algorithm is None and ca.algorithm:
            if self.algorithm is not None:
                algorithm = constants.SIGNATURE_HASH_ALGORITHM_TYPES[self.algorithm]()
            else:
                algorithm = ca.algorithm

        # Make sure that expires is a fixed timestamp
        now = datetime.now(tz=UTC).replace(second=0, microsecond=0)
        if isinstance(not_after, timedelta):
            not_after = now + not_after
        elif not_after is None:
            not_after = now + self.expires
        # else: it's a datetime

        if (
            allow_empty_subject is False
            and not subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            and not configurable_cert_extensions.get(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        ):
            raise ValueError("Must name at least a CN or a subjectAlternativeName.")

        public_key = cast(CertificateIssuerPublicKeyTypes, csr.public_key())
        # COVERAGE NOTE: unable to create CSR other types
        if not isinstance(public_key, constants.PUBLIC_KEY_TYPES):  # pragma: no cover
            raise ValueError(f"{public_key}: Unsupported public key type.")

        self._update_from_ca(
            ca,
            configurable_cert_extensions,
            add_crl_url=add_crl_url,
            add_ocsp_url=add_ocsp_url,
            add_issuer_url=add_issuer_url,
            add_issuer_alternative_name=add_issuer_alternative_name,
        )

        serial = x509.random_serial_number()
        signer_serial = ca.pub.loaded.serial_number
        context = self._get_formatting_context(serial, signer_serial)
        format_extensions(configurable_cert_extensions, context)

        # Add mandatory end-entity certificate extensions
        certificate_extensions = ca.get_end_entity_certificate_extensions(public_key) + list(
            configurable_cert_extensions.values()
        )

        pre_sign_cert.send(
            sender=self.__class__,
            ca=ca,
            csr=csr,
            not_after=not_after,
            algorithm=algorithm,
            subject=subject,
            extensions=certificate_extensions,
            password=key_backend_options,
        )

        return ca.key_backend.sign_certificate(
            ca,
            key_backend_options,
            public_key,
            serial=serial,
            algorithm=algorithm,
            issuer=ca.subject,
            subject=subject,
            not_after=not_after,
            extensions=certificate_extensions,
        )

    def _get_formatting_context(self, serial: int, signer_serial: int) -> dict[str, str | int]:
        context = get_formatting_context(serial, signer_serial)
        kwargs = {"serial": context["SIGNER_SERIAL_HEX"]}
        context["OCSP_PATH"] = reverse("django_ca:ocsp-cert-post", kwargs=kwargs).lstrip("/")
        context["CRL_PATH"] = reverse("django_ca:crl", kwargs=kwargs).lstrip("/")
        return context

    def _update_authority_information_access(
        self,
        extensions: ConfigurableExtensionDict,
        ca_extensions: ConfigurableExtensionDict,
        add_issuer_url: bool,
        add_ocsp_url: bool,
    ) -> None:
        oid = ExtensionOID.AUTHORITY_INFORMATION_ACCESS

        # If there is no extension from the CA there is nothing to merge.
        if oid not in ca_extensions:
            return
        ca_aia_ext = cast(x509.Extension[x509.AuthorityInformationAccess], ca_extensions[oid])
        critical = ca_aia_ext.critical

        has_issuer = has_ocsp = False
        access_descriptions: list[x509.AccessDescription] = []

        if oid in extensions:
            cert_aia_ext = cast(x509.Extension[x509.AuthorityInformationAccess], extensions[oid])
            access_descriptions = list(cert_aia_ext.value)
            has_ocsp = any(
                ad.access_method == AuthorityInformationAccessOID.OCSP for ad in access_descriptions
            )
            has_issuer = any(
                ad.access_method == AuthorityInformationAccessOID.CA_ISSUERS for ad in access_descriptions
            )
            critical = cert_aia_ext.critical

        if add_issuer_url is True and has_issuer is False:
            access_descriptions += [
                ad
                for ad in ca_aia_ext.value
                if ad not in access_descriptions
                and ad.access_method == AuthorityInformationAccessOID.CA_ISSUERS
            ]
        if add_ocsp_url is True and has_ocsp is False:
            access_descriptions += [
                ad
                for ad in ca_aia_ext.value
                if ad not in access_descriptions and ad.access_method == AuthorityInformationAccessOID.OCSP
            ]

        # Finally, sort by OID so that we have more predictable behavior
        access_descriptions = sorted(access_descriptions, key=lambda ad: ad.access_method.dotted_string)

        if access_descriptions:
            extensions[oid] = x509.Extension(
                oid=oid,
                critical=critical,
                value=x509.AuthorityInformationAccess(access_descriptions),
            )

    def _add_crl_distribution_points(
        self, extensions: ConfigurableExtensionDict, ca_extensions: ConfigurableExtensionDict
    ) -> None:
        """Add the CRLDistribution Points extension with the endpoint from the Certificate Authority."""
        if ExtensionOID.CRL_DISTRIBUTION_POINTS not in ca_extensions:
            return
        if ExtensionOID.CRL_DISTRIBUTION_POINTS in extensions:
            return
        extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS] = ca_extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS]

    def _update_issuer_alternative_name(
        self, extensions: ConfigurableExtensionDict, ca_extensions: ConfigurableExtensionDict
    ) -> None:
        oid = ExtensionOID.ISSUER_ALTERNATIVE_NAME
        if oid in ca_extensions and oid not in extensions:
            extensions[oid] = ca_extensions[oid]

    def _update_from_ca(
        self,
        ca: "CertificateAuthority",
        extensions: ConfigurableExtensionDict,
        add_crl_url: bool,
        add_ocsp_url: bool,
        add_issuer_url: bool,
        add_issuer_alternative_name: bool,
    ) -> None:
        """Update data from the given CA.

        * Sets the AuthorityKeyIdentifier extension
        * Sets the OCSP url if add_ocsp_url is True
        * Sets a CRL URL if add_crl_url is True
        * Adds an IssuerAlternativeName if add_issuer_alternative_name is True

        """
        ca_extensions = ca.extensions_for_certificate

        if add_crl_url is True:
            self._add_crl_distribution_points(extensions, ca_extensions)

        self._update_authority_information_access(
            extensions, ca_extensions, add_issuer_url=add_issuer_url, add_ocsp_url=add_ocsp_url
        )

        if add_issuer_alternative_name is not False:
            self._update_issuer_alternative_name(extensions, ca_extensions)

    def _update_cn_from_san(
        self, subject: x509.Name | None, extensions: ConfigurableExtensionDict
    ) -> x509.Name | None:
        # If we already have a common name, return the subject unchanged
        if subject is not None and subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            return subject

        if ExtensionOID.SUBJECT_ALTERNATIVE_NAME in extensions:
            san_ext = cast(
                x509.Extension[x509.SubjectAlternativeName], extensions[ExtensionOID.SUBJECT_ALTERNATIVE_NAME]
            )
            cn_types = (x509.DNSName, x509.IPAddress)
            common_name = next(
                (str(val.value) for val in san_ext.value if isinstance(val, cn_types)),
                None,
            )

            if common_name is not None:
                common_name_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

                if subject is None:  # pragma: no cover
                    return common_name_name
                return merge_x509_names(subject, common_name_name)

        return subject


def get_profile(name: str | None = None) -> Profile:
    """Get profile by the given name.

    Raises ``KeyError`` if the profile is not defined.

    Parameters
    ----------
    name : str, optional
        The name of the profile. If ``None``, the profile configured by
        :ref:`CA_DEFAULT_PROFILE <settings-ca-default-profile>` is used.
    """
    if name is None:
        name = model_settings.CA_DEFAULT_PROFILE

    profile_data = model_settings.CA_PROFILES[name].model_dump(exclude_unset=True)
    if profile_data.get("subject") is False:
        profile_data["subject"] = None
    return Profile.model_validate({**profile_data, "name": name})


class Profiles:
    """A profile handler similar to Django's CacheHandler."""

    def __init__(self) -> None:
        self._profiles = local()

    def __getitem__(self, name: str | None) -> Profile:
        if name is None:
            name = model_settings.CA_DEFAULT_PROFILE

        try:
            return cast(Profile, self._profiles.profiles[name])
        except AttributeError:
            self._profiles.profiles = {}
        except KeyError:
            pass

        self._profiles.profiles[name] = get_profile(name)
        return cast(Profile, self._profiles.profiles[name])

    def __iter__(self) -> Iterator[Profile]:
        for name in model_settings.CA_PROFILES:
            yield self[name]

    def _reset(self) -> None:
        self._profiles = local()


profiles = Profiles()


class DefaultProfileProxy:
    """Default profile proxy, similar to Django's DefaultCacheProxy.

    .. NOTE:: We don't implement setattr/delattr, because Profiles are supposed to be read-only anyway.
    """

    def __getattr__(self, name: str) -> Any:
        return getattr(profiles[model_settings.CA_DEFAULT_PROFILE], name)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DefaultProfileProxy | Profile):
            return False
        return profiles[model_settings.CA_DEFAULT_PROFILE] == other

    def __hash__(self) -> int:  # pragma: no cover
        return hash(id(self))

    def __repr__(self) -> str:
        return f"<DefaultProfile: {self.name}>"

    def __str__(self) -> str:
        return repr(self)


profile = DefaultProfileProxy()

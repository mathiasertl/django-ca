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

"""Django models for the django-ca application.

.. seealso:: https://docs.djangoproject.com/en/dev/topics/db/models/
"""

import hashlib
import json
import logging
import random
import re
import typing
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta, timezone as tz
from typing import Optional, cast

import josepy as jose
from acme import challenges, messages
from pydantic import BaseModel

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.padding import MGF1, PSS, AsymmetricPadding
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPublicKeyTypes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtensionOID, NameOID

from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.validators import MinValueValidator, RegexValidator, URLValidator
from django.db import models
from django.http import HttpRequest
from django.urls import reverse
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.utils.functional import cached_property, classproperty
from django.utils.translation import gettext_lazy as _

from django_ca import constants
from django_ca.acme.constants import BASE64_URL_ALPHABET, IdentifierType, Status
from django_ca.conf import CertificateRevocationListProfile, model_settings
from django_ca.constants import REVOCATION_REASONS, ReasonFlags
from django_ca.deprecation import RemovedInDjangoCA250Warning, deprecate_argument
from django_ca.extensions import get_extension_name
from django_ca.key_backends import KeyBackend, OCSPKeyBackend, key_backends, ocsp_key_backends
from django_ca.managers import (
    AcmeAccountManager,
    AcmeAuthorizationManager,
    AcmeCertificateManager,
    AcmeChallengeManager,
    AcmeOrderManager,
    CertificateAuthorityManager,
    CertificateManager,
    CertificateRevocationListManager,
)
from django_ca.modelfields import (
    AuthorityInformationAccessField,
    CertificateField,
    CertificatePoliciesField,
    CertificateSigningRequestField,
    CRLDistributionPointsField,
    IssuerAlternativeNameField,
    LazyCertificate,
)
from django_ca.openssh.extensions import SSH_HOST_CA, SSH_USER_CA
from django_ca.profiles import profiles
from django_ca.querysets import (
    AcmeAccountQuerySet,
    AcmeAuthorizationQuerySet,
    AcmeCertificateQuerySet,
    AcmeChallengeQuerySet,
    AcmeOrderQuerySet,
    CertificateAuthorityQuerySet,
    CertificateQuerySet,
    CertificateRevocationListQuerySet,
)
from django_ca.signals import post_revoke_cert, post_sign_cert, pre_revoke_cert, pre_sign_cert
from django_ca.typehints import (
    AllowedHashTypes,
    CertificateExtension,
    ConfigurableExtension,
    ConfigurableExtensionDict,
    EndEntityCertificateExtension,
    OCSPKeyBackendDict,
    ParsableKeyType,
)
from django_ca.utils import (
    bytes_to_hex,
    get_crl_cache_key,
    int_to_hex,
    validate_private_key_parameters,
    validate_public_key_parameters,
)

if typing.TYPE_CHECKING:
    from typing import Self  # added in Python 3.11

    from django_stubs_ext.db.models import manager

log = logging.getLogger(__name__)


def acme_slug() -> str:
    """Default function to get an ACME conforming slug."""
    return get_random_string(length=12)


def acme_order_expires() -> datetime:
    """Default function for the expiry of an ACME order."""
    return timezone.now() + model_settings.CA_ACME_ORDER_VALIDITY


def acme_token() -> str:
    """Generate an ACME token for this challenge.

    Note that currently all challenges have the same requirements on tokens, except for DNS challenges
    which seem to allow padding ("=") characters. We ignore the '=' for DNS challenges as our tokens are
    already longer then required.
    """
    return get_random_string(64, allowed_chars=BASE64_URL_ALPHABET)


def default_profile() -> str:
    """Return the default profile (used as default for model fields)."""
    return model_settings.CA_DEFAULT_PROFILE


def validate_past(value: datetime) -> None:
    """Validate that a given datetime is not in the future."""
    if value > timezone.now():
        raise ValidationError(_("Date must be in the past!"))


def pem_validator(value: str) -> None:
    """Validator that ensures a value is a valid PEM public certificate."""
    if not value.startswith("-----BEGIN PUBLIC KEY-----\n"):
        raise ValidationError(_("Not a valid PEM."))
    if not value.endswith("\n-----END PUBLIC KEY-----"):
        raise ValidationError(_("Not a valid PEM."))


def ocsp_key_backend_options_default() -> OCSPKeyBackendDict:
    """Default value for the `ocsp_key_backend` field."""
    return {
        "private_key": {},
        "certificate": {},
    }


class ReasonEncoder(json.JSONEncoder):
    """Encoder for revocation reasons."""

    def default(self, o: x509.ReasonFlags | Iterable[x509.ReasonFlags]) -> str | list[str]:
        if isinstance(o, Iterable):
            return sorted(elem.name for elem in o)
        # if isinstance(o, x509.ReasonFlags):
        #     return o.name
        raise TypeError(f"Object of type {o.__class__.__name__} is not serializable with this encoder.")


class ReasonDecoder(json.JSONDecoder):
    """Decoder for revocation reasons."""

    def decode(self, s: str) -> frozenset[x509.ReasonFlags]:  # type: ignore[override]  # _w is internal arg
        decoded: list[str] = super().decode(s)
        return frozenset(x509.ReasonFlags[elem] for elem in decoded)


class DjangoCAModel(models.Model):
    """Abstract base model for all django-ca models."""

    class Meta:
        abstract = True

    @classproperty
    def admin_add_url(cls) -> str:  # pylint: disable=no-self-argument; false positive
        """URL to add an instance in the admin interface."""
        return reverse(f"admin:{cls._meta.app_label}_{cls._meta.model_name}_add")

    @classproperty
    def admin_changelist_url(cls) -> str:  # pylint: disable=no-self-argument; false positive
        """Changelist URL in the admin interface for the model."""
        return reverse(f"admin:{cls._meta.app_label}_{cls._meta.model_name}_changelist")

    @property
    def admin_change_url(self) -> str:
        """Change URL in the admin interface for the model instance."""
        return reverse(f"admin:{self._meta.app_label}_{self._meta.model_name}_change", args=(self.pk,))


class Watcher(models.Model):
    """A watcher represents an email address that will receive notifications about expiring certificates."""

    name = models.CharField(max_length=64, blank=True, default="", verbose_name=_("CommonName"))
    mail = models.EmailField(verbose_name=_("E-Mail"), unique=True)

    if typing.TYPE_CHECKING:
        # Add typehints for relations, django-stubs has issues if the model defines a custom default manager.
        # See also: https://github.com/typeddjango/django-stubs/issues/1354
        certificates: "manager.RelatedManager[Certificate]"

    def __str__(self) -> str:
        if self.name:
            return f"{self.name} <{self.mail}>"
        return self.mail

    @classmethod
    def from_addr(cls, addr: str) -> "Self":
        """Class constructor that creates an instance from an email address."""
        name = ""
        match = re.match(r"(.*?)\s*<(.*)>", addr)
        if match is not None:
            name, addr = match.groups()

        try:
            watcher = cls.objects.get(mail=addr)
            if watcher.name != name:
                watcher.name = name
                watcher.save()
        except cls.DoesNotExist:
            watcher = cls(mail=addr, name=name)
            watcher.full_clean()
            watcher.save()

        return watcher


class X509CertMixin(DjangoCAModel):
    """Mixin class with common attributes for Certificates and Certificate Authorities."""

    # reasons are defined in http://www.ietf.org/rfc/rfc3280.txt
    REVOCATION_REASONS = REVOCATION_REASONS

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    not_before = models.DateTimeField(blank=False)
    not_after = models.DateTimeField(null=False, blank=False)

    pub = CertificateField(verbose_name=_("Public key"))
    cn = models.CharField(max_length=128, verbose_name=_("CommonName"))
    serial = models.CharField(max_length=64, unique=True, validators=[RegexValidator(r"^[1-9A-F][0-9A-F]*$")])

    # revocation information
    revoked = models.BooleanField(default=False)
    revoked_date = models.DateTimeField(
        null=True, blank=True, verbose_name=_("Revoked on"), validators=[validate_past]
    )
    revoked_reason = models.CharField(
        max_length=32,
        blank=True,
        default="",
        verbose_name=_("Reason for revocation"),
        choices=REVOCATION_REASONS,
    )
    compromised = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("Date of compromise"),
        validators=[validate_past],
        help_text=_("Optional: When this certificate was compromised. You can change this date later."),
    )

    _x509 = None

    class Meta:
        abstract = True

    ##########################
    # Certificate properties #
    ##########################
    # Properties here are shortcuts to properties of the loaded certificate.

    @property
    def algorithm(self) -> AllowedHashTypes | None:
        """A shortcut for :py:attr:`~cg:cryptography.x509.Certificate.signature_hash_algorithm`."""
        return typing.cast(AllowedHashTypes, self.pub.loaded.signature_hash_algorithm)

    @cached_property
    def extensions(self) -> dict[x509.ObjectIdentifier, CertificateExtension]:
        """All extensions of this certificate in a `dict`.

        The key is the OID for the respective extension, allowing easy to look up a particular extension.
        """
        return {e.oid: e for e in self.pub.loaded.extensions}

    @cached_property
    def sorted_extensions(self) -> list[CertificateExtension]:
        """List of extensions sorted by their human-readable name.

        This property is used for display purposes, where a reproducible output is desired.
        """
        return list(sorted(self.pub.loaded.extensions, key=lambda e: get_extension_name(e.oid)))

    @property
    def issuer(self) -> x509.Name:
        """The certificate issuer field as :py:class:`~cg:cryptography.x509.Name`."""
        return self.pub.loaded.issuer

    @property
    def subject(self) -> x509.Name:
        """The certificate subject field as :py:class:`~cg:cryptography.x509.Name`."""
        return self.pub.loaded.subject

    ####################
    # Other properties #
    ####################
    @property
    def bundle_as_pem(self) -> str:
        """Get the bundle as PEM."""
        # TYPE NOTE: bundle is defined in base class but returns a list (considered invariant by mypy). This
        #            means that an abstract "bundle" property here could not be correctly typed.
        return "".join(c.pub.pem for c in self.bundle)  # type:  ignore[attr-defined]

    @property
    def jwk(self) -> jose.jwk.JWKRSA | jose.jwk.JWKEC:
        """Get a JOSE JWK public key for this certificate.

        .. NOTE::

           josepy (the underlying library) does not currently support loading Ed448 or Ed25519 public keys.
           This property will raise `ValueError` if called for a public key based on those algorithms. The
           issue is addressed in `this pull request <https://github.com/certbot/josepy/pull/98>`_.
        """
        public_key = self.pub.loaded.public_key()

        try:
            jwk = jose.jwk.JWK.load(public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))
        except jose.errors.Error as ex:
            raise ValueError(*ex.args) from ex

        # JWK.load() may return a private key instead, so we rule this out here for type safety. This branch
        # should normally not happen.
        if not isinstance(jwk, jose.jwk.JWKRSA | jose.jwk.JWKEC):  # pragma: no cover
            raise TypeError(f"Loading JWK RSA key returned {type(jwk)}.")
        return jwk

    def get_revocation_reason(self) -> x509.ReasonFlags | None:
        """Get the revocation reason of this certificate."""
        if self.revoked is False:
            return None

        return x509.ReasonFlags[self.revoked_reason]

    def get_compromised_time(self) -> datetime | None:
        """Return when this certificate was compromised.

        Returns ``None`` if the time is not known **or** if the certificate is not revoked.
        """
        if self.revoked is False or self.compromised is None:
            return None

        if timezone.is_naive(self.compromised):
            # convert datetime object to UTC and make it naive
            return timezone.make_aware(self.compromised, timezone=tz.utc)

        return self.compromised

    def get_revocation_time(self) -> datetime | None:
        """Get the revocation time."""
        if self.revoked is False:
            return None

        revoked_date = self.revoked_date
        if revoked_date is None:
            log.warning("Inconsistent model state: revoked=True and revoked_date=None.")
            return None

        if timezone.is_naive(revoked_date):
            # convert datetime object to UTC and make it naive
            revoked_date = timezone.make_aware(revoked_date, timezone=tz.utc)

        return revoked_date.replace(microsecond=0)

    def update_certificate(self, value: x509.Certificate) -> None:
        """Update this instance with data from a :py:class:`cg:cryptography.x509.Certificate`.

        This function will also populate the `cn`, `serial, `not_after` and `not_before` fields.
        """
        self.pub = LazyCertificate(value)
        self.cn = next((attr.value for attr in value.subject if attr.oid == NameOID.COMMON_NAME), "")
        self.not_after = value.not_valid_after_utc
        self.not_before = value.not_valid_before_utc

        if settings.USE_TZ is False:
            self.not_after = timezone.make_naive(self.not_after, timezone=tz.utc)
            self.not_before = timezone.make_naive(self.not_before, timezone=tz.utc)

        self.serial = int_to_hex(value.serial_number)  # upper-cased by int_to_hex()

    def get_fingerprint(self, algorithm: hashes.HashAlgorithm) -> str:
        """Get the digest for a certificate as string, including colons."""
        return bytes_to_hex(self.pub.loaded.fingerprint(algorithm))

    def get_revocation(self) -> x509.RevokedCertificate:
        """Get the `RevokedCertificate` instance for this certificate for CRLs.

        This function is just a shortcut for
        :py:class:`~cg:cryptography.x509.RevokedCertificateBuilder`.

        .. seealso:: :py:class:`~cg:cryptography.x509.CertificateRevocationListBuilder`.

        Raises
        ------
        ValueError
            If the certificate is not revoked.

        Returns
        -------
        :py:class:`~cg:cryptography.x509.RevokedCertificate`
        """
        if self.revoked is False:
            raise ValueError("Certificate is not revoked.")
        if self.revoked_date is None:
            raise ValueError("Certificate has no revocation date")

        revoked_cert = (
            x509.RevokedCertificateBuilder()
            .serial_number(self.pub.loaded.serial_number)
            .revocation_date(self.revoked_date)
        )

        reason = self.get_revocation_reason()
        if reason != x509.ReasonFlags.unspecified and reason is not None:
            # RFC 5270, 5.3.1: "reason code CRL entry extension SHOULD be absent instead of using the
            # unspecified (0) reasonCode value"
            revoked_cert = revoked_cert.add_extension(x509.CRLReason(reason), critical=False)

        compromised = self.get_compromised_time()
        if compromised:
            # RFC 5280, 5.3.2 says that this extension MUST be non-critical
            revoked_cert = revoked_cert.add_extension(x509.InvalidityDate(compromised), critical=False)

        return revoked_cert.build()

    def revoke(
        self, reason: ReasonFlags = ReasonFlags.unspecified, compromised: datetime | None = None
    ) -> None:
        """Revoke the current certificate.

        This function emits the ``pre_revoke_cert`` and ``post_revoke_cert`` signals.

        Parameters
        ----------
        reason : :py:class:`~django_ca.constants.ReasonFlags`, optional
            The reason for revocation, defaults to ``ReasonFlags.unspecified``.
        compromised : datetime, optional
            When this certificate was compromised.
        """
        pre_revoke_cert.send(sender=self.__class__, cert=self, reason=reason)

        self.revoked = True
        self.revoked_date = timezone.now()
        self.revoked_reason = reason.name
        self.compromised = compromised
        self.save()

        post_revoke_cert.send(sender=self.__class__, cert=self)


class CertificateAuthority(X509CertMixin):  # type: ignore[django-manager-missing]
    """Model representing a x509 Certificate Authority."""

    DEFAULT_KEY_USAGE = x509.KeyUsage(
        key_cert_sign=True,
        crl_sign=True,
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        encipher_only=False,
        decipher_only=False,
    )

    objects: CertificateAuthorityManager = CertificateAuthorityManager.from_queryset(
        CertificateAuthorityQuerySet
    )()

    if typing.TYPE_CHECKING:
        # Add typehints for relations, django-stubs has issues if the model defines a custom default manager.
        # See also: https://github.com/typeddjango/django-stubs/issues/1354
        children: "CertificateAuthorityManager"
        certificate_set: "CertificateManager"
        acmeaccount_set: "manager.RelatedManager[AcmeAccount]"

    name = models.CharField(max_length=256, help_text=_("A human-readable name"), unique=True)
    enabled = models.BooleanField(default=True)
    parent = models.ForeignKey(
        "self", on_delete=models.SET_NULL, null=True, blank=True, related_name="children"
    )
    key_backend_alias = models.CharField(max_length=256, help_text=_("Backend to handle private keys."))
    key_backend_options = models.JSONField(default=dict, blank=True, help_text=_("Key backend options"))

    # various details used when signing certs
    sign_authority_information_access = AuthorityInformationAccessField(
        constants.EXTENSION_NAMES[ExtensionOID.AUTHORITY_INFORMATION_ACCESS],
        null=True,
        default=None,
        blank=True,
        help_text=_("Add a Authority  Information Access extension when signing certificates."),
    )
    sign_certificate_policies = CertificatePoliciesField(
        constants.EXTENSION_NAMES[ExtensionOID.CERTIFICATE_POLICIES],
        null=True,
        default=None,
        blank=True,
        help_text=_("Add a Certificate Policies extension when signing certificates."),
    )
    sign_crl_distribution_points = CRLDistributionPointsField(
        constants.EXTENSION_NAMES[ExtensionOID.CRL_DISTRIBUTION_POINTS],
        null=True,
        default=None,
        blank=True,
        help_text=_("Add a CRL Distribution Points extension when signing certificates."),
    )
    sign_issuer_alternative_name = IssuerAlternativeNameField(
        constants.EXTENSION_NAMES[ExtensionOID.ISSUER_ALTERNATIVE_NAME],
        null=True,
        default=None,
        blank=True,
        help_text=_("Add an Issuer Alternative Name extension when signing certificates."),
    )

    caa_identity = models.CharField(
        blank=True,
        max_length=32,
        verbose_name=_("CAA identity"),
        help_text=_("CAA identity for this CA (NOTE: Not currently used!)."),
    )
    website = models.URLField(blank=True, help_text=_("Website for your CA."))
    terms_of_service = models.URLField(
        blank=True, verbose_name="Terms of Service", help_text=_("URL to Terms of Service for this CA")
    )

    # OCSP configuration
    ocsp_key_backend_alias = models.CharField(
        max_length=256, help_text=_("Backend to handle private keys for OCSP responder certificates.")
    )
    ocsp_key_backend_options = models.JSONField(
        default=ocsp_key_backend_options_default,
        blank=True,
        help_text=_("Key backend options for using OCSP responder private keys."),
    )
    ocsp_responder_key_validity = models.PositiveSmallIntegerField(
        _("OCSP responder key validity"),
        default=3,
        validators=[MinValueValidator(1)],
        help_text=_("How long <strong>(in days)</strong> OCSP responder keys may be valid."),
    )
    ocsp_response_validity = models.PositiveIntegerField(
        _("OCSP response validity"),
        default=86400,
        validators=[MinValueValidator(600)],
        help_text=_(
            "How long <strong>(in seconds)</strong> OCSP responses may be considered valid by the client."
        ),
    )

    # ACMEv2 fields
    acme_enabled = models.BooleanField(
        default=False,
        verbose_name=_("Enable ACME"),
        help_text=_("Whether it is possible to use ACME for this CA."),
    )
    acme_registration = models.BooleanField(
        default=True,
        verbose_name=_("ACME account registration."),
        help_text=_("Allow ACME clients to register new accounts."),
    )
    acme_profile = models.CharField(
        blank=False,
        default=default_profile,
        max_length=32,
        verbose_name=_("Profile"),
        help_text=_("Profile used when generating ACME certificates."),
    )
    acme_requires_contact = models.BooleanField(
        default=True,
        verbose_name="Requires contact",
        help_text=_("If this CA requires a contact address during account registration."),
    )
    # CAA record and website are general fields

    # API fields
    api_enabled = models.BooleanField(
        default=False,
        verbose_name=_("Enable API"),
        help_text=_("Whether it is possible to use the API for this CA."),
    )

    _key_backend = None
    _ocsp_key_backend = None

    class Meta:
        verbose_name = _("Certificate Authority")
        verbose_name_plural = _("Certificate Authorities")

    def __str__(self) -> str:
        return self.name

    @property
    def key_backend(self) -> KeyBackend[BaseModel, BaseModel, BaseModel]:
        """The key backend that can be used to use the private key."""
        if self._key_backend is None:
            self._key_backend = key_backends[self.key_backend_alias]
        return self._key_backend

    @property
    def ocsp_key_backend(self) -> OCSPKeyBackend:
        """The key backend for the OCSP responder."""
        if self._ocsp_key_backend is None:
            self._ocsp_key_backend = ocsp_key_backends[self.ocsp_key_backend_alias]
        return self._ocsp_key_backend

    def is_usable(self, options: BaseModel | None = None) -> bool:
        """Shortcut determining if the certificate authority can be used for signing."""
        return self.key_backend.is_usable(self, options)

    def check_usable(self, options: BaseModel) -> None:
        """Shortcut determining if the key is usable and raise ValueError otherwise."""
        return self.key_backend.check_usable(self, options)

    @property
    def key_type(self) -> ParsableKeyType:
        """The type of key as a string, e.g. "RSA" or "Ed448"."""
        pub = self.pub.loaded.public_key()
        if isinstance(pub, dsa.DSAPublicKey):
            return "DSA"
        if isinstance(pub, rsa.RSAPublicKey):
            return "RSA"
        if isinstance(pub, ec.EllipticCurvePublicKey):
            return "EC"
        if isinstance(pub, ed25519.Ed25519PublicKey):
            return "Ed25519"
        if isinstance(pub, ed448.Ed448PublicKey):
            return "Ed448"
        raise ValueError(f"{pub}: Unknown key type.")  # pragma: no cover

    def cache_crls(self, key_backend_options: BaseModel) -> None:
        """Function to cache all CRLs for this CA.

        .. versionchanged:: 1.25.0

           Support for passing a custom hash algorithm to this function was removed.
        """
        for crl_profile in model_settings.CA_CRL_PROFILES.values():
            now = datetime.now(tz=tz.utc)

            # If there is an override for the current CA, create a new profile model with values updated from
            # the override.
            if crl_profile_override := crl_profile.OVERRIDES.get(self.serial):
                if crl_profile_override.skip:
                    continue

                config = crl_profile.model_dump(exclude_unset=True)
                config.update(crl_profile_override.model_dump(exclude_unset=True))
                crl_profile = CertificateRevocationListProfile.model_validate(config)

            crl = CertificateRevocationList.objects.create_certificate_revocation_list(
                ca=self,
                key_backend_options=key_backend_options,
                next_update=now + crl_profile.expires,
                only_contains_ca_certs=crl_profile.only_contains_ca_certs,
                only_contains_user_certs=crl_profile.only_contains_user_certs,
                only_contains_attribute_certs=crl_profile.only_contains_attribute_certs,
                only_some_reasons=crl_profile.only_some_reasons,
            )
            crl.cache()

    def get_end_entity_certificate_extensions(
        self, public_key: CertificateIssuerPublicKeyTypes
    ) -> list[EndEntityCertificateExtension]:
        """Get extensions that are unconditionally added to every end entity certificates."""
        return [
            self.get_authority_key_identifier_extension(),
            x509.Extension(
                oid=ExtensionOID.BASIC_CONSTRAINTS,
                critical=True,
                value=x509.BasicConstraints(ca=False, path_length=None),
            ),
            x509.Extension(
                oid=ExtensionOID.SUBJECT_KEY_IDENTIFIER,
                value=x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False,  # MUST be non-critical (RFC 5280, section 4.2.1.2)
            ),
        ]

    @property
    def extensions_for_certificate(self) -> ConfigurableExtensionDict:
        """Get a list of extensions to use for the certificate."""
        extensions: ConfigurableExtensionDict = {}

        if self.sign_authority_information_access is not None:
            extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS] = self.sign_authority_information_access
        if self.sign_certificate_policies is not None:
            extensions[ExtensionOID.CERTIFICATE_POLICIES] = self.sign_certificate_policies
        if self.sign_crl_distribution_points is not None:
            extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS] = self.sign_crl_distribution_points
        if self.sign_issuer_alternative_name:
            extensions[ExtensionOID.ISSUER_ALTERNATIVE_NAME] = self.sign_issuer_alternative_name

        return extensions

    def sign(
        self,
        key_backend_options: BaseModel,
        csr: x509.CertificateSigningRequest,
        subject: x509.Name,
        algorithm: AllowedHashTypes | None = None,
        not_after: datetime | None = None,
        extensions: list[ConfigurableExtension] | None = None,
    ) -> x509.Certificate:
        """Create a signed certificate.

        This function is a low-level signing function, with optional values taken from the configuration.

        Required extensions are added if not provided. Unless already included in `extensions`, this function
        will add the AuthorityKeyIdentifier, BasicConstraints and SubjectKeyIdentifier extensions with values
        coming from the certificate authority.

        .. deprecated:: 2.1.0

           The ``expires`` parameter is deprecated and will be removed in django-ca 2.3.0. use ``not_after``
           instead.

        Parameters
        ----------
        key_backend_options : BaseModel
            Options required for using the private key of the certificate authority.
        csr : :py:class:`~cg:cryptography.x509.CertificateSigningRequest`
            The certificate signing request to sign.
        subject : :class:`~cg:cryptography.x509.Name`
            Subject for the certificate
        algorithm : :class:`~cg:cryptography.hazmat.primitives.hashes.HashAlgorithm`, optional
            Hash algorithm used for signing the certificate, defaults to the algorithm used in the CA.
        not_after : datetime, optional
            When the certificate expires. If not provided, the ``CA_DEFAULT_EXPIRES`` setting will be used.
        extensions : list of :py:class:`~cg:cryptography.x509.Extension`, optional
            List of extensions to add to the certificates. The function will add some extensions unless
            provided here, see above for details.
        """
        if algorithm is None:
            algorithm = self.algorithm

        if not_after is None:
            not_after = timezone.now() + model_settings.CA_DEFAULT_EXPIRES
            not_after = not_after.replace(second=0, microsecond=0)
        if extensions is None:
            extensions = []

        # Ensure that parameters used to generate the public key are valid.
        algorithm = validate_public_key_parameters(self.key_type, algorithm)

        # Ensure that the function did *not* get any extension not meant to be in a certificate or that should
        # not be configurable by the user.
        for extension in extensions:
            if extension.oid not in constants.CONFIGURABLE_EXTENSION_KEYS:
                raise ValueError(f"{extension}: Extension must not be provided by the end user.")

        # Load (and check) the public key
        public_key = typing.cast(CertificateIssuerPublicKeyTypes, csr.public_key())
        # COVERAGE NOTE: unable to create CSR other types
        if not isinstance(public_key, constants.PUBLIC_KEY_TYPES):  # pragma: no cover
            raise ValueError(f"{public_key}: Unsupported public key type.")

        # Add mandatory end-entity certificate extensions
        certificate_extensions = self.get_end_entity_certificate_extensions(public_key) + extensions

        pre_sign_cert.send(
            sender=self.__class__,
            ca=self,
            csr=csr,
            not_after=not_after,
            algorithm=algorithm,
            subject=subject,
            extensions=certificate_extensions,
            key_backend_options=key_backend_options,
        )

        signed_cert = self.key_backend.sign_certificate(
            self,
            key_backend_options,
            public_key,
            serial=x509.random_serial_number(),
            algorithm=algorithm,
            issuer=self.subject,
            subject=subject,
            not_after=not_after,
            extensions=certificate_extensions,
        )

        post_sign_cert.send(sender=self.__class__, ca=self, cert=signed_cert)

        return signed_cert

    def sign_data(
        self,
        data: bytes,
        key_backend_options: BaseModel | None = None,
        algorithm: hashes.HashAlgorithm | Prehashed | None = None,
        padding: AsymmetricPadding | None = None,
        signature_algorithm: ec.EllipticCurveSignatureAlgorithm | None = None,
    ) -> bytes:
        """Shortcut to sign data using this certificate authority with its key backend.

        All parameters except `data` will use sane default parameters, but they can be overridden in case you
        need to provide your own parameters for generating the signature.

        Error handling will depend on the key backend used by this certificate authority. For example, a key
        backend may not support signing data at all or may not support a specific signature algorithm.

        Parameters
        ----------
        data : bytes
            The data to sign.
        key_backend_options : BaseModel, optional
            Key backend options, by default a model for the respective key backend will be created without
            any parameters.
        algorithm : |HashAlgorithm| or |Prehashed|, optional
            The algorithm used for signing with RSA and DSA-based keys or |Prehashed| if `data` is already
            signed. The default is the algorithm is used for signing the CAs certificate.
        padding : |AsymmetricPadding|, optional
            The padding used for signing with RSA-based keys. The default is |PSS| padding using the maximum
            salt length and |MGF1| with the value of `algorithm` as its algorithm.
        signature_algorithm : |EllipticCurveSignatureAlgorithm|, optional
            The signature algorithm used for signing with Elliptic Curve based keys. The default is |ECDSA|
            with SHA512.
        """
        key_backend = self.key_backend
        if key_backend_options is None:
            key_backend_options = key_backend.get_use_private_key_options(self, {})

        key_type = self.key_type
        if key_type == "RSA":
            if algorithm is None:
                algorithm = cast(hashes.HashAlgorithm, self.algorithm)

            padding_algorithm = algorithm
            if padding is None:
                if isinstance(padding_algorithm, Prehashed):
                    # TYPEHINT NOTE: We know self.algorithm is not None for RSA keys
                    padding_algorithm = cast(hashes.HashAlgorithm, self.algorithm)

                padding = PSS(mgf=MGF1(padding_algorithm), salt_length=PSS.MAX_LENGTH)
        elif algorithm is None and key_type == "DSA":
            algorithm = self.algorithm
        elif signature_algorithm is None and key_type == "EC":
            signature_algorithm = ec.ECDSA(hashes.SHA512())

        return key_backend.sign_data(
            self,
            key_backend_options,
            data,
            algorithm=algorithm,
            padding=padding,
            signature_algorithm=signature_algorithm,
        )

    @deprecate_argument("key_type", RemovedInDjangoCA250Warning)
    @deprecate_argument("key_size", RemovedInDjangoCA250Warning)
    @deprecate_argument("elliptic_curve", RemovedInDjangoCA250Warning)
    @deprecate_argument("profile", RemovedInDjangoCA250Warning)
    @deprecate_argument("algorithm", RemovedInDjangoCA250Warning)
    @deprecate_argument("not_after", RemovedInDjangoCA250Warning)
    def generate_ocsp_key(
        self,
        key_backend_options: BaseModel,
        key_type: ParsableKeyType | None = None,
        key_size: int | None = None,
        elliptic_curve: ec.EllipticCurve | None = None,
        profile: str = "ocsp",
        algorithm: AllowedHashTypes | None = None,
        not_after: datetime | timedelta | None = None,
        autogenerated: bool = True,
        force: bool = False,
    ) -> Optional["Certificate"]:
        """Generate OCSP authorized responder certificate.

        This method is intended to be called by a regular, automated job to renew the CAs delegate
        certificates.

        The private key will use the same key type and key parameters as the CAs private key, and the signing
        algorithm will be the same as the one used in the CAs certificate. The subject will be the common name
        of the certificate authority with the suffix `OCSP responder delegate certificate` added, all other
        subject fields are discarded.

        RFC 6960 does not specify much about what a certificate for an authorized responder should look like.
        The default ``ocsp`` profile will create a valid certificate that is usable for all known
        applications, extend it to modify the certificate returned by this function.

        .. seealso::

            `RFC 6960: Online Certificate Status Protocol - OCSP <https://www.rfc-editor.org/rfc/rfc6960>`_

        .. deprecated:: 2.4.0

           The `key_type`, `key_size`, `elliptic_curve`, `profile`, `algorithm` and `not_after` arguments are
           deprecated and will be removed in ``django_ca~=2.4.0``.

        .. deprecated:: 2.1.0

           The ``expires`` parameter is deprecated and will be removed in django-ca 2.3.0. use ``not_after``
           instead.

        Parameters
        ----------
        key_backend_options : BaseModel
            Options required for using the private key of the certificate authority.
        autogenerated : bool, optional
            Set the ``autogenerated`` flag of the certificate. ``True`` by default, since this method is
            usually automatically invoked on a regular basis.
        force : bool, optional
            Set to ``True`` to force regeneration of keys. By default, keys are only regenerated if they
            expire within :ref:`CA_OCSP_RESPONDER_CERTIFICATE_RENEWAL
            <settings-ca-ocsp-responder-certificate-renewal>`.
        """
        if key_type is None:
            key_type = self.key_type
        if algorithm is None:
            algorithm = self.algorithm
        if key_type in ("DSA", "RSA") and key_size is None:
            key_size = self.ocsp_key_backend.get_default_key_size(self)
        if key_type == "EC" and elliptic_curve is None:
            elliptic_curve = self.ocsp_key_backend.get_default_elliptic_curve(self)

        # Ensure that parameters used to generate the private key are valid.
        key_size, elliptic_curve = validate_private_key_parameters(key_type, key_size, elliptic_curve)

        # Ensure that parameters used to generate the public key are valid. Note that we have to use the key
        # type of the **ca** private key (not the OCSP private key), as it is used for signing.
        algorithm = validate_public_key_parameters(self.key_type, algorithm)

        # prepare required keys in dict, so the backends can assume they're present
        self.ocsp_key_backend_options.setdefault("private_key", {})
        self.ocsp_key_backend_options.setdefault("certificate", {})

        now = datetime.now(tz=tz.utc)

        if force is False:
            try:
                responder_certificate_pem = self.ocsp_key_backend_options["certificate"]["pem"].encode()
            except KeyError:
                pass  # key was presumably never generated before
            except Exception:  # pragma: no cover  # pylint: disable=broad-exception-caught
                log.exception("Unknown error when reading existing OCSP responder certificate.")
            else:
                responder_certificate = x509.load_pem_x509_certificate(responder_certificate_pem)
                responder_certificate_expires = responder_certificate.not_valid_after_utc
                if responder_certificate_expires > now + model_settings.CA_OCSP_RESPONDER_CERTIFICATE_RENEWAL:
                    log.info("%s: OCSP responder certificate is not yet scheduled for renewal.")
                    return None

        if not_after is None:
            not_after = now + timedelta(days=self.ocsp_responder_key_validity)

        # Create the private key using the OCSP key backend.
        csr = self.ocsp_key_backend.create_private_key(self, key_type, key_size, elliptic_curve)

        cert = Certificate.objects.create_cert(
            ca=self,
            key_backend_options=key_backend_options,
            csr=csr,
            profile=profiles[profile],
            subject=x509.Name([x509.NameAttribute(oid=NameOID.COMMON_NAME, value="OCSP responder")]),
            algorithm=algorithm,
            autogenerated=autogenerated,
            not_after=not_after,
            add_ocsp_url=False,
        )

        # Save any updates done by the OCSP key backend.
        self.ocsp_key_backend_options["certificate"]["pem"] = cert.pub.pem
        self.ocsp_key_backend_options["certificate"]["pk"] = cert.pk  # just to make any debugging easier
        self.save()

        return cert

    def get_authority_key_identifier(self) -> x509.AuthorityKeyIdentifier:
        """Return the AuthorityKeyIdentifier extension used in certificates signed by this CA."""
        try:
            ski = self.pub.loaded.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        except x509.ExtensionNotFound as ex:
            public_key = typing.cast(CertificateIssuerPublicKeyTypes, self.pub.loaded.public_key())
            if not isinstance(public_key, constants.PUBLIC_KEY_TYPES):  # pragma: no cover
                # COVERAGE NOTE: This does not happen in reality, we never generate keys of this type
                raise TypeError("Cannot get AuthorityKeyIdentifier from this private key type.") from ex
            return x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key)
        return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski.value)

    def get_authority_key_identifier_extension(self) -> x509.Extension[x509.AuthorityKeyIdentifier]:
        """Get the AuthorityKeyIdentifier extension to use in certificates signed by this CA."""
        return x509.Extension(
            critical=False,
            oid=ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
            value=self.get_authority_key_identifier(),
        )

    @property
    def path_length(self) -> int | None:
        """The ``path_length`` attribute of the ``BasicConstraints`` extension."""
        try:
            ext = self.pub.loaded.extensions.get_extension_for_class(x509.BasicConstraints)
        except x509.ExtensionNotFound:  # pragma: no cover - extension should always be present
            return None
        return ext.value.path_length

    @property
    def max_path_length(self) -> int | None:
        """The maximum `path length` for any intermediate CAs signed by this CA.

        This value is either ``None``, if this and all parent CAs don't have a ``path_length`` attribute, or
        an ``int`` if any parent CA has the attribute.
        """
        if self.parent is None:
            return self.path_length

        max_parent = self.parent.max_path_length

        if max_parent is None:
            return self.path_length
        if self.path_length is None:
            return max_parent - 1

        return min(self.path_length, max_parent - 1)

    @property
    def allows_intermediate_ca(self) -> bool:
        """Whether this CA allows creating intermediate CAs."""
        max_path_length = self.max_path_length
        return max_path_length is None or max_path_length > 0

    @property
    def bundle(self) -> list["CertificateAuthority"]:
        """A list of any parent CAs, including this CA.

        The list is ordered so the Root CA will be the first.
        """
        ca = self
        bundle = [ca]

        while ca.parent is not None:
            bundle.append(ca.parent)
            ca = ca.parent
        return bundle

    @property
    def root(self) -> "CertificateAuthority":
        """Get the root CA for this CA."""
        if self.parent is None:
            return self

        ca = self
        while ca.parent is not None:
            ca = ca.parent
        return ca

    @property
    def usable(self) -> bool:
        """True if the CA is currently usable or not."""
        return self.enabled and self.not_before < timezone.now() < self.not_after

    @property
    def is_openssh_ca(self) -> bool:
        """True if this CA is an OpenSSH CA."""
        if SSH_HOST_CA in self.extensions:
            return True
        # COVERAGE NOTE: currently both extensions are always present
        return SSH_USER_CA in self.extensions  # pragma: no cover


class Certificate(X509CertMixin):
    """Model representing a x509 Certificate."""

    objects: CertificateManager = CertificateManager.from_queryset(CertificateQuerySet)()

    watchers = models.ManyToManyField(Watcher, related_name="certificates", blank=True)

    ca = models.ForeignKey(
        CertificateAuthority, on_delete=models.CASCADE, verbose_name=_("Certificate Authority")
    )
    # TYPEHINT NOTE: nullable field confuses django-stubs
    csr = CertificateSigningRequestField(verbose_name=_("CSR"), blank=True, null=True)  # type: ignore[misc]

    # Note: We don't set choices here because the available profiles might be changed by the user.
    profile = models.CharField(
        blank=True,
        default="",
        max_length=32,
        help_text=_("Profile that was used to generate this certificate."),
    )

    autogenerated = models.BooleanField(
        default=False, help_text=_("If this certificate was automatically generated.")
    )

    class Meta:
        permissions = (
            ("revoke_certificate", "Can revoke a certificate"),
            ("sign_certificate", "Can sign a certificate"),
        )

    def __str__(self) -> str:
        return self.cn

    @property
    def bundle(self) -> list[X509CertMixin]:
        """The complete certificate bundle. This includes all CAs as well as the certificates itself."""
        return [typing.cast(X509CertMixin, self), *typing.cast(list[X509CertMixin], self.ca.bundle)]

    @property
    def root(self) -> CertificateAuthority:
        """Get the root CA for this certificate."""
        return self.ca.root


class CertificateRevocationList(DjangoCAModel):
    """The `CertificateRevocationList` is used to store CRLs in the database.

    Only one of `only_contains_ca_certs`, `only_contains_ca_certs` and `only_contains_attribute_certs` can be
    ``True``.

    .. versionadded:: 2.1.0
    """

    #: Certificate Authority that the CRL is generated for.
    ca = models.ForeignKey(
        CertificateAuthority, on_delete=models.CASCADE, verbose_name=_("Certificate Authority")
    )
    #: CRL Number used in this CRL.
    number = models.PositiveIntegerField(
        db_index=True, help_text=_("Monotonically increasing number for the CRLNumber extension.")
    )
    #: When the CRL was generated.
    last_update = models.DateTimeField(help_text=_("The CRL's activation time."))
    #: When the CRL expires.
    next_update = models.DateTimeField(help_text=_("The CRL's next update time."))

    #: True if the CRL contains only CA certificates.
    only_contains_ca_certs = models.BooleanField(default=False)

    #: True if the CRL contains only end-entity certificates.
    only_contains_user_certs = models.BooleanField(default=False)

    #: True if the CRL contains only attribute certificates.
    only_contains_attribute_certs = models.BooleanField(default=False)

    #: Optional list of revocation reasons. If set, the CRL only contains certificates revoked for the given
    #: reasons.
    only_some_reasons = models.JSONField(
        null=True, default=None, encoder=ReasonEncoder, decoder=ReasonDecoder
    )

    #: The DER-encoded binary data of the CRL.
    data = models.BinaryField(null=True)

    objects: CertificateRevocationListManager = CertificateRevocationListManager.from_queryset(
        CertificateRevocationListQuerySet
    )()

    class Meta:
        indexes = (
            # Index to speed-up lookups of the most recent CRL with the given scope.
            models.Index(
                fields=[
                    "ca",
                    "number",
                    "only_contains_user_certs",
                    "only_contains_ca_certs",
                    "only_contains_attribute_certs",
                ]
            ),
        )

    def __str__(self) -> str:
        return f"{self.number} (next update: {self.next_update})"

    @cached_property
    def loaded(self) -> x509.CertificateRevocationList:
        """The CRL loaded into a :class:`cg:cryptography.x509.CertificateRevocationList` object."""
        if self.data is None:
            raise ValueError("CRL is not yet generated for this object.")
        return x509.load_der_x509_crl(bytes(self.data))

    @cached_property
    def pem(self) -> bytes:
        """The CRL encoded in PEM format."""
        return self.loaded.public_bytes(Encoding.PEM)

    def _cache_data(self, serial: str | None = None) -> Iterator[tuple[str, bytes, int]]:
        if self.data is None:
            raise ValueError("CRL is not yet generated for this object.")

        now = datetime.now(tz=tz.utc)
        if self.loaded.next_update_utc is not None:
            expires_seconds = int((self.loaded.next_update_utc - now).total_seconds())
        else:  # pragma: no cover  # we never generate CRLs without a next_update flag.
            expires_seconds = 86400

        if serial is None:
            serial = self.ca.serial

        for encoding in [Encoding.PEM, Encoding.DER]:
            cache_key = get_crl_cache_key(
                serial=serial,
                encoding=encoding,
                only_contains_ca_certs=self.only_contains_ca_certs,
                only_contains_user_certs=self.only_contains_user_certs,
                only_contains_attribute_certs=self.only_contains_attribute_certs,
                only_some_reasons=self.only_some_reasons,
            )

            if expires_seconds >= 600:  # pragma: no branch
                # for longer expiries we subtract a random value so that regular CRL regeneration is
                # distributed a bit
                expires_seconds -= random.randint(1, 5) * 60

            if encoding == Encoding.PEM:
                encoded_crl = self.pem
            else:
                encoded_crl = bytes(self.data)

            yield cache_key, encoded_crl, expires_seconds

    def cache(self, serial: str | None = None) -> None:
        """Cache this instance.

        If `serial` is not given, `self.ca` will be accessed (possibly triggering a database query) to
        generate the cache keys.
        """
        for cache_key, encoded_crl, expires_seconds in self._cache_data(serial):
            cache.set(cache_key, encoded_crl, expires_seconds)


class CertificateOrder(DjangoCAModel):
    """An order for a certificate that is issued asynchronously (usually via the API)."""

    STATUS_PENDING = "pending"
    STATUS_ISSUED = "issued"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = (
        (STATUS_PENDING, _("Choices")),
        (STATUS_FAILED, _("Failed")),
        (STATUS_ISSUED, _("Issued")),
    )

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    certificate_authority = models.ForeignKey(
        CertificateAuthority, on_delete=models.CASCADE, related_name="orders"
    )
    certificate = models.OneToOneField(
        Certificate,
        on_delete=models.CASCADE,
        null=True,
        related_name="order",
        help_text=_("Certificate issued for this order."),
    )
    slug = models.SlugField(unique=True, default=acme_slug, help_text=_("Slug identifying the order."))
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, help_text=_("User used for creating the order.")
    )
    status = models.CharField(
        max_length=8,
        choices=STATUS_CHOICES,
        default=STATUS_PENDING,
        help_text=_("Current status of the order."),
    )
    error_code = models.PositiveSmallIntegerField(
        null=True, blank=True, help_text=_("Machine readable error code.")
    )
    error = models.CharField(blank=True, max_length=256, help_text=_("Human readable error message."))

    def __str__(self) -> str:  # pragma: no cover
        return f"{self.slug} ({self.get_status_display()})"


class AcmeAccount(DjangoCAModel):
    """Implements an ACME account object.

    .. seealso::

        `RFC 8555, 7.1.2 <https://tools.ietf.org/html/rfc8555#section-7.1.2>`_
    """

    # RFC 8555, 7.1.2: "Possible values are "valid", "deactivated", and "revoked"."
    STATUS_VALID = Status.VALID.value
    STATUS_DEACTIVATED = Status.DEACTIVATED.value  # deactivated by user
    STATUS_REVOKED = Status.REVOKED.value  # revoked by server
    STATUS_CHOICES = (
        (STATUS_VALID, _("Valid")),
        (STATUS_DEACTIVATED, _("Deactivated")),
        (STATUS_REVOKED, _("Revoked")),
    )

    objects: AcmeAccountManager = AcmeAccountManager.from_queryset(AcmeAccountQuerySet)()

    # Account meta data
    created = models.DateTimeField(default=timezone.now)
    updated = models.DateTimeField(auto_now=True)

    # Account information
    ca = models.ForeignKey(
        CertificateAuthority, on_delete=models.CASCADE, verbose_name=_("Certificate Authority")
    )
    # Full public key of the account
    # NOTE: Do not make PEM unique, it's incompatible with MySQL.
    pem = models.TextField(verbose_name=_("Public key"), blank=False, validators=[pem_validator])
    # JSON Web Key thumbprint - a hash of the public key, see RFC 7638.
    #   NOTE: Only unique for the given CA to make hash collisions less likely
    thumbprint = models.CharField(max_length=64, unique=True)
    slug = models.SlugField(unique=True, default=acme_slug)
    kid = models.URLField(
        unique=True, validators=[URLValidator(schemes=("http", "https"))], verbose_name=_("Key ID")
    )

    # Fields according to RFC 8555, 7.1.2
    # RFC 8555, 7.1.6: "Account objects are created in the "valid" state"
    status = models.CharField(choices=STATUS_CHOICES, max_length=12, default=STATUS_VALID)
    contact = models.TextField(blank=True, help_text=_("Contact addresses for this account, one per line."))
    terms_of_service_agreed = models.BooleanField(default=False)
    # NOTE: externalAccountBinding is not yet supported
    # NOTE: orders property is provided by reverse relation of the AcmeOrder model

    class Meta:
        verbose_name = _("ACME Account")
        verbose_name_plural = _("ACME Accounts")
        unique_together = (("ca", "thumbprint"),)

    def __str__(self) -> str:
        try:
            return self.contact.split("\n", maxsplit=1)[0].split(":", 1)[1]
        except IndexError:
            return ""

    @property
    def serial(self) -> str:
        """Serial of the CA for this account."""
        return self.ca.serial

    def set_kid(self, request: HttpRequest) -> None:
        """Set the ACME kid based on this accounts CA and slug.

        Note that `slug` and `ca` must be already set when using this method.
        """
        self.kid = request.build_absolute_uri(
            reverse("django_ca:acme-account", kwargs={"slug": self.slug, "serial": self.ca.serial})
        )

    @property
    def usable(self) -> bool:
        """Boolean if the account is currently usable.

        An account is usable if the terms of service have been agreed, the status is "valid" and the
        associated CA is usable.
        """
        tos_agreed = self.terms_of_service_agreed

        # If the CA does not have any terms of service, the client does not need to agree to them to be
        # usable. Some clients (certbot/acme after 1.29.0 and before 2.0.0) never send that they "agree" to
        # the terms of service if the directory endpoint does send a termsOfService element. The registration
        # endpoint sets self.terms_of_service_agreed to False in this case.
        if not self.ca.terms_of_service:
            tos_agreed = True

        return tos_agreed and self.status == AcmeAccount.STATUS_VALID and self.ca.usable


class AcmeOrder(DjangoCAModel):  # type: ignore[django-manager-missing]
    """Implements an ACME order object.

    .. seealso::

        `RFC 8555, 7.1.3 <https://tools.ietf.org/html/rfc8555#section-7.1.3>`_
    """

    # RFC 8555, 7.1.3: "Possible values are "pending", "ready", "processing", "valid", and "invalid"."
    STATUS_PENDING = Status.PENDING.value
    STATUS_READY = Status.READY.value
    STATUS_PROCESSING = Status.PROCESSING.value
    STATUS_VALID = Status.VALID.value
    STATUS_INVALID = Status.INVALID.value

    STATUS_CHOICES = (
        (STATUS_INVALID, _("Invalid")),
        (STATUS_PENDING, _("Pending")),
        (STATUS_PROCESSING, _("Processing")),
        (STATUS_READY, _("Ready")),
        (STATUS_VALID, _("Valid")),
    )

    account = models.ForeignKey(AcmeAccount, on_delete=models.CASCADE, related_name="orders")
    slug = models.SlugField(unique=True, default=acme_slug)

    # Fields according to RFC 8555, 7.1.3
    # RFC 8555, 7.1.6: "Order objects are created in the "pending" state."
    status = models.CharField(choices=STATUS_CHOICES, max_length=10, default=STATUS_PENDING)
    expires = models.DateTimeField(default=acme_order_expires)
    # NOTE: identifiers property is provided by reverse relation of the AcmeAuthorization model
    not_before = models.DateTimeField(null=True)
    not_after = models.DateTimeField(null=True)
    # NOTE: error property is not yet supported
    # NOTE: authorizations property is provided by reverse relation of the AcmeAuthorization model
    # NOTE: finalize property is provided by acme_finalize_url property
    # NOTE: certificate property is provided by reverse relation of the AcmeCertificate model

    objects = AcmeOrderManager.from_queryset(AcmeOrderQuerySet)()

    if typing.TYPE_CHECKING:
        # Add typehints for relations, django-stubs has issues if the model defines a custom default manager.
        # See also: https://github.com/typeddjango/django-stubs/issues/1354
        authorizations: "manager.RelatedManager[AcmeAuthorization]"

    class Meta:
        verbose_name = _("ACME Order")
        verbose_name_plural = _("ACME Orders")

    def __str__(self) -> str:
        return f"{self.slug} ({self.account})"

    @property
    def acme_url(self) -> str:
        """Get the ACME URL path for this order."""
        return reverse("django_ca:acme-order", kwargs={"slug": self.slug, "serial": self.serial})

    @property
    def acme_finalize_url(self) -> str:
        """Get the ACME "finalize" URL path for this order."""
        return reverse("django_ca:acme-order-finalize", kwargs={"slug": self.slug, "serial": self.serial})

    def add_authorizations(self, identifiers: Iterable["messages.Identifier"]) -> list["AcmeAuthorization"]:
        """Add :py:class:`~django_ca.models.AcmeAuthorization` instances for the given identifiers.

        Note that this method already adds the account authorization to the database. It does not verify if it
        already exists and will raise an IntegrityError if it does.

        Example::

            >>> from acme import messages
            >>> identifier = messages.Identifier(typ=messages.IDENTIFIER_FQDN, value='example.com')
            >>> order.add_authorizations([identifier])  # doctest: +SKIP

        Parameters
        ----------
        identifiers : list of :py:class:`acme:acme.messages.Identifier`
            The identifiers for this order.

        Returns
        -------
        list of :py:class:`~django_ca.models.AcmeAuthorization`
        """
        return self.authorizations.bulk_create(
            [AcmeAuthorization(type=ident.typ.name, value=ident.value, order=self) for ident in identifiers]
        )

    @property
    def serial(self) -> str:
        """Serial of the CA for this order."""
        return self.account.serial

    @property
    def usable(self) -> bool:
        """Boolean defining if an order is "usable", meaning it can be used to issue a certificate.

        An order is usable if it is in the "pending" status, has not expired and the account is usable.
        """
        return (
            self.status == AcmeOrder.STATUS_PENDING and self.expires > timezone.now() and self.account.usable
        )


class AcmeAuthorization(DjangoCAModel):
    """Implements an ACME authorization object.

    .. seealso::

        `RFC 8555, 7.1.4 <https://tools.ietf.org/html/rfc8555#section-7.1.4>`_
    """

    # Choices from RFC 8555, section 9.7.7.
    # TODO: acme.messages defines an "ip" identifier, present in acme >= 1.19.0
    TYPE_DNS = IdentifierType.DNS.value
    TYPE_CHOICES = ((TYPE_DNS, _("DNS")),)

    # RFC 8555, 7.1.4: "Possible values are "pending", "valid", "invalid", "deactivated", "expired", and
    #                   "revoked"."
    STATUS_PENDING = Status.PENDING.value
    STATUS_VALID = Status.VALID.value
    STATUS_INVALID = Status.INVALID.value
    STATUS_DEACTIVATED = Status.DEACTIVATED.value
    STATUS_EXPIRED = Status.EXPIRED.value
    STATUS_REVOKED = Status.REVOKED.value
    STATUS_CHOICES = (
        (STATUS_PENDING, _("Pending")),
        (STATUS_VALID, _("Valid")),
        (STATUS_INVALID, _("Invalid")),
        (STATUS_DEACTIVATED, _("Deactivated")),
        (STATUS_EXPIRED, _("Expired")),
        (STATUS_REVOKED, _("Revoked")),
    )

    objects: AcmeAuthorizationManager = AcmeAuthorizationManager.from_queryset(AcmeAuthorizationQuerySet)()

    order = models.ForeignKey(AcmeOrder, on_delete=models.CASCADE, related_name="authorizations")
    slug = models.SlugField(unique=True, default=acme_slug)

    # Fields according to RFC 8555, 7.1.4:
    # NOTE: RFC 8555 does not specify a default value but DNS is the only known value
    type = models.CharField(choices=TYPE_CHOICES, max_length=8, default=TYPE_DNS)  # identifier
    value = models.CharField(max_length=255)  # identifier
    # RFC 8555, 7.1.6: "Authorization objects are created in the "pending" state."
    status = models.CharField(choices=STATUS_CHOICES, max_length=12, default=STATUS_PENDING)
    # NOTE: expires property comes from the linked order
    # NOTE: challenges property is provided by reverse relation of the AcmeChallenge model
    wildcard = models.BooleanField(default=False)

    class Meta:
        unique_together = (("order", "type", "value"),)
        verbose_name = _("ACME Authorization")
        verbose_name_plural = _("ACME Authorizations")

    def __str__(self) -> str:
        return f"{self.type}: {self.value}"

    @property
    def account(self) -> AcmeAccount:
        """Account that this authorization belongs to."""
        return self.order.account

    @property
    def acme_url(self) -> str:
        """Get the ACME URL path for this account authorization."""
        return reverse("django_ca:acme-authz", kwargs={"slug": self.slug, "serial": self.serial})

    @property
    def expires(self) -> datetime:
        """When this authorization expires."""
        return self.order.expires  # so far there is no reason to have a different value here

    @property
    def general_name(self) -> x509.GeneralName:
        """Get the :py:class:`~cg:cryptography.x509.GeneralName` instance for this instance."""
        if self.type == AcmeAuthorization.TYPE_DNS:
            return x509.DNSName(self.value)
        raise ValueError(f"{self.type}: Unsupported type.")  # pragma: no cover

    @property
    def identifier(self) -> "messages.Identifier":
        """Get ACME identifier for this object.

        Returns
        -------
        identifier : :py:class:`acme:acme.messages.Identifier`
        """
        if self.type == AcmeAuthorization.TYPE_DNS:
            return messages.Identifier(typ=messages.IDENTIFIER_FQDN, value=self.value)
        raise ValueError(f"Unknown identifier type: {self.type}")

    @property
    def serial(self) -> str:
        """Serial of the CA for this authorization."""
        return self.order.serial

    @property
    def subject_alternative_name(self) -> str:
        """Get the domain for this challenge as prefixed SubjectAlternativeName.

        This method is intended to be used when creating the ``django_ca.extensions.SubjectAlternativeName``
        extension for a certificate to be signed.
        """
        return f"{self.type}:{self.value}"

    def get_challenges(self) -> list["AcmeChallenge"]:
        """Get list of :py:class:`~django_ca.models.AcmeChallenge` objects for this authorization.

        Note that challenges will be created if they don't exist.
        """
        return [
            AcmeChallenge.objects.get_or_create(auth=self, type=AcmeChallenge.TYPE_HTTP_01)[0],
            # AcmeChallenge.objects.get_or_create(auth=self, type=AcmeChallenge.TYPE_TLS_ALPN_01)[0],
            AcmeChallenge.objects.get_or_create(auth=self, type=AcmeChallenge.TYPE_DNS_01)[0],
        ]

    @property
    def usable(self) -> bool:
        """Boolean defining if an authentication can still can be used in order validation.

        An order is usable if it is in the "pending" or "invalid" status, the order is usable. An
        authorization that is in the "invalid" status is eligible to be retried by the client.
        """
        states = (AcmeAuthorization.STATUS_PENDING, AcmeAuthorization.STATUS_INVALID)
        return self.status in states and self.order.usable


class AcmeChallenge(DjangoCAModel):
    """Implements an ACME Challenge Object.

    .. seealso:: `RFC 8555, section 7.1.5 <https://tools.ietf.org/html/rfc8555#section-7.1.5>`_
    """

    # Possible challenges
    TYPE_HTTP_01 = "http-01"
    TYPE_DNS_01 = "dns-01"
    TYPE_CHOICES = (
        (TYPE_HTTP_01, _("HTTP Challenge")),
        (TYPE_DNS_01, _("DNS Challenge")),
    )

    # RFC 8555, 8: "Possible values are "pending", "processing", "valid", and "invalid"."
    STATUS_PENDING = Status.PENDING.value
    STATUS_PROCESSING = Status.PROCESSING.value
    STATUS_VALID = Status.VALID.value
    STATUS_INVALID = Status.INVALID.value
    STATUS_CHOICES = (
        (STATUS_PENDING, _("Pending")),
        (STATUS_PROCESSING, _("Processing")),
        (STATUS_VALID, _("Valid")),
        (STATUS_INVALID, _("Name")),
    )

    auth = models.ForeignKey(AcmeAuthorization, on_delete=models.CASCADE, related_name="challenges")
    slug = models.SlugField(unique=True, default=acme_slug)

    # Fields according to RFC 8555, 8:
    type = models.CharField(choices=TYPE_CHOICES, max_length=12)
    # NOTE: url property is provided by the acme_url property and computed on the fly
    # RFC 8555, 7.1.6: "Challenge objects are created in the "pending" state."
    status = models.CharField(choices=STATUS_CHOICES, max_length=12, default=STATUS_PENDING)
    validated = models.DateTimeField(null=True, blank=True)
    error = models.CharField(blank=True, max_length=64)  # max_length is just a guess

    # The token field is listed for both HTTP and DNS challenge, which are the most common types, so we
    # include it as an optional field here. It is generated when the token is first accessed.
    token = models.CharField(blank=True, max_length=64, default=acme_token)

    objects = AcmeChallengeManager.from_queryset(AcmeChallengeQuerySet)()

    class Meta:
        unique_together = (("auth", "type"),)
        verbose_name = _("ACME Challenge")
        verbose_name_plural = _("ACME Challenges")

    def __str__(self) -> str:
        return f"{self.auth.value} ({self.type})"

    @property
    def account(self) -> AcmeAccount:
        """Account that this challenge belongs to."""
        return self.auth.account

    @property
    def acme_url(self) -> str:
        """Get the ACME URL path for this challenge."""
        return reverse("django_ca:acme-challenge", kwargs={"slug": self.slug, "serial": self.serial})

    @property
    def acme_challenge(self) -> "challenges.KeyAuthorizationChallenge":
        """Challenge as ACME challenge object.

        Returns
        -------
        :py:class:`acme:acme.challenges.Challenge`
            The acme representation of this class.
        """
        token = self.token.encode()
        if self.type == AcmeChallenge.TYPE_HTTP_01:
            return challenges.HTTP01(token=token)
        if self.type == AcmeChallenge.TYPE_DNS_01:  # pragma: no branch
            return challenges.DNS01(token=token)

        raise ValueError(f"{self.type}: Unsupported challenge type.")  # pragma: no cover

    @property
    def acme_validated(self) -> datetime | None:
        """Timestamp when this challenge was validated.

        This property is a wrapper around the `validated` field. It always returns `None` if the challenge is
        not marked as valid (even if it had a timestamp), and the timestamp will always have a timezone, even
        if ``USE_TZ=False``.
        """
        if self.status != AcmeChallenge.STATUS_VALID or self.validated is None:
            return None

        if timezone.is_naive(self.validated):
            return timezone.make_aware(self.validated, timezone=tz.utc)
        return self.validated

    @property
    def encoded_token(self) -> bytes:
        """Token in base64url encoded form."""
        return jose.b64.b64encode(self.token.encode("ascii"))

    @property
    def expected(self) -> bytes:
        """Expected value for the challenge based on its type."""
        thumbprint = self.account.thumbprint.encode("ascii")
        value = self.encoded_token + b"." + thumbprint

        if self.type == AcmeChallenge.TYPE_HTTP_01:
            return value
        if self.type == AcmeChallenge.TYPE_DNS_01:  # pragma: no branch
            return jose.b64.b64encode(hashlib.sha256(value).digest())
        raise ValueError(f"{self.type}: Unsupported challenge type.")  # pragma: no cover

    def get_challenge(self, request: HttpRequest) -> "messages.ChallengeBody":
        """Get the ACME challenge body for this challenge.

        Returns
        -------
        :py:class:`acme:acme.messages.ChallengeBody`
            The acme representation of this class.
        """
        url = request.build_absolute_uri(self.acme_url)

        # NOTE: RFC855, section 7.5 shows challenges *without* a status, but this object always includes it.
        #       It does not seem to hurt, but might be a slight spec-violation.
        return messages.ChallengeBody(
            chall=self.acme_challenge, _url=url, status=self.status, validated=self.acme_validated
        )

    @property
    def serial(self) -> str:
        """Serial of the CA for this challenge."""
        return self.auth.serial

    @property
    def usable(self) -> bool:
        """Boolean defining if a challenge is "usable", meaning it still can be used in order validation.

        A challenge is usable if it is in the "pending" or "invalid status and the authorization is usable.
        """
        states = (AcmeChallenge.STATUS_PENDING, AcmeChallenge.STATUS_INVALID)
        return self.status in states and self.auth.usable


class AcmeCertificate(DjangoCAModel):
    """Intermediate model for certificates to be issued via ACME."""

    slug = models.SlugField(unique=True, default=acme_slug)
    order = models.OneToOneField(AcmeOrder, on_delete=models.CASCADE)
    cert = models.OneToOneField(Certificate, on_delete=models.CASCADE, null=True)
    csr = models.TextField(verbose_name=_("CSR"))

    objects = AcmeCertificateManager.from_queryset(AcmeCertificateQuerySet)()

    class Meta:
        verbose_name = _("ACME Certificate")
        verbose_name_plural = _("ACME Certificate")

    def __str__(self) -> str:
        return f"{self.slug} ({self.order.get_status_display()})"

    @property
    def acme_url(self) -> str:
        """Get the ACME URL path for this certificate."""
        return reverse("django_ca:acme-cert", kwargs={"slug": self.slug, "serial": self.order.serial})

    def parse_csr(self) -> x509.CertificateSigningRequest:
        """Load the CSR into a cryptography object.

        Returns
        -------
        :py:class:`~cg:cryptography.x509.CertificateSigningRequest`
            The CSR as used by cryptography.
        """
        return x509.load_pem_x509_csr(self.csr.encode())

    @property
    def usable(self) -> bool:
        """Boolean defining if this instance is "usable", meaning we can use it to issue a certificate.

        An ACME certificate is considered usable if no actual certificate has yet been issued, the order is
        not expired and in the "processing" state.
        """
        return (
            self.cert is None
            and self.order.expires > timezone.now()
            and self.order.status == AcmeOrder.STATUS_PROCESSING
        )

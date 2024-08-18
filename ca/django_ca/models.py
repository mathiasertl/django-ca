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
import itertools
import json
import logging
import random
import re
import typing
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone as tz
from typing import Optional, Union

import josepy as jose
from acme import challenges, messages
from pydantic import BaseModel

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPublicKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat
from cryptography.x509.oid import ExtensionOID, NameOID

from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.core.files.storage import storages
from django.core.validators import MinValueValidator, URLValidator
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
from django_ca.extensions import get_extension_name
from django_ca.key_backends import KeyBackend, key_backends
from django_ca.managers import (
    AcmeAccountManager,
    AcmeAuthorizationManager,
    AcmeCertificateManager,
    AcmeChallengeManager,
    AcmeOrderManager,
    CertificateAuthorityManager,
    CertificateManager,
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
)
from django_ca.signals import post_revoke_cert, post_sign_cert, pre_revoke_cert, pre_sign_cert
from django_ca.typehints import (
    AllowedHashTypes,
    CertificateExtension,
    CertificateRevocationListScopes,
    ConfigurableExtension,
    ConfigurableExtensionDict,
    EndEntityCertificateExtension,
    ParsableKeyType,
)
from django_ca.utils import (
    bytes_to_hex,
    generate_private_key,
    get_crl_cache_key,
    int_to_hex,
    read_file,
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


def json_validator(value: Union[str, bytes, bytearray]) -> None:
    """Validated that the given data is valid JSON."""
    try:
        json.loads(value)
    except Exception as e:
        raise ValidationError(_("Must be valid JSON: %(message)s") % {"message": str(e)}) from e


def pem_validator(value: str) -> None:
    """Validator that ensures a value is a valid PEM public certificate."""
    if not value.startswith("-----BEGIN PUBLIC KEY-----\n"):
        raise ValidationError(_("Not a valid PEM."))
    if not value.endswith("\n-----END PUBLIC KEY-----"):
        raise ValidationError(_("Not a valid PEM."))


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

    valid_from = models.DateTimeField(blank=False)
    expires = models.DateTimeField(null=False, blank=False)

    pub = CertificateField(verbose_name=_("Public key"))
    cn = models.CharField(max_length=128, verbose_name=_("CommonName"))
    serial = models.CharField(max_length=64, unique=True)

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
    def algorithm(self) -> Optional[AllowedHashTypes]:
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
    def not_before(self) -> datetime:
        """A timezone-aware datetime representing the beginning of the validity period."""
        return self.pub.loaded.not_valid_before_utc

    @property
    def not_after(self) -> datetime:
        """A timezone-aware datetime representing the end of the validity period."""
        return self.pub.loaded.not_valid_after_utc

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
    def jwk(self) -> Union[jose.jwk.JWKRSA, jose.jwk.JWKEC]:
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
        if not isinstance(jwk, (jose.jwk.JWKRSA, jose.jwk.JWKEC)):  # pragma: no cover
            raise TypeError(f"Loading JWK RSA key returned {type(jwk)}.")
        return jwk

    def get_revocation_reason(self) -> Optional[x509.ReasonFlags]:
        """Get the revocation reason of this certificate."""
        if self.revoked is False:
            return None

        return x509.ReasonFlags[self.revoked_reason]

    def get_compromised_time(self) -> Optional[datetime]:
        """Return when this certificate was compromised.

        Returns ``None`` if the time is not known **or** if the certificate is not revoked.
        """
        if self.revoked is False or self.compromised is None:
            return None

        if timezone.is_naive(self.compromised):
            # convert datetime object to UTC and make it naive
            return timezone.make_aware(self.compromised, timezone=tz.utc)

        return self.compromised

    def get_revocation_time(self) -> Optional[datetime]:
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

        This function will also populate the `cn`, `serial, `expires` and `valid_from` fields.
        """
        self.pub = LazyCertificate(value)
        self.cn = next(
            (attr.value for attr in value.subject if attr.oid == NameOID.COMMON_NAME),  # type: ignore[misc]
            "",
        )
        self.expires = self.not_after
        self.valid_from = self.not_before

        if settings.USE_TZ is False:
            self.expires = timezone.make_naive(self.expires, timezone=tz.utc)
            self.valid_from = timezone.make_naive(self.valid_from, timezone=tz.utc)

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
        self, reason: ReasonFlags = ReasonFlags.unspecified, compromised: Optional[datetime] = None
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
    crl_number = models.TextField(
        default='{"scope": {}}',
        blank=True,
        verbose_name=_("CRL Number"),
        validators=[json_validator],
        help_text=_("Data structure to store the CRL number (see RFC 5280, 5.2.3) depending on the scope."),
    )
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

    def is_usable(self, options: Optional[BaseModel] = None) -> bool:
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

    @property
    def ocsp_responder_certificate(self) -> x509.Certificate:
        """The certificate currently used in the automatically configured OCSP responder.

        This property raises FileNotFoundError if no key has (yet) been generated.
        """
        data = read_file(f"ocsp/{self.serial}.pem")
        return x509.load_pem_x509_certificate(data)

    def cache_crls(self, key_backend_options: BaseModel) -> None:
        """Function to cache all CRLs for this CA.

        .. versionchanged:: 1.25.0

           Support for passing a custom hash algorithm to this function was removed.
        """
        for crl_profile in model_settings.CA_CRL_PROFILES.values():
            # If there is an override for the current CA, create a new profile model with values updated from
            # the override.
            if crl_profile_override := crl_profile.OVERRIDES.get(self.serial):
                if crl_profile_override.skip:
                    continue

                config = crl_profile.model_dump()
                config.update(crl_profile_override.model_dump(exclude_unset=True))
                crl_profile = CertificateRevocationListProfile.model_validate(config)

            expires = int(crl_profile.expires.total_seconds())
            crl = self.get_crl(
                key_backend_options=key_backend_options,
                expires=expires,
                algorithm=self.algorithm,
                scope=crl_profile.scope,
            )

            for encoding in crl_profile.encodings:
                cache_key = get_crl_cache_key(self.serial, encoding, scope=crl_profile.scope)

                if expires >= 600:  # pragma: no branch
                    # for longer expiries we subtract a random value so that regular CRL regeneration is
                    # distributed a bit
                    expires -= random.randint(1, 5) * 60

                encoded_crl = crl.public_bytes(encoding)
                cache.set(cache_key, encoded_crl, expires)

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
        algorithm: Optional[AllowedHashTypes] = None,
        expires: Optional[datetime] = None,
        extensions: Optional[list[ConfigurableExtension]] = None,
    ) -> x509.Certificate:
        """Create a signed certificate.

        This function is a low-level signing function, with optional values taken from the configuration.

        Required extensions are added if not provided. Unless already included in `extensions`, this function
        will add the AuthorityKeyIdentifier, BasicConstraints and SubjectKeyIdentifier extensions with values
        coming from the certificate authority.

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
        expires : datetime, optional
            When the certificate expires. If not provided, the ``CA_DEFAULT_EXPIRES`` setting will be used.
        extensions : list of :py:class:`~cg:cryptography.x509.Extension`, optional
            List of extensions to add to the certificates. The function will add some extensions unless
            provided here, see above for details.
        """
        if algorithm is None:
            algorithm = self.algorithm
        if expires is None:
            expires = timezone.now() + model_settings.CA_DEFAULT_EXPIRES
            expires = expires.replace(second=0, microsecond=0)
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
            expires=expires,
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
            expires=expires,
            extensions=certificate_extensions,
        )

        post_sign_cert.send(sender=self.__class__, ca=self, cert=signed_cert)

        return signed_cert

    def generate_ocsp_key(  # pylint: disable=too-many-locals
        self,
        key_backend_options: BaseModel,
        profile: str = "ocsp",
        expires: Optional[Union[datetime, timedelta]] = None,
        algorithm: Optional[AllowedHashTypes] = None,
        key_size: Optional[int] = None,
        key_type: Optional[ParsableKeyType] = None,
        elliptic_curve: Optional[ec.EllipticCurve] = None,
        autogenerated: bool = True,
        force: bool = False,
    ) -> Optional[tuple[str, str, "Certificate"]]:
        """Generate OCSP authorized responder certificate.

        By default, the certificate will have the same private and public key types as the signing certificate
        authority. The certificate's subject will be the common name of the certificate authority with the
        suffix `OCSP responder delegate certificate` added, all other subject fields are discarded.

        RFC 6960 does not specify much about how a certificate for an authorized responder should look like.
        The default ``ocsp`` profile will create a valid certificate that is usable for all known
        applications, but you a different profile can be used to add any extension values to the certificate.

        .. seealso::

            `RFC 6960: Online Certificate Status Protocol - OCSP <https://www.rfc-editor.org/rfc/rfc6960>`_


        .. versionchanged:: 1.26.0

           * Added the `force` option.
           * Do not regenerate keys if they don't expire within :ref:`CA_OCSP_RESPONDER_CERTIFICATE_RENEWAL
             <settings-ca-ocsp-responder-certificate-renewal>`.

        .. versionchanged:: 1.23.0

           * The `ecc_curve` option was renamed to ``elliptic_curve``.
           * The `key_type`, `key_size`, `elliptic_curve` and `algorithm` parameters now default to what was
             used in the certificate authority.

        Parameters
        ----------
        key_backend_options : BaseModel
            Options required for using the private key of the certificate authority.
        profile : str, optional
            The profile to use for generating the certificate. The default is ``"ocsp"``.
        expires : int or datetime, optional
            Number of days or datetime when this certificate expires. The default is ``3`` (OCSP certificates
            are usually renewed frequently).
        algorithm : :py:class:`~cg:cryptography.hazmat.primitives.hashes.HashAlgorithm`, optional
            Hash algorithm used for signing the OCSP key. Defaults to the algorithm the certificate authority
            was signed with.
        password : bytes, optional
            The password to the CA as bytes, if its private key is encrypted.
        key_size : int, optional
            The key size of the private key, defaults to :ref:`CA_DEFAULT_KEY_SIZE
            <settings-ca-default-key-size>`.
        key_type : {"RSA", "DSA", "EC", "Ed25519", "Ed448"}, optional
            The private key type to use. The default is to use the same key type as the signing CA.
        elliptic_curve : :py:class:`~cg:cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve`, optional
            An elliptic curve to use for EC keys. This parameter is ignored if ``key_type`` is not ``"EC"``.
            Defaults to the :ref:`CA_DEFAULT_ELLIPTIC_CURVE <settings-ca-default-elliptic-curve>`.
        autogenerated : bool, optional
            Set the ``autogenerated`` flag of the certificate. ``True`` by default, since this method is
            usually automatically invoked on a regular basis.
        force : bool, optional
            Set to ``True`` to force regeneration of keys. By default, keys are only regenerated if they
            expire within :ref:`CA_OCSP_RESPONDER_CERTIFICATE_RENEWAL
            <settings-ca-ocsp-responder-certificate-renewal>`.
        """
        now = datetime.now(tz=tz.utc)

        if force is False:
            try:
                responder_certificate = self.ocsp_responder_certificate
            except FileNotFoundError:
                pass  # key was presumably never generated before
            except Exception:  # pragma: no cover  # pylint: disable=broad-exception-caught
                log.exception("Unknown error when reading existing OCSP responder certificate.")
            else:
                responder_certificate_expires = responder_certificate.not_valid_after_utc
                if responder_certificate_expires > now + model_settings.CA_OCSP_RESPONDER_CERTIFICATE_RENEWAL:
                    log.info("%s: OCSP responder certificate is not yet scheduled for renewal.")
                    return None

        if expires is None:
            expires = now + timedelta(days=self.ocsp_responder_key_validity)

        safe_serial = self.serial.replace(":", "")

        if algorithm is None:
            algorithm = self.algorithm

        if key_type is None:
            key_type = self.key_type

        # If the requested private key type and the private key type of the CA is identical, use properties
        # from the CA private key as default
        if key_type == self.key_type:
            if self.key_type in ("RSA", "DSA") and key_size is None:
                key_size = self.key_backend.get_ocsp_key_size(self, key_backend_options)
            elif self.key_type == "EC" and elliptic_curve is None:
                elliptic_curve = self.key_backend.get_ocsp_key_elliptic_curve(self, key_backend_options)

        # Ensure that parameters used to generate the private key are valid.
        key_size, elliptic_curve = validate_private_key_parameters(key_type, key_size, elliptic_curve)

        # Ensure that parameters used to generate the public key are valid. Note that we have to use the key
        # type of the **ca** private key (not the OCSP private key), as it is used for signing.
        algorithm = validate_public_key_parameters(self.key_type, algorithm)

        # generate the private key
        private_key = generate_private_key(key_size, key_type, elliptic_curve)
        private_pem = private_key.private_bytes(
            encoding=Encoding.DER,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        storage = storages[model_settings.CA_DEFAULT_STORAGE_ALIAS]
        private_path = storage.generate_filename(f"ocsp/{safe_serial}.key")

        if isinstance(private_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
            csr_sign_algorithm = None
        elif isinstance(private_key, dsa.DSAPrivateKey):
            csr_sign_algorithm = model_settings.CA_DEFAULT_DSA_SIGNATURE_HASH_ALGORITHM
        else:
            csr_sign_algorithm = model_settings.CA_DEFAULT_SIGNATURE_HASH_ALGORITHM

        # Use a static subject, it seems to be not used at all.
        subject = x509.Name([x509.NameAttribute(oid=NameOID.COMMON_NAME, value="OCSP responder")])

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .sign(private_key, csr_sign_algorithm)
        )

        cert = Certificate.objects.create_cert(
            ca=self,
            key_backend_options=key_backend_options,
            csr=csr,
            profile=profiles[profile],
            subject=subject,
            algorithm=algorithm,
            autogenerated=autogenerated,
            expires=expires,
            add_ocsp_url=False,
        )

        cert_path = storage.generate_filename(f"ocsp/{safe_serial}.pem")

        for path, contents in [(private_path, private_pem), (cert_path, cert.pub.pem.encode())]:
            if storage.exists(path):
                with storage.open(path, "wb") as stream:
                    stream.write(contents)
            else:
                storage.save(path, ContentFile(contents))
        return private_path, cert_path, cert

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

    def get_crl_certs(
        self, scope: typing.Literal[None, "ca", "user", "attribute"], now: datetime
    ) -> Iterable[X509CertMixin]:
        """Get CRLs for the given scope."""
        ca_qs = self.children.filter(expires__gt=now).revoked()
        cert_qs = self.certificate_set.filter(expires__gt=now).revoked()

        if scope == "ca":
            return ca_qs
        if scope == "user":
            return cert_qs
        if scope == "attribute":
            return []  # not really supported
        if scope is None:
            return itertools.chain(ca_qs, cert_qs)
        raise ValueError('scope must be either None, "ca", "user" or "attribute"')

    def get_crl(
        self,
        key_backend_options: BaseModel,
        expires: int = 86400,
        algorithm: Optional[AllowedHashTypes] = None,
        scope: Optional[CertificateRevocationListScopes] = None,
        counter: Optional[str] = None,
        full_name: Optional[Iterable[x509.GeneralName]] = None,
        relative_name: Optional[x509.RelativeDistinguishedName] = None,
        include_issuing_distribution_point: Optional[bool] = None,
    ) -> x509.CertificateRevocationList:
        """Generate a Certificate Revocation List (CRL).

        The ``full_name`` and ``relative_name`` parameters describe how to retrieve the CRL and are used in
        the `Issuing Distribution Point extension <https://tools.ietf.org/html/rfc5280.html#section-5.2.5>`_.
        The former defaults to the ``crl_url`` field, pass ``None`` to not include the value. At most one of
        the two may be set.

        Parameters
        ----------
        key_backend_options : BaseModel
            Options required for using the private key of the certificate authority.
        expires : int
            The time in seconds when this CRL expires. Note that you should generate a new CRL until then.
        algorithm : :class:`~cg:cryptography.hazmat.primitives.hashes.HashAlgorithm`, optional
            The hash algorithm used to generate the signature of the CRL. By default, the algorithm used for
            signing the CA is used. If a value is passed for an Ed25519/Ed448 CA, `ValueError` is raised.
        scope : {None, 'ca', 'user', 'attribute'}, optional
            What to include in the CRL: Use ``"ca"`` to include only revoked certificate authorities and
            ``"user"`` to include only certificates or ``None`` (the default) to include both.
            ``"attribute"`` is reserved for future use and always produces an empty CRL.
        counter : str, optional
            Override the counter-variable for the CRL Number extension. Passing the same key to multiple
            invocations will yield a different sequence then what would ordinarily be returned. The default is
            to use the scope as the key.
        full_name : list of :py:class:`~cg:cryptography.x509.GeneralName`, optional
            List of general names to use in the Issuing Distribution Point extension. If not passed, use
            the full names of the first distribution point in ``sign_crl_distribution_points`` (if present)
            that has full names set.
        relative_name : :py:class:`~cg:cryptography.x509.RelativeDistinguishedName`, optional
            Used in Issuing Distribution Point extension, retrieve the CRL relative to the issuer.
        include_issuing_distribution_point: bool, optional
            Force the inclusion/exclusion of the IssuingDistributionPoint extension. By default, the inclusion
            is automatically determined.

        Returns
        -------
        bytes
            The CRL in the requested format.
        """
        # pylint: disable=too-many-locals; It's not easy to create a CRL. Sorry.

        now = datetime.now(tz=tz.utc)
        now_naive = now.replace(tzinfo=None)

        # Default to the algorithm used by the certificate authority itself (None in case of Ed448/Ed25519
        # based certificate authorities).
        if algorithm is None:
            algorithm = self.algorithm

        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.pub.loaded.subject)
        builder = builder.last_update(now_naive)
        builder = builder.next_update(now_naive + timedelta(seconds=expires))

        parsed_full_name = None
        if full_name is not None:
            parsed_full_name = full_name

        # CRLs for root CAs with scope "ca" (or no scope - this includes CAs) do not set a full_name in the
        # IssuingDistributionPoint extension by default. For full path validation with CRLs, the CRL is also
        # used for validating the Root CA (which does not contain a CRL Distribution Point). But the Full Name
        # in the CRL IDP and the CA CRL DP have to match. See also:
        #       https://github.com/mathiasertl/django-ca/issues/64
        elif scope in ("ca", None) and self.parent is None:
            parsed_full_name = None

        # If CA_DEFAULT_HOSTNAME is set, CRLs with scope "ca" add the same URL in the IssuingDistributionPoint
        # extension that is also added in the CRL Distribution Points extension for CAs issued by this CA.
        # See also:
        #       https://github.com/mathiasertl/django-ca/issues/64
        elif scope == "ca" and model_settings.CA_DEFAULT_HOSTNAME:
            crl_path = reverse("django_ca:ca-crl", kwargs={"serial": self.serial})
            parsed_full_name = [
                x509.UniformResourceIdentifier(f"http://{model_settings.CA_DEFAULT_HOSTNAME}{crl_path}")
            ]
        elif scope in ("user", None) and self.sign_crl_distribution_points:
            full_names = []
            for dpoint in self.sign_crl_distribution_points.value:
                if dpoint.full_name:
                    full_names += dpoint.full_name
            if full_names:
                parsed_full_name = full_names

        # Keyword arguments for the IssuingDistributionPoint extension
        only_contains_attribute_certs = False
        only_contains_ca_certs = False
        only_contains_user_certs = False
        indirect_crl = False

        if scope == "ca":
            only_contains_ca_certs = True
        elif scope == "user":
            only_contains_user_certs = True
        elif scope == "attribute":
            # sorry, nothing we support right now
            only_contains_attribute_certs = True

        if settings.USE_TZ is True:
            crl_certificates = self.get_crl_certs(scope, now)
        else:
            crl_certificates = self.get_crl_certs(scope, now_naive)

        for cert in crl_certificates:
            builder = builder.add_revoked_certificate(cert.get_revocation())

        # Validate that the user has selected a usable algorithm
        validate_public_key_parameters(self.key_type, algorithm)

        # We can only add the IDP extension if one of these properties is set, see RFC 5280, 5.2.5.
        if include_issuing_distribution_point is None:
            include_issuing_distribution_point = (
                only_contains_attribute_certs
                or only_contains_user_certs
                or only_contains_ca_certs
                or parsed_full_name is not None
                or relative_name is not None
            )

        if include_issuing_distribution_point is True:
            builder = builder.add_extension(
                x509.IssuingDistributionPoint(
                    indirect_crl=indirect_crl,
                    only_contains_attribute_certs=only_contains_attribute_certs,
                    only_contains_ca_certs=only_contains_ca_certs,
                    only_contains_user_certs=only_contains_user_certs,
                    full_name=parsed_full_name,
                    only_some_reasons=None,
                    relative_name=relative_name,
                ),
                critical=True,
            )

        # Add AuthorityKeyIdentifier from CA
        aki = self.get_authority_key_identifier()
        builder = builder.add_extension(aki, critical=False)

        # Add the CRLNumber extension (RFC 5280, 5.2.3)
        if counter is None:
            counter = scope or "all"
        crl_number_data = json.loads(self.crl_number)
        crl_number = int(crl_number_data["scope"].get(counter, 0))
        builder = builder.add_extension(x509.CRLNumber(crl_number=crl_number), critical=False)

        # Get the backend.
        if self.is_usable(options=key_backend_options) is False:
            raise ValueError("Backend cannot be used for signing by this process.")

        # increase crl_number for the given scope and save
        crl_number_data["scope"][counter] = crl_number + 1
        self.crl_number = json.dumps(crl_number_data)
        self.save()

        return self.key_backend.sign_certificate_revocation_list(
            ca=self, use_private_key_options=key_backend_options, builder=builder, algorithm=algorithm
        )

    @property
    def path_length(self) -> Optional[int]:
        """The ``path_length`` attribute of the ``BasicConstraints`` extension."""
        try:
            ext = self.pub.loaded.extensions.get_extension_for_class(x509.BasicConstraints)
        except x509.ExtensionNotFound:  # pragma: no cover - extension should always be present
            return None
        return ext.value.path_length

    @property
    def max_path_length(self) -> Optional[int]:
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
        return self.enabled and self.valid_from < timezone.now() < self.expires

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
    csr = CertificateSigningRequestField(verbose_name=_("CSR"), blank=True, null=True)

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
    pem = models.TextField(verbose_name=_("Public key"), unique=True, blank=False, validators=[pem_validator])
    # JSON Web Key thumbprint - a hash of the public key, see RFC 7638.
    #   NOTE: Only unique for the given CA to make hash collisions less likely
    thumbprint = models.CharField(max_length=64)
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
    TYPE_TLS_ALPN_01 = "tls-alpn-01"
    TYPE_CHOICES = (
        (TYPE_HTTP_01, _("HTTP Challenge")),
        (TYPE_DNS_01, _("DNS Challenge")),
        (TYPE_TLS_ALPN_01, _("TLS ALPN Challenge")),
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
        if self.type == AcmeChallenge.TYPE_DNS_01:
            return challenges.DNS01(token=token)
        if self.type == AcmeChallenge.TYPE_TLS_ALPN_01:
            return challenges.TLSALPN01(token=token)

        raise ValueError(f"{self.type}: Unsupported challenge type.")

    @property
    def acme_validated(self) -> Optional[datetime]:
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
        if self.type == AcmeChallenge.TYPE_DNS_01:
            return jose.b64.b64encode(hashlib.sha256(value).digest())
        raise ValueError(f"{self.type}: Unsupported challenge type.")

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

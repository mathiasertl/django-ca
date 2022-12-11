# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca.  If not,
# see <http://www.gnu.org/licenses/>.

"""Django models for the django-ca application.

.. seealso:: https://docs.djangoproject.com/en/dev/topics/db/models/
"""

import base64
import hashlib
import itertools
import json
import logging
import random
import re
import typing
import warnings
from collections import OrderedDict
from datetime import datetime, timedelta
from datetime import timezone as tz
from typing import Dict, Iterable, List, Optional, Tuple, Union

import josepy as jose
from acme import challenges, messages

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, ed448, x448, x25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID

from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.core.validators import URLValidator
from django.db import models
from django.http import HttpRequest
from django.urls import reverse
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.utils.functional import cached_property
from django.utils.text import slugify
from django.utils.translation import gettext_lazy as _

from . import ca_settings
from .acme.constants import BASE64_URL_ALPHABET, IdentifierType, Status
from .constants import EXTENSION_DEFAULT_CRITICAL, REVOCATION_REASONS, ReasonFlags
from .extensions import (
    OID_TO_EXTENSION,
    AuthorityInformationAccess,
    AuthorityKeyIdentifier,
    BasicConstraints,
    CertificatePolicies,
    CRLDistributionPoints,
    ExtendedKeyUsage,
    FreshestCRL,
    InhibitAnyPolicy,
    IssuerAlternativeName,
    KeyUsage,
    NameConstraints,
    OCSPNoCheck,
    PolicyConstraints,
    PrecertificateSignedCertificateTimestamps,
    PrecertPoison,
    SubjectAlternativeName,
    SubjectKeyIdentifier,
    TLSFeature,
    get_extension_name,
)
from .extensions.base import Extension
from .managers import (
    AcmeAccountManager,
    AcmeAuthorizationManager,
    AcmeCertificateManager,
    AcmeChallengeManager,
    AcmeOrderManager,
    CertificateAuthorityManager,
    CertificateManager,
)
from .modelfields import CertificateField, CertificateSigningRequestField, LazyCertificate
from .openssh.extensions import SSH_HOST_CA, SSH_USER_CA
from .profiles import profiles
from .querysets import (
    AcmeAccountQuerySet,
    AcmeAuthorizationQuerySet,
    AcmeCertificateQuerySet,
    AcmeChallengeQuerySet,
    AcmeOrderQuerySet,
    CertificateAuthorityQuerySet,
    CertificateQuerySet,
)
from .signals import post_revoke_cert, post_sign_cert, pre_issue_cert, pre_revoke_cert, pre_sign_cert
from .typehints import (
    Expires,
    ExtensionTypeTypeVar,
    Literal,
    ParsableHash,
    ParsableKeyType,
    ParsableValue,
    PrivateKeyTypes,
    SerializedValue,
)
from .utils import (
    bytes_to_hex,
    ca_storage,
    classproperty,
    format_name,
    generate_private_key,
    get_cert_builder,
    get_crl_cache_key,
    int_to_hex,
    multiline_url_validator,
    parse_encoding,
    parse_expires,
    parse_general_name,
    parse_hash_algorithm,
    read_file,
    split_str,
    validate_key_parameters,
)

log = logging.getLogger(__name__)

_UNSUPPORTED_PRIVATE_KEY_TYPES = (
    dh.DHPrivateKey,
    ed448.Ed448PrivateKey,
    x25519.X25519PrivateKey,
    x448.X448PrivateKey,
)


def acme_slug() -> str:
    """Default function to get an ACME conforming slug."""
    return get_random_string(length=12)


def acme_order_expires() -> datetime:
    """Default function for the expiry of an ACME order."""
    return timezone.now() + ca_settings.ACME_ORDER_VALIDITY


def acme_token() -> str:
    """Generate an ACME token for this challenge.

    Note that currently all challenges have the same requirements on tokens, except for DNS challenges
    which seem to allow padding ("=") characters. We ignore the '=' for DNS challenges as our tokens are
    already longer then required.
    """
    return get_random_string(64, allowed_chars=BASE64_URL_ALPHABET)


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

    @classmethod
    def from_addr(cls, addr: str) -> "Watcher":
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

    def __str__(self) -> str:
        if self.name:
            return f"{self.name} <{self.mail}>"
        return self.mail


class X509CertMixin(DjangoCAModel):
    """Mixin class with common attributes for Certificates and Certificate Authorities."""

    # pylint: disable=too-many-public-methods
    # X.509 certificates are complex. Sorry.

    # reasons are defined in http://www.ietf.org/rfc/rfc3280.txt
    REVOCATION_REASONS = REVOCATION_REASONS

    created = models.DateTimeField(auto_now=True)

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
        verbose_name=_("Reason for revokation"),
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

    @property
    def bundle_as_pem(self) -> str:
        """Get the bundle as PEM."""
        # TYPE NOTE: bundle is defined in base class but returns a list (considered invariant by mypy). This
        #            means that an abstract "bundle" property here could not be correctly typed.
        return "".join(c.pub.pem for c in self.bundle)  # type:  ignore[attr-defined]

    def get_revocation_reason(self) -> Optional[x509.ReasonFlags]:
        """Get the revocation reason of this certificate."""
        if self.revoked is False:
            return None

        return x509.ReasonFlags[self.revoked_reason]

    def get_compromised_time(self) -> Optional[datetime]:
        """Return when this certificate was compromised as a *naive* datetime.

        Returns ``None`` if the time is not known **or** if the certificate is not revoked.
        """
        if self.revoked is False or self.compromised is None:
            return None

        if timezone.is_aware(self.compromised):
            # convert datetime object to UTC and make it naive
            return timezone.make_naive(self.compromised, tz.utc)

        return self.compromised

    def get_revocation_time(self) -> Optional[datetime]:
        """Get the revocation time as naive datetime."""
        if self.revoked is False:
            return None

        revoked_date = self.revoked_date
        if revoked_date is None:
            log.warning("Inconsistent model state: revoked=True and revoked_date=None.")
            return None

        if timezone.is_aware(revoked_date):
            # convert datetime object to UTC and make it naive
            return timezone.make_naive(revoked_date, tz.utc)

        return revoked_date.replace(microsecond=0)

    def update_certificate(self, value: x509.Certificate) -> None:
        """Update this instance with data from a :py:class:`cg:cryptography.x509.Certificate`.

        This function will also populate the `cn`, `serial, `expires` and `valid_from` fields.
        """
        self.pub = LazyCertificate(value)
        self.cn = next(
            (attr.value for attr in value.subject if attr.oid == NameOID.COMMON_NAME), ""  # type: ignore
        )
        self.expires = self.not_after
        self.valid_from = self.not_before
        if settings.USE_TZ:
            self.expires = timezone.make_aware(self.expires, timezone=tz.utc)
            self.valid_from = timezone.make_aware(self.valid_from, timezone=tz.utc)

        self.serial = int_to_hex(value.serial_number)

    ##########################
    # Certificate properties #
    ##########################

    @property
    def algorithm(self) -> Optional[hashes.HashAlgorithm]:
        """A shortcut for :py:attr:`~cg:cryptography.x509.Certificate.signature_hash_algorithm`."""
        return self.pub.loaded.signature_hash_algorithm

    def get_fingerprint(self, algorithm: hashes.HashAlgorithm) -> str:
        """Get the digest for a certificate as string, including colons."""
        return bytes_to_hex(self.pub.loaded.fingerprint(algorithm))

    def get_filename(self, ext: str, bundle: bool = False) -> str:
        """Get a filename safe for any file system and OS for this certificate based on the common name.

        Parameters
        ----------

        ext : str
            The filename extension to use (e.g. ``"pem"``).
        bundle : bool, optional
            Adds "_bundle" as suffix.
        """
        slug = slugify(self.cn.replace(".", "_"))

        if bundle is True:
            return f"{slug}_bundle.{ext.lower()}"
        return f"{slug}.{ext.lower()}"

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

    @property
    def hpkp_pin(self) -> str:
        """The HPKP public key pin for this certificate.

        Inspired by https://github.com/luisgf/hpkp-python/blob/master/hpkp.py.

        .. seealso:: https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning
        """

        public_key_raw = self.pub.loaded.public_key().public_bytes(
            encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo
        )
        public_key_hash = hashlib.sha256(public_key_raw).digest()
        return base64.b64encode(public_key_hash).decode("utf-8")

    @property
    def issuer(self) -> x509.Name:
        """The certificate issuer field as :py:class:`~cg:cryptography.x509.Name`."""
        return self.pub.loaded.issuer

    @property
    def jwk(self) -> Union[jose.jwk.JWKRSA, jose.jwk.JWKEC]:
        """Get a JOSE JWK public key for this certificate."""

        pkey = self.pub.loaded.public_key()
        jwk = jose.jwk.JWK.load(pkey.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))

        # JWK.load() may return a private instead, so we rule this out here for type safety. This branch
        # should normally not happen.
        if not isinstance(jwk, (jose.jwk.JWKRSA, jose.jwk.JWKEC)):  # pragma: no cover
            raise TypeError(f"Loading JWK RSA key returned {type(jwk)}.")
        return jwk

    @property
    def not_before(self) -> datetime:
        """Date/Time before this certificate is **not** valid."""
        return self.pub.loaded.not_valid_before

    @property
    def not_after(self) -> datetime:
        """Date/Time this certificate expires."""
        return self.pub.loaded.not_valid_after

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

    @property
    def subject(self) -> x509.Name:
        """The certificate subject field as :py:class:`~cg:cryptography.x509.Name`."""
        return self.pub.loaded.subject

    @property
    def distinguished_name(self) -> str:
        """The certificate subject formatted as string."""
        return format_name(self.pub.loaded.subject)

    ###################
    # X509 extensions #
    ###################

    @cached_property
    def x509_extensions(self) -> Dict[x509.ObjectIdentifier, "x509.Extension[x509.ExtensionType]"]:
        """All extensions of this certificate in a `dict`.

        The key is the OID for the respective extension, allowing easy to look up a particular extension.
        """
        return {e.oid: e for e in self.pub.loaded.extensions}

    @cached_property
    def sorted_extensions(self) -> List["x509.Extension[x509.ExtensionType]"]:
        """List of extensions sorted by their human readable name.

        This property is used for display purposes, where a reproducible output is desired.
        """
        # NOTE: We need the dotted_string in the sort key if we have multiple unknown extensions, which then
        #       show up as "Unknown OID" and have to be sorted by oid
        return list(sorted(self.x509_extensions.values(), key=lambda e: get_extension_name(e.oid)))

    @cached_property
    def extensions(
        self,
    ) -> List[
        Union[
            Extension[ExtensionTypeTypeVar, ParsableValue, SerializedValue],
            "x509.Extension[x509.ExtensionType]",
        ]
    ]:  # pragma: no cover
        """List of all extensions for this certificate."""
        exts = []

        for ext in self.sorted_extensions:
            if ext.oid in OID_TO_EXTENSION:
                exts.append(getattr(self, OID_TO_EXTENSION[ext.oid].key))

            # extension that does not support new extension framework
            else:
                exts.append(ext)
        return exts

    @cached_property
    def authority_information_access(self) -> Optional[AuthorityInformationAccess]:  # pragma: no cover
        """The ``django_ca.extensions.AuthorityInformationAccess`` extension or ``None`` if not
        present.

        .. deprecated:: 1.22.0

           Extension wrapper classes are deprecated and will be removed in ``django-ca==1.24.0``. Use
           :py:attr:`~django_ca.models.X509CertMixin.x509_extensions` instead.
        """
        try:
            ext = self.pub.loaded.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        except x509.ExtensionNotFound:
            return None
        return AuthorityInformationAccess(ext)

    @cached_property
    def authority_key_identifier(self) -> Optional[AuthorityKeyIdentifier]:  # pragma: no cover
        """The ``django_ca.extensions.AuthorityKeyIdentifier`` extension or ``None`` if not
        present.

        .. deprecated:: 1.22.0

           Extension wrapper classes are deprecated and will be removed in ``django-ca==1.24.0``. Use
           :py:attr:`~django_ca.models.X509CertMixin.x509_extensions` instead.
        """
        try:
            ext = self.pub.loaded.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        except x509.ExtensionNotFound:
            return None
        return AuthorityKeyIdentifier(ext)

    @cached_property
    def basic_constraints(self) -> Optional[BasicConstraints]:  # pragma: no cover
        """The ``django_ca.extensions.BasicConstraints`` extension or ``None`` if not present.

        .. deprecated:: 1.22.0

           Extension wrapper classes are deprecated and will be removed in ``django-ca==1.24.0``. Use
           :py:attr:`~django_ca.models.X509CertMixin.x509_extensions` instead.
        """
        try:
            ext = self.pub.loaded.extensions.get_extension_for_class(x509.BasicConstraints)
        except x509.ExtensionNotFound:
            return None
        return BasicConstraints(ext)

    @cached_property
    def crl_distribution_points(self) -> Optional[CRLDistributionPoints]:  # pragma: no cover
        """The ``django_ca.extensions.CRLDistributionPoints`` extension or ``None`` if not
        present.

        .. deprecated:: 1.22.0

           Extension wrapper classes are deprecated and will be removed in ``django-ca==1.24.0``. Use
           :py:attr:`~django_ca.models.X509CertMixin.x509_extensions` instead.
        """
        try:
            ext = self.pub.loaded.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        except x509.ExtensionNotFound:
            return None
        return CRLDistributionPoints(ext)

    @cached_property
    def certificate_policies(self) -> Optional[CertificatePolicies]:  # pragma: no cover
        """The ``django_ca.extensions.CertificatePolicies`` extension or ``None`` if not present.

        .. deprecated:: 1.22.0

           Extension wrapper classes are deprecated and will be removed in ``django-ca==1.24.0``. Use
           :py:attr:`~django_ca.models.X509CertMixin.x509_extensions` instead.
        """
        try:
            ext = self.pub.loaded.extensions.get_extension_for_class(x509.CertificatePolicies)
        except x509.ExtensionNotFound:
            return None
        return CertificatePolicies(ext)

    @cached_property
    def freshest_crl(self) -> Optional[FreshestCRL]:  # pragma: no cover
        """The ``django_ca.extensions.FreshestCRL`` extension or ``None`` if not present.

        .. deprecated:: 1.22.0

           Extension wrapper classes are deprecated and will be removed in ``django-ca==1.24.0``. Use
           :py:attr:`~django_ca.models.X509CertMixin.x509_extensions` instead.
        """
        try:
            ext = self.pub.loaded.extensions.get_extension_for_class(x509.FreshestCRL)
        except x509.ExtensionNotFound:
            return None
        return FreshestCRL(ext)

    @cached_property
    def inhibit_any_policy(self) -> Optional[InhibitAnyPolicy]:  # pragma: no cover
        """The ``django_ca.extensions.InhibitAnyPolicy`` extension or ``None`` if not present.

        .. deprecated:: 1.22.0

           Extension wrapper classes are deprecated and will be removed in ``django-ca==1.24.0``. Use
           :py:attr:`~django_ca.models.X509CertMixin.x509_extensions` instead.
        """
        try:
            ext = self.pub.loaded.extensions.get_extension_for_class(x509.InhibitAnyPolicy)
        except x509.ExtensionNotFound:
            return None
        return InhibitAnyPolicy(ext)

    @cached_property
    def issuer_alternative_name(self) -> Optional[IssuerAlternativeName]:  # pragma: no cover
        """The ``django_ca.extensions.IssuerAlternativeName`` extension or ``None`` if not
        present.

        .. deprecated:: 1.22.0

           Extension wrapper classes are deprecated and will be removed in ``django-ca==1.24.0``. Use
           :py:attr:`~django_ca.models.X509CertMixin.x509_extensions` instead.
        """
        try:
            ext = self.pub.loaded.extensions.get_extension_for_class(x509.IssuerAlternativeName)
        except x509.ExtensionNotFound:
            return None
        return IssuerAlternativeName(ext)

    @cached_property
    def policy_constraints(self) -> Optional[PolicyConstraints]:  # pragma: no cover
        """The ``django_ca.extensions.PolicyConstraints`` extension or ``None`` if not present.

        .. deprecated:: 1.22.0

           Extension wrapper classes are deprecated and will be removed in ``django-ca==1.24.0``. Use
           :py:attr:`~django_ca.models.X509CertMixin.x509_extensions` instead.
        """
        try:
            ext = self.pub.loaded.extensions.get_extension_for_class(x509.PolicyConstraints)
        except x509.ExtensionNotFound:
            return None
        return PolicyConstraints(ext)

    @cached_property
    def key_usage(self) -> Optional[KeyUsage]:  # pragma: no cover
        """The ``django_ca.extensions.KeyUsage`` extension or ``None`` if not present.

        .. deprecated:: 1.22.0

           Extension wrapper classes are deprecated and will be removed in ``django-ca==1.24.0``. Use
           :py:attr:`~django_ca.models.X509CertMixin.x509_extensions` instead.
        """
        try:
            ext = self.pub.loaded.extensions.get_extension_for_class(x509.KeyUsage)
        except x509.ExtensionNotFound:
            return None
        return KeyUsage(ext)

    @cached_property
    def extended_key_usage(self) -> Optional[ExtendedKeyUsage]:  # pragma: no cover
        """The ``django_ca.extensions.ExtendedKeyUsage`` extension or ``None`` if not present.

        .. deprecated:: 1.22.0

           Extension wrapper classes are deprecated and will be removed in ``django-ca==1.24.0``. Use
           :py:attr:`~django_ca.models.X509CertMixin.x509_extensions` instead.
        """
        try:
            ext = self.pub.loaded.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        except x509.ExtensionNotFound:
            return None
        return ExtendedKeyUsage(ext)

    @cached_property
    def name_constraints(self) -> Optional[NameConstraints]:  # pragma: no cover
        """The ``django_ca.extensions.NameConstraints`` extension or ``None`` if not present.

        .. deprecated:: 1.22.0

           Extension wrapper classes are deprecated and will be removed in ``django-ca==1.24.0``. Use
           :py:attr:`~django_ca.models.X509CertMixin.x509_extensions` instead.
        """
        try:
            ext = self.pub.loaded.extensions.get_extension_for_class(x509.NameConstraints)
        except x509.ExtensionNotFound:
            return None
        return NameConstraints(ext)

    @cached_property
    def ocsp_no_check(self) -> Optional[OCSPNoCheck]:  # pragma: no cover
        """The ``django_ca.extensions.OCSPNoCheck`` extension or ``None`` if not present.

        .. deprecated:: 1.22.0

           Extension wrapper classes are deprecated and will be removed in ``django-ca==1.24.0``. Use
           :py:attr:`~django_ca.models.X509CertMixin.x509_extensions` instead.
        """
        try:
            ext = self.pub.loaded.extensions.get_extension_for_class(x509.OCSPNoCheck)
        except x509.ExtensionNotFound:
            return None
        return OCSPNoCheck(ext)

    @cached_property
    def precert_poison(self) -> Optional[PrecertPoison]:  # pragma: no cover
        """The ``django_ca.extensions.PrecertPoison`` extension or ``None`` if not present.

        .. deprecated:: 1.22.0

           Extension wrapper classes are deprecated and will be removed in ``django-ca==1.24.0``. Use
           :py:attr:`~django_ca.models.X509CertMixin.x509_extensions` instead.
        """
        try:
            self.pub.loaded.extensions.get_extension_for_class(x509.PrecertPoison)
        except x509.ExtensionNotFound:
            return None
        return PrecertPoison()

    @cached_property
    def precertificate_signed_certificate_timestamps(
        self,
    ) -> Optional[PrecertificateSignedCertificateTimestamps]:  # pragma: no cover
        """The ``django_ca.extensions.PrecertificateSignedCertificateTimestamps`` extension or
        ``None`` if not present.

        .. deprecated:: 1.22.0

           Extension wrapper classes are deprecated and will be removed in ``django-ca==1.24.0``. Use
           :py:attr:`~django_ca.models.X509CertMixin.x509_extensions` instead.
        """
        try:
            ext = self.pub.loaded.extensions.get_extension_for_class(
                x509.PrecertificateSignedCertificateTimestamps
            )
        except x509.ExtensionNotFound:
            return None
        return PrecertificateSignedCertificateTimestamps(ext)

    @cached_property
    def subject_alternative_name(self) -> Optional[SubjectAlternativeName]:  # pragma: no cover
        """The ``django_ca.extensions.SubjectAlternativeName`` extension or ``None`` if not
        present.

        .. deprecated:: 1.22.0

           Extension wrapper classes are deprecated and will be removed in ``django-ca==1.24.0``. Use
           :py:attr:`~django_ca.models.X509CertMixin.x509_extensions` instead.
        """
        try:
            ext = self.pub.loaded.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except x509.ExtensionNotFound:
            return None
        return SubjectAlternativeName(ext)

    @cached_property
    def subject_key_identifier(self) -> Optional[SubjectKeyIdentifier]:  # pragma: no cover
        """The ``django_ca.extensions.SubjectKeyIdentifier`` extension or ``None`` if not present.

        .. deprecated:: 1.22.0

           Extension wrapper classes are deprecated and will be removed in ``django-ca==1.24.0``. Use
           :py:attr:`~django_ca.models.X509CertMixin.x509_extensions` instead.
        """
        try:
            ext = self.pub.loaded.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        except x509.ExtensionNotFound:
            return None
        return SubjectKeyIdentifier(ext)

    @cached_property
    def tls_feature(self) -> Optional[TLSFeature]:  # pragma: no cover
        """The ``django_ca.extensions.TLSFeature`` extension or ``None`` if not present.

        .. deprecated:: 1.22.0

           Extension wrapper classes are deprecated and will be removed in ``django-ca==1.24.0``. Use
           :py:attr:`~django_ca.models.X509CertMixin.x509_extensions` instead.
        """
        try:
            ext = self.pub.loaded.extensions.get_extension_for_class(x509.TLSFeature)
        except x509.ExtensionNotFound:
            return None
        return TLSFeature(ext)


class CertificateAuthority(X509CertMixin):
    """Model representing a x509 Certificate Authority."""

    objects: CertificateAuthorityManager = CertificateAuthorityManager.from_queryset(
        CertificateAuthorityQuerySet
    )()

    name = models.CharField(max_length=32, help_text=_("A human-readable name"), unique=True)
    """Human-readable name of the CA, only used for displaying the CA."""
    enabled = models.BooleanField(default=True)
    parent = models.ForeignKey(
        "self", on_delete=models.SET_NULL, null=True, blank=True, related_name="children"
    )
    private_key_path = models.CharField(max_length=256, help_text=_("Path to the private key."))

    # various details used when signing certs
    crl_url = models.TextField(
        blank=True,
        default="",
        validators=[multiline_url_validator],
        verbose_name=_("CRL URLs"),
        help_text=_("URLs, one per line, where you can retrieve the CRL."),
    )
    crl_number = models.TextField(
        default='{"scope": {}}',
        blank=True,
        verbose_name=_("CRL Number"),
        validators=[json_validator],
        help_text=_("Data structure to store the CRL number (see RFC 5280, 5.2.3) depending on the scope."),
    )
    issuer_url = models.URLField(
        blank=True,
        null=True,
        verbose_name=_("Issuer URL"),
        help_text=_("URL to the certificate of this CA (in DER format)."),
    )
    ocsp_url = models.URLField(
        blank=True,
        null=True,
        verbose_name=_("OCSP responder URL"),
        help_text=_("URL of a OCSP responser for the CA."),
    )
    issuer_alt_name = models.CharField(
        blank=True,
        max_length=255,
        default="",
        verbose_name=_("issuerAltName"),
        help_text=_("URL for your CA."),
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

    # ACMEv2 fields
    acme_enabled = models.BooleanField(
        default=False,
        verbose_name=_("Enable ACME"),
        help_text=_("Whether it is possible to use ACME for this CA."),
    )
    acme_requires_contact = models.BooleanField(
        default=True,
        verbose_name="Requires contact",
        help_text=_("If this CA requires a contact address during account registration."),
    )
    # CAA record and website are general fields

    _key = None

    def key(self, password: Optional[Union[str, bytes]] = None) -> PrivateKeyTypes:
        """The CAs private key as private key.

        .. seealso:: :py:func:`~cg:cryptography.hazmat.primitives.serialization.load_pem_private_key`.
        """
        if isinstance(password, str):
            password = password.encode("utf-8")

        if self._key is None:
            key_data = read_file(self.private_key_path)

            try:
                self._key = load_pem_private_key(key_data, password)
            except ValueError as ex:
                # cryptography passes the OpenSSL error directly here and it is notoriously unstable.
                raise ValueError("Could not decrypt private key - bad password?") from ex
        if isinstance(self._key, _UNSUPPORTED_PRIVATE_KEY_TYPES):  # pragma: no cover
            raise ValueError("Private key of this type is not supported.")

        return self._key

    @property
    def key_exists(self) -> bool:
        """``True`` if the private key is locally accessible."""
        if self._key is not None:
            return True
        return ca_storage.exists(self.private_key_path)

    def cache_crls(
        self, password: Optional[Union[str, bytes]] = None, algorithm: ParsableHash = None
    ) -> None:
        """Function to cache all CRLs for this CA.

        .. versionchanged:: 1.22.0

           This function now always generates new CRLs.
        """

        password = password or self.get_password()
        ca_key = self.key(password)
        if isinstance(ca_key, dsa.DSAPrivateKey) and algorithm is None:
            algorithm = hashes.SHA256()
        elif algorithm is not None:
            algorithm = parse_hash_algorithm(algorithm)

        for config in ca_settings.CA_CRL_PROFILES.values():
            overrides = config.get("OVERRIDES", {}).get(self.serial, {})

            if overrides.get("skip"):
                continue

            algorithm = algorithm or parse_hash_algorithm(overrides.get("algorithm", config.get("algorithm")))
            expires = overrides.get("expires", config.get("expires", 86400))
            scope = overrides.get("scope", config.get("scope"))
            full_name = overrides.get("full_name", config.get("full_name"))
            relative_name = overrides.get("relative_name", config.get("relative_name"))
            encodings = overrides.get("encodings", config.get("encodings", ["DER"]))
            crl = self.get_crl(
                expires=expires,
                algorithm=algorithm,
                password=password,
                scope=scope,
                full_name=full_name,
                relative_name=relative_name,
            )

            for encoding in encodings:
                encoding = parse_encoding(encoding)
                cache_key = get_crl_cache_key(self.serial, algorithm, encoding, scope=scope)

                if expires >= 600:  # pragma: no branch
                    # for longer expiries we substract a random value so that regular CRL regeneration is
                    # distributed a bit
                    cache_expires = expires - random.randint(1, 5) * 60

                encoded_crl = crl.public_bytes(encoding)
                cache.set(cache_key, encoded_crl, cache_expires)

    @property
    def extensions_for_certificate(
        self,
    ) -> Dict[x509.ObjectIdentifier, x509.Extension[x509.ExtensionType]]:
        """Get a list of extensions to use for the certificate."""

        extensions: Dict[x509.ObjectIdentifier, x509.Extension[x509.ExtensionType]] = {}
        if self.issuer_alt_name:
            names = [parse_general_name(name) for name in split_str(self.issuer_alt_name, ",")]
            extensions[ExtensionOID.ISSUER_ALTERNATIVE_NAME] = x509.Extension(
                oid=ExtensionOID.ISSUER_ALTERNATIVE_NAME,
                critical=EXTENSION_DEFAULT_CRITICAL[ExtensionOID.ISSUER_ALTERNATIVE_NAME],
                value=x509.IssuerAlternativeName(names),
            )

        access_descriptions = []
        # TODO: use get_authority_information_access_extension() but it does not yet split lines
        if self.ocsp_url:
            ocsp = [parse_general_name(name) for name in self.ocsp_url.splitlines()]
            access_descriptions += [
                x509.AccessDescription(access_method=AuthorityInformationAccessOID.OCSP, access_location=name)
                for name in ocsp
            ]
        if self.issuer_url:
            ca_issuers = [parse_general_name(name) for name in self.issuer_url.splitlines()]
            access_descriptions += [
                x509.AccessDescription(
                    access_method=AuthorityInformationAccessOID.CA_ISSUERS, access_location=name
                )
                for name in ca_issuers
            ]
        if access_descriptions:
            extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS] = x509.Extension(
                oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
                critical=EXTENSION_DEFAULT_CRITICAL[ExtensionOID.AUTHORITY_INFORMATION_ACCESS],
                value=x509.AuthorityInformationAccess(descriptions=access_descriptions),
            )
        if self.crl_url:
            full_name = [parse_general_name(name) for name in self.crl_url.splitlines()]
            extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS] = x509.Extension(
                oid=ExtensionOID.CRL_DISTRIBUTION_POINTS,
                critical=EXTENSION_DEFAULT_CRITICAL[ExtensionOID.CRL_DISTRIBUTION_POINTS],
                value=x509.CRLDistributionPoints(
                    [
                        x509.DistributionPoint(
                            full_name=full_name, relative_name=None, crl_issuer=None, reasons=None
                        )
                    ]
                ),
            )

        return extensions

    def sign(
        self,
        csr: x509.CertificateSigningRequest,
        subject: x509.Name,
        algorithm: Optional[hashes.HashAlgorithm] = None,
        expires: Optional[datetime] = None,
        extensions: Optional[Iterable[x509.Extension[x509.ExtensionType]]] = None,
        cn_in_san: bool = True,
        password: Optional[Union[str, bytes]] = None,
    ) -> x509.Certificate:
        """Create a signed certificate.

        This function is a low-level signing function, with optional values taken from the configuration.

        Required extensions are added if not provided. Unless already included in `extensions`, this function
        will add the AuthorityKeyIdentifier, BasicConstraints and SubjectKeyIdentifier extensions with values
        coming from the certificate authority. The common names in `subject` are added to
        SubjectAlternativeName if `cn_in_san` is ``True``.

        Parameters
        ----------

        csr : :py:class:`~cg:cryptography.x509.CertificateSigningRequest`
            The certificate signing request to sign.
        subject : :class:`~cg:cryptography.x509.Name`
            Subject for the certificate
        algorithm : :class:`~cg:cryptography.hazmat.primitives.hashes.HashAlgorithm`, optional
            Hash algorithm used for signing the certificate, defaults to the ``CA_DIGEST_ALGORITHM`` setting.
        expires : datetime, optional
            When the certificate expires. If not provided, the ``CA_DEFAULT_EXPIRES`` setting will be used.
        extensions : list of :py:class:`~cg:cryptography.x509.Extension`, optional
            List of extensions to add to the certificates. The function will add some extensions unless
            provided here, see above fore details.
        cn_in_san : bool, optional
            Include common names from the subject in the SubjectAlternativeName extension. ``True`` by
            default.
        password : str or bytes, optional
            Password for loading the private key of the CA, if any.
        """
        if algorithm is None:
            algorithm = ca_settings.CA_DIGEST_ALGORITHM
        if expires is None:
            expires = timezone.now() + ca_settings.CA_DEFAULT_EXPIRES
            expires = expires.replace(second=0, microsecond=0)
        if extensions is None:
            extensions = []

        public_key = csr.public_key()
        exts = OrderedDict([(ext.oid, ext) for ext in extensions])

        # Add BasicConstraints extension if not already set.
        if ExtensionOID.BASIC_CONSTRAINTS not in exts:
            exts[ExtensionOID.BASIC_CONSTRAINTS] = x509.Extension(
                oid=ExtensionOID.BASIC_CONSTRAINTS,
                critical=True,
                value=x509.BasicConstraints(ca=False, path_length=None),
            )

        # Make sure that the "ca" value of the Basic Constraints extension is False. If it were True, the
        # certificate would be usable as a CA and we want to make sure that his does not happen here.
        basic_constraints = typing.cast(x509.BasicConstraints, exts[ExtensionOID.BASIC_CONSTRAINTS].value)
        if basic_constraints.ca is True:
            raise ValueError("This function cannot be used to create a Certificate Authority.")

        # Add Subject- and AuthorityKeyIdentifier extensions if not already set.
        if ExtensionOID.SUBJECT_KEY_IDENTIFIER not in exts:
            exts[ExtensionOID.SUBJECT_KEY_IDENTIFIER] = x509.Extension(
                oid=ExtensionOID.SUBJECT_KEY_IDENTIFIER,
                value=x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False,  # MUST be non-critical (RFC 5280, section 4.2.1.2)
            )
        if ExtensionOID.AUTHORITY_KEY_IDENTIFIER not in exts:
            exts[ExtensionOID.AUTHORITY_KEY_IDENTIFIER] = self.get_authority_key_identifier_extension()

        # Add CommonNames to the SubjectAlternativeName extension if cn_in_san == True
        common_names = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        san = typing.cast(
            Optional[x509.Extension[x509.SubjectAlternativeName]],
            exts.get(ExtensionOID.SUBJECT_ALTERNATIVE_NAME),
        )
        if cn_in_san is True:
            for raw_common_name in common_names:
                try:
                    # TYPEHINT NOTE: NameAttribute.value may be bytes but must be str for COMMON_NAME.
                    #   This is guaranteed by the NameAttribute constructor.
                    raw_common_name_value = typing.cast(str, raw_common_name.value)
                    cn = parse_general_name(raw_common_name_value)
                except ValueError:
                    continue

                if not san:
                    san = x509.Extension(
                        oid=ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                        critical=False,
                        value=x509.SubjectAlternativeName([cn]),
                    )
                    exts[ExtensionOID.SUBJECT_ALTERNATIVE_NAME] = san

                elif cn not in san.value:
                    san = x509.Extension(
                        oid=ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                        critical=exts[ExtensionOID.SUBJECT_ALTERNATIVE_NAME].critical,
                        value=x509.SubjectAlternativeName(list(san.value) + [cn]),
                    )
                    exts[ExtensionOID.SUBJECT_ALTERNATIVE_NAME] = san
                # else: CommonName already in SubjectAlternativeName

        # Convert extensions to legacy classes so that we can send the deprecated signal
        with warnings.catch_warnings():  # disable warnings as constructors raise a warning
            warnings.simplefilter("ignore")
            cert_extensions = [OID_TO_EXTENSION[ext.oid](ext) for ext in extensions]
        pre_issue_cert.send(
            sender=self.__class__,
            ca=self,
            csr=csr,
            expires=expires,
            algorithm=algorithm,
            subject=subject,
            extensions=cert_extensions,
            password=password,
        )

        extensions = exts.values()
        pre_sign_cert.send(
            sender=self.__class__,
            ca=self,
            csr=csr,
            expires=expires,
            algorithm=algorithm,
            subject=subject,
            extensions=extensions,
            password=password,
        )
        builder = get_cert_builder(expires)
        builder = builder.public_key(public_key)
        builder = builder.issuer_name(self.subject)
        builder = builder.subject_name(subject)

        for ext in extensions:
            builder = builder.add_extension(extval=ext.value, critical=ext.critical)

        signed_cert = builder.sign(private_key=self.key(password), algorithm=algorithm)
        post_sign_cert.send(sender=self.__class__, ca=self, cert=signed_cert)

        return signed_cert

    def generate_ocsp_key(
        self,
        profile: str = "ocsp",
        expires: Expires = 3,
        algorithm: ParsableHash = None,
        password: Optional[Union[str, bytes]] = None,
        key_size: Optional[int] = None,
        key_type: ParsableKeyType = "RSA",
        ecc_curve: Optional[ec.EllipticCurve] = None,
        autogenerated: bool = True,
    ) -> Tuple[str, str, "Certificate"]:
        """Generate OCSP keys for this CA.

        Parameters
        ----------

        profile : str, optional
            The profile to use for generating the certificate. The default is ``"ocsp"``.
        expires : int or datetime, optional
            Number of days or datetime when this certificate expires. The default is ``3`` (OCSP certificates
            are usually renewed frequently).
        algorithm : str, optional
            Passed to :py:func:`~django_ca.utils.parse_hash_algorithm` and defaults to
            :ref:`CA_DIGEST_ALGORITHM <settings-ca-digest-algorithm>`.
        password : bytes, optional
            The password to the CA as bytes, if its private key is encrypted.
        key_size : int, optional
            The key size of the private key, defaults to :ref:`CA_DEFAULT_KEY_SIZE
            <settings-ca-default-key-size>`.
        key_type : {"RSA", "DSA", "ECC", "EdDSA", "Ed448"}, optional
            The private key type to use, the default is ``"RSA"``.
        ecc_curve : :py:class:`~cg:cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve`, optional
            An elliptic curve to use for ECC keys. This parameter is ignored if ``key_type`` is not ``"ECC"``.
            Defaults to the :ref:`CA_DEFAULT_ECC_CURVE <settings-ca-default-ecc-curve>`.
        autogenerated : bool, optional
            Set the ``autogenerated`` flag of the certificate. ``True`` by default, since this method is
            usually invoked by regular cron jobs.
        """

        password = password or self.get_password()

        # DSA private keys can only sign DSA keys, hash algorithm for DSA keys must be SHA1
        if isinstance(self.key(password), dsa.DSAPrivateKey):
            key_type = "DSA"
        if key_type == "DSA":
            algorithm = hashes.SHA256()

        validate_key_parameters(key_size, key_type, ecc_curve)
        expires = parse_expires(expires)
        algorithm = parse_hash_algorithm(algorithm)
        safe_serial = self.serial.replace(":", "")

        # generate the private key
        private_key = generate_private_key(key_size, key_type, ecc_curve)
        private_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        private_path = ca_storage.generate_filename(f"ocsp/{safe_serial}.key")

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(self.pub.loaded.subject)
            .sign(private_key, hashes.SHA256())
        )

        # TODO: The subject we pass is just a guess - see what public CAs do!?
        # TODO: We never pass expires, we must add it and test the value
        cert = Certificate.objects.create_cert(
            ca=self,
            csr=csr,
            profile=profiles[profile],
            subject=self.subject,
            algorithm=algorithm,
            autogenerated=autogenerated,
            password=password,
            add_ocsp_url=False,
        )

        cert_path = ca_storage.generate_filename(f"ocsp/{safe_serial}.pem")

        for path, contents in [(private_path, private_pem), (cert_path, cert.pub.pem.encode())]:
            if ca_storage.exists(path):
                with ca_storage.open(path, "wb") as stream:
                    stream.write(contents)
            else:
                ca_storage.save(path, ContentFile(contents))
        return private_path, cert_path, cert

    def get_authority_information_access_extension(
        self,
    ) -> Optional[x509.Extension[x509.AuthorityInformationAccess]]:
        """Get the AuthorityInformationAccess extension to use in certificates signed by this CA."""
        # TODO: this function is not used outside of the test suite
        if not self.issuer_url and not self.ocsp_url:
            return None

        descriptions = []
        if self.ocsp_url:
            descriptions.append(
                x509.AccessDescription(
                    access_method=AuthorityInformationAccessOID.OCSP,
                    access_location=parse_general_name(self.ocsp_url),
                )
            )
        if self.issuer_url:
            descriptions.append(
                x509.AccessDescription(
                    access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                    access_location=parse_general_name(self.issuer_url),
                )
            )

        value = x509.AuthorityInformationAccess(descriptions=descriptions)
        return x509.Extension(oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS, critical=False, value=value)

    def get_authority_key_identifier(self) -> x509.AuthorityKeyIdentifier:
        """Return the AuthorityKeyIdentifier extension used in certificates signed by this CA."""
        try:
            ski = self.pub.loaded.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        except x509.ExtensionNotFound as ex:
            public_key = self.pub.loaded.public_key()
            if isinstance(public_key, _UNSUPPORTED_PRIVATE_KEY_TYPES):  # pragma: no cover
                # COVERAGE NOTE: This does not happen in reality, we never generate keys of this type
                raise TypeError("Cannot get AuthorityKeyIdentifier from this private key type.") from ex
            # TYPE NOTE: mypy does not currently recognize isinstance() check above
            return x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key)  # type: ignore[arg-type]
        else:
            return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski.value)

    def get_authority_key_identifier_extension(self) -> x509.Extension[x509.AuthorityKeyIdentifier]:
        """Get the AuthorityKeyIdentifier extension to use in certificates signed by this CA."""

        return x509.Extension(
            critical=False,
            oid=ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
            value=self.get_authority_key_identifier(),
        )

    def get_crl_certs(
        self, scope: Literal[None, "ca", "user", "attribute"], now: datetime
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
        expires: int = 86400,
        algorithm: Optional[hashes.HashAlgorithm] = None,
        password: Optional[Union[str, bytes]] = None,
        scope: Optional[Literal["ca", "user", "attribute"]] = None,
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

        expires : int
            The time in seconds when this CRL expires. Note that you should generate a new CRL until then.
        algorithm : :class:`~cg:cryptography.hazmat.primitives.hashes.HashAlgorithm`, optional
            The hash algorithm to use, defaults to :ref:`CA_DIGEST_ALGORITHM <settings-ca-digest-algorithm>`.
        password : bytes, optional
            Password used to load the private key of the certificate authority. If not passed, the private key
            is assumed to be unencrypted.
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
            ``crl_url`` if set.
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

        now = now_builder = timezone.now()
        if algorithm is None:
            algorithm = ca_settings.CA_DIGEST_ALGORITHM

        if timezone.is_aware(now_builder):
            now_builder = timezone.make_naive(now, tz.utc)
        else:
            now_builder = datetime.utcnow()

        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.pub.loaded.subject)
        builder = builder.last_update(now_builder)
        builder = builder.next_update(now_builder + timedelta(seconds=expires))

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
        elif scope == "ca" and ca_settings.CA_DEFAULT_HOSTNAME:
            crl_path = reverse("django_ca:ca-crl", kwargs={"serial": self.serial})
            parsed_full_name = [
                x509.UniformResourceIdentifier(f"http://{ca_settings.CA_DEFAULT_HOSTNAME}{crl_path}")
            ]
        elif scope in ("user", None) and self.crl_url:
            crl_url = [url.strip() for url in self.crl_url.split()]
            parsed_full_name = [x509.UniformResourceIdentifier(c) for c in crl_url]

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

        for cert in self.get_crl_certs(scope, now):
            builder = builder.add_revoked_certificate(cert.get_revocation())

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

        # increase crl_number for the given scope and save
        crl_number_data["scope"][counter] = crl_number + 1
        self.crl_number = json.dumps(crl_number_data)
        self.save()

        return builder.sign(private_key=self.key(password), algorithm=algorithm)

    def get_password(self) -> Optional[str]:
        """Get password for the private key from the ``CA_PASSWORDS`` setting."""
        return ca_settings.CA_PASSWORDS.get(self.serial)

    @property
    def pathlen(self) -> Optional[int]:
        """The ``pathlen`` attribute of the ``BasicConstraints`` extension (either an ``int`` or ``None``)."""

        try:
            ext = self.pub.loaded.extensions.get_extension_for_class(x509.BasicConstraints)
        except x509.ExtensionNotFound:  # pragma: no cover - extension should always be present
            return None
        return ext.value.path_length

    @property
    def max_pathlen(self) -> Optional[int]:
        """The maximum `pathlen` for any intermediate CAs signed by this CA.

        This value is either ``None``, if this and all parent CAs don't have a ``pathlen`` attribute, or an
        ``int`` if any parent CA has the attribute.
        """

        if self.parent is None:
            return self.pathlen

        max_parent = self.parent.max_pathlen

        if max_parent is None:
            return self.pathlen
        if self.pathlen is None:
            return max_parent - 1

        return min(self.pathlen, max_parent - 1)

    @property
    def allows_intermediate_ca(self) -> bool:
        """Whether this CA allows creating intermediate CAs."""

        max_pathlen = self.max_pathlen
        return max_pathlen is None or max_pathlen > 0

    @property
    def bundle(self) -> List["CertificateAuthority"]:
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
        if SSH_HOST_CA in self.x509_extensions:
            return True
        # COVERAGE NOTE: currently both extensions are always present
        return SSH_USER_CA in self.x509_extensions  # pragma: no cover

    class Meta:
        verbose_name = _("Certificate Authority")
        verbose_name_plural = _("Certificate Authorities")

    def __str__(self) -> str:
        return self.name


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

    @property
    def bundle(self) -> List[X509CertMixin]:
        """The complete certificate bundle. This includes all CAs as well as the certificates itself."""

        return [typing.cast(X509CertMixin, self)] + typing.cast(List[X509CertMixin], self.ca.bundle)

    @property
    def root(self) -> CertificateAuthority:
        """Get the root CA for this certificate."""

        return self.ca.root

    def __str__(self) -> str:
        return self.cn


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


class AcmeOrder(DjangoCAModel):
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

    objects = AcmeOrderManager.from_queryset(AcmeOrderQuerySet)()

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

    def add_authorizations(self, identifiers: Iterable["messages.Identifier"]) -> List["AcmeAuthorization"]:
        """Add :py:class:`~django_ca.models.AcmeAuthorization` instances for the given identifiers.

        Note that this method already adds the account authorization to the database. It does not verify if it
        already exists and will raise an IntegrityError if it does.

        Example::

            >>> from acme import messages
            >>> identifier = messages.Identifier(typ=messages.IDENTIFIER_FQDN, value='example.com')
            >>> order.add_authorizations([identifier])

        Parameters
        ----------
        identifiers : list of :py:class:`acme:acme.messages.Identifier`
            The identifiers for this for this order.

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

    objects = AcmeAuthorizationManager.from_queryset(AcmeAuthorizationQuerySet)()

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

    def get_challenges(self) -> List["AcmeChallenge"]:
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

    objects = AcmeChallengeManager.from_queryset(AcmeChallengeQuerySet)()

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
        """Boolean defining if an challenge is "usable", meaning it still can be used in order validation.

        A challenge is usable if it is in the "pending" or "invalid status and the authorization is usable.
        """
        states = (AcmeChallenge.STATUS_PENDING, AcmeChallenge.STATUS_INVALID)
        return self.status in states and self.auth.usable


class AcmeCertificate(DjangoCAModel):
    """Intermediate model for certificates to be issued via ACME."""

    objects = AcmeCertificateManager.from_queryset(AcmeCertificateQuerySet)()

    slug = models.SlugField(unique=True, default=acme_slug)
    order = models.OneToOneField(AcmeOrder, on_delete=models.CASCADE)
    cert = models.OneToOneField(Certificate, on_delete=models.CASCADE, null=True)
    csr = models.TextField(verbose_name=_("CSR"))

    class Meta:
        verbose_name = _("ACME Certificate")
        verbose_name_plural = _("ACME Certificate")

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

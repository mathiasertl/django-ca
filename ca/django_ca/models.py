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
import binascii
import hashlib
import importlib
import itertools
import json
import logging
import random
import re
from datetime import datetime
from datetime import timedelta

import pytz

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import ExtensionOID

from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.core.validators import URLValidator
from django.db import models
from django.urls import reverse
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.utils.encoding import force_bytes
from django.utils.encoding import force_str
from django.utils.functional import cached_property
from django.utils.text import slugify
from django.utils.translation import gettext_lazy as _

from . import ca_settings
from .acme.constants import BASE64_URL_ALPHABET
from .acme.constants import IdentifierType
from .acme.constants import Status
from .constants import ReasonFlags
from .extensions import OID_TO_EXTENSION
from .extensions import AuthorityInformationAccess
from .extensions import AuthorityKeyIdentifier
from .extensions import BasicConstraints
from .extensions import CertificatePolicies
from .extensions import CRLDistributionPoints
from .extensions import ExtendedKeyUsage
from .extensions import FreshestCRL
from .extensions import InhibitAnyPolicy
from .extensions import IssuerAlternativeName
from .extensions import KeyUsage
from .extensions import NameConstraints
from .extensions import OCSPNoCheck
from .extensions import PolicyConstraints
from .extensions import PrecertificateSignedCertificateTimestamps
from .extensions import PrecertPoison
from .extensions import SubjectAlternativeName
from .extensions import SubjectKeyIdentifier
from .extensions import TLSFeature
from .extensions import get_extension_name
from .managers import AcmeAccountManager
from .managers import AcmeAuthorizationManager
from .managers import AcmeCertificateManager
from .managers import AcmeChallengeManager
from .managers import AcmeOrderManager
from .managers import CertificateAuthorityManager
from .managers import CertificateManager
from .querysets import AcmeAccountQuerySet
from .querysets import AcmeAuthorizationQuerySet
from .querysets import AcmeCertificateQuerySet
from .querysets import AcmeChallengeQuerySet
from .querysets import AcmeOrderQuerySet
from .querysets import CertificateAuthorityQuerySet
from .querysets import CertificateQuerySet
from .signals import post_revoke_cert
from .signals import pre_revoke_cert
from .subject import Subject
from .utils import add_colons
from .utils import ca_storage
from .utils import format_name
from .utils import generate_private_key
from .utils import get_crl_cache_key
from .utils import int_to_hex
from .utils import multiline_url_validator
from .utils import parse_encoding
from .utils import parse_general_name
from .utils import parse_hash_algorithm
from .utils import read_file
from .utils import validate_key_parameters

log = logging.getLogger(__name__)


def acme_slug():
    """Default function to get an ACME conforming slug."""
    return get_random_string(length=12)


def acme_order_expires():
    """Default function for the expiry of an ACME order."""
    return timezone.now() + ca_settings.ACME_ORDER_VALIDITY


def acme_token():
    """Generate an ACME token for this challenge.

    Note that currently all challenges have the same requirements on tokens, except for DNS challenges
    which seem to allow padding ("=") characters. We ignore the '=' for DNS challenges as our tokens are
    already longer then required.
    """
    return get_random_string(64, allowed_chars=BASE64_URL_ALPHABET)


def validate_past(value):
    """Validate that a given datetime is not in the future."""
    if value > timezone.now():
        raise ValidationError(_('Date must be in the past!'))


def json_validator(value):
    """Validated that the given data is valid JSON."""
    try:
        json.loads(value)
    except Exception as e:
        raise ValidationError(_('Must be valid JSON: %(message)s') % {'message': str(e)}) from e


def pem_validator(value):
    """Validator that ensures a value is a valid PEM public certificate."""

    if not value.startswith('-----BEGIN PUBLIC KEY-----\n'):
        raise ValidationError(_('Not a valid PEM.'))
    if not value.endswith('\n-----END PUBLIC KEY-----'):
        raise ValidationError(_('Not a valid PEM.'))

    # TODO: for some reason cryptography cannot load LE account PEMs
    #try:
    #    x509.load_pem_x509_certificate(force_bytes(value), default_backend())
    #except Exception as ex:  # pylint: disable=broad-except
    #    raise ValidationError(_('Not a valid PEM.')) from ex


class DjangoCAModelMixin:
    """Mixin with shared properties for all django-ca models."""

    @property
    def admin_change_url(self):
        """Change URL in the admin interface for the given class."""
        return reverse('admin:%s_%s_change' % (self._meta.app_label, self._meta.model_name), args=(self.pk, ))


class Watcher(models.Model):
    """A watcher represents an email address that will receive notifications about expiring certificates."""
    name = models.CharField(max_length=64, blank=True, default='', verbose_name=_('CommonName'))
    mail = models.EmailField(verbose_name=_('E-Mail'), unique=True)

    @classmethod
    def from_addr(cls, addr):
        """Class constructor that creates an instance from an email address."""
        name = ''
        match = re.match(r'(.*?)\s*<(.*)>', addr)
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

    def __str__(self):
        if self.name:
            return '%s <%s>' % (self.name, self.mail)
        return self.mail


class X509CertMixin(DjangoCAModelMixin, models.Model):
    """Mixin class with common attributes for Certificates and Certificate Authorities."""
    # pylint: disable=too-many-instance-attributes,too-many-public-methods
    # X.509 certificates are complex. Sorry.

    # reasons are defined in http://www.ietf.org/rfc/rfc3280.txt
    REVOCATION_REASONS = (
        (ReasonFlags.aa_compromise.name, _('Attribute Authority compromised')),
        (ReasonFlags.affiliation_changed.name, _('Affiliation changed')),
        (ReasonFlags.ca_compromise.name, _('CA compromised')),
        (ReasonFlags.certificate_hold.name, _('On Hold')),
        (ReasonFlags.cessation_of_operation.name, _('Cessation of operation')),
        (ReasonFlags.key_compromise.name, _('Key compromised')),
        (ReasonFlags.privilege_withdrawn.name, _('Privilege withdrawn')),
        (ReasonFlags.remove_from_crl.name, _('Removed from CRL')),
        (ReasonFlags.superseded.name, _('Superseded')),
        (ReasonFlags.unspecified.name, _('Unspecified')),
    )

    created = models.DateTimeField(auto_now=True)

    valid_from = models.DateTimeField(blank=False)
    expires = models.DateTimeField(null=False, blank=False)

    pub = models.TextField(verbose_name=_('Public key'))
    cn = models.CharField(max_length=128, verbose_name=_('CommonName'))
    serial = models.CharField(max_length=64, unique=True)

    # revocation information
    revoked = models.BooleanField(default=False)
    revoked_date = models.DateTimeField(null=True, blank=True, verbose_name=_('Revoked on'),
                                        validators=[validate_past])
    revoked_reason = models.CharField(
        max_length=32, blank=True, default='', verbose_name=_('Reason for revokation'),
        choices=REVOCATION_REASONS)
    compromised = models.DateTimeField(
        null=True, blank=True, verbose_name=_('Date of compromise'), validators=[validate_past],
        help_text=_('Optional: When this certificate was compromised. You can change this date later.'))

    _x509 = None

    class Meta:
        abstract = True

    def get_revocation_reason(self):
        """Get the revocation reason of this certificate."""
        if self.revoked is False:
            return None

        return x509.ReasonFlags[self.revoked_reason]

    def get_compromised_time(self):
        """Return when this certificate was compromised as a *naive* datetime.

        Returns ``None`` if the time is not known **or** if the certificate is not revoked.
        """
        if self.revoked is False or not self.compromised:
            return None

        if timezone.is_aware(self.compromised):
            # convert datetime object to UTC and make it naive
            return timezone.make_naive(self.compromised, pytz.utc)

        return self.compromised

    def get_revocation_time(self):
        """Get the revocation time as naive datetime."""
        if self.revoked is False:
            return None

        if timezone.is_aware(self.revoked_date):
            # convert datetime object to UTC and make it naive
            return timezone.make_naive(self.revoked_date, pytz.utc)

        return self.revoked_date

    @property
    def x509(self):
        """The underlying :py:class:`cg:cryptography.x509.Certificate`."""
        if self._x509 is None:
            backend = default_backend()
            self._x509 = x509.load_pem_x509_certificate(force_bytes(self.pub), backend)
        return self._x509

    @x509.setter
    def x509(self, value):
        """Setter for the underlying :py:class:`cg:cryptography.x509.Certificate`."""
        self._x509 = value
        self.pub = force_str(self.dump_certificate(Encoding.PEM))
        self.cn = self.subject.get('CN', '')  # pylint: disable=invalid-name
        self.expires = self.not_after
        self.valid_from = self.not_before
        if settings.USE_TZ:
            self.expires = timezone.make_aware(self.expires, timezone=pytz.utc)
            self.valid_from = timezone.make_aware(self.valid_from, timezone=pytz.utc)

        self.serial = int_to_hex(value.serial_number)

    ##########################
    # Certificate properties #
    ##########################

    @property
    def algorithm(self):
        """A shortcut for :py:attr:`~cg:cryptography.x509.Certificate.signature_hash_algorithm`."""
        return self.x509.signature_hash_algorithm

    def dump_certificate(self, encoding=Encoding.PEM):
        """Get the certificate as bytes in the requested format.

        Parameters
        ----------

        encoding : attr of :py:class:`~cg:cryptography.hazmat.primitives.serialization.Encoding`, optional
            The format to return, defaults to ``Encoding.PEM``.
        """

        return self.x509.public_bytes(encoding=encoding)

    def get_digest(self, algo):
        """Get the digest for a certificate as string, including colons."""
        algo = getattr(hashes, algo.upper())()
        return add_colons(binascii.hexlify(self.x509.fingerprint(algo)).upper().decode('utf-8'))

    def get_filename(self, ext, bundle=False):
        """Get a filename safe for any file system and OS for this certificate based on the common name.

        Parameters
        ----------

        ext : str
            The filename extension to use (e.g. 'pem').
        bundle : bool, optional
            Adds "_bundle" as suffix.
        """
        slug = slugify(self.cn.replace('.', '_'))

        if bundle is True:
            return '%s_bundle.%s' % (slug, ext.lower())
        return '%s.%s' % (slug, ext.lower())

    def get_revocation(self):
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
            raise ValueError('Certificate is not revoked.')

        revoked_cert = x509.RevokedCertificateBuilder().serial_number(
            self.x509.serial_number).revocation_date(self.revoked_date)

        reason = self.get_revocation_reason()
        if reason != x509.ReasonFlags.unspecified:
            # RFC 5270, 5.3.1: "reason code CRL entry extension SHOULD be absent instead of using the
            # unspecified (0) reasonCode value"
            revoked_cert = revoked_cert.add_extension(x509.CRLReason(reason), critical=False)

        compromised = self.get_compromised_time()
        if compromised:
            # RFC 5280, 5.3.2 says that this extension MUST be non-critical
            revoked_cert = revoked_cert.add_extension(x509.InvalidityDate(compromised), critical=False)

        return revoked_cert.build(default_backend())

    @property
    def hpkp_pin(self):
        """The HPKP public key pin for this certificate.

        Inspired by https://github.com/luisgf/hpkp-python/blob/master/hpkp.py.

        .. seealso:: https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning
        """

        public_key_raw = self.x509.public_key().public_bytes(
            encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)
        public_key_hash = hashlib.sha256(public_key_raw).digest()
        return base64.b64encode(public_key_hash).decode('utf-8')

    @property
    def issuer(self):
        """The certificate issuer field as :py:class:`~django_ca.subject.Subject`."""
        return Subject([(s.oid, s.value) for s in self.x509.issuer])

    @property
    def not_before(self):
        """Date/Time this certificate was created"""
        return self.x509.not_valid_before

    @property
    def not_after(self):
        """Date/Time this certificate expires."""
        return self.x509.not_valid_after

    def revoke(self, reason='', compromised=None):
        """Revoke the current certificate.

        This function emits the ``pre_revoke_cert`` and ``post_revoke_cert`` signals.

        Parameters
        ----------

        reason : :py:class:`~django_ca.constants.ReasonFlags`, optional
            The reason for revocation, defaults to ``ReasonFlags.unspecified``.
        compromised : datetime, optional
            When this certificate was compromised.
        """
        if not reason:
            reason = ReasonFlags.unspecified

        pre_revoke_cert.send(sender=self.__class__, cert=self, reason=reason)

        self.revoked = True
        self.revoked_date = timezone.now()
        self.revoked_reason = reason.name
        self.compromised = compromised
        self.save()

        post_revoke_cert.send(sender=self.__class__, cert=self)

    @property
    def subject(self):
        """The certificates subject as :py:class:`~django_ca.subject.Subject`."""
        return Subject([(s.oid, s.value) for s in self.x509.subject])

    @property
    def distinguished_name(self):
        """The certificates distinguished name formatted as string."""
        return format_name(self.x509.subject)
    distinguished_name.fget.short_description = 'Distinguished Name'

    ###################
    # X509 extensions #
    ###################

    @cached_property
    def _x509_extensions(self):
        return {e.oid: e for e in self.x509.extensions}

    def get_x509_extension(self, oid):
        """Get extension by a cryptography OID."""
        return self._x509_extensions.get(oid)

    @cached_property
    def _sorted_extensions(self):
        # NOTE: We need the dotted_string in the sort key if we have multiple unknown extensions, which then
        #       show up as "Unknown OID" and have to be sorted by oid
        return list(sorted(self._x509_extensions.values(),
                           key=lambda e: (get_extension_name(e), e.oid.dotted_string)))

    @cached_property
    def extension_fields(self):
        """List of all extensions fields for this certificate."""
        fields = []

        for ext in self._sorted_extensions:
            if ext.oid in OID_TO_EXTENSION:
                fields.append(OID_TO_EXTENSION[ext.oid].key)

            # extension that does not support new extension framework
            else:
                log.warning('Unknown extension encountered: %s (%s)',
                            get_extension_name(ext), ext.oid.dotted_string)
                fields.append(ext)
        return fields

    @cached_property
    def extensions(self):
        """List of all extensions for this certificate."""
        exts = []

        for ext in self._sorted_extensions:
            if ext.oid in OID_TO_EXTENSION:
                exts.append(getattr(self, OID_TO_EXTENSION[ext.oid].key))

            # extension that does not support new extension framework
            else:
                exts.append(ext)
        return exts

    @cached_property
    def authority_information_access(self):  # pylint: disable=inconsistent-return-statements
        """The :py:class:`~django_ca.extensions.AuthorityInformationAccess` extension or ``None`` if not
        present."""
        ext = self.get_x509_extension(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        if ext is not None:
            return AuthorityInformationAccess(ext)

    @cached_property
    def authority_key_identifier(self):  # pylint: disable=inconsistent-return-statements
        """The :py:class:`~django_ca.extensions.AuthorityKeyIdentifier` extension or ``None`` if not
        present."""
        ext = self.get_x509_extension(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        if ext is not None:
            return AuthorityKeyIdentifier(ext)

    @cached_property
    def basic_constraints(self):  # pylint: disable=inconsistent-return-statements
        """The :py:class:`~django_ca.extensions.BasicConstraints` extension or ``None`` if not present."""
        ext = self.get_x509_extension(ExtensionOID.BASIC_CONSTRAINTS)
        if ext is not None:
            return BasicConstraints(ext)

    @cached_property
    def crl_distribution_points(self):  # pylint: disable=inconsistent-return-statements
        """The :py:class:`~django_ca.extensions.CRLDistributionPoints` extension or ``None`` if not
        present."""
        ext = self.get_x509_extension(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        if ext is not None:
            return CRLDistributionPoints(ext)

    @cached_property
    def certificate_policies(self):  # pylint: disable=inconsistent-return-statements
        """The :py:class:`~django_ca.extensions.CertificatePolicies` extension or ``None`` if not present."""
        ext = self.get_x509_extension(ExtensionOID.CERTIFICATE_POLICIES)
        if ext is not None:
            return CertificatePolicies(ext)

    @cached_property
    def freshest_crl(self):  # pylint: disable=inconsistent-return-statements
        """The :py:class:`~django_ca.extensions.FreshestCRL` extension or ``None`` if not present."""
        ext = self.get_x509_extension(ExtensionOID.FRESHEST_CRL)
        if ext is not None:
            return FreshestCRL(ext)

    @cached_property
    def inhibit_any_policy(self):  # pylint: disable=inconsistent-return-statements
        """The :py:class:`~django_ca.extensions.InhibitAnyPolicy` extension or ``None`` if not present."""
        ext = self.get_x509_extension(ExtensionOID.INHIBIT_ANY_POLICY)
        if ext is not None:
            return InhibitAnyPolicy(ext)

    @cached_property
    def issuer_alternative_name(self):  # pylint: disable=inconsistent-return-statements
        """The :py:class:`~django_ca.extensions.IssuerAlternativeName` extension or ``None`` if not
        present."""
        ext = self.get_x509_extension(ExtensionOID.ISSUER_ALTERNATIVE_NAME)
        if ext is not None:
            return IssuerAlternativeName(ext)

    @cached_property
    def policy_constraints(self):  # pylint: disable=inconsistent-return-statements
        """The :py:class:`~django_ca.extensions.PolicyConstraints` extension or ``None`` if not present."""
        ext = self.get_x509_extension(ExtensionOID.POLICY_CONSTRAINTS)
        if ext is not None:
            return PolicyConstraints(ext)

    @cached_property
    def key_usage(self):  # pylint: disable=inconsistent-return-statements
        """The :py:class:`~django_ca.extensions.KeyUsage` extension or ``None`` if not present."""
        ext = self.get_x509_extension(ExtensionOID.KEY_USAGE)
        if ext is not None:
            return KeyUsage(ext)

    @cached_property
    def extended_key_usage(self):  # pylint: disable=inconsistent-return-statements
        """The :py:class:`~django_ca.extensions.ExtendedKeyUsage` extension or ``None`` if not present."""
        ext = self.get_x509_extension(ExtensionOID.EXTENDED_KEY_USAGE)
        if ext is not None:
            return ExtendedKeyUsage(ext)

    @cached_property
    def name_constraints(self):  # pylint: disable=inconsistent-return-statements
        """The :py:class:`~django_ca.extensions.NameConstraints` extension or ``None`` if not present."""
        ext = self.get_x509_extension(ExtensionOID.NAME_CONSTRAINTS)
        if ext is not None:
            return NameConstraints(ext)

    @cached_property
    def ocsp_no_check(self):  # pylint: disable=inconsistent-return-statements
        """The :py:class:`~django_ca.extensions.OCSPNoCheck` extension or ``None`` if not present."""
        ext = self.get_x509_extension(ExtensionOID.OCSP_NO_CHECK)
        if ext is not None:
            return OCSPNoCheck(ext)

    @cached_property
    def precert_poison(self):  # pylint: disable=inconsistent-return-statements
        """The :py:class:`~django_ca.extensions.PrecertPoison` extension or ``None`` if not present."""
        ext = self.get_x509_extension(ExtensionOID.PRECERT_POISON)
        if ext is not None:
            return PrecertPoison(ext)

    @cached_property
    def precertificate_signed_certificate_timestamps(self):  # pylint: disable=inconsistent-return-statements
        """The :py:class:`~django_ca.extensions.PrecertificateSignedCertificateTimestamps` extension or
        ``None`` if not present."""
        ext = self.get_x509_extension(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
        if ext is not None:
            return PrecertificateSignedCertificateTimestamps(ext)

    @cached_property
    def subject_alternative_name(self):  # pylint: disable=inconsistent-return-statements
        """The :py:class:`~django_ca.extensions.SubjectAlternativeName` extension or ``None`` if not
        present."""
        ext = self.get_x509_extension(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        if ext is not None:
            return SubjectAlternativeName(ext)

    @cached_property
    def subject_key_identifier(self):  # pylint: disable=inconsistent-return-statements
        """The :py:class:`~django_ca.extensions.SubjectKeyIdentifier` extension or ``None`` if not present."""
        ext = self.get_x509_extension(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        if ext is not None:
            return SubjectKeyIdentifier(ext)

    @cached_property
    def tls_feature(self):  # pylint: disable=inconsistent-return-statements
        """The :py:class:`~django_ca.extensions.TLSFeature` extension or ``None`` if not present."""
        ext = self.get_x509_extension(ExtensionOID.TLS_FEATURE)
        if ext is not None:
            return TLSFeature(ext)


class CertificateAuthority(X509CertMixin):
    """Model representing a x509 Certificate Authority."""

    objects = CertificateAuthorityManager.from_queryset(CertificateAuthorityQuerySet)()

    name = models.CharField(max_length=32, help_text=_('A human-readable name'), unique=True)
    """Human-readable name of the CA, only used for displaying the CA."""
    enabled = models.BooleanField(default=True)
    parent = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True,
                               related_name='children')
    private_key_path = models.CharField(max_length=256, help_text=_('Path to the private key.'))

    # various details used when signing certs
    crl_url = models.TextField(blank=True, default='', validators=[multiline_url_validator],
                               verbose_name=_('CRL URLs'),
                               help_text=_("URLs, one per line, where you can retrieve the CRL."))
    crl_number = models.TextField(
        default='{"scope": {}}', blank=True, verbose_name=_('CRL Number'), validators=[json_validator],
        help_text=_("Data structure to store the CRL number (see RFC 5280, 5.2.3) depending on the scope.")
    )
    issuer_url = models.URLField(blank=True, null=True, verbose_name=_('Issuer URL'),
                                 help_text=_("URL to the certificate of this CA (in DER format)."))
    ocsp_url = models.URLField(blank=True, null=True, verbose_name=_('OCSP responder URL'),
                               help_text=_("URL of a OCSP responser for the CA."))
    issuer_alt_name = models.CharField(blank=True, max_length=255, default='',
                                       verbose_name=_('issuerAltName'), help_text=_("URL for your CA."))

    caa_identity = models.CharField(
        blank=True, max_length=32, verbose_name=_('CAA identity'),
        help_text=_('CAA identity for this CA (NOTE: Not currently used!).')
    )
    website = models.URLField(blank=True, help_text=_('Website for your CA.'))
    terms_of_service = models.URLField(blank=True, verbose_name='Terms of Service',
                                       help_text=_('URL to Terms of Service for this CA'))

    # ACMEv2 fields
    acme_enabled = models.BooleanField(
        default=False, verbose_name=_('Enable ACME'),
        help_text=_("Whether it is possible to use ACME for this CA."))
    acme_requires_contact = models.BooleanField(default=True, verbose_name='Requires contact', help_text=_(
        'If this CA requires a contact address during account registration.'))
    # CAA record and website are general fields

    _key = None

    def key(self, password):
        """The CAs private key as private key.

        .. seealso:: :py:func:`~cg:cryptography.hazmat.primitives.serialization.load_pem_private_key`.
        """
        if self._key is None:
            key_data = read_file(self.private_key_path)

            self._key = load_pem_private_key(key_data, password, default_backend())
        return self._key

    @property
    def key_exists(self):
        """``True`` if the private key is locally accessible."""
        if self._key is not None:
            return True
        return ca_storage.exists(self.private_key_path)

    def cache_crls(self, password=None, algorithm=None):  # pylint: disable=too-many-locals
        """Function to cache all CRLs for this CA."""

        password = password or self.get_password()
        ca_key = self.key(password)
        if isinstance(ca_key, dsa.DSAPrivateKey) and algorithm is None:
            algorithm = hashes.SHA1()

        for config in ca_settings.CA_CRL_PROFILES.values():
            overrides = config.get('OVERRIDES', {}).get(self.serial, {})

            if overrides.get('skip'):
                continue

            algorithm = algorithm or parse_hash_algorithm(overrides.get('algorithm', config.get('algorithm')))
            expires = overrides.get('expires', config.get('expires', 86400))
            scope = overrides.get('scope', config.get('scope'))
            full_name = overrides.get('full_name', config.get('full_name'))
            relative_name = overrides.get('relative_name', config.get('relative_name'))
            encodings = overrides.get('encodings', config.get('encodings', ['DER', ]))
            crl = None  # only compute crl when it is actually needed

            for encoding in encodings:
                encoding = parse_encoding(encoding)
                cache_key = get_crl_cache_key(self.serial, algorithm, encoding, scope=scope)

                if expires >= 600:  # pragma: no branch
                    # for longer expiries we substract a random value so that regular CRL regeneration is
                    # distributed a bit
                    cache_expires = expires - random.randint(1, 5) * 60

                if cache.get(cache_key) is None:
                    if crl is None:
                        crl = self.get_crl(expires=expires, algorithm=algorithm, password=password,
                                           scope=scope, full_name=full_name, relative_name=relative_name)

                    encoded_crl = crl.public_bytes(encoding)
                    cache.set(cache_key, encoded_crl, cache_expires)

    def generate_ocsp_key(self, profile='ocsp', expires=3, algorithm=None, password=None,
                          key_size=None, key_type=None, ecc_curve=None, autogenerated=True):
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
        key_type : {"RSA", "DSA", "ECC"}, optional
            The private key type to use, the default is ``"RSA"``.
        ecc_curve : str, optional
            Passed to :py:func:`~django_ca.utils.parse_key_curve`, defaults to the :ref:`CA_DEFAULT_ECC_CURVE
            <settings-ca-default-ecc-curve>`.
        autogenerated : bool, optional
            Set the "autogenerated" flag of the certificate. ``True`` by default, since this method is usually
            invoked in an automated cron-like fashion.
        """
        # pylint: disable=too-many-arguments,too-many-locals
        # OCSP is pretty complex, there is no way to trim down the arguments w/o losing features.

        password = password or self.get_password()
        if key_type is None:
            ca_key = self.key(password)
            if isinstance(ca_key, dsa.DSAPrivateKey):
                key_type = 'DSA'
                algorithm = 'SHA1'

        key_size, key_type, ecc_curve = validate_key_parameters(key_size, key_type, ecc_curve)
        if isinstance(expires, int):
            expires = timedelta(days=expires)
        algorithm = parse_hash_algorithm(algorithm)

        # generate the private key
        private_key = generate_private_key(key_size, key_type, ecc_curve)
        private_pem = private_key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8,
                                                encryption_algorithm=serialization.NoEncryption())
        private_path = ca_storage.generate_filename('ocsp/%s.key' % self.serial.replace(':', ''))

        csr = x509.CertificateSigningRequestBuilder().subject_name(self.x509.subject).sign(
            private_key, hashes.SHA256(), default_backend())

        # TODO: The subject we pass is just a guess - see what public CAs do!?  pylint: disable=fixme
        cert = Certificate.objects.create_cert(ca=self, csr=csr, profile=profile, subject=self.subject,
                                               algorithm=algorithm, autogenerated=autogenerated,
                                               password=password, add_ocsp_url=False)

        cert_path = ca_storage.generate_filename('ocsp/%s.pem' % self.serial.replace(':', ''))
        cert_pem = cert.dump_certificate(encoding=Encoding.PEM)

        for path, contents in [(private_path, private_pem), (cert_path, cert_pem)]:
            if ca_storage.exists(path):
                with ca_storage.open(path, 'wb') as stream:
                    stream.write(contents)
            else:
                ca_storage.save(path, ContentFile(contents))
        return private_path, cert_path, cert

    def get_authority_key_identifier(self):
        """Return the AuthorityKeyIdentifier extension used in certificates signed by this CA.

        Returns
        -------

        :py:class:`~cg:cryptography.x509.AuthorityKeyIdentifier`
            The value to use for this extension.
        """

        try:
            ski = self.x509.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        except x509.ExtensionNotFound:
            return x509.AuthorityKeyIdentifier.from_issuer_public_key(self.x509.public_key())
        else:
            return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski.value)

    def get_authority_key_identifier_extension(self):
        """Get the AuthorityKeyIdentifier extension to use in certificates signed by this CA.

        Returns
        -------

        :py:class:`~django_ca.extensions.AuthorityKeyIdentifier`
            The extension to use.
        """

        return AuthorityKeyIdentifier(x509.Extension(
            critical=AuthorityKeyIdentifier.default_critical,
            oid=AuthorityKeyIdentifier.oid,
            value=self.get_authority_key_identifier()
        ))

    def get_crl(self, expires=86400, algorithm=None, password=None, scope=None, counter=None, **kwargs):
        """Generate a Certificate Revocation List (CRL).

        The ``full_name`` and ``relative_name`` parameters describe how to retrieve the CRL and are used in
        the `Issuing Distribution Point extension <https://tools.ietf.org/html/rfc5280.html#section-5.2.5>`_.
        The former defaults to the ``crl_url`` field, pass ``None`` to not include the value. At most one of
        the two may be set.

        Parameters
        ----------

        expires : int
            The time in seconds when this CRL expires. Note that you should generate a new CRL until then.
        algorithm : :py:class:`~cg:cryptography.hazmat.primitives.hashes.Hash` or str, optional
            The hash algorithm to use, passed to :py:func:`~django_ca.utils.parse_hash_algorithm`. The default
            is to use :ref:`CA_DIGEST_ALGORITHM <settings-ca-digest-algorithm>`.
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
        full_name : list of str or :py:class:`~cg:cryptography.x509.GeneralName`, optional
            List of general names to use in the Issuing Distribution Point extension. If not passed, use
            ``crl_url`` if set.
        relative_name : :py:class:`~cg:cryptography.x509.RelativeDistinguishedName`, optional
            Used in Issuing Distribution Point extension, retrieve the CRL relative to the issuer.

        Returns
        -------

        bytes
            The CRL in the requested format.
        """
        # pylint: disable=too-many-statements,too-many-branches,too-many-locals,too-many-arguments
        # It's not easy to create a CRL. Sorry.

        if scope is not None and scope not in ['ca', 'user', 'attribute']:
            raise ValueError('Scope must be either None, "ca", "user" or "attribute"')

        now = now_builder = timezone.now()
        algorithm = parse_hash_algorithm(algorithm)

        if timezone.is_aware(now_builder):
            now_builder = timezone.make_naive(now, pytz.utc)
        else:
            now_builder = datetime.utcnow()

        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.x509.subject)
        builder = builder.last_update(now_builder)
        builder = builder.next_update(now_builder + timedelta(seconds=expires))

        if kwargs.get('full_name'):
            full_name = kwargs['full_name']
            full_name = [parse_general_name(n) for n in full_name]

        # CRLs for root CAs with scope "ca" (or no scope) do not add an IssuingDistributionPoint extension by
        # default. For full path validation with CRLs, the CRL is also used for validating the Root CA (which
        # does not contain a CRL Distribution Point). But the Full Name in the CRL IDP and the CA CRL DP have
        # to match. See also:
        #       https://github.com/mathiasertl/django-ca/issues/64
        elif scope in ('ca', None) and self.parent is None:
            full_name = None

        # If CA_DEFAULT_HOSTNAME is set, CRLs with scope "ca" add the same URL in the IssuingDistributionPoint
        # extension that is also added in the CRL Distribution Points extension for CAs issued by this CA.
        # See also:
        #       https://github.com/mathiasertl/django-ca/issues/64
        elif scope == 'ca' and ca_settings.CA_DEFAULT_HOSTNAME:
            crl_path = reverse('django_ca:ca-crl', kwargs={'serial': self.serial})
            full_name = [x509.UniformResourceIdentifier(
                'http://%s%s' % (ca_settings.CA_DEFAULT_HOSTNAME, crl_path)
            )]
        elif scope in ('user', None) and self.crl_url:
            crl_url = [url.strip() for url in self.crl_url.split()]
            full_name = [x509.UniformResourceIdentifier(c) for c in crl_url]
        else:
            full_name = None

        # Keyword arguments for the IssuingDistributionPoint extension
        idp_kwargs = {
            'only_contains_ca_certs': False,
            'only_contains_user_certs': False,
            'indirect_crl': False,
            'only_contains_attribute_certs': False,
            'only_some_reasons': None,
            'full_name': full_name,
            'relative_name': kwargs.get('relative_name'),
        }

        ca_qs = self.children.filter(expires__gt=now).revoked()
        cert_qs = self.certificate_set.filter(expires__gt=now).revoked()

        if scope == 'ca':
            certs = ca_qs
            idp_kwargs['only_contains_ca_certs'] = True
        elif scope == 'user':
            certs = cert_qs
            idp_kwargs['only_contains_user_certs'] = True
        elif scope == 'attribute':
            # sorry, nothing we support right now
            certs = []
            idp_kwargs['only_contains_attribute_certs'] = True
        else:
            certs = itertools.chain(ca_qs, cert_qs)

        for cert in certs:
            builder = builder.add_revoked_certificate(cert.get_revocation())

        # We can only add the IDP extension if one of these properties is set, see RFC 5280, 5.2.5.
        add_idp = idp_kwargs['only_contains_attribute_certs'] or idp_kwargs['only_contains_user_certs'] \
            or idp_kwargs['only_contains_ca_certs'] or idp_kwargs['full_name'] or idp_kwargs['relative_name']

        if add_idp:  # pragma: no branch
            builder = builder.add_extension(x509.IssuingDistributionPoint(**idp_kwargs), critical=True)

        # Add AuthorityKeyIdentifier from CA
        aki = self.get_authority_key_identifier()
        builder = builder.add_extension(aki, critical=False)

        # Add the CRLNumber extension (RFC 5280, 5.2.3)
        if counter is None:
            counter = scope or 'all'
        crl_number_data = json.loads(self.crl_number)
        crl_number = int(crl_number_data['scope'].get(counter, 0))
        builder = builder.add_extension(x509.CRLNumber(crl_number=crl_number), critical=False)

        # increase crl_number for the given scope and save
        crl_number_data['scope'][counter] = crl_number + 1
        self.crl_number = json.dumps(crl_number_data)
        self.save()

        return builder.sign(private_key=self.key(password), algorithm=algorithm, backend=default_backend())

    def get_password(self):
        """Get password for the private key from the ``CA_PASSWORDS`` setting."""
        return ca_settings.CA_PASSWORDS.get(self.serial)

    @property
    def pathlen(self):
        """The ``pathlen`` attribute of the ``BasicConstraints`` extension (either an ``int`` or ``None``)."""

        try:
            ext = self.x509.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        except x509.ExtensionNotFound:  # pragma: no cover - extension should always be present
            return None
        return ext.value.path_length

    @property
    def max_pathlen(self):
        """The maximum pathlen for any intermediate CAs signed by this CA.

        This value is either ``None``, if this and all parent CAs don't have a ``pathlen`` attribute, or an
        ``int`` if any parent CA has the attribute.
        """

        pathlen = self.pathlen
        if self.parent is None:
            return pathlen

        max_parent = self.parent.max_pathlen

        if max_parent is None:
            return pathlen
        if pathlen is None:
            return max_parent - 1

        return min(self.pathlen, max_parent - 1)

    @property
    def allows_intermediate_ca(self):
        """Wether this CA allows creating intermediate CAs."""

        max_pathlen = self.max_pathlen
        return max_pathlen is None or max_pathlen > 0

    @property
    def bundle(self):
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
    def root(self):
        """Get the root CA for this CA."""

        if self.parent is None:
            return self

        ca = self
        while ca.parent is not None:
            ca = ca.parent
        return ca

    @property
    def usable(self):
        """True if the CA is currently usable or not."""
        return self.enabled and self.valid_from < timezone.now() < self.expires

    class Meta:
        verbose_name = _('Certificate Authority')
        verbose_name_plural = _('Certificate Authorities')

    def __str__(self):
        return self.name


class Certificate(X509CertMixin):
    """Model representing a x509 Certificate."""

    objects = CertificateManager.from_queryset(CertificateQuerySet)()

    watchers = models.ManyToManyField(Watcher, related_name='certificates', blank=True)

    ca = models.ForeignKey(CertificateAuthority, on_delete=models.CASCADE,
                           verbose_name=_('Certificate Authority'))
    csr = models.TextField(verbose_name=_('CSR'), blank=True)

    # Note: We don't set choices here because the available profiles might be changed by the user.
    profile = models.CharField(blank=True, default='', max_length=32,
                               help_text=_('Profile that was used to generate this certificate.'))

    autogenerated = models.BooleanField(default=False,
                                        help_text=_("If this certificate was automatically generated."))

    @property
    def bundle(self):
        """The complete certificate bundle. This includes all CAs as well as the certificates itself."""

        return [self] + self.ca.bundle

    @property
    def root(self):
        """Get the root CA for this certificate."""

        return self.ca.root

    def __str__(self):
        return self.cn


class AcmeAccount(DjangoCAModelMixin, models.Model):
    """Implements an ACME account object.

    .. seealso::

        `RFC 8555, 7.1.2 <https://tools.ietf.org/html/rfc8555#section-7.1.2>`_
    """

    # RFC 8555, 7.1.2: "Possible values are "valid", "deactivated", and "revoked"."
    STATUS_VALID = Status.VALID.value
    STATUS_DEACTIVATED = Status.DEACTIVATED.value  # deactivated by user
    STATUS_REVOKED = Status.REVOKED.value  # revoked by server
    STATUS_CHOICES = (
        (STATUS_VALID, _('Valid')),
        (STATUS_DEACTIVATED, _('Deactivated')),
        (STATUS_REVOKED, _('Revoked')),
    )

    objects = AcmeAccountManager.from_queryset(AcmeAccountQuerySet)()

    # Account meta data
    created = models.DateTimeField(default=timezone.now)
    updated = models.DateTimeField(auto_now=True)

    # Account information
    ca = models.ForeignKey(CertificateAuthority, on_delete=models.CASCADE,
                           verbose_name=_('Certificate Authority'))
    # Full public key of the account
    pem = models.TextField(verbose_name=_('Public key'), unique=True, blank=False, validators=[pem_validator])
    # JSON Web Key thumbprint - a hash of the public key, see RFC 7638.
    #   NOTE: Only unique for the given CA to make hash collisions less likely
    thumbprint = models.CharField(max_length=64)
    slug = models.SlugField(unique=True, default=acme_slug)
    kid = models.URLField(unique=True, validators=[URLValidator(schemes=('http', 'https'))],
                          verbose_name=_('Key ID'))

    # Fields according to RFC 8555, 7.1.2
    # RFC 8555, 7.1.6: "Account objects are created in the "valid" state"
    status = models.CharField(choices=STATUS_CHOICES, max_length=12, default=STATUS_VALID)
    contact = models.TextField(blank=True, help_text=_('Contact addresses for this account, one per line.'))
    terms_of_service_agreed = models.BooleanField(default=False)
    # NOTE: externalAccountBinding is not yet supported
    # NOTE: orders property is provided by reverse relation of the AcmeOrder model

    class Meta:
        verbose_name = _('ACME Account')
        verbose_name_plural = _('ACME Accounts')
        unique_together = (
            ('ca', 'thumbprint'),
        )

    def __str__(self):
        try:
            return self.contact.split('\n')[0].split(':', 1)[1]
        except IndexError:
            return ''

    @property
    def serial(self):
        """Serial of the CA for this account."""
        return self.ca.serial

    def set_kid(self, request):
        """Set the ACME kid based on this accounts CA and slug.

        Note that `slug` and `ca` must be already set when using this method.
        """
        self.kid = request.build_absolute_uri(
            reverse('django_ca:acme-account', kwargs={'slug': self.slug, 'serial': self.ca.serial})
        )

    @property
    def usable(self):
        """Boolean if the account is currently usable.

        An account is usable if the terms of service have been agreed, the status is "valid" and the
        associated CA is usable.
        """
        return self.terms_of_service_agreed and self.status == AcmeAccount.STATUS_VALID and self.ca.usable


class AcmeOrder(DjangoCAModelMixin, models.Model):
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
        (STATUS_INVALID, _('Invalid')),
        (STATUS_PENDING, _('Pending')),
        (STATUS_PROCESSING, _('Processing')),
        (STATUS_READY, _('Ready')),
        (STATUS_VALID, _('Valid')),
    )

    objects = AcmeOrderManager.from_queryset(AcmeOrderQuerySet)()

    account = models.ForeignKey(AcmeAccount, on_delete=models.CASCADE, related_name='orders')
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
        verbose_name = _('ACME Order')
        verbose_name_plural = _('ACME Orders')

    def __str__(self):
        return '%s (%s)' % (self.slug, self.account)

    @property
    def acme_url(self):
        """Get the ACME url path for this order."""
        return reverse('django_ca:acme-order', kwargs={'slug': self.slug, 'serial': self.serial})

    @property
    def acme_finalize_url(self):
        """Get the ACME "finalize" url path for this order."""
        return reverse('django_ca:acme-order-finalize', kwargs={'slug': self.slug, 'serial': self.serial})

    def add_authorizations(self, identifiers):
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
        return self.authorizations.bulk_create([
            AcmeAuthorization(type=ident.typ.name, value=ident.value, order=self) for ident in identifiers
        ])

    @property
    def serial(self):
        """Serial of the CA for this order."""
        return self.account.serial

    @property
    def usable(self):
        """Boolean defining if an order is "usable", meaning it can be used to issue a certificate.

        An order is usable if it is in the "pending" status, has not expired and the account is usable.
        """
        return self.status == AcmeOrder.STATUS_PENDING and self.expires > timezone.now() \
            and self.account.usable


class AcmeAuthorization(models.Model):
    """Implements an ACME authorization object.

    .. seealso::

        `RFC 8555, 7.1.4 <https://tools.ietf.org/html/rfc8555#section-7.1.4>`_
    """
    # Choices from RFC 8555, section 9.7.7.
    TYPE_DNS = IdentifierType.DNS.value
    TYPE_CHOICES = (
        (TYPE_DNS, _('DNS')),
    )

    # RFC 8555, 7.1.4: "Possible values are "pending", "valid", "invalid", "deactivated", "expired", and
    #                   "revoked"."
    STATUS_PENDING = Status.PENDING.value
    STATUS_VALID = Status.VALID.value
    STATUS_INVALID = Status.INVALID.value
    STATUS_DEACTIVATED = Status.DEACTIVATED.value
    STATUS_EXPIRED = Status.EXPIRED.value
    STATUS_REVOKED = Status.REVOKED.value
    STATUS_CHOICES = (
        (STATUS_PENDING, _('Pending')),
        (STATUS_VALID, _('Valid')),
        (STATUS_INVALID, _('Invalid')),
        (STATUS_DEACTIVATED, _('Deactivated')),
        (STATUS_EXPIRED, _('Expired')),
        (STATUS_REVOKED, _('Revoked')),
    )

    objects = AcmeAuthorizationManager.from_queryset(AcmeAuthorizationQuerySet)()

    order = models.ForeignKey(AcmeOrder, on_delete=models.CASCADE, related_name='authorizations')
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
        unique_together = (
            ('order', 'type', 'value'),
        )
        verbose_name = _('ACME Authorization')
        verbose_name_plural = _('ACME Authorizations')

    def __str__(self):
        return '%s: %s' % (self.type, self.value)

    @property
    def account(self):
        """Account that this authorization belongs to."""
        return self.order.account

    @property
    def acme_url(self):
        """Get the ACME url path for this account authorization."""
        return reverse('django_ca:acme-authz', kwargs={'slug': self.slug, 'serial': self.serial})

    @property
    def expires(self):
        """When this authorization expires."""
        return self.order.expires  # so far there is no reason to have a different value here

    @property
    def identifier(self):
        """Get ACME identifier for this object.

        Returns
        -------

        identifier : :py:class:`acme:acme.messages.Identifier`
        """
        # Programatic import to make sure that the acme library is an optional dependency
        messages = importlib.import_module('acme.messages')

        if self.type == AcmeAuthorization.TYPE_DNS:
            return messages.Identifier(typ=messages.IDENTIFIER_FQDN, value=self.value)
        raise ValueError('Unknown identifier type: %s' % self.type)

    @property
    def serial(self):
        """Serial of the CA for this authorization."""
        return self.order.serial

    @property
    def subject_alternative_name(self):
        """Get the domain for this challenge as prefixed SubjectAlternativeName.

        This method is intended to be used when creating the
        :py:class:`~django_ca.extensions.SubjectAlternativeName` extension for a certificate to be signed.
        """
        return '%s:%s' % (self.type, self.value)

    def get_challenges(self):
        """Get list of :py:class:`~django_ca.models.AcmeChallenge` objects for this authorization.

        Note that challenges will be created if they don't exist.
        """

        return [
            AcmeChallenge.objects.get_or_create(auth=self, type=AcmeChallenge.TYPE_HTTP_01)[0],
            AcmeChallenge.objects.get_or_create(auth=self, type=AcmeChallenge.TYPE_DNS_01)[0],
        ]

    @property
    def usable(self):
        """Boolean defining if an auth is "usable", meaning it still can be used in order validation

        An order is usable if it is in the "pending" or "invalid" status, the order is usable. An
        authorization that is in the "invalid" status is eligible to be retried by the client.
        """
        states = (AcmeAuthorization.STATUS_PENDING, AcmeAuthorization.STATUS_INVALID)
        return self.status in states and self.order.usable


class AcmeChallenge(models.Model):
    """Implements an ACME Challenge Object.

    .. seealso:: `RFC 8555, section 7.1.5 <https://tools.ietf.org/html/rfc8555#section-7.1.5>`_
    """

    # Possible challenges
    TYPE_HTTP_01 = 'http-01'
    TYPE_DNS_01 = 'dns-01'
    TYPE_TLS_ALPN_01 = 'tls-alpn-01'
    TYPE_CHOICES = (
        (TYPE_HTTP_01, _('HTTP Challenge')),
        (TYPE_DNS_01, _('DNS Challenge')),
        (TYPE_TLS_ALPN_01, _('TLS ALPN Challenge')),
    )

    # RFC 8555, 8: "Possible values are "pending", "processing", "valid", and "invalid"."
    STATUS_PENDING = Status.PENDING.value
    STATUS_PROCESSING = Status.PROCESSING.value
    STATUS_VALID = Status.VALID.value
    STATUS_INVALID = Status.INVALID.value
    STATUS_CHOICES = (
        (STATUS_PENDING, _('Pending')),
        (STATUS_PROCESSING, _('Processing')),
        (STATUS_VALID, _('Valid')),
        (STATUS_INVALID, _('Name')),
    )

    objects = AcmeChallengeManager.from_queryset(AcmeChallengeQuerySet)()

    auth = models.ForeignKey(AcmeAuthorization, on_delete=models.CASCADE, related_name='challenges')
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
        unique_together = (
            ('auth', 'type'),
        )
        verbose_name = _('ACME Challenge')
        verbose_name_plural = _('ACME Challenges')

    def __str__(self):
        return '%s (%s)' % (self.auth.value, self.type)

    @property
    def acme_url(self):
        """Get the ACME url path for this challenge."""
        return reverse('django_ca:acme-challenge', kwargs={'slug': self.slug, 'serial': self.serial})

    @property
    def acme_challenge(self):
        """Challenge as ACME challenge object.

        Returns
        -------

        acme.messages.Challenge
            The acme representation of this class.
        """
        # Programatic import to make sure that the acme library is an optional dependency
        challenges = importlib.import_module('acme.challenges')

        token = self.token.encode()
        if self.type == AcmeChallenge.TYPE_HTTP_01:
            return challenges.HTTP01(token=token)
        if self.type == AcmeChallenge.TYPE_DNS_01:
            return challenges.DNS01(token=token)
        if self.type == AcmeChallenge.TYPE_TLS_ALPN_01:
            return challenges.TLSALPN01(token=token)

        raise ValueError('%s: Unsupported challenge type.' % self.type)

    @property
    def acme_validated(self):
        """Timestamp when this challenge was validated.

        This property is a wrapper around the `validated` field. It always returns `None` if the challenge is
        not marked as valid (even if it had a timestamp), and the timestamp will always have a timezone, even
        if ``USE_TZ=False``.
        """
        if self.status != AcmeChallenge.STATUS_VALID or self.validated is None:
            return None

        if timezone.is_naive(self.validated):
            return timezone.make_aware(self.validated, timezone=pytz.UTC)
        return self.validated

    def get_challenge(self, request):
        """Get the ACME challenge body for this challenge.

        Returns
        -------

        acme.messages.ChallengeBody
            The acme representation of this class.
        """

        # Programatic import to make sure that the acme library is an optional dependency
        messages = importlib.import_module('acme.messages')

        url = request.build_absolute_uri(self.acme_url)

        # NOTE: RFC855, section 7.5 shows challenges *without* a status, but this object always includes it.
        #       It does not seem to hurt, but might be a slight spec-violation.
        return messages.ChallengeBody(chall=self.acme_challenge, _url=url, status=self.status,
                                      validated=self.acme_validated)

    @property
    def serial(self):
        """Serial of the CA for this challenge."""
        return self.auth.serial

    @property
    def usable(self):
        """Boolean defining if an challenge is "usable", meaning it still can be used in order validation.

        A challenge is usable if it is in the "pending" or "invalid status and the authorization is usable.
        """
        states = (AcmeChallenge.STATUS_PENDING, AcmeChallenge.STATUS_INVALID)
        return self.status in states and self.auth.usable


class AcmeCertificate(models.Model):
    """Intermediate model for certificates to be issued via ACME."""

    objects = AcmeCertificateManager.from_queryset(AcmeCertificateQuerySet)()

    slug = models.SlugField(unique=True, default=acme_slug)
    order = models.OneToOneField(AcmeOrder, on_delete=models.CASCADE)
    cert = models.OneToOneField(Certificate, on_delete=models.CASCADE, null=True)
    csr = models.TextField(verbose_name=_('CSR'))

    class Meta:
        verbose_name = _('ACME Certificate')
        verbose_name_plural = _('ACME Certificate')

    @property
    def acme_url(self):
        """Get the ACME url path for this certificate."""
        return reverse('django_ca:acme-cert', kwargs={'slug': self.slug, 'serial': self.order.serial})

    def parse_csr(self):
        """Load the CSR into a cryptography object.

        Returns
        -------

        :py:class:`~cg:cryptography.x509.CertificateSigningRequest`
            The CSR as used by cryptography.
        """
        return x509.load_pem_x509_csr(self.csr.encode(), default_backend())

    @property
    def usable(self):
        """Boolean defining if this instance is "usable", meaning we can use it to issue a certificate.

        An ACME certificate is considered usable if no actuall certificate has yet been issued, the order is
        not expired and in the "processing" state.
        """
        return self.cert is None and self.order.expires > timezone.now() \
            and self.order.status == AcmeOrder.STATUS_PROCESSING

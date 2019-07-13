# -*- coding: utf-8 -*-
#
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

import base64
import binascii
import hashlib
import itertools
import json
import logging
import os
import re
from datetime import datetime
from datetime import timedelta

import pytz

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import ExtensionOID

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.db import models
from django.urls import reverse
from django.utils import six
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.encoding import force_str
from django.utils.text import slugify
from django.utils.translation import ugettext_lazy as _

from . import ca_settings
from .constants import ReasonFlags
from .extensions import AuthorityInformationAccess
from .extensions import AuthorityKeyIdentifier
from .extensions import BasicConstraints
from .extensions import CertificatePolicies
from .extensions import CRLDistributionPoints
from .extensions import ExtendedKeyUsage
from .extensions import IssuerAlternativeName
from .extensions import KeyUsage
from .extensions import NameConstraints
from .extensions import OCSPNoCheck
from .extensions import PrecertificateSignedCertificateTimestamps
from .extensions import SubjectAlternativeName
from .extensions import SubjectKeyIdentifier
from .extensions import TLSFeature
from .extensions import UnrecognizedExtension
from .managers import CertificateAuthorityManager
from .managers import CertificateManager
from .profiles import get_cert_profile_kwargs
from .querysets import CertificateAuthorityQuerySet
from .querysets import CertificateQuerySet
from .signals import post_revoke_cert
from .signals import pre_revoke_cert
from .subject import Subject
from .utils import add_colons
from .utils import ca_storage
from .utils import format_name
from .utils import generate_private_key
from .utils import get_expires
from .utils import get_extension_name
from .utils import int_to_hex
from .utils import multiline_url_validator
from .utils import parse_encoding
from .utils import parse_general_name
from .utils import parse_hash_algorithm
from .utils import read_file
from .utils import validate_key_parameters

log = logging.getLogger(__name__)

if ca_settings.CRYPTOGRAPHY_HAS_PRECERT_POISON:  # pragma: no branch, pragma: only cryptography>=2.4
    from .extensions import PrecertPoison


def validate_past(value):
    if value > timezone.now():
        raise ValidationError(_('Date must be in the past!'))


def json_validator(value):
    try:
        json.loads(value)
    except Exception as e:
        raise ValidationError(_('Must be valid JSON: %(message)s') % {'message': str(e)})


class Watcher(models.Model):
    name = models.CharField(max_length=64, null=True, blank=True, verbose_name=_('CommonName'))
    mail = models.EmailField(verbose_name=_('E-Mail'), unique=True)

    @classmethod
    def from_addr(cls, addr):
        name = None
        match = re.match(r'(.*?)\s*<(.*)>', addr)
        if match is not None:
            name, addr = match.groups()

        try:
            w = cls.objects.get(mail=addr)
            if w.name != name:
                w.name = name
                w.save()
        except cls.DoesNotExist:
            w = cls(mail=addr, name=name)
            w.full_clean()
            w.save()

        return w

    def __str__(self):
        if self.name:
            return '%s <%s>' % (self.name, self.mail)
        return self.mail


class X509CertMixin(models.Model):
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
        max_length=32, null=True, blank=True, verbose_name=_('Reason for revokation'),
        choices=REVOCATION_REASONS)
    compromised = models.DateTimeField(
        null=True, blank=True, verbose_name=_('Date of compromise'), validators=[validate_past],
        help_text=_('Optional: When this certificate was compromised. You can change this date later.'))

    _x509 = None
    _extensions = None

    class Meta:
        abstract = True

    def get_revocation_reason(self):
        """Get the revocation reason of this certificate."""
        if self.revoked is False:
            return

        return x509.ReasonFlags[self.revoked_reason]

    def get_compromised_time(self):
        if self.revoked is False or not self.compromised:
            return

        if timezone.is_aware(self.compromised):
            # convert datetime object to UTC and make it naive
            return timezone.make_naive(self.compromised, pytz.utc)

        return self.compromised

    def get_revocation_time(self):
        """Get the revocation time as naive datetime.

        Note that this method is only used by cryptography>=2.4.
        """
        if self.revoked is False:
            return

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
        self._x509 = value
        self.pub = force_str(self.dump_certificate(Encoding.PEM))
        self.cn = self.subject.get('CN', '')
        self.expires = self.not_after
        self.valid_from = self.not_before
        if settings.USE_TZ:
            self.expires = timezone.make_aware(self.expires, timezone=pytz.utc)
            self.valid_from = timezone.make_aware(self.valid_from, timezone=pytz.utc)

        self.serial = int_to_hex(value.serial_number)

    @property
    def admin_change_url(self):
        return reverse('admin:%s_%s_change' % (self._meta.app_label, self._meta.verbose_name),
                       args=(self.pk, ))

    ##########################
    # Certificate properties #
    ##########################

    @property
    def algorithm(self):
        return self.x509.signature_hash_algorithm

    def dump_certificate(self, encoding=Encoding.PEM):
        return self.x509.public_bytes(encoding=encoding)

    def get_digest(self, algo):
        algo = getattr(hashes, algo.upper())()
        return add_colons(binascii.hexlify(self.x509.fingerprint(algo)).upper().decode('utf-8'))

    def get_filename(self, ext, bundle=False):
        slug = slugify(self.cn.replace('.', '_'))

        if bundle is True:
            return '%s_bundle.%s' % (slug, ext.lower())
        else:
            return '%s.%s' % (slug, ext.lower())

    def get_revocation(self):
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
        # taken from https://github.com/luisgf/hpkp-python/blob/master/hpkp.py

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

    @property
    def ocsp_status(self):  # pragma: only cryptography<2.4
        """Get the OCSP status. This version is only used by the oscrypto based OCSP responder.

        The OCSP status 'good' does not say if the certificate has expired.

        **Deprecated:** This function will be removed after 1.13.0.
        """

        if self.revoked is False:
            return 'good'
        if self.revoked_reason == ReasonFlags.unspecified.name:
            return 'revoked'

        return self.revoked_reason

    def revoke(self, reason=None, compromised=None):
        if reason is None:
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

    def distinguishedName(self):
        return format_name(self.x509.subject)
    distinguishedName.short_description = 'Distinguished Name'

    ###################
    # X509 extensions #
    ###################
    OID_MAPPING = {
        ExtensionOID.AUTHORITY_INFORMATION_ACCESS: 'authority_information_access',
        ExtensionOID.AUTHORITY_KEY_IDENTIFIER: 'authority_key_identifier',
        ExtensionOID.BASIC_CONSTRAINTS: 'basic_constraints',
        ExtensionOID.CRL_DISTRIBUTION_POINTS: 'crl_distribution_points',
        ExtensionOID.CERTIFICATE_POLICIES: 'certificate_policies',
        ExtensionOID.EXTENDED_KEY_USAGE: 'extended_key_usage',
        ExtensionOID.ISSUER_ALTERNATIVE_NAME: 'issuer_alternative_name',
        ExtensionOID.KEY_USAGE: 'key_usage',
        ExtensionOID.NAME_CONSTRAINTS: 'name_constraints',
        ExtensionOID.OCSP_NO_CHECK: 'ocsp_no_check',
        ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS: 'precertificate_signed_certificate_timestamps',
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME: 'subject_alternative_name',
        ExtensionOID.SUBJECT_KEY_IDENTIFIER: 'subject_key_identifier',
        ExtensionOID.TLS_FEATURE: 'tls_feature',
    }

    if ca_settings.CRYPTOGRAPHY_HAS_PRECERT_POISON:  # pragma: no branch, pragma: only cryptography>=2.4
        OID_MAPPING[ExtensionOID.PRECERT_POISON] = 'precert_poison'

    @property
    def _sorted_extensions(self):
        if self._extensions is None:
            self._extensions = list(sorted(
                self.x509.extensions, key=lambda e: (get_extension_name(e), e.oid.dotted_string)
            ))
        return self._extensions

    def get_extension_fields(self):
        for ext in self._sorted_extensions:
            if ext.oid in self.OID_MAPPING:
                yield self.OID_MAPPING[ext.oid]

            # extension that does not support new extension framework
            else:
                log.warning('Unknown extension encountered: %s (%s)',
                            get_extension_name(ext), ext.oid.dotted_string)
                yield ext

    def get_extensions(self):
        for ext in self._sorted_extensions:
            if ext.oid in self.OID_MAPPING:
                yield getattr(self, self.OID_MAPPING[ext.oid])

            # extension that does not support new extension framework
            else:
                yield ext

    @property
    def authority_information_access(self):
        try:
            ext = self.x509.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        except x509.ExtensionNotFound:
            return None
        return AuthorityInformationAccess(ext)

    @property
    def authority_key_identifier(self):
        """The :py:class:`~django_ca.extensions.AuthorityKeyIdentifier` extension, or ``None`` if it doesn't
        exist."""
        try:
            ext = self.x509.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        except x509.ExtensionNotFound:
            return None
        return AuthorityKeyIdentifier(ext)

    @property
    def basic_constraints(self):
        try:
            ext = self.x509.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        except x509.ExtensionNotFound:
            return None
        return BasicConstraints(ext)

    @property
    def crl_distribution_points(self):
        try:
            ext = self.x509.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        except x509.ExtensionNotFound:
            return None
        return CRLDistributionPoints(ext)

    @property
    def certificate_policies(self):
        try:
            ext = self.x509.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
        except x509.ExtensionNotFound:
            return None
        return CertificatePolicies(ext)

    @property
    def issuer_alternative_name(self):
        try:
            ext = self.x509.extensions.get_extension_for_oid(ExtensionOID.ISSUER_ALTERNATIVE_NAME)
        except x509.ExtensionNotFound:
            return None

        return IssuerAlternativeName(ext)

    @property
    def key_usage(self):
        """The :py:class:`~django_ca.extensions.KeyUsage` extension, or ``None`` if it doesn't exist."""
        try:
            ext = self.x509.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        except x509.ExtensionNotFound:
            return None
        return KeyUsage(ext)

    @property
    def extended_key_usage(self):
        """The :py:class:`~django_ca.extensions.ExtendedKeyUsage` extension, or ``None`` if it doesn't
        exist."""
        try:
            ext = self.x509.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        except x509.ExtensionNotFound:
            return None
        return ExtendedKeyUsage(ext)

    @property
    def name_constraints(self):
        try:
            ext = self.x509.extensions.get_extension_for_oid(ExtensionOID.NAME_CONSTRAINTS)
        except x509.ExtensionNotFound:
            return None

        return NameConstraints(ext)

    @property
    def ocsp_no_check(self):
        try:
            ext = self.x509.extensions.get_extension_for_oid(ExtensionOID.OCSP_NO_CHECK)
        except x509.ExtensionNotFound:
            return None

        return OCSPNoCheck(ext)

    @property
    def precert_poison(self):  # pragma: only cryptography>=2.4
        try:
            ext = self.x509.extensions.get_extension_for_oid(ExtensionOID.PRECERT_POISON)
        except x509.ExtensionNotFound:
            return None

        return PrecertPoison(ext)

    @property
    def precertificate_signed_certificate_timestamps(self):
        try:
            ext = self.x509.extensions.get_extension_for_oid(
                ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
        except x509.ExtensionNotFound:
            return None

        if isinstance(ext.value, x509.UnrecognizedExtension):
            # Older versions of OpenSSL (and LibreSSL) cannot parse this extension
            # see https://github.com/pyca/cryptography/blob/master/tests/x509/test_x509_ext.py#L4455-L4459
            return UnrecognizedExtension(
                ext,
                name=get_extension_name(ext),
                error='Requires OpenSSL 1.1.0f or later')
        else:  # pragma: only SCT
            return PrecertificateSignedCertificateTimestamps(ext)

    @property
    def subject_alternative_name(self):
        try:
            ext = self.x509.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        except x509.ExtensionNotFound:
            return None

        return SubjectAlternativeName(ext)

    @property
    def subject_key_identifier(self):
        """The :py:class:`~django_ca.extensions.SubjectKeyIdentifier` extension, or ``None`` if it doesn't
        exist."""
        try:
            ext = self.x509.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        except x509.ExtensionNotFound:
            return None
        return SubjectKeyIdentifier(ext)

    @property
    def tls_feature(self):
        """The :py:class:`~django_ca.extensions.TLSFeature` extension, or ``None`` if it doesn't exist."""
        try:
            ext = self.x509.extensions.get_extension_for_oid(ExtensionOID.TLS_FEATURE)
        except x509.ExtensionNotFound:
            return None
        return TLSFeature(ext)


class CertificateAuthority(X509CertMixin):
    objects = CertificateAuthorityManager.from_queryset(CertificateAuthorityQuerySet)()

    name = models.CharField(max_length=32, help_text=_('A human-readable name'), unique=True)
    """Human-readable name of the CA, only used for displaying the CA."""
    enabled = models.BooleanField(default=True)
    parent = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True,
                               related_name='children')
    private_key_path = models.CharField(max_length=256, help_text=_('Path to the private key.'))

    # various details used when signing certs
    crl_url = models.TextField(blank=True, null=True, validators=[multiline_url_validator],
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

    _key = None

    def key(self, password):
        if self._key is None:
            if os.path.isabs(self.private_key_path):
                log.warning('%s: CA uses absolute path. Use "manage.py migrate_ca" to update.', self.serial)

            key_data = read_file(self.private_key_path)

            self._key = load_pem_private_key(key_data, password, default_backend())
        return self._key

    @property
    def key_exists(self):
        if self._key is not None:
            return True
        elif os.path.isabs(self.private_key_path):
            log.warning('%s: CA uses absolute path. Use "manage.py migrate_ca" to update.', self.serial)
            return os.path.exists(self.private_key_path)
        else:
            return ca_storage.exists(self.private_key_path)

    def generate_ocsp_key(self, profile='ocsp', expires=3, algorithm=None, password=None,
                          key_size=None, key_type=None, ecc_curve=None):
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

        """
        key_size, key_type, ecc_curve = validate_key_parameters(key_size, key_type, ecc_curve)
        if isinstance(expires, six.integer_types):
            expires = get_expires(expires)
        algorithm = parse_hash_algorithm(algorithm)

        # generate the private key
        private_key = generate_private_key(key_size, key_type, ecc_curve)
        private_pem = private_key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8,
                                                encryption_algorithm=serialization.NoEncryption())
        private_path = ca_storage.generate_filename('ocsp/%s.key' % self.serial.replace(':', ''))

        csr = x509.CertificateSigningRequestBuilder().subject_name(self.x509.subject).sign(
            private_key, hashes.SHA256(), default_backend())

        kwargs = get_cert_profile_kwargs(profile)
        # TODO: This value is just a guess - see what public CAs do!?
        kwargs['subject'] = self.subject
        cert = Certificate.objects.init(
            ca=self,
            csr=csr,
            expires=expires,
            ocsp_url=False,
            password=password,
            **kwargs
        )

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
        """Return the AuthorityKeyIdentifier extension used in certificates signed by this CA."""

        try:
            ski = self.x509.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        except x509.ExtensionNotFound:
            return x509.AuthorityKeyIdentifier.from_issuer_public_key(self.x509.public_key())
        else:
            if ca_settings.CRYPTOGRAPHY_AKI_REQUIRES_EXTENSION:  # pragma: only cryptography<2.7
                return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)
            else:  # pragma: only cryptography>=2.7
                return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski.value)

    def get_crl(self, expires=86400, encoding=None, algorithm=None, password=None, scope=None, counter=None,
                **kwargs):
        """Generate a Certificate Revocation List (CRL).

        The ``full_name`` and ``relative_name`` parameters describe how to retrieve the CRL and are used in
        the `Issuing Distribution Point extension <https://tools.ietf.org/html/rfc5280.html#section-5.2.5>`_.
        The former defaults to the ``crl_url`` field, pass ``None`` to not include the value. At most one of
        the two may be set.

        Parameters
        ----------

        expires : int
            The time in seconds when this CRL expires. Note that you should generate a new CRL until then.
        encoding : :py:class:`~cg:cryptography.hazmat.primitives.serialization.Encoding` or str, optional
            The encoding format for the CRL, passed to :py:func:`~django_ca.utils.parse_encoding`. The default
            value is ``"PEM"``.
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

        if scope is not None and scope not in ['ca', 'user', 'attribute']:
            raise ValueError('Scope must be either None, "ca", "user" or "attribute"')
        encoding = parse_encoding(encoding)

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

        if 'full_name' in kwargs:
            full_name = kwargs['full_name']
            full_name = [parse_general_name(n) for n in full_name]
        elif self.crl_url:
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

        if add_idp and ca_settings.CRYPTOGRAPHY_HAS_IDP:  # pragma: no branch, pragma: only cryptography>=2.5
            builder = builder.add_extension(x509.IssuingDistributionPoint(**idp_kwargs), critical=True)

        # Add AuthorityKeyIdentifier from CA if present
        try:
            aki = self.x509.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
            builder = builder.add_extension(aki.value, critical=aki.critical)
        except x509.ExtensionNotFound:
            pass

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

        crl = builder.sign(private_key=self.key(password), algorithm=algorithm, backend=default_backend())
        return crl.public_bytes(encoding)

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
        elif pathlen is None:
            return max_parent - 1
        else:
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

    class Meta:
        verbose_name = _('Certificate Authority')
        verbose_name_plural = _('Certificate Authorities')

    def __str__(self):
        return self.name


class Certificate(X509CertMixin):
    objects = CertificateManager.from_queryset(CertificateQuerySet)()

    watchers = models.ManyToManyField(Watcher, related_name='certificates', blank=True)

    ca = models.ForeignKey(CertificateAuthority, on_delete=models.CASCADE,
                           verbose_name=_('Certificate Authority'))
    csr = models.TextField(verbose_name=_('CSR'), blank=True)

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

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
import re

import pytz

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.certificate_transparency import LogEntryType
from cryptography.x509.extensions import UnrecognizedExtension
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.x509.oid import ExtensionOID

from django.conf import settings
from django.db import models
from django.urls import reverse
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.encoding import force_str
from django.utils.text import slugify
from django.utils.translation import ugettext_lazy as _
from django.core.files.storage import default_storage

from .extensions import AuthorityKeyIdentifier
from .extensions import BasicConstraints
from .extensions import ExtendedKeyUsage
from .extensions import IssuerAlternativeName
from .extensions import KeyUsage
from .extensions import SubjectAlternativeName
from .extensions import SubjectKeyIdentifier
from .extensions import TLSFeature
from .managers import CertificateAuthorityManager
from .managers import CertificateManager
from .querysets import CertificateAuthorityQuerySet
from .querysets import CertificateQuerySet
from .signals import post_revoke_cert
from .signals import pre_revoke_cert
from .subject import Subject
from .utils import add_colons
from .utils import format_general_name
from .utils import format_general_names
from .utils import format_name
from .utils import int_to_hex
from .utils import multiline_url_validator
from . import ca_settings


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
        ('', _('No reason')),
        ('aa_compromise', _('Attribute Authority compromised')),
        ('affiliation_changed', _('Affiliation changed')),
        ('ca_compromise', _('CA compromised')),
        ('certificate_hold', _('On Hold')),
        ('cessation_of_operation', _('Cessation of operation')),
        ('key_compromise', _('Key compromised')),
        ('privilege_withdrawn', _('Privilege withdrawn')),
        ('remove_from_crl', _('Removed from CRL')),
        ('superseded', _('Superseded')),
        ('unspecified', _('Unspecified')),
    )

    created = models.DateTimeField(auto_now=True)

    valid_from = models.DateTimeField(blank=False)
    expires = models.DateTimeField(null=False, blank=False)

    pub = models.TextField(verbose_name=_('Public key'))
    cn = models.CharField(max_length=128, verbose_name=_('CommonName'))
    serial = models.CharField(max_length=64, unique=True)

    # revocation information
    revoked = models.BooleanField(default=False)
    revoked_date = models.DateTimeField(null=True, blank=True, verbose_name=_('Revoked on'))
    revoked_reason = models.CharField(
        max_length=32, null=True, blank=True, verbose_name=_('Reason for revokation'),
        choices=REVOCATION_REASONS)

    _x509 = None

    class Meta:
        abstract = True

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

        if self.revoked_reason:
            reason_flag = getattr(x509.ReasonFlags, self.revoked_reason)
            revoked_cert = revoked_cert.add_extension(x509.CRLReason(reason_flag), critical=False)

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
    def ocsp_status(self):
        # NOTE: The OCSP status 'good' does not say if the certificate has expired.
        if self.revoked is False:
            return 'good'

        return self.revoked_reason or 'revoked'

    def revoke(self, reason=None):
        pre_revoke_cert.send(sender=self.__class__, cert=self, reason=reason)

        self.revoked = True
        self.revoked_date = timezone.now()
        self.revoked_reason = reason
        self.save()

        post_revoke_cert.send(sender=self.__class__, cert=self)

    @property
    def subject(self):
        """The certificates subject as :py:class:`~django_ca.subject.Subject`."""
        return Subject([(s.oid, s.value) for s in self.x509.subject])

    ###################
    # X509 extensions #
    ###################
    OID_MAPPING = {
        ExtensionOID.AUTHORITY_KEY_IDENTIFIER: 'authority_key_identifier',
        ExtensionOID.BASIC_CONSTRAINTS: 'basic_constraints',
        ExtensionOID.EXTENDED_KEY_USAGE: 'extended_key_usage',
        ExtensionOID.ISSUER_ALTERNATIVE_NAME: 'issuer_alternative_name',
        ExtensionOID.KEY_USAGE: 'key_usage',
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME: 'subject_alternative_name',
        ExtensionOID.SUBJECT_KEY_IDENTIFIER: 'subject_key_identifier',
        ExtensionOID.TLS_FEATURE: 'tls_feature',
    }

    def get_extension_fields(self):
        for ext in sorted(self.x509.extensions, key=lambda e: e.oid._name.title()):
            if ext.oid in self.OID_MAPPING:
                yield self.OID_MAPPING[ext.oid]

            # extension that does not support new extension framework
            else:
                name = ext.oid._name.replace(' ', '')
                if hasattr(self, name):
                    yield name
                elif name == 'cRLDistributionPoints':
                    yield 'cRLDistributionPoints'
                else:  # pragma: no cover  - we have a function for everything we support
                    #warnings.warn('Unknown extension encountered: %s' % ext.oid._name)
                    yield ext

    def get_extensions(self):
        for ext in sorted(self.x509.extensions, key=lambda e: e.oid._name):
            if ext.oid in self.OID_MAPPING:
                yield getattr(self, self.OID_MAPPING[ext.oid])

            # extension that does not support new extension framework
            else:
                name = ext.oid._name.replace(' ', '')
                if hasattr(self, name):
                    value = getattr(self, name)()
                    yield name, value
                elif name == 'cRLDistributionPoints':
                    yield name, self.crlDistributionPoints()
                else:  # pragma: no cover  - we have a function for everything we support
                    yield name, (ext.critical, ext.oid)

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

    #################################
    # Old-style extension accessors #
    #################################

    def authorityInfoAccess(self):
        try:
            ext = self.x509.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        except x509.ExtensionNotFound:
            return None

        output = []
        for desc in ext.value:
            if desc.access_method == AuthorityInformationAccessOID.OCSP:
                output.append('OCSP - %s' % format_general_name(desc.access_location))
            elif desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                output.append('CA Issuers - %s' % format_general_name(desc.access_location))
            else:  # pragma: no cover - we don't know any other access methods
                output.append('Unknown')

        return ext.critical, output

    def certificatePolicies(self):
        try:
            ext = self.x509.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
        except x509.ExtensionNotFound:
            return None

        policies = []
        for value in ext.value:
            output = 'OID %s: ' % value.policy_identifier.dotted_string
            if value.policy_qualifiers is None:
                output += "None"
            else:
                output += ', '.join([self._parse_policy_qualifier(p) for p in value.policy_qualifiers])
            policies.append(output)

        return ext.critical, policies

    def crlDistributionPoints(self):
        try:
            ext = self.x509.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        except x509.ExtensionNotFound:
            return None

        value = []
        for dp in ext.value:
            if dp.full_name:
                value.append('Full Name: %s' % format_general_names(dp.full_name))
            else:  # pragma: no cover - not really used in the wild
                value.append('Relative Name: %s' % format_name(dp.relative_name.value))

        return ext.critical, value

    def distinguishedName(self):
        return format_name(self.x509.subject)
    distinguishedName.short_description = 'Distinguished Name'

    def signedCertificateTimestampList(self):
        try:
            ext = self.x509.extensions.get_extension_for_oid(
                ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
        except x509.ExtensionNotFound:
            return None

        if isinstance(ext.value, UnrecognizedExtension):
            # Older versions of OpenSSL (and LibreSSL) cannot parse this extension
            # see https://github.com/pyca/cryptography/blob/master/tests/x509/test_x509_ext.py#L4455-L4459
            return ext.critical, ['Parsing requires OpenSSL 1.1.0f+']

        timestamps = []
        for entry in ext.value:
            if entry.entry_type == LogEntryType.PRE_CERTIFICATE:
                entry_type = 'Precertificate'
            elif entry.entry_type == LogEntryType.X509_CERTIFICATE:  # pragma: no cover - unseen in the wild
                # NOTE: same pragma is also in django_ca.admin.CertificateMixin.signedCertificateTimestampList
                entry_type = 'x509 certificate'
            else:  # pragma: no cover - only the above two are part of the standard
                # NOTE: same pragma is also in django_ca.admin.CertificateMixin.signedCertificateTimestampList
                entry_type = 'unknown'

            timestamps.append('%s (%s): %s\n%s' % (
                entry_type, entry.version.name, entry.timestamp,
                '\n%s' % binascii.hexlify(entry.log_id).decode('utf-8')
            ))

        return ext.critical, timestamps

    def _parse_policy_qualifier(self, qualifier):
        if isinstance(qualifier, x509.extensions.UserNotice):
            # https://tools.ietf.org/html/rfc5280#section-4.2.1.4
            notice_ref = qualifier.notice_reference
            text = qualifier.explicit_text
            if notice_ref is None:
                return text
            else:  # pragma: no cover - unseen in the wild
                org = notice_ref.organization
                numbers = notice_ref.notice_numbers
                if not numbers:
                    return '%s (Reference: %s)' % (text, org)
                elif len(numbers) == 1:
                    return '%s (Reference: %s, number %s)' % (text, org, numbers[0])
                else:
                    return '%s (Reference: %s, numbers %s)' % (text, org, ', '.join(numbers))

        return qualifier


class CertificateAuthority(X509CertMixin):
    objects = CertificateAuthorityManager.from_queryset(CertificateAuthorityQuerySet)()

    name = models.CharField(max_length=32, help_text=_('A human-readable name'), unique=True)
    """Human-readable name of the CA, only used for displaying the CA."""
    enabled = models.BooleanField(default=True)
    parent = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True,
                               related_name='children')
    private_key_path = models.FileField(upload_to=ca_settings.CA_DIR, help_text=_('Path to the private key.'))

    # various details used when signing certs
    crl_url = models.TextField(blank=True, null=True, validators=[multiline_url_validator],
                               verbose_name=_('CRL URLs'),
                               help_text=_("URLs, one per line, where you can retrieve the CRL."))
    issuer_url = models.URLField(blank=True, null=True, verbose_name=_('Issuer URL'),
                                 help_text=_("URL to the certificate of this CA (in DER format)."))
    ocsp_url = models.URLField(blank=True, null=True, verbose_name=_('OCSP responder URL'),
                               help_text=_("URL of a OCSP responser for the CA."))
    issuer_alt_name = models.URLField(blank=True, null=True, verbose_name=_('issuerAltName'),
                                      help_text=_("URL for your CA."))

    _key = None

    def key(self, password):
        if self._key is None:
            with default_storage.open(self.private_key_path, 'rb') as f:
                key_data = f.read()

            self._key = load_pem_private_key(key_data, password, default_backend())
        return self._key

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

    def nameConstraints(self):
        try:
            ext = self.x509.extensions.get_extension_for_oid(ExtensionOID.NAME_CONSTRAINTS)
        except x509.ExtensionNotFound:
            return None

        value = []
        if ext.value.permitted_subtrees:
            for general_name in ext.value.permitted_subtrees:
                value.append('Permitted: %s' % format_general_name(general_name))

        if ext.value.excluded_subtrees:
            for general_name in ext.value.excluded_subtrees:
                value.append('Excluded: %s' % format_general_name(general_name))

        return ext.critical, value

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

    def __str__(self):
        return self.cn

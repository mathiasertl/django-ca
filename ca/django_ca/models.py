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
from collections import OrderedDict

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.x509.oid import ExtensionOID

from django.db import models
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.encoding import force_str
from django.utils.translation import ugettext_lazy as _

from .managers import CertificateAuthorityManager
from .managers import CertificateManager
from .querysets import CertificateAuthorityQuerySet
from .querysets import CertificateQuerySet
from .utils import EXTENDED_KEY_USAGE_REVERSED
from .utils import KEY_USAGE_MAPPING
from .utils import OID_NAME_MAPPINGS
from .utils import add_colons
from .utils import format_general_names
from .utils import format_name
from .utils import int_to_hex
from .utils import multiline_url_validator


class Watcher(models.Model):
    name = models.CharField(max_length=64, null=True, blank=True, verbose_name=_('CommonName'))
    mail = models.EmailField(verbose_name=_('E-Mail'), unique=True)

    @classmethod
    def from_addr(cls, addr):
        name = None
        match = re.match('(.*?)\s*<(.*)>', addr)
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
    created = models.DateTimeField(auto_now=True)
    expires = models.DateTimeField(null=False, blank=False)

    pub = models.TextField(verbose_name=_('Public key'))
    cn = models.CharField(max_length=128, verbose_name=_('CommonName'))
    serial = models.CharField(max_length=64, unique=True)

    _x509 = None

    @property
    def x509(self):
        if self._x509 is None:
            backend = default_backend()
            self._x509 = x509.load_pem_x509_certificate(force_bytes(self.pub), backend)
        return self._x509

    @x509.setter
    def x509(self, value):
        self._x509 = value
        self.pub = force_str(self.dump_certificate(Encoding.PEM))
        self.cn = self.subject['CN']
        self.expires = self.not_after
        self.serial = int_to_hex(value.serial_number)

    @property
    def subject(self):
        return OrderedDict([(OID_NAME_MAPPINGS[s.oid], s.value) for s in self.x509.subject])

    @property
    def issuer(self):
        return OrderedDict([(OID_NAME_MAPPINGS[s.oid], s.value) for s in self.x509.issuer])

    @property
    def not_before(self):
        return self.x509.not_valid_before

    @property
    def not_after(self):
        return self.x509.not_valid_after

    def extensions(self):
        for ext in sorted(self.x509.extensions, key=lambda e: e.oid._name):
            name = ext.oid._name
            if hasattr(self, name):
                yield name, getattr(self, name)()
            else:  # pragma: no cover  - we have a function for everything we support
                yield name, str(ext.value)

    def distinguishedName(self):
        return format_name(self.x509.subject)
    distinguishedName.short_description = 'Distinguished Name'

    def subjectAltName(self):
        try:
            ext = self.x509.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        except x509.ExtensionNotFound:
            return ''

        value = format_general_names(ext.value)
        if ext.critical:  # pragma: no cover - not usually critical
            value = 'critical,%s' % value

        return value
    subjectAltName.short_description = 'subjectAltName'

    def crlDistributionPoints(self):
        try:
            crldp = self.x509.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        except x509.ExtensionNotFound:
            return ''

        value = ''
        for dp in crldp.value:
            if dp.full_name:
                value += 'Full Name: %s\n' % format_general_names(dp.full_name)
            else:  # pragma: no cover - not really used in the wild
                value += 'Relative Name:\n  %s' % format_name(dp.relative_name.value)

        if crldp.critical:  # pragma: no cover - not usually critical
            value = 'critical,%s' % value

        return value.strip()
    crlDistributionPoints.short_description = 'crlDistributionPoints'

    def authorityInfoAccess(self):
        try:
            ext = self.x509.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        except x509.ExtensionNotFound:
            return ''

        output = ''
        for desc in ext.value:
            if desc.access_method == AuthorityInformationAccessOID.OCSP:
                output += 'OCSP - %s\n' % format_general_names([desc.access_location])
            elif desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS:  # pragma: no branch
                output += 'CA Issuers - %s\n' % format_general_names([desc.access_location])

        if ext.critical:  # pragma: no cover - not usually critical
            output = 'critical,%s' % output
        return output
    authorityInfoAccess.short_description = 'authorityInfoAccess'

    def basicConstraints(self):
        try:
            ext = self.x509.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        except x509.ExtensionNotFound:  # pragma: no cover - extension should always be present
            return ''

        if ext.value.ca is True:
            value = 'CA:TRUE'
        else:
            value = 'CA:FALSE'
        if ext.value.path_length is not None:
            value = '%s, pathlen:%s' % (value, ext.value.path_length)

        if ext.critical:  # pragma: no branch - should always be critical
            value = 'critical,%s' % value
        return value
    basicConstraints.short_description = 'basicConstraints'

    def keyUsage(self):
        value = ''
        try:
            ext = self.x509.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        except x509.ExtensionNotFound:
            return value

        usages = []
        for key, value in KEY_USAGE_MAPPING.items():
            try:
                if getattr(ext.value, value):
                    usages.append(key)
            except ValueError:
                pass
        value = ','.join(sorted(usages))

        if ext.critical:
            value = 'critical,%s' % value
        return value
    keyUsage.short_description = 'keyUsage'

    def extendedKeyUsage(self):
        value = ''
        try:
            ext = self.x509.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        except x509.ExtensionNotFound:
            return value

        usages = []
        for usage in ext.value:
            usages.append(EXTENDED_KEY_USAGE_REVERSED[usage])
        value = ','.join(sorted(usages))

        if ext.critical:  # pragma: no cover - not usually critical
            value = 'critical,%s' % value
        return value
    extendedKeyUsage.short_description = 'extendedKeyUsage'

    def subjectKeyIdentifier(self):
        try:
            ext = self.x509.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        except x509.ExtensionNotFound:  # pragma: no cover - extension should always be present
            return ''

        hexlified = binascii.hexlify(ext.value.digest).upper().decode('utf-8')
        value = add_colons(hexlified)
        if ext.critical:  # pragma: no cover - not usually critical
            value = 'critical,%s' % value
        return value
    subjectKeyIdentifier.short_description = 'subjectKeyIdentifier'

    def issuerAltName(self):
        try:
            ext = self.x509.extensions.get_extension_for_oid(ExtensionOID.ISSUER_ALTERNATIVE_NAME)
        except x509.ExtensionNotFound:
            return ''

        value = format_general_names(ext.value)
        if ext.critical:  # pragma: no cover - not usually critical
            value = 'critical,%s' % value
        return value
    issuerAltName.short_description = 'issuerAltName'

    def authorityKeyIdentifier(self):
        try:
            ext = self.x509.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        except x509.ExtensionNotFound:  # pragma: no cover - extension should always be present
            return ''

        hexlified = binascii.hexlify(ext.value.key_identifier).upper().decode('utf-8')
        value = 'keyid:%s\n' % add_colons(hexlified)
        if ext.critical:  # pragma: no cover - not usually critical
            value = 'critical,%s' % value
        return value
    authorityKeyIdentifier.short_description = 'authorityKeyIdentifier'

    def get_digest(self, algo):
        algo = getattr(hashes, algo.upper())()
        return add_colons(binascii.hexlify(self.x509.fingerprint(algo)).upper().decode('utf-8'))

    @property
    def hpkp_pin(self):
        # taken from https://github.com/luisgf/hpkp-python/blob/master/hpkp.py

        public_key_raw = self.x509.public_key().public_bytes(
            encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)
        public_key_hash = hashlib.sha256(public_key_raw).digest()
        return base64.b64encode(public_key_hash).decode('utf-8')

    def dump_certificate(self, encoding=Encoding.PEM):
        return self.x509.public_bytes(encoding=encoding)

    class Meta:
        abstract = True


class CertificateAuthority(X509CertMixin):
    objects = CertificateAuthorityManager.from_queryset(CertificateAuthorityQuerySet)()

    name = models.CharField(max_length=32, help_text=_('A human-readable name'), unique=True)
    enabled = models.BooleanField(default=True)
    parent = models.ForeignKey('self', null=True, blank=True, related_name='children')
    private_key_path = models.CharField(max_length=256, help_text=_('Path to the private key.'))

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

    @property
    def key(self):
        if self._key is None:
            with open(self.private_key_path, 'rb') as f:
                self._key = load_pem_private_key(f.read(), None, default_backend())
        return self._key

    @property
    def pathlen(self):
        try:
            ext = self.x509.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        except x509.ExtensionNotFound:  # pragma: no cover - extension should always be present
            return ''
        return ext.value.path_length

    def nameConstraints(self):
        try:
            ext = self.x509.extensions.get_extension_for_oid(ExtensionOID.NAME_CONSTRAINTS)
        except x509.ExtensionNotFound:
            return ''

        value = ''
        if ext.value.permitted_subtrees:  # pragma: no branch
            value += 'Permitted:\n'
            for general_name in ext.value.permitted_subtrees:
                value += '  %s\n' % format_general_names([general_name])
        if ext.value.excluded_subtrees:  # pragma: no branch
            value += 'Excluded:\n'
            for general_name in ext.value.excluded_subtrees:
                value += '  %s\n' % format_general_names([general_name])

        if ext.critical:  # pragma: no branch - currently always critical
            value = 'critical,%s' % value

        return value
    nameConstraints.short_description = 'nameConstraints'

    class Meta:
        verbose_name = _('Certificate Authority')
        verbose_name_plural = _('Certificate Authorities')

    def __str__(self):
        return self.name


class Certificate(X509CertMixin):
    objects = CertificateManager.from_queryset(CertificateQuerySet)()

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

    watchers = models.ManyToManyField(Watcher, related_name='certificates', blank=True)

    ca = models.ForeignKey(CertificateAuthority, verbose_name=_('Certificate Authority'))
    csr = models.TextField(verbose_name=_('CSR'))

    revoked = models.BooleanField(default=False)
    revoked_date = models.DateTimeField(null=True, blank=True, verbose_name=_('Revoked on'))
    revoked_reason = models.CharField(
        max_length=32, null=True, blank=True, verbose_name=_('Reason for revokation'),
        choices=REVOCATION_REASONS)

    def revoke(self, reason=None):
        self.revoked = True
        self.revoked_date = timezone.now()
        self.revoked_reason = reason
        self.save()

    def get_revocation(self):
        """Get a crypto.Revoked object or None if the cert is not revoked."""

        if self.revoked is False:
            raise ValueError('Certificate is not revoked.')

        revoked_cert = x509.RevokedCertificateBuilder().serial_number(self.x509.serial).revocation_date(
            self.revoked_date)

        if self.revoked_reason:
            reason_flag = getattr(x509.ReasonFlags, self.revoked_reason)
            revoked_cert = revoked_cert.add_extension(x509.CRLReason(reason_flag), critical=False)

        return revoked_cert.build(default_backend())

    @property
    def ocsp_status(self):
        # NOTE: The OCSP status 'good' does not say if the certificate has expired.
        if self.revoked is False:
            return 'good'

        return self.revoked_reason or 'revoked'

    def __str__(self):
        return self.cn

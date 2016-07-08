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
import hashlib
import re

from django.db import models
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.encoding import force_text
from django.utils.translation import ugettext_lazy as _

from OpenSSL import crypto

from .managers import CertificateAuthorityManager
from .managers import CertificateManager
from .querysets import CertificateAuthorityQuerySet
from .querysets import CertificateQuerySet
from .utils import format_date
from .utils import format_subject
from .utils import multiline_url_validator
from .utils import parse_date
from .utils import serial_from_int


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

    pub = models.TextField(null=False, blank=False, verbose_name=_('Public key'))
    cn = models.CharField(max_length=64, null=False, blank=False, verbose_name=_('CommonName'))
    serial = models.CharField(max_length=48, null=False, blank=False, unique=True)

    _x509 = None
    _extensions = None

    @property
    def x509(self):
        if not self.pub:  # pragma: no cover
            return None

        if self._x509 is None:
            self._x509 = crypto.load_certificate(crypto.FILETYPE_PEM, self.pub)
        return self._x509

    @x509.setter
    def x509(self, value):
        self._x509 = value
        self.pub = crypto.dump_certificate(crypto.FILETYPE_PEM, value).decode('utf-8')
        self.cn = dict(self.x509.get_subject().get_components()).get(b'CN').decode('utf-8')
        self.expires = self.not_after

        # compute serial with ':' after every second character
        self.serial = serial_from_int(value.get_serial_number())

    @property
    def subject(self):
        return {force_text(k): force_text(v) for k, v in self.x509.get_subject().get_components()}

    @property
    def issuer(self):
        return {force_text(k): force_text(v) for k, v in self.x509.get_issuer().get_components()}

    @property
    def extensions(self):
        if self.x509 is None:  # pragma: no cover
            return {}

        if self._extensions is None:
            exts = [self.x509.get_extension(i) for i in range(0, self.x509.get_extension_count())]
            self._extensions = {ext.get_short_name(): ext for ext in exts}
        return self._extensions

    @property
    def not_before(self):
        return parse_date(self.x509.get_notBefore().decode('utf-8'))

    @property
    def not_after(self):
        return parse_date(self.x509.get_notAfter().decode('utf-8'))

    def ext_as_str(self, key):
        if key not in self.extensions:
            return ''

        value = self.extensions[key]
        if value.get_critical():
            return 'critical,%s' % value
        return str(value)

    def distinguishedName(self):
        return format_subject(self.x509.get_subject())
    distinguishedName.short_description = 'Distinguished Name'

    def subjectAltName(self):
        return self.ext_as_str(b'subjectAltName')
    subjectAltName.short_description = 'subjectAltName'

    def crlDistributionPoints(self):
        return self.ext_as_str(b'crlDistributionPoints')
    crlDistributionPoints.short_description = 'crlDistributionPoints'

    def authorityInfoAccess(self):
        return self.ext_as_str(b'authorityInfoAccess')
    authorityInfoAccess.short_description = 'authorityInfoAccess'

    def basicConstraints(self):
        return self.ext_as_str(b'basicConstraints')
    basicConstraints.short_description = 'basicConstraints'

    def keyUsage(self):
        return self.ext_as_str(b'keyUsage')
    keyUsage.short_description = 'keyUsage'

    def extendedKeyUsage(self):
        return self.ext_as_str(b'extendedKeyUsage')
    extendedKeyUsage.short_description = 'extendedKeyUsage'

    def subjectKeyIdentifier(self):
        return self.ext_as_str(b'subjectKeyIdentifier')
    subjectKeyIdentifier.short_description = 'subjectKeyIdentifier'

    def issuerAltName(self):
        return self.ext_as_str(b'issuerAltName')
    issuerAltName.short_description = 'issuerAltName'

    def authorityKeyIdentifier(self):
        return self.ext_as_str(b'authorityKeyIdentifier')
    authorityKeyIdentifier.short_description = 'authorityKeyIdentifier'

    def get_digest(self, algo):
        return self.x509.digest(algo).decode('utf-8')

    @property
    def hpkp_pin(self):
        # taken from
        # https://github.com/shazow/urllib3/pull/607/files#diff-f86c7f2eb1a0a2deadac493decdd0b7eR337

        key = self.x509.get_pubkey()
        public_key_raw = crypto.dump_publickey(crypto.FILETYPE_ASN1, key)
        public_key_hash = hashlib.sha256(public_key_raw).digest()
        return base64.b64encode(public_key_hash).decode('utf-8')

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
            with open(self.private_key_path) as f:
                self._key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

        return self._key

    @property
    def pathlen(self):
        constraints = self.basicConstraints()
        if 'pathlen' in constraints:
            return int(constraints.split('pathlen:')[1])
        return None

    class Meta:
        verbose_name = _('Certificate Authority')
        verbose_name_plural = _('Certificate Authorities')

    def __str__(self):
        return self.name


class Certificate(X509CertMixin):
    objects = CertificateManager.from_queryset(CertificateQuerySet)()

    # reasons are defined in http://www.ietf.org/rfc/rfc3280.txt
    # TODO: add privilegeWithdrawn and aACompromise
    REVOCATION_REASONS = (
        ('', _('No reason')),
        ('unspecified', _('Unspecified')),
        ('keyCompromise', _('Key compromised')),
        ('CACompromise', _('CA compromised')),
        ('affiliationChanged', _('Affiliation changed')),
        ('superseded', _('Superseded')),
        ('cessationOfOperation', _('Cessation of operation')),
        ('certificateHold', _('On Hold')),
        # Not currently useful according to "man ca",
        #('removeFromCRL', _('Remove from CRL')),
    )
    OCSP_REASON_MAPPINGS = {
        'keyCompromise': 'key_compromise',
        'CACompromise': 'ca_compromise',
        'affiliationChanged': 'affiliation_changed',
        'superseded': 'superseded',
        'cessationOfOperation': 'cessation_of_operation',
        'certificateHold': 'certificate_hold',
        'removeFromCRL': 'remove_from_crl',
        'privilegeWithdrawn': 'privilege_withdrawn',
        'aACompromise': 'aa_compromise',
    }

    watchers = models.ManyToManyField(Watcher, related_name='certificates', blank=True)

    ca = models.ForeignKey(CertificateAuthority, verbose_name=_('Certificate Authority'))
    csr = models.TextField(null=False, blank=False, verbose_name=_('CSR'))

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

        r = crypto.Revoked()
        # set_serial expects a str without the ':'
        r.set_serial(force_bytes(self.serial.replace(':', '')))
        if self.revoked_reason:
            r.set_reason(force_bytes(self.revoked_reason))
        r.set_rev_date(force_bytes(format_date(self.revoked_date)))
        return r

    @property
    def ocsp_status(self):
        # NOTE: The OCSP status 'good' does not say if the certificate has expired.
        if self.revoked is False:
            return 'good'

        return self.OCSP_REASON_MAPPINGS.get(self.revoked_reason, 'revoked')

    def __str__(self):
        return self.cn

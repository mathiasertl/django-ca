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

import re

from django.db import models
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _

from OpenSSL import crypto

from .utils import format_date
from .managers import CertificateManager
from .querysets import CertificateQuerySet


class Watcher(models.Model):
    name = models.CharField(max_length=64, null=True, blank=True, verbose_name=_('CommonName'))
    mail = models.EmailField(verbose_name=_('E-Mail'))

    @classmethod
    def from_addr(cls, addr):
        defaults = {}
        if '<' in addr:
            name, addr = re.match('(.*) <(.*)>', addr).groups()
            defaults['name'] = name

        return cls.objects.update_or_create(mail=addr, defaults=defaults)[0]

    def __str__(self):
        if self.name:
            return '%s <%s>' % (self.name, self.mail)
        return self.mail


class Certificate(models.Model):
    _x509 = None
    _extensions = None

    objects = CertificateManager.from_queryset(CertificateQuerySet)()

    watchers = models.ManyToManyField(Watcher, related_name='certificates', blank=True)

    created = models.DateTimeField(auto_now=True)
    expires = models.DateTimeField(null=False, blank=False)

    csr = models.TextField(null=False, blank=False, verbose_name=_('CSR'))
    pub = models.TextField(null=False, blank=False, verbose_name=_('Public key'))

    cn = models.CharField(max_length=64, null=False, blank=False, verbose_name=_('CommonName'))
    serial = models.CharField(max_length=35, null=False, blank=False)
    revoked = models.BooleanField(default=False)
    revoked_date = models.DateTimeField(null=True, blank=True, verbose_name=_('Revoked on'))
    revoked_reason = models.CharField(max_length=32, null=True, blank=True,
                                      verbose_name=_('Reason for revokation'))

    def subjectAltName(self):
        return self.extensions.get(b'subjectAltName', '')
    subjectAltName.short_description = 'subjectAltName'

    def crlDistributionPoints(self):
        return self.extensions.get(b'crlDistributionPoints', '')
    crlDistributionPoints.short_description = 'crlDistributionPoints'

    def authorityInfoAccess(self):
        return self.extensions.get(b'authorityInfoAccess', '')
    authorityInfoAccess.short_description = 'authorityInfoAccess'

    def basicConstraints(self):
        if b'basicConstraints' not in self.extensions:
            return ''
        value = self.extensions[b'basicConstraints']
        if value.get_critical():
            value = 'critical,%s' % value
        return value
    basicConstraints.short_description = 'basicConstraints'

    def keyUsage(self):
        return self.extensions.get(b'keyUsage', '')
    keyUsage.short_description = 'keyUsage'

    def extendedKeyUsage(self):
        return self.extensions.get(b'extendedKeyUsage', '')
    extendedKeyUsage.short_description = 'extendedKeyUsage'

    def subjectKeyIdentifier(self):
        return self.extensions.get(b'subjectKeyIdentifier', '')
    subjectKeyIdentifier.short_description = 'subjectKeyIdentifier'

    def issuerAltName(self):
        return self.extensions.get(b'issuerAltName', '')
    issuerAltName.short_description = 'issuerAltName'

    def authorityKeyIdentifier(self):
        return self.extensions.get(b'authorityKeyIdentifier', '')
    authorityKeyIdentifier.short_description = 'authorityKeyIdentifier'

    def save(self, *args, **kwargs):
        if self.pk is None or self.serial is None:
            self.serial = hex(self.x509.get_serial_number())[2:].upper()
        super(Certificate, self).save(*args, **kwargs)

    @property
    def x509(self):
        if not self.pub:
            return None

        if self._x509 is None:
            self._x509 = crypto.load_certificate(crypto.FILETYPE_PEM, self.pub)
        return self._x509

    @property
    def extensions(self):
        if self.x509 is None:
            return {}

        if self._extensions is None:
            exts = [self.x509.get_extension(i) for i in range(0, self.x509.get_extension_count())]
            self._extensions = {ext.get_short_name(): ext for ext in exts}
        return self._extensions

    @property
    def distinguishedName(self):
        name = self.x509.get_subject()
        return '/%s' % '/'.join(['%s=%s' % (k.decode('utf-8'), v.decode('utf-8'))
                                 for k, v in name.get_components()])

    def revoke(self, reason=None):
        self.revoked = True
        self.revoked_date = timezone.now()
        self.revoked_reason = reason
        self.save()

    def get_revocation(self):
        """Get a crypto.Revoked object or None if the cert is not revoked."""

        if self.revoked:
            r = crypto.Revoked()
            r.set_serial(bytes(self.serial, 'utf-8'))
            if self.revoked_reason:
                r.set_reason(bytes(self.revoked_reason, 'utf-8'))
            r.set_rev_date(bytes(format_date(self.revoked_date), 'utf-8'))
            return r

    def __str__(self):
        return self.cn

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

class X509CertMixin(object):
    _x509 = None
    _extensions = None

    @property
    def x509(self):
        if not self.pub:
            return None

        if self._x509 is None:
            self._x509 = crypto.load_certificate(crypto.FILETYPE_PEM, self.pub)
        return self._x509

    @x509.setter
    def x509(self, value):
        self._x509 = value
        self.pub = crypto.dump_certificate(crypto.FILETYPE_PEM, value)

        # set serial
        s = hex(value.get_serial_number())[2:].upper()
        self.serial = ':'.join(a+b for a,b in zip(s[::2], s[1::2]))

    @property
    def extensions(self):
        if self.x509 is None:
            return {}

        if self._extensions is None:
            exts = [self.x509.get_extension(i) for i in range(0, self.x509.get_extension_count())]
            self._extensions = {ext.get_short_name(): ext for ext in exts}
        return self._extensions

    def ext_as_str(self, key):
        if key not in self.extensions:
            return ''

        value = self.extensions[key]
        if value.get_critical():
            value = 'critical,%s' % value
        return value

    def distinguishedName(self):
        name = self.x509.get_subject()
        return '/%s' % '/'.join(['%s=%s' % (k.decode('utf-8'), v.decode('utf-8'))
                                 for k, v in name.get_components()])
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


class CertificateAuthority(models.Model, X509CertMixin):
    name = models.CharField(max_length=32, help_text=_('A human-readable name'))
    serial = models.CharField(max_length=48, null=False, blank=False)
    created = models.DateTimeField(auto_now=True)
    enabled = models.BooleanField(default=True)
    pub = models.TextField(null=False, blank=False, verbose_name=_('Public key'))
    parent = models.ForeignKey('self', null=True, blank=True, related_name='children')
    private_key_path = models.CharField(max_length=256, help_text=_('Path to the private key.'))

    _key = None

    @property
    def key(self):
        if self._key is None:
            with open(self.private_key_path) as f:
                return crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

        return self._key

    def save(self, *args, **kwargs):
        if not self.serial:
            s = hex(self.x509.get_serial_number())[2:].upper()
            self.serial = ':'.join(a+b for a,b in zip(s[::2], s[1::2]))
        super(CertificateAuthority, self).save(*args, **kwargs)

    def __str__(self):
        return self.name


class Certificate(models.Model, X509CertMixin):
    objects = CertificateQuerySet.as_manager()

    watchers = models.ManyToManyField(Watcher, related_name='certificates', blank=True)

    created = models.DateTimeField(auto_now=True)
    expires = models.DateTimeField(null=False, blank=False)

    ca = models.ForeignKey(CertificateAuthority, verbose_name=_('Certificate Authority'))
    csr = models.TextField(null=False, blank=False, verbose_name=_('CSR'))
    pub = models.TextField(null=False, blank=False, verbose_name=_('Public key'))

    cn = models.CharField(max_length=64, null=False, blank=False, verbose_name=_('CommonName'))
    serial = models.CharField(max_length=48, null=False, blank=False)
    revoked = models.BooleanField(default=False)
    revoked_date = models.DateTimeField(null=True, blank=True, verbose_name=_('Revoked on'))
    revoked_reason = models.CharField(max_length=32, null=True, blank=True,
                                      verbose_name=_('Reason for revokation'))

    def save(self, *args, **kwargs):
        if self.pk is None and not self.cn:
            self.cn = dict(self.x509.get_subject().get_components()).get(b'CN').decode('utf-8')
        if self.pk is None or self.serial is None:
            s = hex(self.x509.get_serial_number())[2:].upper()
            self.serial = ':'.join(a+b for a,b in zip(s[::2], s[1::2]))
        super(Certificate, self).save(*args, **kwargs)

    def revoke(self, reason=None):
        self.revoked = True
        self.revoked_date = timezone.now()
        self.revoked_reason = reason
        self.save()

    def get_revocation(self):
        """Get a crypto.Revoked object or None if the cert is not revoked."""

        if self.revoked:
            r = crypto.Revoked()
            # set_serial expects a str without the ':'
            r.set_serial(bytes(self.serial.replace(':', ''), 'utf-8'))
            if self.revoked_reason:
                r.set_reason(bytes(self.revoked_reason, 'utf-8'))
            r.set_rev_date(bytes(format_date(self.revoked_date), 'utf-8'))
            return r

    def __str__(self):
        return self.cn

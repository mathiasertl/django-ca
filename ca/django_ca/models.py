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

from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _

from OpenSSL import crypto

from .utils import format_date
from .managers import CertificateManager


class Certificate(models.Model):
    _x509 = None
    _extensions = None

    objects = CertificateManager()

    watchers = models.ManyToManyField(User)

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

    def save(self, *args, **kwargs):
        if self.pk is None or self.serial is None:
            self.serial = hex(self.x509.get_serial_number())[2:-1].upper()
        super(Certificate, self).save(*args, **kwargs)

    @property
    def x509(self):
        if self._x509 is None:
            self._x509 = crypto.load_certificate(crypto.FILETYPE_PEM, self.pub)
        return self._x509

    @property
    def extensions(self):
        if self._extensions is None:
            exts = [self.x509.get_extension(i) for i in range(0, self.x509.get_extension_count())]
            self._extensions = {ext.get_short_name(): ext for ext in exts}
        return self._extensions

    @property
    def distinguishedName(self):
        name = self.x509.get_subject()
        return '/%s'  % '/'.join(['%s=%s' % (k.decode('utf-8'), v.decode('utf-8'))
                                  for k, v in name.get_components()])

    def revoke(self, reason=None):
        self.revoked = True
        self.revoked_date = timezone.ow()
        self.revoked_reason = reason
        self.save()

    def get_revocation(self):
        """Get a crypto.Revoked object or None if the cert is not revoked."""

        if self.revoked:
            r = crypto.Revoked()
            r.set_serial(str(self.serial))
            if self.revoked_reason:
                r.set_reason(str(self.revoked_reason))
            r.set_rev_date(format_date(self.revoked_date))
            return r

    def __str__(self):
        return self.cn

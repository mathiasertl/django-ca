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

from django.db import models
from django.db.models import Q
from django.utils import timezone


class DjangoCAMixin(object):
    def get_by_serial_or_cn(self, identifier):
        identifier = identifier.strip()
        serial = identifier.upper()

        return self.get(Q(serial__startswith=serial) | Q(cn=identifier))

    def revoked(self):
        """Return revoked certificates."""

        return self.filter(revoked=True)


class CertificateAuthorityQuerySet(models.QuerySet, DjangoCAMixin):
    def enabled(self):
        return self.filter(enabled=True)


class CertificateQuerySet(models.QuerySet, DjangoCAMixin):
    def not_yet_valid(self):
        """Return certificates that are not yet valid."""

        return self.filter(revoked=False, valid_from__gt=timezone.now())

    def valid(self):
        """Return valid certificates."""

        now = timezone.now()
        return self.filter(revoked=False, expires__gt=now, valid_from__lt=now)

    def expired(self):
        """Returns expired certificates.

        Note that this method does not return revoked certificates that would otherwise be expired.
        """
        return self.filter(revoked=False, expires__lt=timezone.now())

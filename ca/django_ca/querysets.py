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


class CertificateQuerySet(models.QuerySet):
    def valid(self):
        """Return valid certificates."""

        return self.filter(revoked=False, expires__gt=timezone.now())

    def expired(self):
        """Returns expired certificates.

        Note that this method does not return revoked certificates that would otherwise be expired.
        """
        return self.filter(revoked=False, expires__lt=timezone.now())

    def revoked(self):
        """Return revoked certificates."""

        return self.filter(revoked=True)

    def get_by_serial_or_cn(self, identifier):
        return self.get(Q(serial=identifier) | Q(cn=identifier))

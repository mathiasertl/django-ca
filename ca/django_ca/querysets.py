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

"""QuerySet classes for DjangoCA models."""

from django.db import models
from django.db.models import Q
from django.utils import timezone

from .utils import sanitize_serial


class DjangoCAMixin:
    """Mixin with common methods for CertificateAuthority and Certificate models."""

    def get_by_serial_or_cn(self, identifier):
        """Get a model by serial *or* by common name.

        This method is meant to get a CA from a user input value. If `identifier` is a serial, colons (``:``)
        and leading zeros are ignored. If no exact match is found it will search for CAs starting with that
        value. For example, if a CA has the serial ``ABCDE``, it will be found with "ABCDE", "A:BC:DE",
        "0A:BC:DE" or just "0AB" as `identifier`.
        """
        identifier = identifier.strip()
        exact_query = startswith_query = Q(cn=identifier)

        try:
            serial = sanitize_serial(identifier)
            exact_query |= Q(serial=serial)
            startswith_query |= Q(serial__startswith=serial)
        except ValueError:
            pass

        try:
            # Imported CAs might have a shorter serial and there is a chance that it might become impossible
            # to select a CA by serial if its serial matches another CA with a longer serial. So we try to
            # match by exact serial first.
            return self.get(exact_query)
        except self.model.DoesNotExist:
            return self.get(startswith_query)

    def revoked(self):
        """Return revoked certificates."""

        return self.filter(revoked=True)


class CertificateAuthorityQuerySet(models.QuerySet, DjangoCAMixin):
    """QuerySet for the CertificateAuthority model."""

    def disabled(self):
        """Return CAs that are disabled."""
        return self.filter(enabled=False)

    def enabled(self):
        """Return CAs that are enabled."""
        return self.filter(enabled=True)

    def valid(self):
        """Return CAs that are currently valid."""
        now = timezone.now()
        return self.filter(expires__gt=now, valid_from__lt=now)

    def invalid(self):
        """Return CAs that are either expired or not yet valid."""
        now = timezone.now()
        return self.exclude(expires__gt=now, valid_from__lt=now)

    def usable(self):
        """Return CAs that are enabled and currently valid."""
        return self.enabled().valid()


class CertificateQuerySet(models.QuerySet, DjangoCAMixin):
    """QuerySet for the Certificate model."""

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

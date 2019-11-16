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

from datetime import timedelta

from django.utils import timezone

from .constants import ReasonFlags

# We need a two-letter year, otherwise OCSP doesn't work
date_format = '%y%m%d%H%M%SZ'


def get_index(ca):
    now = timezone.now()
    yesterday = now - timedelta(seconds=86400)
    certs = ca.certificate_set.order_by('expires', 'cn', 'serial')

    # Write index file (required by "openssl ocsp")
    for cert in certs.filter(expires__gt=yesterday, valid_from__lt=now):
        revocation = ''
        if cert.expires < now:
            status = 'E'
        elif cert.revoked:
            status = 'R'

            revocation = cert.revoked_date.strftime(date_format)
            if cert.revoked_reason != ReasonFlags.unspecified.name:
                revocation += ',%s' % cert.revoked_reason
        else:
            status = 'V'

        # Format see: http://pki-tutorial.readthedocs.org/en/latest/cadb.html
        yield '%s\n' % '\t'.join([
            status,
            cert.x509.not_valid_after.strftime(date_format),
            revocation,
            cert.serial.replace(':', ''),
            'unknown',  # we don't save to any file
            cert.distinguishedName(),
        ])

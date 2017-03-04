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

from datetime import datetime

# We need a two-letter year, otherwise OCSP doesn't work
date_format = '%y%m%d%H%M%SZ'


def get_index(ca):
    now = datetime.utcnow()

    # Write index file (required by "openssl ocsp")
    for cert in ca.certificate_set.all():
        revocation = ''
        if cert.expires < now:
            status = 'E'
        elif cert.revoked:
            status = 'R'

            revocation = cert.revoked_date.strftime(date_format)
            if cert.revoked_reason:
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

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

from django.conf import settings

from .crl import get_crl
from .models import Certificate

# We need a two-letter year, otherwise OCSP doesn't work
date_format = '%y%m%d%H%M%SZ'


def get_index():
    now = datetime.utcnow()

    # Write index file (required by "openssl ocsp")
    for cert in Certificate.objects.all():
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
            cert.x509.get_notAfter().decode('utf-8'),
            revocation,
            cert.serial,
            'unknown',  # we don't save to any file
            cert.distinguishedName,
        ])

def get_ocsp_crl(**kwargs):
    """TODO: Verify that this is really needed!?"""
    crl = get_crl(**kwargs).decode('utf-8')

    # Write cafile (required by "openssl ocsp")
    with open(settings.CA_CRT) as ca_file, open(settings.CA_FILE_PEM, 'w') as out:
        ca = ca_file.read()
        out.write(ca)
        out.write(crl)

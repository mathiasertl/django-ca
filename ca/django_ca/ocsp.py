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

import os
import sys

from datetime import datetime

from . import ca_settings
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
            cert.serial.replace(':', ''),
            'unknown',  # we don't save to any file
            cert.distinguishedName(),
        ])

def write_index(path=None, stdout=None):
    if path is None:
        path = ca_settings.CA_OCSP_INDEX_PATH

    # if path is still None, we don't do anything
    if path is None:
        return

    if path == '-':
        if stdout is None:
            stdout = sys.stdout

        for line in get_index():
            stdout.write(line)
    else:
        dirname = os.path.dirname(path)
        if dirname and not os.path.exists(dirname):
            os.makedirs(dirname)

        with open(path, 'w') as out:
            for line in get_index():
                out.write(line)

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
from argparse import FileType

from django.conf import settings
from django.core.management.base import BaseCommand

from OpenSSL import crypto

from django_ca.models import Certificate
from django_ca.utils import get_ca_crt
from django_ca.utils import get_ca_key

# We need a two-letter year, otherwise OCSP doesn't work
date_format = '%y%m%d%H%M%SZ'


class Command(BaseCommand):
    help = "Write the certificate revocation list (CRL)."

    def add_arguments(self, parser):
        parser.add_argument('path', type=FileType('w'))

    def handle(self, path, **options):
        crl = crypto.CRL()
        index = []
        now = datetime.utcnow()

        for cert in Certificate.objects.all():
            revocation = ''
            if cert.expires < now:
                status = 'E'
            elif cert.revoked:
                status = 'R'
                crl.add_revoked(cert.get_revocation())  # add to CRL

                revocation = cert.revoked_date.strftime(date_format)
                if cert.revoked_reason:
                    revocation += ',%s' % cert.revoked_reason
            else:
                status = 'V'

            # Format see: http://pki-tutorial.readthedocs.org/en/latest/cadb.html
            index.append((
                status,
                cert.x509.get_notAfter().decode('utf-8'),
                revocation,
                cert.serial,
                'unknown',  # we don't save to any file
                cert.distinguishedName,
            ))

        # Write CRL
        crl = crl.export(get_ca_crt(), get_ca_key())
        path.write(crl.decode('utf-8'))

        # Write index file (required by "openssl ocsp")
        with open(settings.CA_INDEX, 'w') as index_file:
            for entry in index:
                index_file.write('%s\n' % '\t'.join(entry))

        # Write cafile (required by "openssl ocsp")
        with open(settings.CA_CRT) as ca_file, open(settings.CA_FILE_PEM, 'w') as out:
            ca = ca_file.read()
            out.write(ca)
            out.write(crl.decode('utf-8'))

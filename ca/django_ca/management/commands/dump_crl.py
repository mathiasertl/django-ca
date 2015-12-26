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

from argparse import FileType

from OpenSSL import crypto

from django.core.management.base import BaseCommand
from django.core.management.base import CommandError

from django_ca.crl import get_crl

# We need a two-letter year, otherwise OCSP doesn't work
date_format = '%y%m%d%H%M%SZ'


class Command(BaseCommand):
    help = "Write the certificate revocation list (CRL)."

    def add_arguments(self, parser):
        parser.add_argument(
            '-d', '--days', type=int,
            help="The number of days until the next update of this CRL (default: 100).")
        parser.add_argument('-t', '--type', choices=['pem', 'asn1', 'text', 'der'],
                            help="Format of the CRL file (default: pem).")
        parser.add_argument('--digest',
                            help="The name of the message digest to use (default: sha512).")
        parser.add_argument('path', type=FileType('wb'))

    def handle(self, path, **options):
        kwargs = {}
        if options['days']:
            kwargs['days'] = options['days']
        if options['type']:
            if options.get('type') == 'der':
                options['type'] = 'asn1'
            kwargs['type'] = getattr(crypto, 'FILETYPE_%s' % options['type'].upper())
        if options['digest']:
            kwargs['digest'] = bytes(options['digest'], 'utf-8')

        crl = get_crl(**kwargs)
        if 'b' not in path.mode:  # writing to stdout
            if kwargs['type'] == 'asn1':
                raise CommandError("ASN1 cannot be reliably printed to stdout.")

            crl = crl.decode('utf-8')
        path.write(crl)

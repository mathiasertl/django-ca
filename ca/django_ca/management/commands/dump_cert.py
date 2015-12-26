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

from django.core.management.base import BaseCommand
from django.core.management.base import CommandError

from OpenSSL import crypto

from django_ca.models import Certificate

# We need a two-letter year, otherwise OCSP doesn't work
date_format = '%y%m%d%H%M%SZ'


class Command(BaseCommand):
    help = "Dump a certificate to a file."

    def add_arguments(self, parser):
        parser.add_argument(
            '-f', '--format', choices=['pem', 'asn1', 'text', 'der'], default='pem',
            help='The format to use, default is %(default)s.')
        parser.add_argument('serial', help='''The serial of the certificate to dump.
 The "list_certs" command lists all known certificates.''')
        parser.add_argument('path', type=FileType('wb'),
                            help='Path where to dump the certificate. Use "-" for stdout.')

    def handle(self, serial, path, **options):
        try:
            cert = Certificate.objects.get(serial=serial)
        except Certificate.DoesNotExist:
            raise CommandError('Certificate with given serial not found.')

        format = options.get('format')
        if format == 'pem':
            data = cert.pub.encode('utf-8')
        elif format == 'asn1' or format == 'der':
            data = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert.x509)
        elif format == 'text':
            data = crypto.dump_certificate(crypto.FILETYPE_TEXT, cert.x509)

        if 'b' not in path.mode:
            if format == 'asn1':
                raise CommandError("ASN1 cannot be reliably printed to stdout.")
            data = data.decode('utf-8')
        path.write(data)

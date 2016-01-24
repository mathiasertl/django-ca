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

from django.core.management.base import CommandError

from OpenSSL import crypto

from django_ca.management.base import CertCommand
from django_ca.models import Certificate


class Command(CertCommand):
    help = "Dump a certificate to a file."
    certificate_queryset = Certificate.objects.all()

    def add_arguments(self, parser):
        super(Command, self).add_arguments(parser)
        self.add_format(parser)
        parser.add_argument('path', type=FileType('wb'),
                            help='Path where to dump the certificate. Use "-" for stdout.')

    def handle(self, cert, path, **options):
        cert = self.get_certificate(cert)
        data = crypto.dump_certificate(options['format'], cert.x509)

        if 'b' not in path.mode:
            if options['format'] == crypto.FILETYPE_ASN1:
                raise CommandError("ASN1 cannot be reliably printed to stdout.")
            data = data.decode('utf-8')
        path.write(data)

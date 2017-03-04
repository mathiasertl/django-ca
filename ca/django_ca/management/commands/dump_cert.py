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

from django.core.management.base import CommandError

from django_ca.management.base import CertCommand


class Command(CertCommand):
    allow_revoked = True
    binary_output = True
    help = "Dump a certificate to a file."

    def add_arguments(self, parser):
        super(Command, self).add_arguments(parser)
        self.add_format(parser)
        parser.add_argument('path', nargs='?', default='-',
                            help='Path where to dump the certificate. Use "-" for stdout.')

    def handle(self, cert, path, **options):
        data = cert.dump_certificate(options['format'])
        if path == '-':
            self.stdout.write(data, ending=b'')
        else:
            try:
                with open(path, 'wb') as stream:
                    stream.write(data)
            except IOError as e:
                raise CommandError(e)

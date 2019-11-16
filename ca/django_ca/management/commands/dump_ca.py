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

from cryptography.hazmat.primitives.serialization import Encoding

from django.core.management.base import CommandError

from ..base import BaseCommand


class Command(BaseCommand):
    help = "Dump a certificate authority to a file."
    binary_output = True

    def add_arguments(self, parser):
        super(BaseCommand, self).add_arguments(parser)
        self.add_format(parser)
        self.add_ca(parser, arg='ca', allow_disabled=True)
        parser.add_argument('-b', '--bundle', default=False, action='store_true',
                            help='Dump the whole certificate bundle.')
        parser.add_argument('path', nargs='?', default='-',
                            help='Path where to dump the certificate. Use "-" for stdout.')

    def handle(self, ca, path, **options):
        if options['bundle'] and options['format'] == Encoding.DER:
            raise CommandError('Cannot dump bundle when using DER format.')

        if options['bundle']:
            certs = ca.bundle
        else:
            certs = [ca]

        data = b''.join([c.dump_certificate(options['format']) for c in certs])
        if path == '-':
            self.stdout.write(data, ending=b'')
        else:
            try:
                with open(path, 'wb') as stream:
                    stream.write(data)
            except IOError as e:
                raise CommandError(e)

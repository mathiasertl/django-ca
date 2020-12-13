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

"""Management command to write a CRL to stdout or a file.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-management-commands/
"""

from django.core.management.base import CommandError

from ..base import BaseCommand


class Command(BaseCommand):  # pylint: disable=missing-class-docstring
    help = "Write the certificate revocation list (CRL)."
    binary_output = True

    def add_arguments(self, parser):
        parser.add_argument(
            '-e', '--expires', type=int, default=86400, metavar='SECONDS',
            help="Seconds until a new CRL will be available (default: %(default)s).")
        parser.add_argument('path', nargs='?', default='-',
                            help='Path for the output file. Use "-" for stdout.')
        parser.add_argument(
            '--ca-crl', action='store_true', default=False,
            help="*DEPRECATED:* Use --scope=ca instead. Generate the CRL for revoked child CAs.")
        parser.add_argument(
            '-s', '--scope', choices=['ca', 'user', 'attribute'],
            help='Limit the scope for the CRL (default: %(default)s).')
        self.add_algorithm(parser)
        self.add_format(parser)
        self.add_ca(parser, allow_disabled=True)
        self.add_password(parser)
        super().add_arguments(parser)

    def handle(self, path, **options):  # pylint: disable=arguments-differ
        if options['ca_crl']:
            self.stderr.write(self.style.WARNING('WARNING: --ca-crl is deprecated, use --scope=ca instead.'))
            options['scope'] = 'ca'

        kwargs = {
            'expires': options['expires'],
            'algorithm': options['algorithm'],
            'password': options['password'],
            'scope': options['scope'],
        }

        # See if we can work with the private key
        ca = options['ca']
        self.test_private_key(ca, options['password'])

        try:
            crl = ca.get_crl(**kwargs).public_bytes(options['format'])
        except Exception as ex:
            # Note: all parameters are already sanitized by parser actions
            raise CommandError(ex) from ex

        if path == '-':
            self.stdout.write(crl, ending=b'')
        else:
            try:
                with open(path, 'wb') as stream:
                    stream.write(crl)
            except IOError as ex:
                raise CommandError(ex) from ex

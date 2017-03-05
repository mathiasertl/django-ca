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

from django_ca.management.base import CertCommand


class Command(CertCommand):
    binary_output = True
    allow_revoked = True
    help = 'View a certificate. The "list_certs" command lists all known certificates.'

    def add_arguments(self, parser):
        parser.add_argument(
            '-n', '--no-pem', default=False, action='store_true',
            help='Do not output public certificate in PEM format.')
        parser.add_argument(
            '-e', '--extensions', default=False, action='store_true',
            help='Show all extensions, not just subjectAltName.')
        self.add_format(parser)
        super(Command, self).add_arguments(parser)

    def handle(self, cert, **options):
        self.stdout.write('Common Name: %s' % cert.cn)

        # self.stdout.write notBefore/notAfter
        self.stdout.write('Valid from: %s' % cert.not_before.strftime('%Y-%m-%d %H:%M'))
        self.stdout.write('Valid until: %s' % cert.not_after.strftime('%Y-%m-%d %H:%M'))

        # self.stdout.write status
        if cert.revoked:
            self.stdout.write('Status: Revoked')
        elif cert.expires < datetime.utcnow():
            self.stdout.write('Status: Expired')
        else:
            self.stdout.write('Status: Valid')

        # self.stdout.write extensions
        if options['extensions']:
            for name, value in cert.extensions():
                self.stdout.write('%s:\n    %s' % (name, value))
        else:
            san = cert.subjectAltName()
            if san:
                self.stdout.write('subjectAltName:\n    %s' % san)

        self.stdout.write('Watchers:')
        for watcher in cert.watchers.all():
            self.stdout.write('* %s' % watcher)

        self.stdout.write('Digest:')
        for algo in ['md5', 'sha1', 'sha256', 'sha512']:
            self.stdout.write('    %s: %s' % (algo, cert.get_digest(algo)))

        self.stdout.write('HPKP pin: %s' % cert.hpkp_pin)

        if not options['no_pem']:
            self.stdout.write('')
            self.stdout.write(cert.dump_certificate(options['format']))

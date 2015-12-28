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
from django_ca.models import Certificate

DATE_FMT = '%Y%m%d%H%M%SZ'


class Command(CertCommand):
    help = 'View a certificate. The "list_certs" command lists all known certificates.'
    certificate_queryset = Certificate.objects.all()

    def add_arguments(self, parser):
        parser.add_argument(
            '-n', '--no-pem', default=False, action='store_true',
            help='Do not output public certificate in PEM format.')
        parser.add_argument(
            '-e', '--extensions', default=False, action='store_true',
            help='Show all extensions, not just subjectAltName.')
        super(Command, self).add_arguments(self, parser)

    def handle(self, cert, **options):
        cert = self.get_certificate(cert)
        self.stdout.write('Common Name: %s' % cert.cn)

        # self.stdout.write notBefore/notAfter
        validFrom = datetime.strptime(cert.x509.get_notBefore().decode('utf-8'), DATE_FMT)
        validUntil = datetime.strptime(cert.x509.get_notAfter().decode('utf-8'), DATE_FMT)
        self.stdout.write('Valid from: %s' % validFrom.strftime('%Y-%m-%d %H:%M'))
        self.stdout.write('Valid until: %s' % validUntil.strftime('%Y-%m-%d %H:%M'))

        # self.stdout.write status
        if cert.revoked:
            self.stdout.write('Status: Revoked')
        elif cert.expires < datetime.utcnow():
            self.stdout.write('Status: Expired')
        else:
            self.stdout.write('Status: Valid')

        # self.stdout.write extensions
        if options['extensions']:
            for name, value in cert.extensions.items():
                self.stdout.write("%s:" % name.decode('utf-8'))
                for line in str(value).strip().splitlines():
                    self.stdout.write("    %s" % line)
        else:
            ext = cert.extensions.get('subjectAltName')
            if ext:
                self.stdout.write('%s:' % ext.get_short_name().decode('utf-8'))
                self.stdout.write("    %s" % ext)

        self.stdout.write('Watchers:')
        for watcher in cert.watchers.all():
            self.stdout.write('* %s' % watcher)

        self.stdout.write('Digest:')
        for algo in ['md5', 'sha1', 'sha256', 'sha512']:
            value = cert.x509.digest(algo).decode('utf-8')
            self.stdout.write('    %s: %s' % (algo, value))

        if not options['no_pem']:
            self.stdout.write(cert.pub.strip())

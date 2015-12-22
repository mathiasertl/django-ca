# -*- coding: utf-8 -*-
#
# This file is part of fsinf-certificate-authority
# (https://github.com/fsinf/certificate-authority).
#
# fsinf-certificate-authority is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software Foundation, either
# version 3 of the License, or (at your option) any later version.
#
# fsinf-certificate-authority is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
# PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# fsinf-certificate-authority.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import unicode_literals

from datetime import datetime

from django.core.management.base import BaseCommand
from django.core.management.base import CommandError
from django.utils import six

from certificate_authority.models import Certificate

DATE_FMT = '%Y%m%d%H%M%SZ'


class Command(BaseCommand):
    help = 'View a certificate by serial. The "list_certs" command lists all known certificates.'

    def add_arguments(self, parser):
        parser.add_argument(
            '-n', '--no-pem', default=False, action='store_true',
            help='Do not output public certificate in PEM format.')
        parser.add_argument(
            '-e', '--extensions', default=False, action='store_true',
            help='Show all extensions, not just subjectAltName.')
        parser.add_argument('serial')

    def handle(self, serial, **options):
        try:
            cert = Certificate.objects.get(serial=serial)
        except Certificate.DoesNotExist:
            raise CommandError('Certificate with given serial not found.')
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
            for name, value in six.iteritems(cert.extensions):
                self.stdout.write("%s:" % name.decode('utf-8'))
                for line in str(value).strip().splitlines():
                    self.stdout.write("    %s" % line)
        else:
            ext = cert.extensions.get('subjectAltName')
            if ext:
                self.stdout.write('%s:' % ext.get_short_name().decode('utf-8'))
                self.stdout.write("    %s" % ext)

        emails = cert.watchers.values_list('email', flat=True)
        self.stdout.write('Watchers: %s' % ', '.join(emails))

        self.stdout.write('Digest:')
        for algo in ['md5', 'sha1', 'sha256', 'sha512']:
            value = cert.x509.digest(algo).decode('utf-8')
            self.stdout.write('    %s: %s' % (algo, value))

        if not options['no_pem']:
            self.stdout.write(cert.pub.strip())

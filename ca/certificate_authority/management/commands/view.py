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
from optparse import make_option

from django.core.management.base import BaseCommand
from django.core.management.base import CommandError
from django.utils import six

from certificate_authority.models import Certificate

DATE_FMT = '%Y%m%d%H%M%SZ'


class Command(BaseCommand):
    args = '<serial>'
    help = 'View a given certificate by ID'
    option_list = BaseCommand.option_list + (
        make_option(
            '-n', '--no-pem',
            default=False,
            action='store_true',
            help='Do not output public certificate in PEM format.'
        ),
        make_option(
            '-e', '--extensions',
            default=False,
            action='store_true',
            help='Show all extensions, not just subjectAltName.'
        ),
    )

    def handle(self, *args, **options):
        if len(args) != 1:
            raise CommandError('Please give exactly one serial (first colum of list command)')

        try:
            cert = Certificate.objects.get(serial=args[0])
        except Certificate.DoesNotExist:
            raise CommandError('Certificate with given serial not found.')
        print('Common Name: %s' % cert.cn)

        # print notBefore/notAfter
        validFrom = datetime.strptime(cert.x509.get_notBefore(), DATE_FMT)
        validUntil = datetime.strptime(cert.x509.get_notAfter(), DATE_FMT)
        print('Valid from: %s' % validFrom.strftime('%Y-%m-%d %H:%M'))
        print('Valid until: %s' % validUntil.strftime('%Y-%m-%d %H:%M'))

        # print status
        if cert.revoked:
            print('Status: Revoked')
        elif cert.expires < datetime.utcnow():
            print('Status: Expired')
        else:
            print('Status: Valid')

        # print extensions
        if options['extensions']:
            for name, value in six.iteritems(cert.extensions):
                print("%s:" % name)
                for line in str(value).strip().splitlines():
                    print("\t%s" % line)
        else:
            ext = cert.extensions.get('subjectAltName')
            if ext:
                print('%s:' % ext.get_short_name())
                print("\t%s" % str(ext))

        emails = cert.watchers.values_list('email', flat=True)
        print('Watchers: %s' % ', '.join(emails))

        print('Digest:')
        print('    md5: %s' % cert.x509.digest(str('md5')))
        print('    sha1: %s' % cert.x509.digest(str('sha1')))
        print('    sha256: %s' % cert.x509.digest(str('sha256')))
        print('    sha512: %s' % cert.x509.digest(str('sha512')))

        if not options['no_pem']:
            print(cert.pub.strip())

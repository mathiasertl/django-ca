# -*- coding: utf-8 -*-
#
# This file is part of fsinf-certificate-authority (https://github.com/fsinf/certificate-authority).
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

from certificate_authority.models import Certificate


class Command(BaseCommand):
    help = "List all certificates."

    option_list = BaseCommand.option_list + (
        make_option('--expired',
            default=False,
            action='store_true',
            help='Also list expired certificates.'
        ),
        make_option('--revoked',
            default=False,
            action='store_true',
            help='Also list revoked certificates.'
        ),
    )

    def handle(self, *args, **options):
        certs = Certificate.objects.all()

        if not options['expired']:
            certs = certs.filter(expires__gt=datetime.now())
        if not options['revoked']:
            certs = certs.filter(revoked=False)

        for cert in certs:
            if cert.revoked is True:
                info = 'revoked'
            else:
                info = 'expires: %s' % cert.expires.strftime('%Y-%m-%d')
            print('%s: %s (%s)' % (cert.serial, cert.cn, info))

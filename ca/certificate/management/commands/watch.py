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
from datetime import timedelta
from optparse import make_option

from django.conf import settings
from django.core.mail import send_mail
from django.core.management.base import BaseCommand

from certificate.models import Certificate


class Command(BaseCommand):
    help = "Send notifications about expiring certificates to watchers."

    option_list = BaseCommand.option_list + (
        make_option('--days', type='int', default=14,
                    help='Warn DAYS days ahead of time (default: %default).'
        ),
    )

    def handle(self, *args, **options):
        now = datetime.utcnow()
        expires = now + timedelta(days=options['days'])

        qs = Certificate.objects.filter(expires__lt=expires, expires__gt=now)
        for cert in qs:
            timestamp = cert.expires.strftime('%Y-%m-%d')
            subj = 'Certificate expiration for %s on %s' % (cert.cn, timestamp)
            msg = 'The certificate for %s will expire on %s.' % (cert.cn, timestamp)
            to = [u.email for u in cert.watchers.all()]
            send_mail(subj, msg, settings.DEFAULT_FROM_EMAIL, to)

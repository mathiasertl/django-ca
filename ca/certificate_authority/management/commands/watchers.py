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

from optparse import make_option

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from django.core.management.base import CommandError

from certificate.models import Certificate


class Command(BaseCommand):
    args = '<serial>'
    help = "Add/remove watchers to a specific certificate."

    option_list = BaseCommand.option_list + (
        make_option(
            '--add',
            metavar='EMAIL',
            default=[],
            action='append',
            help='Add an email to the watchlist (may be given multiple times)'
        ),
        make_option(
            '--rm',
            metavar='EMAIL',
            default=[],
            action='append',
            help='Remove an email from the watchlist (may be given multiple times)'
        ),
    )

    def handle(self, *args, **options):
        if len(args) != 1:
            raise CommandError("Please give exactly one serial (first colum of list command).")

        try:
            cert = Certificate.objects.get(serial=args[0])
        except Certificate.DoesNotExist:
            raise CommandError('Certificate with given serial not found.')

        # add users:
        add = [User.objects.get_or_create(email=e, defaults={'username': e})[0]
               for e in options['add']]
        cert.watchers.add(*add)

        # remove users:
        if options['rm']:
            cert.watchers.filter(email__in=options['rm']).delete()

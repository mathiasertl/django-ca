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

from django_ca.management.base import CertCommand

from django_ca.crl import write_crl
from django_ca.ocsp import write_index


class Command(CertCommand):
    help = "Revoke a certificate."

    def add_arguments(self, parser):
        parser.add_argument('--reason', help="An optional reason for revokation.")
        super(Command, self).add_arguments(parser)

    def handle(self, cert, **options):
        self.get_certificate(cert).revoke(reason=options.get('reason'))
        write_crl()
        write_index()

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

from argparse import FileType

from django.core.management.base import BaseCommand

from django_ca.ocsp import get_index

# We need a two-letter year, otherwise OCSP doesn't work
date_format = '%y%m%d%H%M%SZ'


class Command(BaseCommand):
    help = "Write an OCSP index file."

    def add_arguments(self, parser):
        parser.add_argument('path', type=FileType('w'),
                            help="Where to write the index (default: %(default)s)")

    def handle(self, path, **options):
        # Write index file (required by "openssl ocsp")
        for line in get_index():
            path.write(line)

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

"""Management command to cache CRLs.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-management-commands/
"""

from ...tasks import cache_crls
from ...tasks import run_task
from ..base import BaseCommand


class Command(BaseCommand):  # pylint: disable=missing-class-docstring
    help = "Cache CRLs"

    def add_arguments(self, parser):
        parser.add_argument('serial', nargs='*',
                            help="Generate CRLs for the given CAs. If omitted, generate CRLs for all CAs.")

    def handle(self, **options):  # pylint: disable=arguments-differ
        run_task(cache_crls, options['serial'])

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

"""Management command to write an OCSP index to stdout or a file.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-management-commands/
"""

from ...ocsp import get_index
from ..base import BaseCommand


class Command(BaseCommand):  # pylint: disable=missing-class-docstring
    help = "Write an OCSP index file."

    def add_arguments(self, parser):
        self.add_ca(parser, allow_disabled=True)
        parser.add_argument('path', type=str, default='-', nargs='?',
                            help="Where to write the index (default: stdout)")

    def handle(self, ca, path, **options):  # pylint: disable=arguments-differ
        if path == '-':
            for line in get_index(ca):
                self.stdout.write(line)
        else:
            with open(path, 'w') as stream:
                for line in get_index(ca):
                    stream.write(line)

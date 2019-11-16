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
from django_ca.models import Watcher


class Command(CertCommand):
    help = '''Add/remove addresses to be notified of an expiring certificate. The
        "list_certs" command lists all known certificates.

        E-Mail addresses can be verbatim ("user@example.com") or with a name, e.g. "Your Name
        <user@example.com>", the latter case must be quoted on the shell.
        '''

    def add_arguments(self, parser):
        parser.add_argument(
            '-a', '--add', metavar='EMAIL', default=[], action='append',
            help='''Address that now should be notified when the certificate expires. Add an email
                to be notified of an expiring certificate (may be given multiple times).''')
        parser.add_argument(
            '-r', '--rm', metavar='EMAIL', default=[], action='append',
            help='''Address that shoult no longer be notified when the certificate expires
                (may be given multiple times).''')
        super(Command, self).add_arguments(parser)

    def handle(self, cert, **options):
        # add/remove users:
        cert.watchers.add(*[Watcher.from_addr(addr) for addr in options['add']])
        cert.watchers.remove(*[Watcher.from_addr(addr) for addr in options['rm']])

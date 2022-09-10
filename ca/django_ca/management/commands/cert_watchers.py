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

"""Management command to add/remove certificate watchers.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-management-commands/
"""

import typing

from django.core.management.base import CommandParser

from ...models import Certificate, Watcher
from ..base import BaseCommand
from ..mixins import CertCommandMixin


class Command(CertCommandMixin, BaseCommand):
    """Implement the :command:`manage.py cert_watchers` command."""

    help = """Add/remove addresses to be notified of an expiring certificate. The
        "list_certs" command lists all known certificates.

        E-Mail addresses can be verbatim ("user@example.com") or with a name, e.g. "Your Name
        <user@example.com>", the latter case must be quoted on the shell.
        """

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "-a",
            "--add",
            metavar="EMAIL",
            default=[],
            action="append",
            help="""Address that now should be notified when the certificate expires. Add an email
                to be notified of an expiring certificate (may be given multiple times).""",
        )
        parser.add_argument(
            "-r",
            "--rm",
            metavar="EMAIL",
            default=[],
            action="append",
            help="""Address that shoult no longer be notified when the certificate expires
                (may be given multiple times).""",
        )
        super().add_arguments(parser)

    def handle(self, cert: Certificate, **options: typing.Any) -> None:  # type: ignore[override]
        cert.watchers.add(*[Watcher.from_addr(addr) for addr in options["add"]])
        cert.watchers.remove(*[Watcher.from_addr(addr) for addr in options["rm"]])

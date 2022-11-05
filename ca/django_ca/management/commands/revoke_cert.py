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

"""Management command to revoke a certificate.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-management-commands/
"""

import typing

from django.core.management.base import CommandError, CommandParser

from ...constants import ReasonFlags
from ...models import Certificate
from ..actions import ReasonAction
from ..base import BaseCommand
from ..mixins import CertCommandMixin


class Command(CertCommandMixin, BaseCommand):  # pylint: disable=missing-class-docstring
    allow_revoked = True
    help = "Revoke a certificate."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--reason", action=ReasonAction, help="An optional reason for revokation.")
        super().add_arguments(parser)

    def handle(self, cert: Certificate, reason: ReasonFlags, **options: typing.Any) -> None:
        if cert.revoked:
            raise CommandError(f"{cert.serial}: Certificate is already revoked.")

        cert.revoke(reason=reason)

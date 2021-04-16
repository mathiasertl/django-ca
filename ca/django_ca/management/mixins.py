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

"""Mixins for :py:class:`~django:django.core.management.BaseCommand` classes."""

from django.core.management.base import CommandParser

from ..typehints import Protocol
from .actions import CertificateAction


class CommandProtocol(Protocol):
    """Protocol for mixin classes, so that mypy can detect any issues."""

    def add_arguments(self, parser: CommandParser) -> None:
        """Entry point for subclassed commands to add custom arguments."""


class CertCommandMixin(CommandProtocol):
    """Mixin for commands that operate on a single certificate."""

    allow_revoked = False

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "cert",
            action=CertificateAction,
            allow_revoked=self.allow_revoked,
            help="""Certificate by CommonName or serial. If you give a CommonName (which is not by
                definition unique) there must be only one valid certificate with the given
                CommonName.""",
        )
        super().add_arguments(parser)

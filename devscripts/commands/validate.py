# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU General
# Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca. If not, see
# <http://www.gnu.org/licenses/>.

"""Validate various aspects of this repository not covered in unit tests."""

import argparse
from types import ModuleType

from devscripts.commands import DevSubCommand


class Command(DevSubCommand):
    """Class implementing the ``dev.py validate`` command."""

    help_text = "Validate various aspects of this repository not covered in unit tests."
    module_name = "validation"
    modules = (("django_ca", "django-ca"),)

    django_ca: ModuleType

    docker_options = argparse.ArgumentParser(add_help=False)
    docker_options.add_argument(
        "--docker-prune",
        default=False,
        action="store_true",
        help="Prune system before building Docker image.",
    )
    docker_options.add_argument(
        "--no-rebuild",
        default=True,
        dest="build",
        action="store_false",
        help="Do not rebuild the image before testing.",
    )

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

"""Command to create requirements-pinned.txt."""

import argparse
import os
import tempfile

from devscripts.commands import DevCommand
from devscripts.utils import run


class Command(DevCommand):
    """Class implementing the ``dev.py pin-requirements`` command."""

    help_text = "Update requirements-pinned.txt."

    def handle(self, args: argparse.Namespace) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            run(["python", "-m", "venv", tmpdir])
            pip = os.path.join(tmpdir, "bin", "pip")
            run([pip, "install", "-U", "pip", "setuptools", "wheel"])
            run([pip, "install", "-e", ".[api,celery,redis,psycopg3,yaml]"])
            with open("requirements-pinned.txt", "wb") as stream:
                run([pip, "freeze", "--exclude-editable"], stdout=stream)

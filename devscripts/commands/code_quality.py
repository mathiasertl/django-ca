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

"""Run linters and manage.py check commands."""

import argparse
import os
import subprocess
from typing import Any, List, Union

from devscripts import config
from devscripts.commands import DevCommand


class Command(DevCommand):
    """Class implementing the ``dev.py code-quality`` command."""

    help_text = "Run linters and manage.py check commands."
    description = help_text + " This command does **not** invoke pylint (too slow) or mypy."

    def manage(self, *args: str) -> "subprocess.CompletedProcess[Any]":
        """Shortcut to run manage.py with warnings turned into errors."""
        python: List[Union[str, "os.PathLike[str]"]] = ["python"]

        # Django 4.2 introduced a new way of handling storages
        known_warnings = [
            "default",  # equivalent to "python -Wd"
            "ignore:django.core.files.storage.get_storage_class is deprecated",  # pragma: only django<4.2
            "ignore:X509Extension support in pyOpenSSL is deprecated",  # from acme==2.8.0
            "ignore:Support for class-based `config` is deprecated",  # from django-ninja==1.1
        ]
        env = dict(os.environ, PYTHONWARNINGS=",".join(known_warnings))

        python.append(config.MANAGE_PY.relative_to(config.ROOT_DIR))
        python += args
        return self.run(*python, env=env)

    def handle(self, args: argparse.Namespace) -> None:
        config.SHOW_COMMANDS = True
        config.SHOW_COMMAND_OUTPUT = True

        self.run("ruff", "format", "--diff", ".")
        self.run("ruff", "check", ".")
        self.run("pre-commit", "run", "--all-files")

        self.manage("check")
        self.manage("makemigrations", "--check")

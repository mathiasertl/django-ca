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

"""Common functionality for dev.py subcommands."""

import importlib
import os
import subprocess
import sys
from pathlib import Path

from termcolor import colored

import django

from . import utils


class CommandError(Exception):
    """Exception class for handling dev.py errors."""

    def __init__(self, value, code=1):
        super().__init__()
        self.value = value
        self.code = code


class DevCommand:
    """Base class for all dev.py sub-commands."""

    def add_arguments(self, parser):
        """Add arguments to the command line parser."""

    def handle(self, args):
        """Method that is supposed to be implemented by sub-commands."""
        raise NotImplementedError

    def exec(self, args):
        """Default argparse entry point."""
        try:
            self.handle(args)
        except CommandError as ex:
            print(colored(f"ERROR: {ex.value}", "red", attrs=["bold"]))
            sys.exit(ex.code)

    def setup_django(self, settings_module="ca.test_settings"):
        """Call ``django.setup()`` and set ``DJANGO_SETTINGS_MODULE``."""
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", settings_module)
        django.setup()

    def run(self, *args, check=True, **kwargs):
        """Shortcut to run the given command."""
        args = [str(arg) if isinstance(arg, Path) else arg for arg in args]
        try:
            utils.run(args, check=check, **kwargs)
        except subprocess.CalledProcessError as ex:
            raise CommandError(f"{args[0]} returned with exit status {ex.returncode}.") from ex


def add_command(cmd_subparser, name):
    """Add a subcommand with the given name to the sub-command parser.

    The function expects to find ``Command`` class to be defined in `devscripts.{name}`.
    """

    mod_name = name.replace("-", "_")
    mod = importlib.import_module(f"devscripts.{mod_name}")
    cmd = mod.Command()

    cmd_parser = cmd_subparser.add_parser(name, help=cmd.help)
    cmd_parser.set_defaults(func=cmd.exec)
    cmd.add_arguments(cmd_parser)
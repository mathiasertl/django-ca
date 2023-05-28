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
import argparse
import importlib
import os
import subprocess
import sys
from typing import Any, Tuple, Union

import django

from devscripts import config, utils


class CommandError(Exception):
    """Exception class for handling dev.py errors."""

    def __init__(self, value: str, code: int = 1) -> None:
        super().__init__()
        self.value = value
        self.code = code


class ParserError(CommandError):
    """Exception that allows a command to show usage information."""

    def __init__(self, value: str, code: int = 2) -> None:
        super().__init__(value, code)


class DevCommand:
    """Base class for all dev.py sub-commands."""

    modules: Tuple[Tuple[str, str], ...] = tuple()

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add arguments to the command line parser."""

    def handle(self, args: argparse.Namespace) -> None:
        """Method that is supposed to be implemented by sub-commands."""
        raise NotImplementedError

    def exec(self, parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
        """Default argparse entry point."""

        for mod_name, pip_name in self.modules:
            mod = importlib.import_module(mod_name)
            setattr(self, mod_name, mod)

        if args.quiet:
            config.OUTPUT_COMMANDS = False

        try:
            self.handle(args)
        except ParserError as ex:
            parser.error(ex.value)
        except CommandError as ex:
            print(f"ERROR: {ex.value}")
            sys.exit(ex.code)

    def setup_django(self, settings_module: str = "ca.test_settings") -> None:
        """Call ``django.setup()`` and set ``DJANGO_SETTINGS_MODULE``."""
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", settings_module)
        django.setup()

    def run(self, *args: Union[str, "os.PathLike[str]"], check: bool = True, **kwargs: Any) -> None:
        """Shortcut to run the given command."""
        str_args = tuple(str(arg) if isinstance(arg, os.PathLike) else arg for arg in args)
        try:
            utils.run(str_args, check=check, **kwargs)
        except subprocess.CalledProcessError as ex:
            raise CommandError(f"{args[0]} returned with exit status {ex.returncode}.") from ex


def add_command(cmd_subparser: "argparse._SubParsersAction[argparse.ArgumentParser]", name: str) -> None:
    """Add a subcommand with the given name to the sub-command parser.

    The function expects to find ``Command`` class to be defined in `devscripts.{name}`.
    """

    mod_name = name.replace("-", "_")
    mod = importlib.import_module(f"devscripts.commands.{mod_name}")
    cmd = mod.Command()

    help_text = None
    description = None
    if cmd.__doc__ is not None:
        doc_lines = cmd.__doc__.splitlines()
        help_text = doc_lines[0].strip()
        if len(doc_lines) > 1:
            description = " ".join(doc_lines[1:]).strip()

    cmd_parser = cmd_subparser.add_parser(name, help=help_text, description=description)
    cmd_parser.set_defaults(func=cmd.exec)
    cmd.add_arguments(cmd_parser)

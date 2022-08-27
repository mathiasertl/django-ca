#!/usr/bin/env python3
#
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

"""Various commands used in development."""

import argparse

from devscripts.commands import add_command

parser = argparse.ArgumentParser(description="Helper-script for various tasks during development.")
commands = parser.add_subparsers(dest="command")

add_command(commands, "clean")
add_command(commands, "code-quality")
add_command(commands, "coverage")
add_command(commands, "docker-test")
add_command(commands, "init-demo")
add_command(commands, "recreate-fixtures")
add_command(commands, "test")
add_command(commands, "update-ca-data")
add_command(commands, "validate")
args = parser.parse_args()

if hasattr(args, "func"):
    args.func(parser, args)
else:  # no subcommand given
    parser.print_help()

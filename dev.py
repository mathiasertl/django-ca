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
import sys

from devscripts.commands import add_subcommands

parser = argparse.ArgumentParser(description="Helper-script for various tasks during development.")
parser.add_argument(
    "--show-commands", default=False, action="store_true", help="Show commands being executed."
)
parser.add_argument("--show-output", default=False, action="store_true", help="Show ouptut of commands.")
add_subcommands(parser, "devscripts.commands")
args = parser.parse_args()

if hasattr(args, "func"):
    exit_code = args.func(parser, args)
    if isinstance(exit_code, int):
        sys.exit(exit_code)
else:  # no subcommand given
    parser.print_help()

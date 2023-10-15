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

from devscripts.commands import add_subcommands

parser = argparse.ArgumentParser(description="Helper-script for various tasks during development.")
parser.add_argument("-q", "--quiet", default=False, action="store_true", help="Do not display commands.")
add_subcommands(parser, "devscripts.commands")
args = parser.parse_args()

if hasattr(args, "func"):
    args.func(parser, args)
else:  # no subcommand given
    parser.print_help()

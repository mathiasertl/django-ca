#!/usr/bin/env python3
#
# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca. If not,
# see <http://www.gnu.org/licenses/>.

"""Release script."""

import argparse
from importlib import import_module

from validation.docker import validate_docker_image

# pylint: disable=no-name-in-module  # false positive due to dev.py in top-level
from dev.out import ok
from dev.utils import redirect_output

# pylint: enable=no-name-in-module


def validate_state():
    """Validate state of various config files."""
    validate_state_mod = import_module("validate-state")
    with redirect_output() as stream:
        errors = validate_state_mod.validate_state()

    if errors == 0:
        ok("State validated.")
    else:
        print(stream.getvalue())
        raise RuntimeError("State validation failed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Build a django-ca release.")
    parser.add_argument("release", help="The actual release you want to build.")
    args = parser.parse_args()

    validate_state()
    validate_docker_image(release=args.release)

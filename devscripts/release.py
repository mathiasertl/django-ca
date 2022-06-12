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
import subprocess
from importlib import import_module

from validation.docker import validate_docker_image

# pylint: disable=no-name-in-module  # false positive due to dev.py in top-level
from dev import config
from dev.out import info
from dev.out import ok
from dev.out import warn
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


def create_docker_image(prune):
    """Create the docker image."""
    if prune:
        subprocess.run(["docker", "system", "prune", "-af"], check=True, stdout=subprocess.DEVNULL)
    else:
        warn("Not pruning Docker daemon before building")

    info("Building docker image...")
    subprocess.run(
        ["docker", "build", "--progress=plain", "-t", config.DOCKER_TAG, "."],
        check=True,
        env={
            "DOCKER_BUILDKIT": "1",
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    ok("Docker image built.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Build a django-ca release.")
    docker_grp = parser.add_argument_group("Docker options")
    docker_grp.add_argument(
        "--no-docker-prune",
        default=True,
        dest="docker_prune",
        action="store_false",
        help="Prune system before building Docker image.",
    )
    docker_grp.add_argument(
        "--skip-docker", default=False, action="store_true", help="Skip Docker image tests."
    )

    parser.add_argument("release", help="The actual release you want to build.")
    args = parser.parse_args()
    validate_state()

    if not args.skip_docker:
        validate_docker_image(config.DOCKER_TAG, args.release, prune=args.docker_prune)

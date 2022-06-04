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

import argparse
import io
import os
import subprocess
import sys
from contextlib import contextmanager
from contextlib import redirect_stderr
from contextlib import redirect_stdout
from importlib import import_module

from dev.out import err
from dev.out import info
from dev.out import ok
from dev.out import warn
from dev.utils import tmpdir

DOCKER_TAG = "mathiasertl/django-ca"


@contextmanager
def silence():
    f = io.StringIO()
    with redirect_stdout(f), redirect_stderr(f):
        yield f


def docker(cmd, *args, **kwargs):
    proc = subprocess.run(
        ["docker", "run", "--rm"] + list(args) + [DOCKER_TAG] + cmd,
        capture_output=True,
        check=True,
        text=True,
        **kwargs,
    )
    return proc


def validate_state():
    """Validate state of various config files."""
    validate_state = import_module("validate-state")
    with silence() as stream:
        errors = validate_state.validate_state()

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
        ["docker", "build", "--progress=plain", "-t", DOCKER_TAG, "."],
        check=True,
        env={
            "DOCKER_BUILDKIT": "1",
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    ok("Docker image built.")


def test_docker_image(release):
    print("\nValidating Docker image...")
    proc = docker(
        ["manage", "shell", "-c", "import django_ca; print(django_ca.__version__)"],
    )
    actual_release = proc.stdout.strip()
    if actual_release != release:
        err(f"Docker image identifies as {actual_release}.")
        sys.exit(1)
    ok(f"Image identifies as {actual_release}.")

    cwd = os.getcwd()
    docker(
        ["devscripts/test-imports.py", "--all-extras"],
        "-v",
        f"{cwd}/setup.cfg:/usr/src/django-ca/setup.cfg",
        "-v",
        f"{cwd}/devscripts/:/usr/src/django-ca/devscripts",
        "-w",
        "/usr/src/django-ca/",
    )
    ok("Imports validated.")

    with tmpdir() as tmpdirname:
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Build a django-ca release.")
    docker_grp = parser.add_argument_group("Docker options")
    docker_grp.add_argument(
        "--no-prune",
        default=True,
        dest="docker_prune",
        action="store_false",
        help="Prune system before building Docker image.",
    )
    parser.add_argument("release", help="The actual release you want to build.")
    args = parser.parse_args()
    validate_state()
    # create_docker_image(args.docker_prune)
    test_docker_image(args.release)

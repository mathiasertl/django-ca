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
import sys
from importlib import import_module

import semantic_version
from git import Repo
from validation.docker import build_docker_image
from validation.docker import validate_docker_image
from validation.docker_compose import validate_docker_compose
from validation.docker_compose import validate_docker_compose_files

# pylint: disable=no-name-in-module  # false positive due to dev.py in top-level
from dev import config
from dev.out import err
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
    parser.add_argument(
        "--delete-tag",
        action="store_true",
        default=False,
        help="Delete the tag again after release (for testing).",
    )
    parser.add_argument("release", help="The actual release you want to build.")
    args = parser.parse_args()

    repo = Repo(str(config.ROOT_DIR))
    if repo.is_dirty(untracked_files=True):
        err("Repository has untracked changes.")
        sys.exit(1)

    # Make sure that user passed a valid semantic version
    try:
        ver = semantic_version.Version(args.release)
        if ver.prerelease or ver.build:
            raise ValueError("Version has prerelease or build number.")
    except ValueError as ex:
        err(ex)
        sys.exit(1)

    sys.path.insert(0, str(config.SRC_DIR))
    import django_ca

    # Make sure that the software identifies as the right version
    if django_ca.__version__ != args.release:
        err(f"ca/django_ca/__init__.py: Version is {django_ca.__version__}")
        sys.exit(1)

    # Make sure that the docker-compose files are present and default to the about-to-be-released version
    if validate_docker_compose_files(args.release) != 0:
        sys.exit(1)

    git_tag = repo.create_tag(args.release, sign=True, message=f"version {args.release}")
    try:
        validate_state()
        build_docker_image(release=args.release)
        validate_docker_image(release=args.release)
        validate_docker_compose(release=args.release)

        if args.delete_tag:
            repo.delete_tag(git_tag)
    except Exception as ex:  # pylint: disable=broad-except
        err(ex)
        repo.delete_tag(git_tag)
        sys.exit(1)

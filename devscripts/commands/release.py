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

import sys

import semantic_version
from git import Repo

from devscripts import config
from devscripts.commands import CommandError
from devscripts.commands import DevCommand
from devscripts.out import err
from devscripts.out import ok
from devscripts.utils import redirect_output
from devscripts.validation import docker
from devscripts.validation import docker_compose
from devscripts.validation import state

import django_ca


def validate_state():
    """Validate state of various config files."""
    with redirect_output() as stream:
        errors = state.validate()

    if errors == 0:
        ok("State validated.")
    else:
        print(stream.getvalue())
        raise RuntimeError("State validation failed.")


class Command(DevCommand):
    """Create a new release."""

    def add_arguments(self, parser):
        parser.add_argument(
            "--delete-tag",
            action="store_true",
            default=False,
            help="Delete the tag again after release (for testing).",
        )
        parser.add_argument("release", help="The actual release you want to build.")

    def pre_tag_checks(self, release):
        """Perform checks that can be done before we even tag the repository."""

        repo = Repo(str(config.ROOT_DIR))
        if repo.is_dirty(untracked_files=True):
            err("Repository has untracked changes.")
            sys.exit(1)

        # Make sure that user passed a valid semantic version
        ver = semantic_version.Version(release)
        if ver.prerelease or ver.build:
            raise CommandError("Version has prerelease or build number.")

        # Make sure that the software identifies as the right version
        if django_ca.__version__ != release:
            raise CommandError(f"ca/django_ca/__init__.py: Version is {django_ca.__version__}")

        # Make sure that the docker-compose files are present and default to the about-to-be-released version
        if docker_compose.validate_docker_compose_files(release) != 0:
            raise CommandError("docker-compose files in inconsistent state.")

        return repo

    def handle(self, args):
        repo = self.pre_tag_checks(args.release)

        git_tag = repo.create_tag(args.release, sign=True, message=f"version {args.release}")
        try:
            validate_state()
            docker.validate(release=args.release, prune=True, build=True, quiet=True)
            docker_compose.validate(release=args.release, prune=False, build=False, quiet=True)

            if args.delete_tag:
                repo.delete_tag(git_tag)
        except Exception as ex:  # pylint: disable=broad-except
            repo.delete_tag(git_tag)
            raise CommandError(str(ex)) from ex

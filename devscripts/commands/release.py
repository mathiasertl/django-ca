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

import difflib
import importlib
import sys
from datetime import date

from devscripts import config
from devscripts.commands import CommandError
from devscripts.commands import DevCommand
from devscripts.out import err
from devscripts.out import ok
from devscripts.utils import redirect_output


class Command(DevCommand):
    """Create a new release."""

    modules = (
        ("django_ca", "django-ca"),
        ("git", "GitPython"),
        ("semantic_version", "semantic-version"),
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--delete-tag",
            action="store_true",
            default=False,
            help="Delete the tag again after release (for testing).",
        )
        parser.add_argument("release", help="The actual release you want to build.")

    def _validate_changelog(self, release):
        path = str(config.DOCS_SOURCE_DIR / "changelog.rst")
        with open(path, encoding="utf-8") as stream:
            changelog = stream.read()
        changelog_header = changelog.splitlines(keepends=True)[:11]
        expected = f"""#########
ChangeLog
#########

.. _changelog-head:

.. _changelog-{release}:

*******************
{release} ({date.today().strftime('%Y-%m-%d')})
*******************""".splitlines(
            keepends=True
        )
        if changelog_header != expected:
            diff = difflib.unified_diff(changelog_header, expected, fromfile=path, tofile="expected")
            raise CommandError(f"ChangeLog has improper header:\n\n{''.join(diff)}")

    def pre_tag_checks(self, release):
        """Perform checks that can be done before we even tag the repository."""

        docker_compose = importlib.import_module("devscripts.validation.docker_compose")

        repo = self.git.Repo(str(config.ROOT_DIR))  # pylint: disable=no-member  # from lazy import
        if repo.is_dirty(untracked_files=True):
            err("Repository has untracked changes.")
            sys.exit(1)

        # Make sure that user passed a valid semantic version
        ver = self.semantic_version.Version(release)  # pylint: disable=no-member  # from lazy import
        if ver.prerelease or ver.build:
            raise CommandError("Version has prerelease or build number.")

        # Make sure that the software identifies as the right version
        version = self.django_ca.__version__  # pylint: disable=no-member  # from lazy import
        if version != release:
            raise CommandError(f"ca/django_ca/__init__.py: Version is {version}")

        # Make sure that the docker-compose files are present and default to the about-to-be-released version
        if docker_compose.validate_docker_compose_files(release) != 0:
            raise CommandError("docker-compose files in inconsistent state.")

        # Validate that docs/source/changelog.rst has a proper header
        self._validate_changelog(release)

        return repo

    def validate_state(self):
        """Validate state of various config files."""
        state = importlib.import_module("devscripts.validation.state")
        with redirect_output() as stream:
            errors = state.validate()

        if errors == 0:
            ok("State validated.")
        else:
            print(stream.getvalue())
            raise RuntimeError("State validation failed.")

    def handle(self, args):
        # Validation modules is imported on execution so that external libraries used there do not
        # automatically become dependencies for all other dev.py commands.
        docker = importlib.import_module("devscripts.validation.docker")
        docker_compose = importlib.import_module("devscripts.validation.docker_compose")
        wheel = importlib.import_module("devscripts.validation.wheel")

        repo = self.pre_tag_checks(args.release)

        git_tag = repo.create_tag(args.release, sign=True, message=f"version {args.release}")
        try:
            self.validate_state()
            docker.validate(release=args.release, prune=True, build=True)
            docker_compose.validate(release=args.release, prune=False, build=False)
            wheel.validate(release=args.release)

            if args.delete_tag:
                repo.delete_tag(git_tag)
        except Exception as ex:  # pylint: disable=broad-except
            repo.delete_tag(git_tag)
            raise CommandError(str(ex)) from ex

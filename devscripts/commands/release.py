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

"""Release script."""

import argparse
import difflib
import importlib
import sys
import types
import typing
from datetime import date

from devscripts import config
from devscripts.commands import CommandError, DevCommand
from devscripts.out import err, info, ok

if typing.TYPE_CHECKING:
    from git import Repo


class Command(DevCommand):
    """Class implementing the ``dev.py release`` command."""

    help_text = "Create a new release."

    modules = (
        ("django_ca", "django-ca"),
        ("git", "GitPython"),
        ("semantic_version", "semantic-version"),
    )
    django_ca: types.ModuleType
    git: types.ModuleType
    semantic_version: types.ModuleType

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--dry-run",
            action="store_true",
            default=False,
            help="Delete the tag, don't upload release artifacts (for testing).",
        )
        parser.add_argument(
            "--no-rebuild",
            action="store_false",
            default=True,
            dest="build",
            help="Do not build release artifacts (for testing, assumes that they have been built before).",
        )
        parser.add_argument(
            "--no-upload",
            dest="upload",
            default=True,
            action="store_false",
            help="Do not upload release artifacts.",
        )
        parser.add_argument("release", help="The actual release you want to build.")

    def _validate_changelog(self, release: str) -> None:
        today = date.today().strftime("%Y-%m-%d")
        path = config.DOCS_SOURCE_DIR / "changelog" / f"{today}_{release}.rst"
        with open(path, encoding="utf-8") as stream:
            changelog = stream.read()
        changelog_header = changelog.splitlines(keepends=True)[:3]
        expected = f"""##################
{release} ({date.today().strftime("%Y-%m-%d")})
##################\n""".splitlines(keepends=True)
        if changelog_header != expected:
            diff = difflib.unified_diff(changelog_header, expected, fromfile=str(path), tofile="expected")
            raise CommandError(f"ChangeLog has improper header:\n\n{''.join(diff)}")

    def pre_tag_checks(self, release: str) -> "Repo":
        """Perform checks that can be done before we even tag the repository."""
        docker_compose = importlib.import_module("devscripts.validation.docker_compose")

        repo = typing.cast("Repo", self.git.Repo(str(config.ROOT_DIR)))
        if repo.is_dirty(untracked_files=True):
            err("Repository has untracked changes.")
            sys.exit(1)

        # Make sure that user passed a valid semantic version
        ver = self.semantic_version.Version(release)
        if ver.prerelease or ver.build:
            raise CommandError("Version has prerelease or build number.")

        # Make sure that the software identifies as the right version
        version = self.django_ca.__version__
        if version != release:
            raise CommandError(f"ca/django_ca/__init__.py: Version is {version}")

        # Make sure that the docker compose files are present and default to the about-to-be-released version
        if docker_compose.validate_docker_compose_files(release) != 0:
            raise CommandError("docker compose files in inconsistent state.")

        # Validate that docs/source/changelog.rst has a proper header
        self._validate_changelog(release)

        return repo

    def handle(self, args: argparse.Namespace) -> None:
        repo = self.pre_tag_checks(args.release)

        git_tag = repo.create_tag(args.release, sign=True, message=f"version {args.release}")
        try:
            self.command("validate", "state")

            if args.build:
                # Clean up before creating any release artifacts
                self.run("docker", "system", "prune", "-af")
                self.command("clean")

                # Build release artifacts
                self.command("build", "wheel", "--release", args.release)
                _release, docker_tag = self.command("build", "docker", "--release", args.release)
                ok("Finished building release artifacts.")
            else:
                docker_tag = self.get_docker_tag(args.release)

            self.command("validate", "docker", "--no-rebuild", "--release", args.release)
            self.command("validate", "docker-compose", "--no-rebuild", "--release", args.release)
            self.command("validate", "wheel")
            ok("Finished validation.")

            if args.dry_run:
                repo.delete_tag(git_tag)
            else:  # This is a real release, so upload artifacts
                info("Uploading release artifacts...")

                # Prepare alternative Docker tags
                revision_tag = f"{docker_tag}-1"
                latest_tag = f"{config.DOCKER_TAG}:latest"
                self.run("docker", "tag", docker_tag, revision_tag)
                self.run("docker", "tag", docker_tag, latest_tag)

                alpine_tag = f"{docker_tag}-alpine"
                alpine_latest_tag = f"{config.DOCKER_TAG}:latest"
                alpine_revision_tag = f"{alpine_tag}-1"
                self.run("docker", "tag", alpine_tag, alpine_revision_tag)
                self.run("docker", "tag", alpine_tag, alpine_latest_tag)

                # Push GIT tag
                repo.remotes.origin.push(refspec=git_tag)

                # Upload wheel
                self.run("uv", "publish", "dist/*")

                # Upload Docker image
                self.run("docker", "push", docker_tag)
                self.run("docker", "push", revision_tag)
                self.run("docker", "push", latest_tag)
                self.run("docker", "push", alpine_tag)
                self.run("docker", "push", alpine_revision_tag)
                self.run("docker", "push", alpine_latest_tag)

                ok("Uploaded release artifacts.")

        except Exception as ex:
            repo.delete_tag(git_tag)
            raise CommandError(str(ex)) from ex

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
import types
import typing
from datetime import date
from pathlib import Path

from devscripts import config
from devscripts.commands import CommandError, DevCommand
from devscripts.out import info, ok

if typing.TYPE_CHECKING:
    from git import Repo


class Command(DevCommand):
    """Class implementing the ``dev.py release`` command."""

    help_text = "Create a new release."

    modules = (
        ("django_ca", "django-ca"),
        ("git", "GitPython"),
        ("semantic_version", "semantic-version"),
        ("yaml", "PyYAML"),
    )
    django_ca: types.ModuleType
    git: types.ModuleType
    semantic_version: types.ModuleType
    yaml: types.ModuleType

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

    def test_docker_maintenance_action(self, release: str) -> None:
        """Test that the docker-maintenance action was updated."""
        path = Path(".github", "workflows", "docker-maintenance.yml")
        with open(config.ROOT_DIR / path, encoding="utf-8") as stream:
            workflow = self.yaml.safe_load(stream)
        if workflow["env"]["NEWEST_DJANGO_CA"] != release:
            raise CommandError(f"{path}: NEWEST_DJANGO_CA was not updated.")
        if release not in workflow["jobs"]["build"]["strategy"]["matrix"]["version"]:
            raise CommandError(f"{path}: matrix does not contain {release}.")

    def pre_tag_checks(self, release: str) -> "Repo":
        """Perform checks that can be done before we even tag the repository."""
        docker_compose = importlib.import_module("devscripts.docker")

        repo = typing.cast("Repo", self.git.Repo(str(config.ROOT_DIR)))
        if repo.is_dirty(untracked_files=True):
            raise CommandError("Repository has untracked changes.")

        # Make sure that the docker compose files are present and default to the about-to-be-released version
        if docker_compose.validate_docker_compose_files(release) != 0:
            raise CommandError("docker compose files in inconsistent state.")

        self.test_docker_maintenance_action(release)

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
                _release, _docker_tag = self.command("build", "docker", "--release", args.release)
                ok("Finished building release artifacts.")

            self.command("validate", "docker", "--no-rebuild", "--release", args.release)
            self.command("validate", "docker-compose", "--no-rebuild", "--release", args.release)
            ok("Finished validation.")

            if args.dry_run:
                repo.delete_tag(git_tag)
            else:  # This is a real release, so upload artifacts
                info("Uploading release artifacts...")
                # Push GIT tag
                repo.remotes.origin.push(refspec=git_tag)

                ok("Uploaded release artifacts.")

        except Exception as ex:
            repo.delete_tag(git_tag)
            raise CommandError(str(ex)) from ex

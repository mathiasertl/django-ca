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

"""Module implementing the command to build a Docker image."""

import argparse
from types import ModuleType

from devscripts import config
from devscripts.commands import DevCommand
from devscripts.out import info


class Command(DevCommand):
    """Command class implementing the command to build a Python Wheel."""

    help_text = "Build the Docker image."
    description = "Builds the Docker image."

    modules = (("django_ca", "django-ca"),)
    django_ca: ModuleType

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--prune", dest="docker_prune", default=True, help="Remove Docker data before building image."
        )
        parser.add_argument("--release", help="Version to use (default: current version).")
        parser.add_argument(
            "--no-alpine",
            dest="alpine",
            action="store_false",
            default=True,
            help="Do not build Alpine based image.",
        )
        parser.add_argument(
            "--no-debian",
            dest="debian",
            action="store_false",
            default=True,
            help="Do not build Debian based image.",
        )

    def handle(self, args: argparse.Namespace) -> tuple[str, str]:  # type: ignore[override]
        if args.release:
            release = args.release
        else:
            release = self.django_ca.__version__

        tag = self.get_docker_tag(release)
        cwd = config.ROOT_DIR
        env = {"DOCKER_BUILDKIT": "1"}

        # NOTE: docker-py does not yet support BuildKit, so we call the CLI directly. See also:
        #   https://github.com/docker/docker-py/issues/2230
        if args.debian:
            info(f"Building Debian based image as {tag}...")
            self.run(
                "docker",
                "build",
                "-t",
                tag,
                "--build-arg",
                f"DJANGO_CA_VERSION={release}",
                ".",
                env=env,
                cwd=cwd,
            )
        if args.alpine:
            alpine_tag = f"{tag}-alpine"
            info(f"Building Alpine based image as {alpine_tag}...")
            self.run(
                "docker",
                "build",
                "-t",
                alpine_tag,
                "-f",
                "Dockerfile.alpine",
                "--build-arg",
                f"DJANGO_CA_VERSION={release}",
                ".",
                env=env,
                cwd=cwd,
            )

        return release, tag

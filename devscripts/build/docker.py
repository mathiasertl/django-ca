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

    help_text = "Build a Docker image."
    description = "Builds the Docker image."

    modules = (("django_ca", "django-ca"),)
    django_ca: ModuleType

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--upload", default=False, action="store_true", help="Upload Docker image.")
        parser.add_argument("--revision", default=1, type=int, help="Image revision (default: %(default)s).")

    def handle(self, args: argparse.Namespace) -> None:
        release = self.django_ca.__version__
        tag = f"{config.DOCKER_TAG}:{release}"
        info(f"Building Docker image as {tag}")
        self.run("docker", "build", "-t", tag, ".", env={"DOCKER_BUILDKIT": "1"}, cwd=config.ROOT_DIR)
        self.run("docker", "tag", tag, f"{tag}-1")
        self.run("docker", "tag", tag, f"{config.DOCKER_TAG}:latest")

        if args.upload:
            self.run("docker", "push", tag)
            self.run("docker", "push", f"{tag}-1")
            self.run("docker", "push", f"{config.DOCKER_TAG}:latest")

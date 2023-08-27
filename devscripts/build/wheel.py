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

"""Module implementing the command to build a Python Wheel."""

import argparse
import os
from types import ModuleType

from devscripts import config
from devscripts.commands import DevCommand
from devscripts.out import ok


class Command(DevCommand):
    """Command class implementing the command to build a Python Wheel."""

    help_text = "Build a Python Wheel."
    description = "Builds a Python Wheel inside a Docker image."

    modules = (("django_ca", "django-ca"),)
    django_ca: ModuleType

    def handle(self, args: argparse.Namespace) -> None:
        release = self.django_ca.__version__
        destination_dir = config.ROOT_DIR / "dist"
        project_config = config.get_project_config()

        os.makedirs(destination_dir, exist_ok=True)

        latest_python_version = project_config["python-major"][-1]

        image = self.docker_build(
            tag=f"django-ca-build-wheel:{release}",
            dockerfile=config.DEVSCRIPTS_FILES / "Dockerfile.wheel",
            buildargs={"IMAGE": f"python:{latest_python_version}"},
            path=str(config.ROOT_DIR),
        )
        self.docker_run(image, volumes=[f"{destination_dir}:/dist/"], user=f"{os.getuid()}:{os.getgid()}")
        ok(f"Built Wheel in {destination_dir}")

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

"""Functions for validating the Docker image and the respective tutorial."""

import argparse
import subprocess
import time
from types import ModuleType
from typing import TYPE_CHECKING, Any

from setuptools.config.pyprojecttoml import read_configuration

from devscripts import config, utils
from devscripts.commands import CommandError, DevCommand
from devscripts.out import info, ok

if TYPE_CHECKING:
    from docker.client import DockerClient


def run(release: str, image: str, python_version: str, extra: str = "") -> "subprocess.CompletedProcess[Any]":
    """Actually run a given wheel test."""
    wheel = f"dist/django_ca-{release}-py3-none-any.whl"
    command = "devscripts/standalone/test-imports.py"

    if extra:
        wheel += f"[{extra}]"
        command += f" --extra={extra}"

    dependencies = ""
    if python_version == "3.10":  # pragma: only py<3.11
        # We read pyproject.toml, so older python versions need an extra library.
        dependencies += "tomli"

    commands = [
        "echo Installing wheel...",
        f"uv pip install {dependencies} {wheel}",
        "echo Check dependencies...",
        f".venv/bin/python {command}",
    ]

    return utils.docker_run("--rm", image, "/bin/sh", "-c", "; ".join(commands))


class Command(DevCommand):
    """Class implementing the ``dev.py validate wheel`` command."""

    modules = (("django_ca", "django-ca"),)
    django_ca: ModuleType
    help_text = "Test wheel with extras on various distributions."

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.pyproject_toml = read_configuration(config.ROOT_DIR / "pyproject.toml")
        self.extra_choices = [
            "none",
            *list(self.pyproject_toml["project"]["optional-dependencies"]),
        ]

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--python",
            choices=config.PYTHON_RELEASES,
            default=[],
            action="append",
            help="Only test the specified Python version (can be given multiple times).",
        )

        parser.add_argument(
            "--extra",
            choices=self.extra_choices,
            default=[],
            action="append",
            help="Only test the specified extras, add 'none' for no extras (can be given multiple times).",
        )

    def handle(self, args: argparse.Namespace) -> None:
        info("Testing Python wheel...")
        release = self.django_ca.__version__
        client: DockerClient = self.docker.from_env()

        python_versions = args.python
        if not python_versions:
            python_versions = config.PYTHON_RELEASES

        extras = args.extra
        if not extras:
            extras = self.extra_choices

        test_no_extras = "none" in extras
        extras = [extra for extra in extras if extra != "none"]

        for pyver in python_versions:
            info(f"Testing with Python {pyver}.", indent="  ")

            # build the image
            try:
                image, _logs = client.images.build(
                    path=str(config.ROOT_DIR),
                    dockerfile=str(config.DEVSCRIPTS_FILES / "Dockerfile.wheel.test"),
                    buildargs={"IMAGE": f"python:{pyver}"},
                )
            except self.docker.errors.BuildError as ex:
                for elem in ex.build_log:
                    if line := elem.get("stream"):
                        print(line, end="")
                    else:
                        print(elem)
                raise CommandError("Building Docker image failed, see above for output.") from ex

            if test_no_extras:
                info("Test with no extras", indent="    ")
                run(release, image.id, python_version=pyver)

            for extra in extras:
                info(f"Test extra: {extra}", indent="    ")
                run(release, image.id, extra=extra, python_version=pyver)

            time.sleep(1)
            image.remove(force=True)
        ok("Python wheel validated.")

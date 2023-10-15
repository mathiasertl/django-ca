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
import os
import subprocess
import time
from types import ModuleType
from typing import Any

import docker
from setuptools.config.pyprojecttoml import read_configuration

from devscripts import config, utils
from devscripts.commands import DevCommand
from devscripts.out import info


def run(release: str, image: str, pip_cache_dir: str, extra: str = "") -> "subprocess.CompletedProcess[Any]":
    """Actually run a given wheel test."""
    docker_pip_cache = "/tmp/cache"
    wheel = f"dist/django_ca-{release}-py3-none-any.whl"
    command = "devscripts/standalone/test-imports.py"

    if extra:
        wheel += f"[{extra}]"
        command += f" --extra={extra}"

    commands = [
        "python -m venv /tmp/venv",
        # NOTE: We require at least setuptools>=68.1 for reading package configuration from pyproject.toml
        f"/tmp/venv/bin/pip install --cache-dir={docker_pip_cache} -U pip setuptools>=68.1",
        f"/tmp/venv/bin/pip install --cache-dir={docker_pip_cache} {wheel}",
        f"/tmp/venv/bin/python {command}",
    ]

    try:
        return utils.docker_run(
            "-v",
            f"{pip_cache_dir}:{docker_pip_cache}",
            f"--user={os.getuid()}:{os.getgid()}",
            "--rm",
            image,
            "/bin/sh",
            "-c",
            "; ".join(commands),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except subprocess.CalledProcessError as ex:
        print(ex.stdout)
        raise


class Command(DevCommand):
    modules = (("django_ca", "django-ca"),)
    django_ca: ModuleType
    help_text = "Test wheel with extras on various distributions."

    def handle(self, args: argparse.Namespace) -> None:
        info("Testing Python wheel...")
        release = self.django_ca.__version__
        project_config = config.get_project_config()
        client = docker.from_env()

        host_pip_cache = subprocess.run(
            ["pip", "cache", "dir"], check=True, capture_output=True, text=True
        ).stdout.strip()
        project_configuration = read_configuration(config.ROOT_DIR / "pyproject.toml")

        for pyver in project_config["python-major"]:
            info(f"Testing with Python {pyver}.", indent="  ")

            # build the image
            image, _logs = client.images.build(
                path=str(config.ROOT_DIR),
                dockerfile=str(config.DEVSCRIPTS_FILES / "Dockerfile.wheel"),
                buildargs={"IMAGE": f"python:{pyver}"},
                target="test",
            )

            # get cache dir in image
            run(release, image.id, host_pip_cache)

            for extra in list(project_configuration["project"]["optional-dependencies"]):
                info(f"Test extra: {extra}", indent="    ")
                run(release, image.id, host_pip_cache, extra=extra)

            time.sleep(1)
            image.remove(force=True)
        info("Python wheel is okay.")

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
import pathlib
from types import ModuleType
from typing import Sequence

from django.core.management.utils import get_random_secret_key

from devscripts import config, utils
from devscripts.commands import DevCommand
from devscripts.out import err, info, ok
from devscripts.tutorial import start_tutorial


def _test_version(docker_tag: str, release: str) -> int:
    proc = utils.docker_run(
        docker_tag,
        "manage",
        "shell",
        "-c",
        "import django_ca; print(django_ca.__version__)",
        capture_output=True,
        text=True,
    )
    actual_release = proc.stdout.strip()
    if actual_release != release:
        return err(f"Docker image identifies as {actual_release}.")
    return ok(f"Image identifies as {actual_release}.")


def _test_alpine_version(docker_tag: str, alpine_version: str) -> int:
    proc = utils.docker_run(
        docker_tag,
        "cat",
        "/etc/alpine-release",
        capture_output=True,
        text=True,
    )
    actual_release = proc.stdout.strip()
    actual_major = config.minor_to_major(actual_release)

    if actual_major != alpine_version:
        return err(f"Docker image uses outdated Alpine Linux version {actual_release}.")
    return ok(f"Docker image uses Alpine Linux {actual_release}.")


def _test_extras(docker_tag: str) -> int:
    cwd = os.getcwd()
    utils.docker_run(
        "-v",
        f"{cwd}/pyproject.toml:/usr/src/django-ca/pyproject.toml",
        "-v",
        f"{cwd}/devscripts/:/usr/src/django-ca/devscripts",
        "-w",
        "/usr/src/django-ca/",
        docker_tag,
        "devscripts/standalone/test-imports.py",
        "--all-extras",
    )
    return ok("Imports validated.")


def _test_clean(docker_tag: str) -> int:
    """Make sure that the Docker image does not contain any unwanted files."""
    cwd = os.getcwd()
    script = "check-clean-docker.py"
    utils.docker_run(
        "-v", f"{cwd}/devscripts/standalone/{script}:/tmp/{script}", docker_tag, f"/tmp/{script}"
    )
    return ok("Docker image is clean.")


def _test_connectivity(src: pathlib.Path) -> int:
    standalone_dest = "/usr/src/django-ca/ca/"
    script_name = "test-connectivity.py"
    script_path = os.path.join(standalone_dest, script_name)

    for container in ["frontend", "backend"]:
        docker_cp(str(src / script_name), container, standalone_dest)
        utils.docker_exec("frontend", script_path)

    return ok("Tested connectivity.")


def docker_cp(src: str, container: str, dest: str) -> None:
    """Copy file into the container."""
    utils.run(["docker", "cp", src, f"{container}:{dest}"])


def build_docker_image(release: str, prune: bool = True, build: bool = True) -> str:
    """Build the docker image."""
    if prune:
        utils.run(["docker", "system", "prune", "-af"])

    tag = f"{config.DOCKER_TAG}:{release}"
    if build:
        info("Building docker image...")
        utils.run(["docker", "build", "-t", tag, "."], env={"DOCKER_BUILDKIT": "1"})
        ok(f"Docker image built as {tag}.")
    return tag


def validate_docker_image(release: str, docker_tag: str) -> int:
    """Validate the Docker image."""
    print("Validating Docker image...")

    errors = 0
    standalone_src = pathlib.Path().absolute() / "devscripts" / "standalone"
    project_config = config.get_project_config()

    _test_clean(docker_tag)
    if release is not None:
        errors += _test_version(docker_tag, release)
    errors += _test_alpine_version(docker_tag, project_config["alpine"][-1])
    errors += _test_extras(docker_tag)

    context = {
        "backend_host": "backend",
        "ca_default_hostname": "localhost",
        "docker_tag": docker_tag,
        "frontend_host": "frontend",
        "network": "django-ca",
        "nginx_host": "nginx",
        "postgres_host": "postgres",
        "postgres_password": "random-password",
        "redis_host": "redis",
        "secret_key": get_random_secret_key(),
    }

    info("Testing tutorial...")
    with start_tutorial("quickstart_with_docker", context) as tut:
        tut.write_template("localsettings.yaml.jinja")
        tut.write_template("nginx.conf.jinja")

        with tut.run("start-dependencies.yaml"), tut.run("start-django-ca.yaml"), tut.run(
            "start-nginx.yaml"
        ), tut.run("setup-cas.yaml"):
            errors += _test_connectivity(standalone_src)

            print("Now running running django-ca, please visit:\n\n\thttp://localhost/admin\n")
            input("Press enter to continue:")

    return errors


class Command(DevCommand):
    """Class implementing the ``dev.py validate docker`` command."""

    modules = (("django_ca", "django-ca"),)
    django_ca: ModuleType
    help_text = "Validate Docker setup."

    @property
    def parser_parents(self) -> Sequence[argparse.ArgumentParser]:
        # pylint: disable-next=no-member  # set in the constructor of parent class
        return [self.parent.docker_options]  # type: ignore[attr-defined]  # see pylint above

    def handle(self, args: argparse.Namespace) -> None:
        release = self.django_ca.__version__
        docker_tag = build_docker_image(release=release, prune=args.docker_prune, build=args.build)
        validate_docker_image(release, docker_tag)

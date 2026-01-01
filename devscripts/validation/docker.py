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
from collections.abc import Sequence
from types import ModuleType

from devscripts import config, utils
from devscripts.commands import CommandError, DevCommand
from devscripts.docker import docker_run
from devscripts.out import err, info, ok


def _test_version(docker_tag: str, release: str) -> int:
    proc = docker_run(
        docker_tag,
        "manage",
        "shell",
        "-v",
        "0",
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
    docker_tag += "-alpine"
    proc = docker_run(docker_tag, "cat", "/etc/alpine-release", capture_output=True, text=True)
    actual_release = proc.stdout.strip()
    actual_major = config.minor_to_major(actual_release)

    if actual_major != alpine_version:
        return err(f"Docker image uses outdated Alpine Linux version {actual_release}.")
    return ok(f"Docker image uses Alpine Linux {actual_release}.")


def _test_debian_version(docker_tag: str, debian_version: str) -> int:
    proc = docker_run(docker_tag, "lsb_release", "-cs", capture_output=True, text=True)
    actual_release = proc.stdout.strip()

    if actual_release != debian_version:
        return err(f"Docker image uses outdated Debian Linux version {actual_release}.")
    return ok(f"Docker image uses Debian Linux {actual_release}.")


def _test_extras(docker_tag: str) -> int:
    cwd = os.getcwd()
    docker_run(
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
    proc = docker_run(
        "-v", f"{cwd}/devscripts/standalone/{script}:/tmp/{script}", docker_tag, f"/tmp/{script}", check=False
    )
    if proc.returncode != 0:
        return err("Docker image is not clean.")
    return ok("Docker image is clean.")


def validate_docker_image(release: str, docker_tag: str) -> int:
    """Validate the Docker image."""
    print("Validating Docker image...")

    errors = 0
    errors += _test_clean(docker_tag)
    errors += _test_version(docker_tag, release)
    errors += _test_alpine_version(docker_tag, config.ALPINE_RELEASES[-1])
    errors += _test_debian_version(docker_tag, config.DEBIAN_RELEASES[-1])
    errors += _test_extras(docker_tag)
    return errors


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


class Command(DevCommand):
    """Class implementing the ``dev.py validate docker`` command."""

    modules = (("django_ca", "django-ca"),)
    django_ca: ModuleType
    help_text = "Validate Docker setup."

    @property
    def parser_parents(self) -> Sequence[argparse.ArgumentParser]:
        # TYPEHINT NOTE: It's a subcommand, so we know parent is not None
        return [self.parent.docker_options]  # type: ignore[union-attr]

    def run_tutorial(self, release: str, docker_tag: str, alpine: bool = False) -> int:
        """Run the Compose tutorial."""
        errors = 0
        if alpine:
            docker_tag += "-alpine"

        defines = ["-D", "BUILD_IMAGE", "no", "-D", "RELEASE", release, "-D", "DOCKER_TAG", docker_tag]
        if alpine:
            defines += ["-D", "DOCKER_IMAGE_VARIANT", "alpine"]

        proc = utils.run(
            ["structured-tutorial", "--non-interactive", *defines, "tutorials/docker/tutorial.yaml"]
        )
        if proc.returncode != 0:
            errors += err("Error running tutorial.")
        return errors

    def handle(self, args: argparse.Namespace) -> int:
        if args.docker_prune:
            self.run("docker", "system", "prune", "-af")

        if args.release:
            release = args.release
            docker_tag = self.get_docker_tag(args.release)
        elif args.build:
            release, docker_tag = self.command("build", "docker")
        else:
            release = self.django_ca.__version__
            docker_tag = self.get_docker_tag(release)

        errors = validate_docker_image(release, docker_tag)
        info("Running tutorial...")
        errors = self.run_tutorial(release, docker_tag)
        info("Running tutorial with Alpine image...")
        errors = self.run_tutorial(release, docker_tag, alpine=True)

        if errors != 0:
            raise CommandError(f"A total of {errors} error(s) found!")

        return ok("Validated Docker image.")

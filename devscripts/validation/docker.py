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

"""Functions for validating the Docker image and the respective tutorial."""

import os

from devscripts import config
from devscripts import utils
from devscripts.out import err
from devscripts.out import info
from devscripts.out import ok
from devscripts.tutorial import start_tutorial


def _test_version(docker_tag, release):
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


def _test_extras(docker_tag):
    cwd = os.getcwd()
    utils.docker_run(
        "-v",
        f"{cwd}/setup.cfg:/usr/src/django-ca/setup.cfg",
        "-v",
        f"{cwd}/devscripts/:/usr/src/django-ca/devscripts",
        "-w",
        "/usr/src/django-ca/",
        docker_tag,
        "devscripts/test-imports.py",
        "--all-extras",
    )
    return ok("Imports validated.")


def _test_clean(docker_tag):
    """Make sure that the Docker image does not contain any unwanted files."""
    cwd = os.getcwd()
    script = "check-clean-docker.py"
    utils.docker_run(
        "-v", f"{cwd}/devscripts/standalone/{script}:/tmp/{script}", docker_tag, f"/tmp/{script}"
    )
    return ok("Docker image is clean.")


def build_docker_image(release, prune=True, build=True, quiet=False) -> str:
    """Build the docker image."""

    if prune:
        utils.run(["docker", "system", "prune", "-af"], quiet=quiet, capture_output=True)

    tag = f"{config.DOCKER_TAG}:{release}"
    if build:
        info("Building docker image...")
        utils.run(
            ["docker", "build", "-t", tag, "."],
            env={"DOCKER_BUILDKIT": "1"},
            quiet=quiet,
            capture_output=True,
        )
        ok("Docker image built.")
    return tag


def validate_docker_image(release, docker_tag, quiet=False):
    """Validate the Docker image."""
    print("Validating Docker image...")

    errors = 0

    _test_clean(docker_tag, release)
    if release is not None:
        errors += _test_version(docker_tag, release)
    errors += _test_extras(docker_tag)

    context = {
        "backend_host": "backend",
        "ca_default_hostname": "localhost",
        "frontend_host": "frontend",
        "network": "django-ca",
        "nginx_host": "nginx",
        "postgres_host": "postgres",
        "postgres_password": "random-password",
        "redis_host": "redis",
    }

    info("Testing tutorial...")
    with start_tutorial("quickstart_with_docker", context, quiet=quiet) as tut:
        tut.write_template("localsettings.yaml.jinja")
        tut.write_template("nginx.conf.jinja")

        with tut.run("start-dependencies.yaml"), tut.run("start-django-ca.yaml"), tut.run(
            "start-nginx.yaml"
        ), tut.run("setup-cas.yaml"):
            print("Now running running django-ca, please visit:\n\n\thttp://localhost/admin\n")
            input("Press enter to continue:")

    return errors


def validate(release, prune, build, quiet=False):
    """Main validation entry function."""
    docker_tag = build_docker_image(release=release, prune=prune, build=build)
    validate_docker_image(release, docker_tag, quiet=quiet)

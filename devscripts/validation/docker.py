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

from jinja2 import Environment
from jinja2 import FileSystemLoader

# pylint: disable=no-name-in-module  # false positive due to dev.py
from dev import config
from dev import utils
from dev.out import err
from dev.out import info
from dev.out import ok

# pylint: enable=no-name-in-module


def _test_version(release):
    proc = utils.docker_run(
        config.DOCKER_TAG,
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


def _test_extras():
    cwd = os.getcwd()
    utils.docker_run(
        "-v",
        f"{cwd}/setup.cfg:/usr/src/django-ca/setup.cfg",
        "-v",
        f"{cwd}/devscripts/:/usr/src/django-ca/devscripts",
        "-w",
        "/usr/src/django-ca/",
        config.DOCKER_TAG,
        "devscripts/test-imports.py",
        "--all-extras",
    )
    return ok("Imports validated.")


def build_docker_image(quiet=False):
    """Build the docker image."""

    info("Building docker image...")
    utils.run(
        ["docker", "build", "-t", config.DOCKER_TAG, "."],
        env={"DOCKER_BUILDKIT": "1"},
        quiet=quiet,
        capture_output=True,
    )
    ok("Docker image built.")


def validate_docker_image(release=None, prune=True, build=True, quiet=False):
    """Validate the Docker image."""
    print("Validating Docker image...")

    if prune:
        utils.run(["docker", "system", "prune", "-af"], quiet=quiet, capture_output=True)

    if build:
        build_docker_image(quiet=quiet)

    errors = 0
    if release is not None:
        errors += _test_version(release)
    errors += _test_extras()

    env = Environment(loader=FileSystemLoader(config.DOC_TEMPLATES_DIR), autoescape=False)
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
    localsettings = env.get_template("quickstart_with_docker/localsettings.yaml.jinja").render(**context)
    nginx = env.get_template("quickstart_with_docker/nginx.conf.jinja").render(**context)

    with utils.tmpdir():
        with open("localsettings.yaml", "w", encoding="utf-8") as stream:
            stream.write(localsettings)
        with open("nginx.conf", "w", encoding="utf-8") as stream:
            stream.write(nginx)

        with utils.console_include(
            "quickstart_with_docker/start-dependencies.yaml", context, quiet=quiet
        ), utils.console_include(
            "quickstart_with_docker/start-django-ca.yaml", context, quiet=quiet
        ), utils.console_include(
            "quickstart_with_docker/start-nginx.yaml", context, quiet=quiet
        ), utils.console_include(
            "quickstart_with_docker/setup-cas.yaml", context, quiet=quiet
        ):
            print("Now running running django-ca, please visit:\n\n\thttp://localhost/admin\n")
            input("Press enter to continue:")

    if release:
        utils.run(["docker", "tag", config.DOCKER_TAG, f"{config.DOCKER_TAG}:{release}"], quiet=quiet)

    return errors

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

import os
import subprocess
from contextlib import contextmanager

from jinja2 import Environment
from jinja2 import FileSystemLoader

from dev import config
from dev import utils
from dev.out import err
from dev.out import ok
from dev.out import warn


@contextmanager
def postgres(network, password):
    with utils.docker_container(
        "postgres", name="postgres", network=network, environment={"POSTGRES_PASSWORD": password}
    ) as container:
        yield container


@contextmanager
def redis(network):
    with utils.docker_container("redis", name="redis", network=network) as container:
        yield container


def validate_docker_image(tag, release, prune=True):
    print("\nValidating Docker image...")

    if prune:
        subprocess.run(["docker", "system", "prune", "-af"], check=True, stdout=subprocess.DEVNULL)
    else:
        warn("Not pruning Docker daemon before building")

    errors = 0
    proc = utils.docker_run(
        tag,
        "manage",
        "shell",
        "-c",
        "import django_ca; print(django_ca.__version__)",
        capture_output=True,
        text=True,
    )
    actual_release = proc.stdout.strip()
    if actual_release != release:
        errors += err(f"Docker image identifies as {actual_release}.")
    ok(f"Image identifies as {actual_release}.")

    cwd = os.getcwd()
    utils.docker_run(
        "-v",
        f"{cwd}/setup.cfg:/usr/src/django-ca/setup.cfg",
        "-v",
        f"{cwd}/devscripts/:/usr/src/django-ca/devscripts",
        "-w",
        "/usr/src/django-ca/",
        tag,
        "devscripts/test-imports.py",
        "--all-extras",
    )
    ok("Imports validated.")

    # shared variables
    postgres_password = "password"

    env = Environment(loader=FileSystemLoader(config.DOC_TEMPLATES_DIR), autoescape=False)
    context = {
        "ca_default_hostname": "localhost",
        "frontend_host": "frontend",
        "postgres_host": "postgres",
        "postgres_password": postgres_password,
        "redis_host": "redis",
    }
    localsettings = env.get_template("quickstart_with_docker/localsettings.yaml.jinja").render(**context)
    nginx = env.get_template("quickstart_with_docker/nginx.conf.jinja").render(**context)

    with utils.tmpdir():
        with open("localsettings.yaml", "w") as stream:
            stream.write(localsettings)
        with open("nginx.conf", "w") as stream:
            stream.write(nginx)

        # Create Docker network
        with utils.docker_network("djca-docker-quickstart") as network:

            # Create Postgres and Redis containers
            with postgres(network.id, postgres_password), redis(network.id):
                pass

    return errors

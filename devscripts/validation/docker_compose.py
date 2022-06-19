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

"""Functions for validating docker-compose and the respective tutorial."""

import os

# pylint: disable=no-name-in-module  # false positive due to dev.py
from dev import config
from dev import utils
from dev.out import err
from dev.tutorial import start_tutorial

# pylint: enable=no-name-in-module


def validate_docker_compose(release=None, quiet=False):
    """Validate the docker-compose file (and the tutorial)."""
    print("Validating docker-compose setup...")

    errors = 0

    docker_compose_yml = os.path.join(config.ROOT_DIR, "docker-compose.yml")
    if release:
        docker_compose_yml = os.path.join(config.DOCS_DIR, "source", "_files", release, "docker-compose.yml")

    if not os.path.exists(docker_compose_yml):
        return err(f"{docker_compose_yml}: File not found.")

    context = {
        "ca_default_hostname": "localhost",
        "postgres_password": "random-password",
        "privkey_path": "",
        "pubkey_path": "",
    }

    with start_tutorial("quickstart_with_docker_compose", context) as tutorial:
        tutorial.write_template("docker-compose.override.yml.jinja")
        tutorial.write_template(".env.jinja")

        with utils.console_include("quickstart_with_docker_compose/dhparam.yaml", context, quiet=quiet):
            print(os.listdir("."))

    return errors


print("in mod", validate_docker_compose)

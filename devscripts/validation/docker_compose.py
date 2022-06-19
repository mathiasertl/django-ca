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

from jinja2 import Environment
from jinja2 import FileSystemLoader

# pylint: disable=no-name-in-module  # false positive due to dev.py
from dev import config
from dev import utils
from dev.out import err

# pylint: enable=no-name-in-module


def validate_docker_compose(release=None, quiet=False):  # pylint: disable=unused-argument
    """Validate the docker-compose file (and the tutorial)."""
    print("Validating docker-compose setup...")

    errors = 0

    docker_compose_yml = os.path.join(config.ROOT_DIR, "docker-compose.yml")
    if release:
        docker_compose_yml = os.path.join(config.DOCS_DIR, "source", "_files", release, "docker-compose.yml")

    if not os.path.exists(docker_compose_yml):
        return err(f"{docker_compose_yml}: File not found.")

    env = Environment(loader=FileSystemLoader(config.DOC_TEMPLATES_DIR), autoescape=False)
    context = {
        "ca_default_hostname": "localhost",
        "postgres_password": "random-password",
    }
    overrides = env.get_template("quickstart_with_docker_compose/docker-compose.override.yml.jinja").render(
        **context
    )

    with utils.tmpdir():
        with open("docker-compose.override.yml", "w", encoding="utf-8") as stream:
            stream.write(overrides)

    return errors

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

from jinja2 import Environment
from jinja2 import FileSystemLoader

# pylint: disable=no-name-in-module  # false positive due to dev.py
from dev import config
from dev import utils

# pylint: enable=no-name-in-module


def validate_docker_compose(release=None, quiet=False):
    """Validate the docker-compose file (and the tutorial)."""
    print("Validating docker-compose setup...")

    errors = 0

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

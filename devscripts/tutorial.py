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

"""Helper functions/classes for testing Sphinx tutorials."""

import os
import typing
from contextlib import contextmanager

import jinja2

from devscripts import config, utils


class Tutorial:
    """Wrapper class for testing a tutorial from Sphinx.

    This class lets you easily render templates or run commands from a sphinx tutorial.
    """

    def __init__(self, name: str, context: dict[str, typing.Any]) -> None:
        self.name = name
        self.context = context
        self.context["sphinx"] = False
        self.context["validation"] = True

        # Get a strict Jinja2 environment
        self.env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(config.DOC_TEMPLATES_DIR),
            autoescape=False,
            undefined=jinja2.StrictUndefined,
        )

    def write_template(self, name: str) -> None:
        """Write a template with the given name."""
        dest, ext = os.path.splitext(name)
        if ext != ".jinja":
            raise ValueError(f"{name}: Template extension should be 'jinja'.")

        template = self.env.get_template(os.path.join(self.name, name))
        content = template.render(**self.context)

        with open(dest, "w", encoding="utf-8") as stream:
            stream.write(content)

    @contextmanager
    def run(self, path: str) -> typing.Iterator[None]:
        """Run commands from the specified YAML file."""
        path = os.path.join(self.name, path)
        with utils.console_include(path, self.context):
            yield


@contextmanager
def start_tutorial(name: str, context: dict[str, typing.Any]) -> typing.Iterator[Tutorial]:
    """Context manager to start a tutorial in a temporary directory."""
    with utils.tmpdir():
        yield Tutorial(name, context=context)

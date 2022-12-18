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

"""Sphinx extension for django-ca specific features."""

import typing

from .console_include import ConsoleIncludeDirective
from .mapping_table import MappingDocumentor
from .template_include import TemplateDirective

if typing.TYPE_CHECKING:
    from sphinx.application import Sphinx


def setup(app: "Sphinx") -> typing.Dict[str, bool]:
    """Sphinx setup function."""
    app.add_autodocumenter(MappingDocumentor)

    app.add_directive("template-include", TemplateDirective)
    app.add_directive("console-include", ConsoleIncludeDirective)
    return {"parallel_read_safe": True, "parallel_write_safe": True}

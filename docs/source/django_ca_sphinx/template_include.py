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

"""A directive that lets you include a Jinja2 template as a rendered code block."""

import typing

from docutils.parsers.rst import directives
from docutils.statemachine import StringList
from jinja2 import Environment, FileSystemLoader
from sphinx.directives.code import CodeBlock  # code-block directive from Sphinx
from sphinx.util.typing import OptionSpec


class TemplateDirective(CodeBlock):
    """A directive that lets you include a Jinja2 template as a rendered code block.

    django-ca uses this directive to include Jinja2 templates as config files etc. in the documentation (with
    syntax highlighting) and to use the same templates in integration test scripts.

    Usage::

        .. template-include:: yaml example.yaml.jinja
           :context: optional-context

    The above example will render :file:`example.yaml.jinja` as YAML file and use the ``optional-context``
    context from the ``jinja_contexts`` setting.

    Technically this directive inherits from the implementation for the stock ``.. code-block::`` directive
    and overrides the built-in ``content`` property to provide the value of the rendered Jinja2 template.
    Various settings from the ``sphinx-jinja`` extension are also reused.
    """

    required_arguments = 2
    has_content = False
    # RUFF NOTE: Suggested fix (ClassVar) does not work for overriding values.
    option_spec: OptionSpec = dict(  # type: ignore[misc]  # noqa: RUF012
        CodeBlock.option_spec, context=directives.unchanged
    )

    def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
        super().__init__(*args, **kwargs)
        self.jinja_env = Environment(
            loader=FileSystemLoader(self.config.jinja_base, followlinks=True), **self.config.jinja_env_kwargs
        )
        self.jinja_env.filters.update(self.config.jinja_filters)
        self.jinja_env.tests.update(self.config.jinja_tests)
        self.jinja_env.globals.update(self.config.jinja_globals)
        # TYPEHINT NOTE: false positive
        self.jinja_env.policies.update(self.config.jinja_policies)  # type: ignore[attr-defined]

    @property
    def content(self) -> StringList:
        """Actually render the template."""
        template = self.jinja_env.get_template(self.arguments[1])
        context_name = self.options.get("context")

        # get the context
        if not context_name:
            context = {}
        elif context_name not in self.config.jinja_contexts:
            raise ValueError(f"{context_name}: Unknown context specified.")
        else:
            context = self.config.jinja_contexts[context_name].copy()

        content = template.render(**context)
        return StringList(content.splitlines())

    @content.setter
    def content(self, value: typing.Any) -> None:
        """Setter for content (used by the constructor). Disregards the value."""

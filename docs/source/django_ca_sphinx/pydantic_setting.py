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

"""pydantic-setting directive."""

import json
import types
from datetime import timedelta
from typing import Annotated, Any, ClassVar, Literal, Union, get_args, get_origin

import yaml
from docutils import nodes
from docutils.parsers.rst import DirectiveError, directives
from docutils.statemachine import StringList
from jinja2 import Environment
from pydantic import BaseModel, ConfigDict, TypeAdapter
from pydantic.fields import FieldInfo
from pydantic_core import PydanticUndefined
from rich.pretty import pretty_repr
from sphinx.util import logging
from sphinx.util.docutils import SphinxDirective
from sphinx.util.nodes import nested_parse_with_titles

from django.conf import settings

from ca.settings_utils import ProjectSettingsModelMixin
from django_ca.conf import SettingsModel

# Logger with the Sphinx logging API:
#   https://www.sphinx-doc.org/en/master/extdev/logging.html
log = logging.getLogger(__name__)

env = Environment()
template = env.from_string("""{% if default -%}
    **Type:** {% if field_type in ('dict', 'list', 'tuple') -%}
        :ref:`{{ field_type }} <settings-types-collections>`
    {%- elif field_type in ('bool', 'int', 'float', 'str', 'timedelta') -%}
        :ref:`{{ field_type }} <settings-types-{{ field_type }}>`
    {%- else -%}
        Unknown field type: {{ field_type }}
    {%- endif -%}
, **default:**
{%- endif %}
{%- if explanation %} {{ explanation }}{% else %}

.. tab:: Python

    .. code-block:: python

        {{ setting }} = {{ value|indent("        ") }}

.. tab:: YAML

    .. code-block:: YAML

        {{ yaml|indent("        ") }}

.. tab:: Environment variable

    {% if env is none %}
    ``{{ prefix|default("DJANGO_CA_") }}{{ setting }}`` not set.
    {% else %}
    .. code-block::

        {{ prefix|default("DJANGO_CA_") }}{{ setting }}='{{ env }}'
    {%- endif %}
{% endif %}
{%- if default and description %}

{{ description }}{% endif %}""")


class ProjectSettingsModel(ProjectSettingsModelMixin, SettingsModel):
    """Model representing settings plus project settings."""

    model_config = ConfigDict(from_attributes=True, arbitrary_types_allowed=True)


model_settings = ProjectSettingsModel.model_validate(settings)


class PydanticSettingDirective(SphinxDirective):
    """
    Sphinx directive to document Pydantic model fields.

    Usage:
        .. pydantic-field:: module.path.to.Model.field_name
           :default:
           :example: 0
    """

    required_arguments = 1  # The setting name
    optional_arguments = 0
    option_spec: ClassVar[dict[str, Any]] = {
        "default": directives.flag,  # Flag option (no value needed)
        "example": directives.nonnegative_int,  # Integer option
    }
    has_content = False

    def get_field_type(self, field_type: type[Any] | None) -> tuple[type[Any], bool]:
        """Get the field type from the given field info.

        For optional typehints, as well as dicts, tuples and lists, this will return the unsubscripted
        type hints, e.g.::

            >>> get_field_type(dict[str, str] | None)
            dict
        """
        if field_type is None:  # pragma: no cover
            raise self.error("No type annotation for the field type")
        origin = get_origin(field_type)
        optional = False

        if (  # pragma: only py<3.14: origin is UnionType in Py<3.14
            origin is Union or origin is types.UnionType
        ):
            optional = True
            args = get_args(field_type)
            field_type_args = [a for a in args if a is not types.NoneType]
            if len(field_type_args) == 1:
                field_type = field_type_args[0]

        if origin is dict or origin is tuple or origin is list:
            field_type = origin
        return field_type, optional

    def get_example_value(self, setting: str, field_info: FieldInfo) -> Any:
        """Get the example value for the given field."""
        example_idx = self.options["example"]
        if not hasattr(field_info, "examples"):
            raise self.error(f"{setting}: No example defined.")

        if field_info.examples is None:
            raise self.error(f"{setting}: No examples defined.")

        try:
            return field_info.examples[example_idx]
        except IndexError as ex:
            raise self.error(f"{setting}: Example index out of range.") from ex

    def prepare_value(self, setting: str, value: Any) -> tuple[str, str, str]:
        """Prepare the value for rendering.

        This returns the value as it is valid and "pretty" in Python, YAML and environment variable.
        """
        yaml_value = env_value = value

        if isinstance(value, bool):
            if value is True:
                env_value = "true"
            else:
                env_value = "false"
        elif isinstance(value, timedelta):
            type_adapter = TypeAdapter(timedelta)
            env_value = yaml_value = type_adapter.dump_json(value).decode("ascii").strip('"')
        elif isinstance(value, dict):
            yaml_value = {}
            for k, v in value.items():
                if isinstance(v, BaseModel):
                    yaml_value[k] = v.model_dump(mode="json", exclude_unset=True)
                else:
                    yaml_value[k] = v
            value = yaml_value
            env_value = json.dumps(yaml_value)
        elif isinstance(value, list | tuple):
            env_value = json.dumps(value)
        elif isinstance(value, BaseModel):
            yaml_value = value.model_dump(mode="json")
            env_value = value.model_dump_json().strip('"')
            value = value.model_dump()

        repr_value = repr(value)
        if len(repr_value) + len(setting) > 80:
            repr_value = pretty_repr(value, indent_size=4, max_width=80)

        yaml_value = yaml.safe_dump({setting: yaml_value})

        return repr_value, yaml_value, env_value

    def get_field_type_key(self, field_type: Any) -> str:
        """Get the field type key for rendering it in the template."""
        if field_type in (bool, int, float, str, dict, list, timedelta):
            return field_type.__name__  # type: ignore[no-any-return]
        if field_type is tuple:
            return "list"

        origin = get_origin(field_type)
        if origin is Literal:
            args = set(type(t) for t in get_args(field_type))
            if args == {str}:
                return "str"
            raise self.error(f"Annotated with type {args}")
        if origin is Annotated:
            return self.get_field_type_key(get_args(field_type)[0])

        if isinstance(type(field_type), type) and issubclass(field_type, BaseModel):
            return "dict"

        return str(field_type)

    def get_text(self, setting: str) -> str:
        """Get the text for the extension."""
        # Get the field info
        field_info: FieldInfo = ProjectSettingsModel.model_fields[setting]
        description = field_info.description

        extra = field_info.json_schema_extra
        if not isinstance(extra, dict):  # may be None (not defined) or a callable)
            extra = {}

        field_type, optional = self.get_field_type(field_info.annotation)
        field_type_key = self.get_field_type_key(field_type)

        # Handle 'default' option
        if "default" in self.options or "example" not in self.options:
            if explanation := extra.get("default_explanation"):
                return template.render(
                    explanation=explanation, description=description, field_type=field_type_key, default=True
                )

            shows_default = True
            value = field_info.default
            if field_type is dict and field_info.default_factory is dict:
                value = {}
            elif field_info.default_factory is not None:
                value = getattr(model_settings, setting)
            elif model_value := getattr(model_settings, setting):
                value = model_value
            elif optional and value is None:
                text = template.render(
                    explanation="Not set.", description=description, field_type=field_type_key, default=True
                )
                return text
            elif value == PydanticUndefined:
                raise self.error(f"{setting}: No default defined.")

        # Handle 'example' option
        elif "example" in self.options:
            shows_default = False
            value = self.get_example_value(setting, field_info)
        else:
            raise self.error(f"{setting}: Either `example` or `default` must be defined.")

        value, yaml_value, env_value = self.prepare_value(setting, value)

        output = template.render(
            setting=setting,
            value=value,
            yaml=yaml_value,
            env=env_value,
            default=shows_default,
            description=description,
            field_type=field_type_key,
        ).strip()
        return output

    def run(self) -> list[nodes.Node]:
        # Parse the field path
        setting = self.arguments[0]

        if self.options.get("default") and self.options.get("example"):
            raise self.error("You can't specify both `default` and `example`")
        if setting not in ProjectSettingsModel.model_fields:
            raise self.error(f"Setting '{setting}' not found.")

        try:
            output = self.get_text(setting)

            # Create a container node to hold the parsed content
            container = nodes.container()

            # Convert the output lines to a StringList for parsing
            # The second argument is the source name (for error reporting)
            rst_text = StringList(output.splitlines(), source=setting)

            # Parse the reStructuredText content
            # This allows the text to use other directives, roles, etc.
            nested_parse_with_titles(self.state, rst_text, container)

            return [container]

        except DirectiveError as ex:  # from raise self.error()
            log.exception(ex)
            raise
        except Exception as ex:
            # Otherwise, wrap it in a directive error
            log.exception(ex)
            raise self.error(f"{setting}: Unexpected error: {ex}, {type(ex)}") from ex

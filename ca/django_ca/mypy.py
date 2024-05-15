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

"""Mypy plugin for django-ca.

The plugin adds proper type hinting to attribute access on ``django_ca.conf.model_settings``.
"""

from typing import Callable, Optional, cast

from mypy.checker import TypeChecker
from mypy.errorcodes import ATTR_DEFINED
from mypy.nodes import MemberExpr, TypeInfo, Var
from mypy.plugin import AttributeContext, Plugin
from mypy.types import AnyType, Instance, Type, TypeOfAny

from django_ca.conf import SettingsModel


class DjangoCaPlugin(Plugin):
    """Plugin implementation.

    .. seealso:: https://mypy.readthedocs.io/en/latest/extending_mypy.html
    """

    _settings_model_type_info = None

    def get_settings_model_type_info(self, api: TypeChecker) -> TypeInfo:
        """Get cached version of the type info for SettingsModel."""
        if self._settings_model_type_info is None:
            module_file = api.modules[SettingsModel.__module__]
            symbol_table_node = module_file.names[SettingsModel.__qualname__]

            # Mypy thinks symbol_table_node is a SymbolNode, but it is in fact a TypeInfo
            # (= subclass of SymbolNode).
            self._settings_model_type_info = cast(TypeInfo, symbol_table_node.node)
        return self._settings_model_type_info

    def settings_proxy_attribute_callback(self, ctx: AttributeContext) -> Type:  # noqa: PLR0911
        """Callback for attribute access to django_ca.conf.SettingsProxy."""
        # Get context attributes with more specific types. Mypy typehints these attributes to higher-level
        # classes (presumably because AttributeContext may be used in a different context as well). We narrow
        # the type to what is observed in practice here:
        member_expr = ctx.context
        if not isinstance(member_expr, MemberExpr):
            ctx.api.fail("ctx.context has unexpected type.", member_expr)
            return AnyType(TypeOfAny.from_error)

        instance = ctx.type
        if not isinstance(instance, Instance):
            ctx.api.fail("ctx.type has unexpected type.", member_expr)
            return AnyType(TypeOfAny.from_error)

        attr_name: str = member_expr.name  # attribute name that is accessed

        # Return type of instance attributes defined for SettingsProxy itself
        # (in this case, SettingsProxy.__getattr__() is not even called)
        if attr_type := instance.type.names.get(attr_name):
            # Narrow down type (probably doesn't happen in practice)
            if not isinstance(attr_type.node, Var):
                ctx.api.fail("Attribute node is not a variable.", member_expr)
                return AnyType(TypeOfAny.from_error)

            # Make sure that the attribute has a typehint and log an error otherwise.
            if attr_type.node.type is None:
                ctx.api.fail(f'"{attr_name}": Attribute has no typehint.', member_expr)
                return AnyType(TypeOfAny.unannotated)

            return attr_type.node.type

        # All settings must be upper case, simply throw error if not
        if not attr_name.isupper():
            ctx.api.fail(f'Setting name must be upper case: "{attr_name}"', member_expr, code=ATTR_DEFINED)
            return AnyType(TypeOfAny.from_error)

        # Return type of model field for SettingsModel if defined.
        type_info = self.get_settings_model_type_info(ctx.api)  # type: ignore[arg-type]
        if attr_type := type_info.names.get(attr_name):
            # Narrow down type (probably doesn't happen in practice)
            if not isinstance(attr_type.node, Var):
                ctx.api.fail("Attribute node is not a variable.", member_expr)
                return AnyType(TypeOfAny.from_error)

            # Make sure that the attribute has a typehint and log an error otherwise. Since Pydantic models
            # always have a type hint, this probably never happens in practice.
            if attr_type.node.type is None:
                ctx.api.fail(f'"{attr_name}": Attribute has no typehint.', member_expr)
                return AnyType(TypeOfAny.unannotated)

            return attr_type.node.type

        # At this point, the attribute is not an attribute of SettingsProxy and not a model field for
        # SettingsModel, so it is actually an undefined setting.
        ctx.api.fail(f'Undefined setting "{attr_name}"', member_expr)
        return AnyType(TypeOfAny.from_error)

    def get_attribute_hook(self, fullname: str) -> Optional[Callable[[AttributeContext], Type]]:
        """Hook called by mypy to get the type for attributes."""
        if fullname.startswith("django_ca.conf.SettingsProxy"):
            return self.settings_proxy_attribute_callback
        return None


# pylint: disable-next=unused-argument  # defined in the plugin api
def plugin(version: str) -> type[DjangoCaPlugin]:
    """Plugin entry point for mypy (name of function is pre-defined)."""
    return DjangoCaPlugin

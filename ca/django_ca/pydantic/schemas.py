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

"""Collection of custom schemas.

.. seealso:: https://docs.pydantic.dev/latest/concepts/types/#using-getpydanticschema-to-reduce-boilerplate
"""

from pydantic import GetPydanticSchema
from pydantic_core import core_schema

from django.utils.functional import Promise
from django.utils.translation import gettext_lazy


def get_promise_schema() -> GetPydanticSchema:
    """Schema for Django promises, aka translated strings."""

    def _json_validator(value: str) -> Promise:
        return gettext_lazy(value)

    def _json_serializer(value: Promise) -> str:
        return str(value)

    json_schema = core_schema.chain_schema(
        [
            core_schema.str_schema(),
            core_schema.no_info_plain_validator_function(_json_validator),
        ]
    )

    python_schema = core_schema.is_instance_schema(Promise)

    return GetPydanticSchema(
        lambda tp, handler: core_schema.json_or_python_schema(
            json_schema,
            python_schema=core_schema.union_schema([python_schema, json_schema]),
            serialization=core_schema.plain_serializer_function_ser_schema(
                _json_serializer, when_used="json"
            ),
        )
    )

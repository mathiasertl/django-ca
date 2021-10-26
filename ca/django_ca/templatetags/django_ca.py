# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca.  If not,
# see <http://www.gnu.org/licenses/>.

"""Template tags used by the admin interface."""

import typing

from cryptography import x509

from django import template
from django.contrib.admin.templatetags.admin_modify import submit_row

from ..utils import add_colons
from ..utils import bytes_to_hex
from ..utils import format_general_name
from ..utils import format_name
from ..utils import int_to_hex

register = template.Library()


register.filter("format_name", format_name)


@register.filter
def format_general_names(value: typing.Iterable[x509.GeneralName]) -> typing.List[str]:
    """A template tag to format general names.

    Note that currently general names always occur as list.
    """
    return [format_general_name(v) for v in value]


@register.filter
def as_hex(value: typing.Union[int, bytes]) -> str:
    """Takes a bytes value and returns its hex representation."""

    if isinstance(value, int):
        return add_colons(int_to_hex(value))
    return bytes_to_hex(value)


@register.filter
def oid_name(value: x509.ObjectIdentifier) -> str:
    """Get name of an OID."""
    return value._name  # pylint: disable=protected-access; only way to get the OID name


@register.filter
def is_user_notice(value: typing.Any) -> bool:
    """Return ``True`` if `value` is :py:class:`~cg:cryptography.x509.UserNotice`."""
    return isinstance(value, x509.UserNotice)


@register.inclusion_tag("django_ca/admin/submit_line.html", takes_context=True)
def django_ca_certificate_submit_row(context: template.context.RequestContext) -> template.context.Context:
    """Submit row for certificate change view."""
    return submit_row(context)

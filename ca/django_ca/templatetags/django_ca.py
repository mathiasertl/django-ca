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

from cryptography import x509

from django import template
from django.contrib.admin.templatetags.admin_modify import submit_row

from ..utils import add_colons
from ..utils import bytes_to_hex
from ..utils import format_general_name
from ..utils import format_name
from ..utils import format_relative_name
from ..utils import int_to_hex

register = template.Library()


register.filter('format_name', format_name)
register.filter('format_relative_name', format_relative_name)


@register.filter
def format_general_names(value):
    """A template tag to format general names.

    Note that currently general names always occur as list.
    """
    return [format_general_name(v) for v in value]


@register.filter
def as_hex(value):
    """Takes a bytes value and returns its hex representation."""

    if isinstance(value, int):
        return add_colons(int_to_hex(value))
    else:
        return bytes_to_hex(value)


@register.filter
def oid_name(value):
    return value._name


@register.filter
def is_user_notice(value):
    return isinstance(value, x509.UserNotice)


@register.inclusion_tag('django_ca/admin/submit_line.html', takes_context=True)
def django_ca_certificate_submit_row(context):
    return submit_row(context)

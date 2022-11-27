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
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from django.utils.translation import gettext as _

from ..constants import EXTENDED_KEY_USAGE_NAMES, EXTENSION_CRITICAL_HELP, EXTENSION_RFC_DEFINITION
from ..extensions.utils import key_usage_items, signed_certificate_timestamp_values
from ..utils import add_colons, bytes_to_hex, format_general_name, format_name, int_to_hex

register = template.Library()


register.filter("format_name", format_name)
register.filter("key_usage_items", key_usage_items)
register.filter("signed_certificate_timestamp_values", signed_certificate_timestamp_values)


@register.filter
def critical_help(dotted_string: str) -> str:
    """Return help text informing the user if the extension should be marked as critical or not."""
    oid = x509.ObjectIdentifier(dotted_string)
    rfc = EXTENSION_RFC_DEFINITION[oid]
    help_text = EXTENSION_CRITICAL_HELP.get(oid, "")

    return _("RFC %(rfc)s says this extension %(help_text)s.") % {"help_text": help_text, "rfc": rfc}


@register.filter
def access_method(
    value: x509.AuthorityInformationAccess, oid: x509.ObjectIdentifier
) -> typing.List[x509.AccessDescription]:
    """Get all entries of an `AuthorityInformationAccess` extension with the given access method `oid`."""
    return [ad.access_location for ad in value if ad.access_method == oid]


@register.filter
def sort_reasons(reasons: x509.ReasonFlags) -> typing.List[str]:
    """Return a sorted list of reasons."""
    # TYPE NOTE: mypy does not detect enum x509.ReasonsFlags as iterable
    return sorted(r.name for r in reasons)  # type: ignore[attr-defined]


@register.filter
def extended_key_usage_list(value: x509.ExtendedKeyUsage) -> str:
    """Return a HTML-formatted list of extended key usage entries."""
    lines = []
    for oid in value:
        name = EXTENDED_KEY_USAGE_NAMES.get(oid, oid.dotted_string)
        lines.append(format_html("<li>{}</li>", name))

    return mark_safe("".join(lines))


@register.filter
def enum(mod: typing.Any, cls_name_and_member: str) -> typing.Any:
    """A filter that makes enum members accessible in Django templates.

    Django will try to call callables, and since enums are callable, an empty string is returned instead in
    the template.
    """
    cls_name, member = cls_name_and_member.split(".", 1)
    enum_cls = getattr(mod, cls_name)
    return getattr(enum_cls, member)


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

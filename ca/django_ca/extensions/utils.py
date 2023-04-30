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

"""``django_ca.extensions.utils`` contains various utility classes used by X.509 extensions."""

from typing import Iterator, Tuple

from cryptography import x509
from cryptography.x509.certificate_transparency import LogEntryType, SignedCertificateTimestamp

from django.template.loader import render_to_string

from django_ca.constants import KEY_USAGE_NAMES
from django_ca.utils import bytes_to_hex


def extension_as_admin_html(extension: x509.Extension[x509.ExtensionType]) -> str:
    """Convert an extension to HTML code suitable for the admin interface."""
    template = f"django_ca/admin/extensions/{extension.oid.dotted_string}.html"
    if isinstance(extension.value, x509.UnrecognizedExtension):
        template = "django_ca/admin/extensions/unrecognized_extension.html"

    return render_to_string([template], context={"extension": extension, "x509": x509})


def key_usage_items(value: x509.KeyUsage) -> Iterator[str]:
    """Get a list of basic key usages."""
    for attr, name in KEY_USAGE_NAMES.items():
        try:
            if getattr(value, attr):
                yield name
        except ValueError:
            # x509.KeyUsage raises ValueError on some attributes to ensure consistency
            pass


def signed_certificate_timestamp_values(sct: SignedCertificateTimestamp) -> Tuple[str, str, str, str]:
    """Get values from a SignedCertificateTimestamp as a tuple of strings."""
    if sct.entry_type == LogEntryType.PRE_CERTIFICATE:
        entry_type = "Precertificate"
    elif sct.entry_type == LogEntryType.X509_CERTIFICATE:  # pragma: no cover  # Unseen in the wild
        entry_type = "x509 certificate"
    else:  # pragma: no cover  # We support everything that has been specified so far
        entry_type = "unknown"
    return entry_type, sct.version.name, bytes_to_hex(sct.log_id), sct.timestamp.isoformat(" ")

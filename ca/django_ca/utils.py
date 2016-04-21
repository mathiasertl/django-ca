# -*- coding: utf-8 -*-
#
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

"""Central functions to load CA key and cert as PKey/X509 objects."""

import re
import uuid

from copy import deepcopy
from datetime import datetime
from datetime import timedelta
from ipaddress import ip_address

from django.core.validators import URLValidator
from django.core.serializers.json import DjangoJSONEncoder
from django.utils.encoding import force_text
from django.utils.functional import Promise
from django.utils.translation import ugettext_lazy as _

from OpenSSL import crypto

from django_ca import ca_settings

# List of possible subject fields, in order
SUBJECT_FIELDS = ['C', 'ST', 'L', 'O', 'OU', 'CN', 'emailAddress', ]

# Description strings for various X509 extensions, taken from "man x509v3_config".
EXTENDED_KEY_USAGE_DESC = _('Purposes for which the certificate public key can be used for.')
KEY_USAGE_DESC = _('Permitted key usages.')
SAN_OPTIONS_RE = '(email|URI|IP|DNS|RID|dirName|otherName):'
_datetime_format = '%Y%m%d%H%M%SZ'


class LazyEncoder(DjangoJSONEncoder):
    """Encoder that also encodes strings translated with ugettext_lazy."""

    def default(self, obj):
        if isinstance(obj, Promise):
            return force_text(obj)
        return super(LazyEncoder, self).default(obj)


def parse_date(date):
    return datetime.strptime(date, _datetime_format)


def format_date(date):
    """Format date as ASN1 GENERALIZEDTIME, as required by various fields."""
    return date.strftime(_datetime_format)


def is_power2(num):
    """Return True if num is a power of 2."""
    return num != 0 and ((num & (num - 1)) == 0)


def multiline_url_validator(value):
    """Validate that a TextField contains one valid URL per line.

    .. seealso:: https://docs.djangoproject.com/en/1.9/ref/validators/
    """
    validator = URLValidator()

    for line in value.splitlines():
        validator(line)


def get_cert_subject(d):
    """Returns an itemized dictionary in the correct order for a x509 subject."""
    return sorted(d.items(), key=lambda e: SUBJECT_FIELDS.index(e[0]))


def get_basic_cert(expires, now=None):
    """Get a basic X509 cert object.

    Parameters
    ----------

    expires : int
        When, in number of days from now, this certificate will expire.
    """
    if expires < 0:
        raise ValueError("Expires must not be negative.")

    if now is None:  # pragma: no cover
        now = datetime.utcnow()
    now = now.replace(second=0, microsecond=0)

    not_before = format_date(now)

    # make expires to a datetime
    expires = now + timedelta(days=expires + 1)
    expires = expires.replace(hour=0, minute=0, second=0, microsecond=0)

    not_after = format_date(expires)

    cert = crypto.X509()
    cert.set_version(2) # V3 certificate
    cert.set_serial_number(uuid.uuid4().int)
    cert.set_notBefore(not_before.encode('utf-8'))
    cert.set_notAfter(not_after.encode('utf-8'))
    return cert


def get_cert_profile_kwargs(name=None):
    """Get kwargs suitable for get_cert X509 keyword arguments from the given profile."""

    if name is None:
        name = ca_settings.CA_DEFAULT_PROFILE

    profile = deepcopy(ca_settings.CA_PROFILES[name])
    kwargs = {
        'cn_in_san': profile['cn_in_san'],
        'subject': profile['subject'],
    }
    for arg in ['keyUsage', 'extendedKeyUsage']:
        config = profile.get(arg)
        if config is None or not config.get('value'):
            continue

        critical = config.get('critical', 'True')
        if isinstance(config['value'], str):
            kwargs[arg] = (critical, bytes(config['value'], 'utf-8'))
        elif isinstance(config['value'], bytes):
            kwargs[arg] = (critical, config['value'])
        else:
            kwargs[arg] = (critical, bytes(','.join(config['value']), 'utf-8'))
    return kwargs


def get_subjectAltName(names, cn=None):
    """Compute the value of the subjectAltName extension based on the given list of names.

    The `cn` parameter, if provided, is prepended if not present in the list of names.

    This method supports the `IP`, `email`, `URI` and `DNS` options automatically, if you need a
    different option (or think the automatic parsing is wrong), give the full value verbatim (e.g.
    `otherName:1.2.3.4;UTF8:some other identifier`.
    """
    values = []
    names = sorted(set(names))

    for name in names:
        if not name:
            continue
        if isinstance(name, bytes):
            name = name.decode('utf-8')

        # Match any known literal values
        if re.match(SAN_OPTIONS_RE, name):
            values.append(name)
            continue

        try:
            ip_address(name)
            values.append('IP:%s' % name)
            continue
        except ValueError:
            pass

        if re.match('[a-z0-9]{2,}://', name):
            values.append('URI:%s' % name)
        elif '@' in name:
            values.append('email:%s' % name)
        else:
            values.append('DNS:%s' % name)

    if cn is not None:
        value = 'DNS:%s' % cn
        if value not in values:
            values.insert(0, value)

    return bytes(','.join(values), 'utf-8')

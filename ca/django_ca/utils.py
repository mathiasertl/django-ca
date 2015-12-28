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

from datetime import datetime
from datetime import timedelta
from ipaddress import ip_address

from django.conf import settings

from OpenSSL import crypto

CA_KEY = None
CA_CRT = None


def format_date(date):
    """Format date as ASN1 GENERALIZEDTIME, as required by various fields."""
    return date.strftime('%Y%m%d%H%M%SZ')


def get_ca_key(reload=False):
    global CA_KEY
    if CA_KEY is None or reload is True:
        with open(settings.CA_KEY) as ca_key:
            CA_KEY = crypto.load_privatekey(crypto.FILETYPE_PEM, ca_key.read())
    return CA_KEY


def get_ca_crt(reload=False):
    global CA_CRT
    if CA_CRT is None or reload is True:
        with open(settings.CA_CRT) as ca_crt:
            CA_CRT = crypto.load_certificate(crypto.FILETYPE_PEM, ca_crt.read())
    return CA_CRT

def get_basic_cert(expires):
    not_before = format_date(datetime.utcnow() - timedelta(minutes=5))
    not_after = format_date(expires)

    cert = crypto.X509()
    cert.set_serial_number(uuid.uuid4().int)
    cert.set_notBefore(not_before.encode('utf-8'))
    cert.set_notAfter(not_after.encode('utf-8'))
    return cert


def get_subjectAltName(names, cn=None):
    """Compute the value of the subjectAltName extension based on the given list of names.

    The `cn` parameter, if provided, isprepended if not present in the list of names.

    This method supports the `IP`, `email`, `URI` and `DNS` options automatically, if you need a
    different option (or think the automatic parsing is wrong), give the full value verbatim (e.g.
    `otherName:1.2.3.4;UTF8:some other identifier`.
    """
    values = []
    names = sorted(set(names))
    if cn is not None and cn not in names:
        names.insert(0, cn)

    for name in names:
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
        elif ':' in name:
            values.append(name)
        else:
            values.append('DNS:%s' % name)

    return bytes(','.join(values), 'utf-8')

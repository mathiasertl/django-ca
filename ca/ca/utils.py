# -*- coding: utf-8 -*-
#
# This file is part of fsinf-certificate-authority
# (https://github.com/fsinf/certificate-authority).
#
# fsinf-certificate-authority is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software Foundation, either
# version 3 of the License, or (at your option) any later version.
#
# fsinf-certificate-authority is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
# PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# fsinf-certificate-authority.  If not, see <http://www.gnu.org/licenses/>.

"""Central functions to load CA key and cert as PKey/X509 objects."""

from __future__ import unicode_literals

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

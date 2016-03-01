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

import os

from OpenSSL import crypto

from django_ca import ca_settings
from django_ca.models import Certificate


def get_crl(ca, **kwargs):
    """Function to generate a Certificate Revocation List (CRL).

    All keyword arguments are passed as-is to :py:func:`OpenSSL.crypto.CRL.export`. Please see the
    documentation of that function for details.

    Parameters
    ----------

    type : int
    days : int
    digest : hash
        Unlike the current pyOpenSSL default (md5), sha512 is the default.


    Returns
    -------

    Returns the CRL as bytes (since this is what pyOpenSSL returns).
    """
    kwargs.setdefault('digest', b'sha512')

    crl = crypto.CRL()
    for cert in Certificate.objects.revoked():
        crl.add_revoked(cert.get_revocation())
    return crl.export(ca.key, ca.x509, **kwargs)


def get_crl_settings():
    """Get CRL settings with appropriate defaults."""

    try:
        settings = dict(ca_settings.CA_CRL_SETTINGS)
    except TypeError:  # CA_CRL_SETTINGS is most likely None (not defined).
        settings = {}

    settings.setdefault('digest', b'sha512')
    settings.setdefault('days', 1)
    settings.setdefault('type', crypto.FILETYPE_PEM)

    if isinstance(settings['type'], str):
        settings['type'] = getattr(crypto, 'FILETYPE_%s' % settings['type'])
    if isinstance(settings['digest'], str):
        settings['digest'] = bytes(settings['digest'], 'utf-8')

    return settings


def write_crl():
    """Write the CRL based on ``CA_CRL_SETTINGS``.

    This method silently does nothing if no path is defined.
    """
    settings = get_crl_settings()
    if not settings.get('path'):
        return

    path = settings.pop('path')

    crl = get_crl(**settings)
    dirname = os.path.dirname(path)
    if dirname and not os.path.exists(dirname):
        os.makedirs(dirname)

    with open(path, 'wb') as out:
        out.write(crl)
        out.flush()

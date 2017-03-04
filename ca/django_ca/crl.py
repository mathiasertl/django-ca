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

from datetime import datetime
from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from django.utils import timezone

from django_ca.models import Certificate


def get_crl(ca, encoding, expires, algorithm):
    """Function to generate a Certificate Revocation List (CRL).

    All keyword arguments are passed as-is to :py:func:`OpenSSL.crypto.CRL.export`. Please see the
    documentation of that function for details.

    Parameters
    ----------

    ca : :py:class:`~django_ca.models.CertificateAuthority`
    encoding : :py:class:`cryptography:cryptography.hazmat.primitives.serialization.Encoding`
        The encoding format for the CRL.
    expires : int
        The time in seconds until a new CRL will be generated
    algorithm : :py:class:`cryptography:cryptography.hazmat.primitives import hashes`
        The hash algorithm to use.


    Returns
    -------

    bytes
        The CRL in the requested format.
    """
    now = datetime.utcnow()
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca.x509.subject)
    builder = builder.last_update(now)
    builder = builder.next_update(now + timedelta(seconds=expires))

    for cert in Certificate.objects.filter(ca=ca, expires__gt=timezone.now()).revoked():
        builder = builder.add_revoked_certificate(cert.get_revocation())

    crl = builder.sign(private_key=ca.key, algorithm=algorithm, backend=default_backend())
    return crl.public_bytes(encoding)

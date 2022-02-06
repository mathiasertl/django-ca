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

"""ACME utility functions."""

import josepy as jose

from cryptography import x509


def parse_acme_csr(value: str) -> x509.CertificateSigningRequest:
    """Convert the CSR as received via ACMEv2 into a valid CSR.

    ACMEv2 sends the CSR as a base64url encoded string of its DER /ASN.1 representation.

    Returns
    -------

    :py:class:`~cg:cryptography.x509.CertificateSigningRequest`
        The CSR as used by cryptography.
    """
    decoded = jose.json_util.decode_b64jose(value)
    return x509.load_der_x509_csr(decoded)

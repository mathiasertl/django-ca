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

"""Utility functions for OCSP tests."""

import base64
from http import HTTPStatus
from typing import Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ocsp

from django.test import Client
from django.urls import reverse

from django_ca.models import Certificate, CertificateAuthority
from django_ca.tests.base.typehints import HttpResponse


def ocsp_request(
    client: Client,
    certificate: CertificateAuthority | Certificate,
    nonce: bytes | None = None,
    hash_algorithm: type[hashes.HashAlgorithm] = hashes.SHA256,
    nonce_critical: bool = False,
    method: Literal["get", "post"] = "get",
) -> "HttpResponse":
    """Make an OCSP get request."""
    if isinstance(certificate, CertificateAuthority):
        ca = certificate.parent
        assert ca is not None, "OCSP queries can only be done for root CAs."
        url_name = f"django_ca:ocsp-ca-{method}"
    else:
        ca = certificate.ca
        url_name = f"django_ca:ocsp-cert-{method}"

    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(certificate.pub.loaded, ca.pub.loaded, hash_algorithm())

    if nonce is not None:  # Add Nonce if requested
        builder = builder.add_extension(x509.OCSPNonce(nonce), nonce_critical)

    request = builder.build()
    request_data = request.public_bytes(Encoding.DER)

    if method == "get":
        url = reverse(
            url_name, kwargs={"serial": ca.serial, "data": base64.b64encode(request_data).decode("utf-8")}
        )
        response = client.get(url)
    else:
        url = reverse(url_name, kwargs={"serial": ca.serial})
        response = client.post(url, data=request_data, content_type="application/ocsp-request")
    assert response.status_code == HTTPStatus.OK
    return response

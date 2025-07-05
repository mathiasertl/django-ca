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

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ocsp

from django.test import Client
from django.urls import reverse

from django_ca.key_backends.storages import StoragesOCSPBackend
from django_ca.key_backends.storages.models import StoragesUsePrivateKeyOptions
from django_ca.models import Certificate, CertificateAuthority
from django_ca.tests.base.constants import CERT_DATA
from django_ca.tests.base.typehints import HttpResponse


def generate_ocsp_key(ca: CertificateAuthority) -> tuple[CertificateIssuerPrivateKeyTypes, Certificate]:
    """Generate an OCSP key for the given CA and return private kay and public key model instance."""
    key_backend_options = StoragesUsePrivateKeyOptions(password=CERT_DATA[ca.name].get("password"))
    ocsp_cert = ca.generate_ocsp_key(key_backend_options)
    assert ocsp_cert is not None
    ocsp_key_backend = ca.ocsp_key_backend
    assert isinstance(ocsp_key_backend, StoragesOCSPBackend)
    private_key = ocsp_key_backend.load_private_key(ca)
    return private_key, ocsp_cert


def ocsp_get(
    client: Client,
    certificate: CertificateAuthority | Certificate,
    nonce: bytes | None = None,
    hash_algorithm: type[hashes.HashAlgorithm] = hashes.SHA256,
) -> "HttpResponse":
    """Make an OCSP get request."""
    if isinstance(certificate, CertificateAuthority):
        ca = certificate.parent
        assert ca is not None, "OCSP queries can only be done for root CAs."
        url_name = "django_ca:ocsp-ca-get"
    else:
        ca = certificate.ca
        url_name = "django_ca:ocsp-cert-get"

    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(certificate.pub.loaded, ca.pub.loaded, hash_algorithm())

    if nonce is not None:  # Add Nonce if requested
        builder = builder.add_extension(x509.OCSPNonce(nonce), False)

    request = builder.build()

    url = reverse(
        url_name,
        kwargs={
            "serial": ca.serial,
            "data": base64.b64encode(request.public_bytes(Encoding.DER)).decode("utf-8"),
        },
    )
    response = client.get(url)
    assert response.status_code == HTTPStatus.OK
    return response

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

"""Test certificate model."""

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

import pytest

from django_ca.pydantic.certificate import CertificateModel
from django_ca.tests.base.constants import CERT_DATA
from django_ca.tests.pydantic.base import assert_cryptography_model


def test_certificatemodel(any_cert: str) -> None:
    """Test CertificateModel."""
    cert: x509.Certificate = CERT_DATA[any_cert]["pub"]["parsed"]
    if isinstance(cert.signature_hash_algorithm, hashes.SHA1):
        raise pytest.skip("SHA1 certificates are not supported here.")
    assert isinstance(cert, x509.Certificate)
    pem = cert.public_bytes(Encoding.PEM).decode("ascii")
    model = assert_cryptography_model(
        CertificateModel,
        {
            "serial_number": cert.serial_number,
            "version": cert.version,
            "not_valid_before": cert.not_valid_before_utc,
            "not_valid_after": cert.not_valid_after_utc,
            "issuer": cert.issuer,
            "subject": cert.subject,
            "signature_hash_algorithm": cert.signature_hash_algorithm,
            "signature_algorithm_oid": cert.signature_algorithm_oid,
            "public_key_algorithm_oid": cert.public_key_algorithm_oid,
            "signature_algorithm_parameters": cert.signature_algorithm_parameters,
            "extensions": cert.extensions,
            "pem": pem,
        },
        cert,
        has_equality=False,
    )
    assert isinstance(model, CertificateModel)
    assert model.cryptography == cert
    assert model.fingerprint(hashes.SHA256()) == cert.fingerprint(hashes.SHA256())
    assert model.fingerprint("SHA-256") == cert.fingerprint(hashes.SHA256())
    assert model.public_key() == cert.public_key()
    assert model.public_bytes(Encoding.PEM) == cert.public_bytes(Encoding.PEM)
    assert model.public_bytes("PEM") == cert.public_bytes(Encoding.PEM)

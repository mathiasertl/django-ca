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

from typing import Any

from pydantic import ValidationError

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

import pytest
from _pytest.fixtures import SubRequest

from django_ca.models import Certificate, CertificateAuthority
from django_ca.pydantic.certificate import (
    CertificateModel,
    DjangoCertificateAuthorityModel,
    DjangoCertificateModel,
)
from django_ca.tests.base.constants import CERT_DATA
from django_ca.tests.pydantic.base import assert_cryptography_model


def test_certificate_model(any_cert: str) -> None:
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


@pytest.mark.django_db
def test_django_certificate_authority_model(ca: CertificateAuthority) -> None:
    """Test DjangoCertificateAuthorityModel."""
    if isinstance(ca.pub.loaded.signature_hash_algorithm, hashes.SHA1):
        pytest.xfail("SHA1 signature hash algorithm is not supported here.")
    if ca.name == "letsencrypt_x1":
        pytest.xfail(
            "letsencrypt_x1 defines NameConstraints as non-critical, but spec says it must be critical."
        )

    model = DjangoCertificateAuthorityModel.model_validate(ca)
    assert model.name == ca.name
    assert model.fingerprints == {
        "SHA-256": ca.get_fingerprint(hashes.SHA256()),
        "SHA-512": ca.get_fingerprint(hashes.SHA512()),
    }
    assert model.certificate.pem == ca.pub.pem


@pytest.mark.django_db
def test_django_certificate_authority_model_with_hash_algorithms(root: CertificateAuthority) -> None:
    """Test DjangoCertificateAuthorityModel."""
    model = DjangoCertificateAuthorityModel.model_validate(
        root, context={"hash_algorithms": (hashes.SHA3_256(), hashes.SHA3_512())}
    )
    assert model.fingerprints == {
        "SHA3/256": root.get_fingerprint(hashes.SHA3_256()),
        "SHA3/512": root.get_fingerprint(hashes.SHA3_512()),
    }


@pytest.mark.parametrize("value", ([], None, (None,)))
def test_invalid_hash_algorithms(root: CertificateAuthority, value: Any) -> None:
    """Test passing invalid hash algorithms as validation context."""
    with pytest.raises(ValidationError, match=r"hash_algorithms must be a tuple of hash algorithms\."):
        DjangoCertificateAuthorityModel.model_validate(root, context={"hash_algorithms": value})


@pytest.mark.django_db
def test_django_certificate_model(request: "SubRequest", usable_cert: Certificate) -> None:
    """Test CertificateModel."""
    # TYPEHINT NOTE: value was just set, so it's not yet a LazyCSRField
    csr = usable_cert.csr.public_bytes(Encoding.PEM).decode("ascii")  # type: ignore[attr-defined]

    model = assert_cryptography_model(
        DjangoCertificateModel,
        {
            "id": usable_cert.id,
            "created": usable_cert.created,
            "updated": usable_cert.updated,
            "revoked": usable_cert.revoked,
            "revoked_date": usable_cert.revoked_date,
            "revoked_reason": usable_cert.revoked_reason,
            "compromised": usable_cert.compromised,
            "certificate": usable_cert.pub.loaded,
            "fingerprints": {
                "SHA-256": usable_cert.get_fingerprint(hashes.SHA256()),
                "SHA-512": usable_cert.get_fingerprint(hashes.SHA512()),
            },
            "ca": usable_cert.ca_id,
            "csr": csr,
            "profile": usable_cert.profile,
            "autogenerated": usable_cert.autogenerated,
            "watchers": usable_cert.watchers.all(),
        },
        usable_cert,
        has_equality=False,
    )
    assert isinstance(model.csr, str), model.csr
    assert model.csr == csr


@pytest.mark.django_db
def test_django_management_model_with_no_csr(root_cert: Certificate) -> None:
    """Test loading a cert with no CSR."""
    root_cert.csr = None  # type: ignore[assignment]
    root_cert.save()
    model = DjangoCertificateModel.model_validate(root_cert)
    assert model.csr is None


@pytest.mark.django_db
def test_django_management_model_with_model_field(root_cert: Certificate) -> None:
    """Test loading a cert with a CSR field as loaded from the database.

    The fixture currently sets CSR to the cryptography value, but when loaded from the db, it's the lazy model
    field.
    """
    root_cert.refresh_from_db()
    model = DjangoCertificateModel.model_validate(root_cert)
    assert model.csr == root_cert.csr.pem

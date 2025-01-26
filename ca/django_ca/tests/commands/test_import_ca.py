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

"""Test the import_ca management command."""

import typing
from pathlib import Path
from typing import Any, Optional, cast
from unittest import mock

import pkcs11

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from django.conf import settings
from django.core.management import CommandError

import pytest

from django_ca.conf import model_settings
from django_ca.key_backends import key_backends
from django_ca.key_backends.db.models import DBUsePrivateKeyOptions
from django_ca.key_backends.hsm import HSMBackend
from django_ca.key_backends.hsm.keys import (
    PKCS11Ed448PrivateKey,
    PKCS11Ed25519PrivateKey,
    PKCS11EllipticCurvePrivateKey,
    PKCS11RSAPrivateKey,
)
from django_ca.key_backends.hsm.models import HSMUsePrivateKeyOptions
from django_ca.key_backends.storages import StoragesBackend
from django_ca.key_backends.storages.models import StoragesUsePrivateKeyOptions
from django_ca.models import Certificate, CertificateAuthority
from django_ca.tests.base.assertions import assert_command_error, assert_signature
from django_ca.tests.base.constants import CERT_DATA, TIMESTAMPS
from django_ca.tests.base.utils import (
    authority_information_access,
    certificate_policies,
    cmd,
    cmd_e2e,
    crl_distribution_points,
    distribution_point,
    issuer_alternative_name,
    uri,
)

pytestmark = [pytest.mark.usefixtures("tmpcadir"), pytest.mark.usefixtures("db")]


def import_ca(
    name: str, key_path: Optional[Path] = None, pem_path: Optional[Path] = None, **kwargs: Any
) -> CertificateAuthority:
    """Execute the import_ca command."""
    key_path = key_path or CERT_DATA["root"]["key_path"]
    pem_path = pem_path or CERT_DATA["root"]["pub_path"]
    out, err = cmd("import_ca", name, key_path, pem_path, **kwargs)
    assert out == ""
    assert err == ""
    return CertificateAuthority.objects.get(name=name)


def import_ca_e2e(hostname: str, *args: str) -> CertificateAuthority:
    """Shortcut for running the import_ca command."""
    key_path = str(CERT_DATA["root"]["key_path"])
    pem_path = str(CERT_DATA["root"]["pub_path"])

    out, err = cmd_e2e(["import_ca", hostname, *args, key_path, pem_path])
    assert out == ""
    assert err == ""

    return CertificateAuthority.objects.get(name=hostname)


@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])
def test_basic(usable_ca_name: str) -> None:
    """Test basic import command.

    Note: freeze time because we verify the certificate here.
    """
    cert_data = CERT_DATA[usable_ca_name]

    key_path = cert_data["key_path"]
    pem_path = cert_data["pub_path"]
    ca = import_ca(usable_ca_name, key_path, pem_path, import_password=cert_data.get("password"))
    ca.full_clean()  # assert e.g. max_length in serials

    if not cert_data.get("parent"):
        assert_signature([ca], ca)
    assert ca.pub.loaded.version == x509.Version.v3

    # test the private key
    # NOTE: password is always None since we don't encrypt the stored key with --password
    ca_key = ca.key_backend.get_key(  # type: ignore[attr-defined]  # we assume StoragesBackend
        ca, StoragesUsePrivateKeyOptions(password=None)
    )
    if cert_data["key_type"] == "EC":
        key = typing.cast(ec.EllipticCurvePrivateKey, ca_key)
        assert isinstance(key, ec.EllipticCurvePrivateKey)
    elif cert_data["key_type"] == "RSA":
        key = typing.cast(rsa.RSAPrivateKey, ca_key)  # type: ignore[assignment]
        assert isinstance(key, rsa.RSAPrivateKey)
    elif cert_data["key_type"] == "DSA":
        key = typing.cast(dsa.DSAPrivateKey, ca_key)  # type: ignore[assignment]
        assert isinstance(key, dsa.DSAPrivateKey)
    elif cert_data["key_type"] == "Ed25519":
        key = typing.cast(ed25519.Ed25519PrivateKey, ca_key)  # type: ignore[assignment]
        assert isinstance(key, ed25519.Ed25519PrivateKey)
    elif cert_data["key_type"] == "Ed448":
        key = typing.cast(ed448.Ed448PrivateKey, ca_key)  # type: ignore[assignment]
        assert isinstance(key, ed448.Ed448PrivateKey)
    else:  # just to be sure we cover everything
        raise ValueError(f"CA with unknown key type encountered: {cert_data['key_type']}")

    if cert_data["key_type"] not in ("EC", "Ed25519", "Ed448"):
        assert key.key_size == cert_data["key_size"]
    assert ca.serial == cert_data["serial"]

    assert ca.acme_enabled is False
    assert ca.acme_registration is True
    assert ca.acme_profile == model_settings.CA_DEFAULT_PROFILE
    assert ca.acme_requires_contact is True
    assert ca.api_enabled is False


@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])
def test_password(ca_name: str, key_backend: StoragesBackend) -> None:
    """Test importing a CA with a password for the private key.

    Note: freeze time because we verify the certificate here.
    """
    password = b"test_password"
    key_path = CERT_DATA["root"]["key_path"]
    pem_path = CERT_DATA["root"]["pub_path"]
    ca = import_ca(ca_name, key_path, pem_path, password=password)
    assert_signature([ca], ca)
    ca.full_clean()  # assert e.g. max_length in serials
    assert ca.pub.loaded.version == x509.Version.v3

    # test the private key
    with pytest.raises(TypeError, match="^Password was not given but private key is encrypted$"):
        key_backend.get_key(ca, StoragesUsePrivateKeyOptions(password=None))

    ca_key = key_backend.get_key(ca, StoragesUsePrivateKeyOptions(password=password))
    assert isinstance(ca_key, rsa.RSAPrivateKey)
    assert ca_key.key_size == CERT_DATA["root"]["key_size"]
    assert ca.serial == CERT_DATA["root"]["serial"]


def test_sign_options(ca_name: str) -> None:
    """Test setting the sign options."""
    ca_issuer = "http://issuer.example.com"
    ocsp_responder = "http://ocsp.example.com"
    crl1 = "http://crl1.example.com"
    crl2 = "http://crl2.example.com"
    ian = "http://ian.example.com"

    ca = import_ca_e2e(
        ca_name,
        f"--sign-ca-issuer={ca_issuer}",
        f"--sign-ocsp-responder={ocsp_responder}",
        f"--sign-issuer-alternative-name={ian}",
        f"--sign-crl-full-name={crl1}",
        f"--sign-crl-full-name={crl2}",
        # Certificate Policies extension
        "--sign-policy-identifier=1.2.3",
        "--sign-certification-practice-statement=https://cps.example.com",
        "--sign-user-notice=explicit-text",
    )

    assert ca.sign_authority_information_access == authority_information_access(
        ocsp=[uri(ocsp_responder)], ca_issuers=[uri(ca_issuer)]
    )
    assert ca.sign_issuer_alternative_name == issuer_alternative_name(uri(ian))
    assert ca.sign_crl_distribution_points == crl_distribution_points(
        distribution_point([uri(crl1), uri(crl2)])
    )
    # Certificate Policies extension
    assert ca.sign_certificate_policies == certificate_policies(
        x509.PolicyInformation(
            policy_identifier=x509.ObjectIdentifier("1.2.3"),
            policy_qualifiers=[
                "https://cps.example.com",
                x509.UserNotice(notice_reference=None, explicit_text="explicit-text"),
            ],
        )
    )


def test_acme_arguments(ca_name: str) -> None:
    """Test ACME arguments."""
    ca = import_ca_e2e(
        ca_name,
        "--acme-enable",
        "--acme-disable-account-registration",
        "--acme-contact-optional",
        "--acme-profile=client",
    )
    assert ca.acme_enabled
    assert ca.acme_profile == "client"
    assert ca.acme_requires_contact is False
    assert ca.acme_registration is False


def test_rest_api_arguments(ca_name: str) -> None:
    """Test REST API arguments."""
    ca = import_ca_e2e(ca_name, "--api-enable")
    assert ca.api_enabled


def test_ocsp_responder_arguments(ca_name: str) -> None:
    """Test OCSP responder arguments."""
    ca = import_ca_e2e(ca_name, "--ocsp-responder-key-validity=10", "--ocsp-response-validity=3600")
    assert ca.ocsp_responder_key_validity == 10
    assert ca.ocsp_response_validity == 3600


def test_key_backend_option(ca_name: str) -> None:
    """Test the --key-backend option."""
    key_path = CERT_DATA["root"]["key_path"]
    certificate_path = CERT_DATA["root"]["pub_path"]
    cmd_e2e(["import_ca", ca_name, str(key_path), str(certificate_path), "--key-backend=default"])

    ca = CertificateAuthority.objects.get(name=ca_name)
    assert ca.key_backend_alias == "default"


def test_secondary_key_backend(ca_name: str) -> None:
    """Use secondary key backend with a password."""
    key_path = CERT_DATA["root"]["key_path"]
    certificate_path = CERT_DATA["root"]["pub_path"]
    cmd_e2e(
        [
            "import_ca",
            ca_name,
            str(key_path),
            str(certificate_path),
            "--key-backend=secondary",
            "--secondary-password=foobar",
            "--secondary-path=secondary-ca-path",
        ]
    )

    ca: CertificateAuthority = CertificateAuthority.objects.get(name=ca_name)
    assert ca.key_backend_alias == "secondary"
    assert ca.key_backend_options["path"].startswith("secondary-ca-path")
    assert isinstance(ca.key_backend, StoragesBackend)
    assert ca.key_backend.get_key(ca, StoragesUsePrivateKeyOptions(password=b"foobar"))  # type: ignore[attr-defined]


@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])  # b/c of signature validation in the end.
@pytest.mark.usefixtures("softhsm_token")
@pytest.mark.parametrize("ca_name", ("root", "ec", "ed25519", "ed448"))
@pytest.mark.hsm
def test_hsm_store_key(ca_name: str, subject: x509.Name) -> None:
    """Test storing keys in the HSM."""
    key_backend = cast(HSMBackend, key_backends["hsm"])
    ca_data = CERT_DATA[ca_name]
    key_path = ca_data["key_path"]
    pem_path = ca_data["pub_path"]

    ca = import_ca(
        ca_name,
        key_path,
        pem_path,
        key_backend=key_backend,
        hsm_key_label=ca_name,
    )

    assert ca.pub.loaded == ca_data["pub"]["parsed"]
    key_backend_options = dict(ca.key_backend_options)  # copy so that we don't modify the original
    assert key_backend_options.pop("key_id")
    assert key_backend_options == {"key_label": ca_name, "key_type": ca_data["key_type"]}

    # Verify that public and private key can be accessed from the HSM.
    with key_backend.session(so_pin=None, user_pin=settings.PKCS11_USER_PIN) as session:
        private_key = key_backend._get_private_key(ca, session)  # pylint: disable=protected-access

        # Assert basic private key properties
        assert isinstance(
            private_key,
            (
                PKCS11RSAPrivateKey,
                PKCS11EllipticCurvePrivateKey,
                PKCS11Ed25519PrivateKey,
                PKCS11Ed448PrivateKey,
            ),
        )
        if isinstance(private_key, (PKCS11RSAPrivateKey, PKCS11EllipticCurvePrivateKey)):
            assert private_key.key_size == ca_data["pub"]["parsed"].public_key().key_size
        if isinstance(private_key, PKCS11EllipticCurvePrivateKey):
            assert private_key.curve == ca_data["pub"]["parsed"].public_key().curve

        # Test the underlying private key
        pkcs11_private_key = private_key.pkcs11_private_key
        assert isinstance(pkcs11_private_key, pkcs11.PrivateKey)

        # Make sure that the public key stored in the HSM is identical to what we fed into it.
        assert private_key.public_key() == ca_data["pub"]["parsed"].public_key()

        # Sign a certificate to make sure that the key is actually usable
        cert_data = CERT_DATA[f"{ca_name}-cert"]
        csr = cert_data["csr"]["parsed"]
        cert = Certificate.objects.create_cert(
            ca, HSMUsePrivateKeyOptions(user_pin=settings.PKCS11_USER_PIN), csr, subject=subject
        )
        assert_signature([ca], cert)


def test_hsm_store_key_with_dsa_keys() -> None:
    """Test storing DSA keys in the HSM, which is not supported at all."""
    cert_data = CERT_DATA["dsa"]
    key_path = cert_data["key_path"]
    pem_path = cert_data["pub_path"]

    with assert_command_error(r"^DSA: Not supported by the hsm key backend\.$"):
        import_ca("dsa", key_path, pem_path, key_backend=key_backends["hsm"], hsm_key_label="dsa")


@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])  # b/c of signature validation in the end.
def test_with_db_backend(usable_ca_name_by_type: str, subject: x509.Name) -> None:
    """Test storing ED448/Ed25519 keys in the HSM, which is not supported."""
    cert_data = CERT_DATA[usable_ca_name_by_type]
    key_path = cert_data["key_path"]
    pem_path = cert_data["pub_path"]

    import_ca(usable_ca_name_by_type, key_path, pem_path, key_backend=key_backends["db"])

    ca = CertificateAuthority.objects.get(name=usable_ca_name_by_type)
    assert ca.key_backend.is_usable(ca) is True
    assert ca.key_backend.check_usable(ca, DBUsePrivateKeyOptions()) is None

    # Sign a certificate to make sure that the key is actually usable
    cert_data = CERT_DATA[f"{usable_ca_name_by_type}-cert"]
    csr = cert_data["csr"]["parsed"]
    cert = Certificate.objects.create_cert(ca, DBUsePrivateKeyOptions(), csr, subject=subject)
    assert_signature([ca], cert)


def test_bogus_public_key(ca_name: str) -> None:
    """Test importing a CA with a bogus public key."""
    key_path = CERT_DATA["root"]["key_path"]
    with assert_command_error(r"^Unable to load public key\.$"):
        import_ca(ca_name, key_path, Path(__file__).resolve())


def test_bogus_private_key(ca_name: str) -> None:
    """Test importing a CA with a bogus private key."""
    pem_path = CERT_DATA["root"]["pub_path"]
    with assert_command_error(r"^Unable to load private key\.$"):
        import_ca(ca_name, Path(__file__).resolve(), pem_path)


def test_invalid_private_key_type(tmp_path: Path, ca_name: str, x448_private_key: X448PrivateKey) -> None:
    """Test importing a CA with an invalid private key type."""
    private_key_der = x448_private_key.private_bytes(
        Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()
    )
    private_key_path = tmp_path / "x448.key"
    with open(private_key_path, "wb") as stream:
        stream.write(private_key_der)

    pem_path = CERT_DATA["root"]["pub_path"]
    with assert_command_error(r"^X448PrivateKey: Invalid private key type\.$"):
        import_ca(ca_name, private_key_path, pem_path)


def test_model_validation_error(ca_name: str, key_backend: StoragesBackend) -> None:
    """Test model validation is tested properly.

    NOTE: This example is contrived for the default backend, as the type of the password would already be
    checked by argparse. Other backends however might have other validation mechanisms.
    """
    with assert_command_error(r"^password: Input should be a valid bytes$"):
        import_ca(ca_name, key_backend=key_backend, password=123)


def test_model_command_error(ca_name: str, key_backend: StoragesBackend) -> None:
    """Test model retrieval raising a CommandError."""
    msg = "some command error"
    with assert_command_error(rf"^{msg}$", returncode=3):
        with mock.patch.object(
            key_backend,
            "get_store_private_key_options",
            autospec=True,
            side_effect=CommandError(msg, returncode=3),
        ):
            import_ca(ca_name, key_backend=key_backend, password=123)


def test_import_generic_exception(ca_name: str, key_backend: StoragesBackend) -> None:
    """Test model retrieval raising arbitrary exception."""
    msg = "some command error"
    with assert_command_error(rf"^{msg}$"):
        with mock.patch.object(
            key_backend,
            "store_private_key",
            autospec=True,
            side_effect=ValueError(msg),
        ):
            import_ca(ca_name, key_backend=key_backend, password=None)


def test_model_generic_exception(ca_name: str, key_backend: StoragesBackend) -> None:
    """Test model retrieval raising arbitrary exception."""
    msg = "some command error"
    with assert_command_error(rf"^{msg}$"):
        with mock.patch.object(
            key_backend,
            "get_store_private_key_options",
            autospec=True,
            side_effect=ValueError(msg),
        ):
            import_ca(ca_name, key_backend=key_backend)

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

"""Test the CertificateAuthority model."""

# pylint: disable=redefined-outer-name  # requested pytest fixtures show up this way.

import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, NoReturn, Optional, Union, cast
from unittest import mock

from pydantic import BaseModel

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding, load_der_private_key
from cryptography.x509.oid import CertificatePoliciesOID, ExtensionOID

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.files.storage import storages
from django.db import connection

import pytest
from freezegun import freeze_time
from pytest_django.fixtures import SettingsWrapper

from django_ca.conf import model_settings
from django_ca.deprecation import RemovedInDjangoCA230Warning
from django_ca.key_backends.storages import StoragesUsePrivateKeyOptions
from django_ca.models import Certificate, CertificateAuthority
from django_ca.pydantic import CertificatePoliciesModel
from django_ca.tests.base.assertions import (
    assert_certificate,
    assert_crl,
    assert_removed_in_230,
    assert_sign_cert_signals,
)
from django_ca.tests.base.constants import CERT_DATA, TIMESTAMPS
from django_ca.tests.base.utils import (
    authority_information_access,
    basic_constraints,
    certificate_policies,
    crl_cache_key,
    crl_distribution_points,
    distribution_point,
    get_idp,
    issuer_alternative_name,
    uri,
)
from django_ca.tests.models.base import assert_bundle
from django_ca.typehints import PolicyQualifier

key_backend_options = StoragesUsePrivateKeyOptions(password=None)

CACHE_KEY_KWARGS = {
    "only_contains_ca_certs": False,
    "only_contains_user_certs": False,
    "only_contains_attribute_certs": False,
    "only_some_reasons": None,
}


@contextmanager
def generate_ocsp_key(
    ca: CertificateAuthority, key_backend_options: BaseModel, *args: Any, **kwargs: Any
) -> Iterator[tuple[CertificateIssuerPrivateKeyTypes, Certificate]]:
    """Context manager to  create an OCSP key and test some basic properties."""
    private_path, cert_path, cert = ca.generate_ocsp_key(  # type: ignore[misc]
        key_backend_options, *args, **kwargs
    )
    assert cert.autogenerated is True

    storage = storages[model_settings.CA_DEFAULT_STORAGE_ALIAS]
    with storage.open(private_path) as priv_key_stream:
        key = cast(
            CertificateIssuerPrivateKeyTypes, load_der_private_key(priv_key_stream.read(), password=None)
        )

    yield key, cert


def test_key_type(usable_cas: list[CertificateAuthority]) -> None:
    """Test the key type of CAs."""
    cas = {ca.name: ca for ca in usable_cas}
    assert cas["root"].key_type == "RSA"
    assert cas["dsa"].key_type == "DSA"
    assert cas["ec"].key_type == "EC"
    assert cas["ed25519"].key_type == "Ed25519"
    assert cas["ed448"].key_type == "Ed448"


def test_bundle_as_pem(root: CertificateAuthority, child: CertificateAuthority) -> None:
    """Test bundles of various CAs."""
    assert_bundle([root], root)
    assert_bundle([child, root], child)


def test_path_length(usable_ca: CertificateAuthority) -> None:
    """Test the path_length attribute."""
    assert usable_ca.path_length == CERT_DATA[usable_ca.name].get("path_length")


def test_root(root: CertificateAuthority, child: CertificateAuthority) -> None:
    """Test the root attribute."""
    assert root.root == root
    assert child.root == root


@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])
@pytest.mark.usefixtures("clear_cache")
@pytest.mark.usefixtures("child")  # to make sure that they don't show up when they're not revoked.
@pytest.mark.usefixtures("root_cert")  # to make sure that they don't show up when they're not revoked.
def test_get_crl(usable_root: CertificateAuthority) -> None:
    """Test getting the CRL for a CertificateAuthority."""
    with assert_removed_in_230(r"^get_crl\(\) is deprecated and will be removed in django-ca 2\.3\.$"):
        crl = usable_root.get_crl(key_backend_options)
    assert_crl(crl, signer=usable_root)


@pytest.mark.usefixtures("clear_cache")
@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])
def test_cache_crls(settings: SettingsWrapper, usable_ca: CertificateAuthority) -> None:
    """Test caching of CRLs."""
    ca_private_key_options = StoragesUsePrivateKeyOptions(password=CERT_DATA[usable_ca.name].get("password"))
    der_user_key = crl_cache_key(usable_ca.serial, only_contains_user_certs=True)
    pem_user_key = crl_cache_key(usable_ca.serial, Encoding.PEM, only_contains_user_certs=True)
    der_ca_key = crl_cache_key(usable_ca.serial, only_contains_ca_certs=True)
    pem_ca_key = crl_cache_key(usable_ca.serial, Encoding.PEM, only_contains_ca_certs=True)
    user_idp = get_idp(full_name=None, only_contains_user_certs=True)
    ca_idp = get_idp(full_name=None, only_contains_ca_certs=True)

    assert cache.get(der_ca_key) is None
    assert cache.get(pem_ca_key) is None
    assert cache.get(der_user_key) is None
    assert cache.get(pem_user_key) is None

    usable_ca.cache_crls(ca_private_key_options)

    der_user_crl = cache.get(der_user_key)
    pem_user_crl = cache.get(pem_user_key)
    assert_crl(
        der_user_crl,
        idp=user_idp,
        encoding=Encoding.DER,
        signer=usable_ca,
        algorithm=usable_ca.algorithm,
    )
    assert_crl(
        pem_user_crl,
        idp=user_idp,
        encoding=Encoding.PEM,
        signer=usable_ca,
        algorithm=usable_ca.algorithm,
    )

    der_ca_crl = cache.get(der_ca_key)
    pem_ca_crl = cache.get(pem_ca_key)
    assert_crl(
        der_ca_crl,
        idp=ca_idp,
        encoding=Encoding.DER,
        signer=usable_ca,
        algorithm=usable_ca.algorithm,
    )
    assert_crl(
        pem_ca_crl,
        idp=ca_idp,
        encoding=Encoding.PEM,
        signer=usable_ca,
        algorithm=usable_ca.algorithm,
    )

    # cache again - which will force triggering a new computation
    usable_ca.cache_crls(ca_private_key_options)

    # Get CRLs from cache - we have a new CRLNumber
    der_user_crl = cache.get(der_user_key)
    pem_user_crl = cache.get(pem_user_key)
    assert_crl(
        der_user_crl,
        idp=user_idp,
        crl_number=1,
        encoding=Encoding.DER,
        signer=usable_ca,
        algorithm=usable_ca.algorithm,
    )
    assert_crl(
        pem_user_crl,
        idp=user_idp,
        crl_number=1,
        encoding=Encoding.PEM,
        signer=usable_ca,
        algorithm=usable_ca.algorithm,
    )

    der_ca_crl = cache.get(der_ca_key)
    pem_ca_crl = cache.get(pem_ca_key)
    assert_crl(
        der_ca_crl,
        idp=ca_idp,
        crl_number=1,
        encoding=Encoding.DER,
        signer=usable_ca,
        algorithm=usable_ca.algorithm,
    )
    assert_crl(
        pem_ca_crl,
        idp=ca_idp,
        crl_number=1,
        encoding=Encoding.PEM,
        signer=usable_ca,
        algorithm=usable_ca.algorithm,
    )

    # clear caches and skip generation
    cache.clear()
    crl_profiles = {
        k: v.model_dump(exclude={"encodings", "scope"}) for k, v in model_settings.CA_CRL_PROFILES.items()
    }
    crl_profiles["ca"]["OVERRIDES"][usable_ca.serial] = {"skip": True}
    crl_profiles["user"]["OVERRIDES"][usable_ca.serial] = {"skip": True}

    settings.CA_CRL_PROFILES = crl_profiles
    usable_ca.cache_crls(ca_private_key_options)

    assert cache.get(der_ca_key) is None
    assert cache.get(pem_ca_key) is None
    assert cache.get(der_user_key) is None
    assert cache.get(pem_user_key) is None


@pytest.mark.usefixtures("clear_cache")
@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])
@pytest.mark.parametrize(
    "parameters",
    (
        {"only_contains_ca_certs": True},
        {"only_contains_user_certs": True},
        {"only_contains_attribute_certs": True},
        {"only_contains_user_certs": True, "only_some_reasons": frozenset([x509.ReasonFlags.key_compromise])},
    ),
)
def test_cache_crls_with_profiles(
    settings: SettingsWrapper, usable_root: CertificateAuthority, parameters: dict[str, Any]
) -> None:
    """Test cache_crls() with various CRL profiles."""
    settings.CA_CRL_PROFILES = {"test": parameters}
    usable_root.cache_crls(key_backend_options)

    der_key = crl_cache_key(usable_root.serial, **parameters)
    pem_key = crl_cache_key(usable_root.serial, Encoding.PEM, **parameters)

    der_crl = x509.load_der_x509_crl(cache.get(der_key))
    pem_crl = x509.load_pem_x509_crl(cache.get(pem_key))
    idp = get_idp(**parameters)

    assert_crl(der_crl, idp=idp, signer=usable_root)
    assert_crl(pem_crl, idp=idp, signer=usable_root)


@pytest.mark.usefixtures("clear_cache")
@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])
def test_cache_crls_with_overrides(settings: SettingsWrapper, usable_root: CertificateAuthority) -> None:
    """Test cache_crls() with overrides for CRL profiles."""
    ca_crl_profile = model_settings.CA_CRL_PROFILES["user"].model_dump(exclude={"encodings", "scope"})
    ca_crl_profile["OVERRIDES"] = {usable_root.serial: {"expires": timedelta(days=3)}}

    der_user_key = crl_cache_key(usable_root.serial, only_contains_user_certs=True)
    pem_user_key = crl_cache_key(usable_root.serial, Encoding.PEM, only_contains_user_certs=True)

    settings.CA_CRL_PROFILES = {"user": ca_crl_profile}
    usable_root.cache_crls(key_backend_options)

    der_user_crl = x509.load_der_x509_crl(cache.get(der_user_key))
    pem_user_crl = x509.load_pem_x509_crl(cache.get(pem_user_key))
    assert der_user_crl.next_update_utc == TIMESTAMPS["everything_valid"] + timedelta(days=3)
    assert pem_user_crl.next_update_utc == TIMESTAMPS["everything_valid"] + timedelta(days=3)


def test_max_path_length(root: CertificateAuthority, child: CertificateAuthority) -> None:
    """Test getting the maximum path_length."""
    assert root.max_path_length == CERT_DATA[root.name].get("max_path_length")
    assert child.max_path_length == CERT_DATA[child.name].get("max_path_length")


def test_allows_intermediate(root: CertificateAuthority, child: CertificateAuthority) -> None:
    """Test checking if this CA allows intermediate CAs."""
    assert root.allows_intermediate_ca is True
    assert child.allows_intermediate_ca is False


def test_generate_ocsp_key(usable_ca: CertificateAuthority) -> None:
    """Test generate_ocsp_key()."""
    private_key_options = StoragesUsePrivateKeyOptions(password=CERT_DATA[usable_ca.name].get("password"))
    with generate_ocsp_key(usable_ca, private_key_options) as (key, cert):
        ca_key = usable_ca.key_backend.get_key(  # type: ignore[attr-defined]  # we assume StoragesBackend
            usable_ca, private_key_options
        )
        assert isinstance(key, type(ca_key))


def test_generate_ocsp_responder_certificate_for_ec_ca(
    settings: SettingsWrapper, usable_ec: CertificateAuthority
) -> None:
    """Test generate_ocsp_key() with elliptic curve based certificate authority."""
    settings.CA_DEFAULT_ELLIPTIC_CURVE = "secp192r1"
    # EC key for an EC based CA should inherit the key
    with generate_ocsp_key(usable_ec, key_backend_options, key_type="EC") as (key, cert):
        key = cast(ec.EllipticCurvePrivateKey, key)
        assert isinstance(key, ec.EllipticCurvePrivateKey)

        # Since the CA is EC-based, they curve is inherited from the CA (not from the default setting).
        assert isinstance(key.curve, ec.SECP256R1)


def test_generate_ocsp_responder_certificate_for_rsa_ca(
    settings: SettingsWrapper, usable_root: CertificateAuthority
) -> None:
    """Test generating an EC-based OCSP responder certificate with an RSA-based certificate authority."""
    settings.CA_DEFAULT_ELLIPTIC_CURVE = "secp192r1"
    with generate_ocsp_key(usable_root, key_backend_options, key_type="EC") as (key, cert):
        key = cast(ec.EllipticCurvePrivateKey, key)
        assert isinstance(key, ec.EllipticCurvePrivateKey)

        # Since the CA is not EC-based, it uses the default elliptic curve.
        assert isinstance(key.curve, type(model_settings.CA_DEFAULT_ELLIPTIC_CURVE))


def test_generate_ocsp_responder_certificate_for_rsa_ca_with_custom_curve(
    settings: SettingsWrapper, usable_root: CertificateAuthority
) -> None:
    """Test generating EC-based OCSP responder certificates with a custom elliptic curve."""
    settings.CA_DEFAULT_ELLIPTIC_CURVE = "secp192r1"
    curve = ec.BrainpoolP256R1
    with generate_ocsp_key(usable_root, key_backend_options, key_type="EC", elliptic_curve=curve()) as (
        key,
        cert,
    ):
        key = cast(ec.EllipticCurvePrivateKey, key)
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert isinstance(key.curve, curve)


def test_regenerate_ocsp_responder_certificate(usable_root: CertificateAuthority) -> None:
    """Test regenerating an OCSP responder certificate that is due to expire soon."""
    with freeze_time(TIMESTAMPS["everything_valid"]) as frozen_time:
        # TYPEHINT NOTE: We know that the certificate was not yet generated here
        ocsp_responder_key_data = usable_root.generate_ocsp_key(key_backend_options)
        assert ocsp_responder_key_data is not None
        _, _, ocsp_responder_certificate = ocsp_responder_key_data

        # OCSP key is not immediately regenerated
        assert usable_root.generate_ocsp_key(key_backend_options) is None
        assert usable_root.ocsp_responder_certificate == ocsp_responder_certificate.pub.loaded

        frozen_time.tick(delta=timedelta(days=2))
        updated_ocsp_responder_key_data = usable_root.generate_ocsp_key(key_backend_options)
        assert updated_ocsp_responder_key_data is not None
        _, _, updated_ocsp_responder_certificate = updated_ocsp_responder_key_data
        assert updated_ocsp_responder_certificate.not_after > ocsp_responder_certificate.not_after


def test_force_regenerate_ocsp_responder_certificate(usable_root: CertificateAuthority) -> None:
    """Test forcing recreation of OCSP responder certificates."""
    with generate_ocsp_key(usable_root, key_backend_options) as (key, cert):
        key = cast(rsa.RSAPrivateKey, key)
        assert isinstance(key, rsa.RSAPrivateKey)

    # force regenerating the OCSP key:
    with generate_ocsp_key(usable_root, key_backend_options, force=True) as (key_renewed, cert_renewed):
        assert cert_renewed.serial != cert.serial


def test_regenerate_ocsp_key_with_deprecated_expires(usable_root: CertificateAuthority) -> None:
    """Test calling generate_ocsp_key() with deprecated expires parameter."""
    not_after = datetime.now(tz=timezone.utc) + model_settings.CA_DEFAULT_EXPIRES + timedelta(days=3)
    warning = (
        r"^Argument `expires` is deprecated and will be removed in django-ca 2.3, use `not_after` instead\.$"
    )
    with pytest.warns(RemovedInDjangoCA230Warning, match=warning):
        _, _, certificate = usable_root.generate_ocsp_key(  # type: ignore[misc]
            key_backend_options, expires=not_after
        )
    assert certificate.not_after == not_after.replace(second=0, microsecond=0)


def test_regenerate_ocsp_key_with_not_after_and_expires(root: CertificateAuthority) -> None:
    """Test calling generate_ocsp_key() with both not_after and (deprecated) expires, which is an error."""
    not_after = datetime.now(tz=timezone.utc) + model_settings.CA_DEFAULT_EXPIRES + timedelta(days=3)
    warning = (
        r"^Argument `expires` is deprecated and will be removed in django-ca 2.3, use `not_after` instead\.$"
    )
    with (
        pytest.warns(RemovedInDjangoCA230Warning, match=warning),
        pytest.raises(ValueError, match=r"^`not_before` and `expires` cannot both be set\.$"),
    ):
        root.generate_ocsp_key(key_backend_options, not_after=not_after, expires=not_after)


def test_empty_extensions_for_certificate(root: CertificateAuthority) -> None:
    """Test extensions_for_certificate property when no values are set."""
    root.sign_certificate_policies = None
    root.sign_issuer_alternative_name = None
    root.sign_crl_distribution_points = None
    root.sign_authority_information_access = None
    root.save()
    assert root.extensions_for_certificate == {}


def test_extensions_for_certificate(root: CertificateAuthority) -> None:
    """Test extensions_for_certificate property."""
    root.sign_authority_information_access = authority_information_access(
        ca_issuers=[uri("http://issuer.example.com")], ocsp=[uri("http://ocsp.example.com")]
    )
    root.sign_certificate_policies = certificate_policies(
        x509.PolicyInformation(policy_identifier=CertificatePoliciesOID.ANY_POLICY, policy_qualifiers=None)
    )
    root.sign_crl_distribution_points = crl_distribution_points(
        distribution_point([uri("http://crl.example.com")])
    )
    root.sign_issuer_alternative_name = issuer_alternative_name(uri("http://ian.example.com"))
    root.save()

    assert root.extensions_for_certificate == {
        ExtensionOID.AUTHORITY_INFORMATION_ACCESS: root.sign_authority_information_access,
        ExtensionOID.CERTIFICATE_POLICIES: root.sign_certificate_policies,
        ExtensionOID.CRL_DISTRIBUTION_POINTS: root.sign_crl_distribution_points,
        ExtensionOID.ISSUER_ALTERNATIVE_NAME: root.sign_issuer_alternative_name,
    }


def test_serial(usable_ca: CertificateAuthority) -> None:
    """Test getting the serial."""
    assert usable_ca.serial == CERT_DATA[usable_ca.name].get("serial")


@pytest.mark.parametrize(("name", "algorithm"), (("sha256", hashes.SHA256()), ("sha512", hashes.SHA512())))
def test_get_fingerprint(name: str, algorithm: hashes.HashAlgorithm, usable_ca: CertificateAuthority) -> None:
    """Test getting the fingerprint value."""
    assert usable_ca.get_fingerprint(algorithm) == CERT_DATA[usable_ca.name][name]


def test_get_authority_key_identifier_extension(ca: CertificateAuthority) -> None:
    """Test getting the authority key id extension for CAs."""
    ext = ca.get_authority_key_identifier_extension()
    assert ext.value.key_identifier == CERT_DATA[ca.name]["subject_key_identifier"].value.key_identifier


def test_get_authority_key_identifier(usable_ca: CertificateAuthority) -> None:
    """Test getting the authority key identifier."""
    key_identifier = usable_ca.get_authority_key_identifier().key_identifier
    assert key_identifier == CERT_DATA[usable_ca.name]["subject_key_identifier"].value.key_identifier


def test_get_authority_key_identifier_with_no_extension(child: CertificateAuthority) -> None:
    """Test getting the authority key identifier when a CA does not have the extension."""

    # NOTE: all have this, so we have to mock this.
    def side_effect(cls: Any) -> NoReturn:
        raise x509.ExtensionNotFound("mocked", x509.SubjectKeyIdentifier.oid)

    with mock.patch(
        "cryptography.x509.extensions.Extensions.get_extension_for_class", side_effect=side_effect
    ):
        key_identifier = child.get_authority_key_identifier().key_identifier
        assert key_identifier == CERT_DATA["child"]["subject_key_identifier"].value.key_identifier


@pytest.mark.parametrize("full_clean", (True, False))
def test_sign_certificate_policies(
    root: CertificateAuthority,
    certificate_policies: x509.Extension[x509.CertificatePolicies],
    full_clean: bool,
) -> None:
    """Test setting ``sign_certificate_policies`` the field and saving, parametrized by full_clean()."""
    assert root.sign_certificate_policies is None
    root.sign_certificate_policies = certificate_policies
    assert root.sign_certificate_policies == certificate_policies

    if full_clean is True:
        root.full_clean()
        assert root.sign_certificate_policies == certificate_policies

    root.save()
    assert CertificateAuthority.objects.get(pk=root.pk).sign_certificate_policies == certificate_policies


@pytest.mark.parametrize("full_clean", (True, False))
def test_sign_certificate_policies_with_model(
    root: CertificateAuthority,
    certificate_policies: x509.Extension[x509.CertificatePolicies],
    full_clean: bool,
) -> None:
    """Test setting ``sign_certificate_policies`` the field and saving, parametrized by full_clean()."""
    assert root.sign_certificate_policies is None
    model = CertificatePoliciesModel.model_validate(certificate_policies)
    root.sign_certificate_policies = model
    assert root.sign_certificate_policies == model  # just setting does nothing

    if full_clean is True:
        root.full_clean()
        assert root.sign_certificate_policies == certificate_policies

    root.save()
    assert CertificateAuthority.objects.get(pk=root.pk).sign_certificate_policies == certificate_policies


@pytest.mark.parametrize("full_clean", (True, False))
def test_sign_certificate_policies_with_serialized_model(
    root: CertificateAuthority,
    certificate_policies: x509.Extension[x509.CertificatePolicies],
    full_clean: bool,
) -> None:
    """Test setting ``sign_certificate_policies`` the field and saving, parametrized by full_clean()."""
    assert root.sign_certificate_policies is None
    model = CertificatePoliciesModel.model_validate(certificate_policies)
    root.sign_certificate_policies = model.model_dump(mode="json")

    if full_clean is True:
        root.full_clean()
        assert root.sign_certificate_policies == certificate_policies

    root.save()
    assert CertificateAuthority.objects.get(pk=root.pk).sign_certificate_policies == certificate_policies


def _old_serialize_policy_qualifier(qualifier: PolicyQualifier) -> Union[str, dict[str, Any]]:
    """Duplicate of old CertificatePolicies serialization."""
    if isinstance(qualifier, str):
        return qualifier

    value: dict[str, Any] = {}
    if qualifier.explicit_text:
        value["explicit_text"] = qualifier.explicit_text

    if qualifier.notice_reference is not None:
        value["notice_reference"] = {
            "notice_numbers": qualifier.notice_reference.notice_numbers,
        }
        if qualifier.notice_reference.organization is not None:
            value["notice_reference"]["organization"] = qualifier.notice_reference.organization
    return value


def _old_serialize_policy_information(
    policy_information: x509.PolicyInformation,
) -> dict[str, Any]:
    """Duplicate of old CertificatePolicies serialization."""
    policy_qualifiers: Optional[list[Union[str, dict[str, Any]]]] = None
    if policy_information.policy_qualifiers is not None:
        policy_qualifiers = [_old_serialize_policy_qualifier(q) for q in policy_information.policy_qualifiers]

    serialized = {
        "policy_identifier": policy_information.policy_identifier.dotted_string,
        "policy_qualifiers": policy_qualifiers,
    }
    return serialized


def _old_certificate_policies_serialization(
    extension: x509.Extension[x509.CertificatePolicies],
) -> dict[str, Any]:
    """Duplicate of old CertificatePolicies serialization."""
    value = [_old_serialize_policy_information(pi) for pi in extension.value]
    return {"critical": extension.critical, "value": value}


@pytest.mark.parametrize("full_clean", (True, False))
def test_sign_certificate_policies_with_old_serialized_data(
    root: CertificateAuthority,
    certificate_policies: x509.Extension[x509.CertificatePolicies],
    full_clean: bool,
) -> None:
    """Test setting ``sign_certificate_policies`` the field and saving, parametrized by full_clean()."""
    assert root.sign_certificate_policies is None
    root.sign_certificate_policies = _old_certificate_policies_serialization(  # type: ignore[assignment]
        certificate_policies
    )

    if full_clean is True:
        root.full_clean()
        assert root.sign_certificate_policies == certificate_policies

    root.save()
    assert CertificateAuthority.objects.get(pk=root.pk).sign_certificate_policies == certificate_policies


def test_sign_certificate_policies_with_loading_old_serialized_data(
    root: CertificateAuthority, certificate_policies: x509.Extension[x509.CertificatePolicies]
) -> None:
    """Test loading old serialized data from the database."""
    serialized_data = _old_certificate_policies_serialization(certificate_policies)
    with connection.cursor() as cursor:
        cursor.execute(
            "UPDATE django_ca_certificateauthority SET sign_certificate_policies = %s WHERE id = %s",
            [json.dumps(serialized_data), root.id],
        )
    assert CertificateAuthority.objects.get(pk=root.pk).sign_certificate_policies == certificate_policies


def test_sign_certificate_policies_with_invalid_types(root: CertificateAuthority) -> None:
    """Test sign_certificate_policies with invalid types."""
    root.sign_certificate_policies = True  # type: ignore[assignment]  # what we're testing
    with pytest.raises(ValidationError, match=r"True: Not a cryptography\.x509\.Extension class\."):
        root.save()

    extension = x509.Extension(critical=True, oid=ExtensionOID.OCSP_NO_CHECK, value=x509.OCSPNoCheck())
    root.sign_certificate_policies = extension  # type: ignore[assignment]
    with pytest.raises(ValidationError, match=r"Expected an instance of CertificatePolicies\."):
        root.save()


def test_sign_certificate_policies_with_invalid_pydantic_data(root: CertificateAuthority) -> None:
    """Test sign_certificate_policies with invalid data that looks like Pydantic data."""
    root.sign_certificate_policies = {  # type: ignore[assignment]
        "type": "certificate_policies",
        "critical": "wrong-type",
    }
    with pytest.raises(ValidationError, match=r"The value cannot be parsed to an extension\."):
        root.save()


def test_sign_certificate_policies_with_invalid_serialized_data(root: CertificateAuthority) -> None:
    """Test sign_certificate_policies with invalid old serialized data."""
    root.sign_certificate_policies = True  # type: ignore[assignment]
    with pytest.raises(ValidationError, match=r"The value cannot be parsed to an extension\."):
        root.full_clean()

    root.sign_certificate_policies = {"critical": "not-a-bool"}  # type: ignore[assignment]
    with pytest.raises(ValidationError, match=r"The value cannot be parsed to an extension\."):
        root.full_clean()

    root.sign_certificate_policies = {"critical": True, "value": "not-a-list"}  # type: ignore[assignment]
    with pytest.raises(ValidationError, match=r"The value cannot be parsed to an extension\."):
        root.full_clean()

    root.sign_certificate_policies = {"critical": True, "value": [{"foo": "bar"}]}  # type: ignore[assignment]
    with pytest.raises(ValidationError, match=r"The value cannot be parsed to an extension\."):
        root.full_clean()


@freeze_time(TIMESTAMPS["everything_valid"])
def test_sign(subject: x509.Name, usable_root: CertificateAuthority) -> None:
    """Test the simplest invocation of the function."""
    now = datetime.now(tz=timezone.utc)
    csr = CERT_DATA["child-cert"]["csr"]["parsed"]
    with assert_sign_cert_signals():
        cert = usable_root.sign(key_backend_options, csr, subject=subject)

    assert_certificate(cert, subject, hashes.SHA256, signer=usable_root)
    assert cert.not_valid_after_utc == now + model_settings.CA_DEFAULT_EXPIRES


@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])
def test_sign_with_non_default_values(subject: x509.Name, usable_root: CertificateAuthority) -> None:
    """Pass non-default parameters."""
    csr = CERT_DATA["child-cert"]["csr"]["parsed"]
    algorithm = hashes.SHA256()
    not_after = datetime.now(tz=timezone.utc) + model_settings.CA_DEFAULT_EXPIRES + timedelta(days=3)
    with assert_sign_cert_signals():
        cert = usable_root.sign(
            key_backend_options, csr, subject=subject, algorithm=algorithm, not_after=not_after
        )

    assert_certificate(cert, subject, hashes.SHA256, signer=usable_root)
    assert cert.not_valid_after_utc == not_after


@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])
def test_sign_with_deprecated_expires(subject: x509.Name, usable_root: CertificateAuthority) -> None:
    """Pass non-default parameters."""
    csr = CERT_DATA["child-cert"]["csr"]["parsed"]
    algorithm = hashes.SHA256()
    not_after = datetime.now(tz=timezone.utc) + model_settings.CA_DEFAULT_EXPIRES + timedelta(days=3)
    warning = (
        r"^Argument `expires` is deprecated and will be removed in django-ca 2.3, use `not_after` instead\.$"
    )
    with pytest.warns(RemovedInDjangoCA230Warning, match=warning):
        cert = usable_root.sign(
            key_backend_options, csr, subject=subject, algorithm=algorithm, expires=not_after
        )
    assert cert.not_valid_after_utc == not_after


def test_sign_with_not_after_and_expires(root: CertificateAuthority, subject: x509.Name) -> None:
    """Test error when passing extensions that may not be passed to this function."""
    not_after = datetime.now(tz=timezone.utc) + model_settings.CA_DEFAULT_EXPIRES + timedelta(days=3)
    csr = CERT_DATA["child-cert"]["csr"]["parsed"]
    warning = (
        r"^Argument `expires` is deprecated and will be removed in django-ca 2.3, use `not_after` instead\.$"
    )
    with (
        pytest.warns(RemovedInDjangoCA230Warning, match=warning),
        pytest.raises(ValueError, match=r"^`not_before` and `expires` cannot both be set\.$"),
    ):
        root.sign(key_backend_options, csr, subject=subject, not_after=not_after, expires=not_after)


@pytest.mark.parametrize(
    "extension",
    (
        basic_constraints(ca=True),
        x509.Extension(
            oid=ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
            critical=True,
            value=x509.AuthorityKeyIdentifier(
                key_identifier=b"1", authority_cert_issuer=None, authority_cert_serial_number=None
            ),
        ),
        x509.Extension(
            oid=ExtensionOID.SUBJECT_KEY_IDENTIFIER,
            critical=True,
            value=x509.SubjectKeyIdentifier(digest=b"1"),
        ),
        x509.Extension(oid=ExtensionOID.INHIBIT_ANY_POLICY, critical=True, value=x509.InhibitAnyPolicy(1)),
    ),
)
def test_sign_with_invalid_extensions(
    root: CertificateAuthority, subject: x509.Name, extension: x509.Extension[x509.ExtensionType]
) -> None:
    """Test error when passing extensions that may not be passed to this function."""
    csr = CERT_DATA["child-cert"]["csr"]["parsed"]
    msg = rf"{extension.oid.dotted_string}.* Extension must not be provided by the end user\."
    with pytest.raises(ValueError, match=msg):
        root.sign(
            key_backend_options,
            csr,
            subject=subject,
            extensions=[extension],  # type: ignore[list-item]  # what we're testing
        )

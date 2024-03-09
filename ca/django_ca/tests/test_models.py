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

"""Test Django model classes."""

# pylint: disable=redefined-outer-name  # requested pytest fixtures show up this way.

import json
import re
import typing
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone as tz
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple, Type, Union
from unittest import mock

import josepy as jose
from acme import challenges, messages
from pydantic import BaseModel

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding, load_der_private_key
from cryptography.x509.oid import CertificatePoliciesOID, ExtensionOID, NameOID

from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db import connection, transaction
from django.db.utils import IntegrityError
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

import pytest
from freezegun import freeze_time

from django_ca import ca_settings
from django_ca.backends.storages import LoadPrivateKeyOptions
from django_ca.constants import ReasonFlags
from django_ca.deprecation import not_valid_after, not_valid_before
from django_ca.modelfields import LazyCertificate, LazyCertificateSigningRequest
from django_ca.models import (
    AcmeAccount,
    AcmeAuthorization,
    AcmeCertificate,
    AcmeChallenge,
    AcmeOrder,
    Certificate,
    CertificateAuthority,
    Watcher,
    X509CertMixin,
)
from django_ca.pydantic.extensions import CertificatePoliciesModel
from django_ca.tests.base.constants import CERT_DATA, CERT_PEM_REGEX, TIMESTAMPS
from django_ca.tests.base.mixins import AcmeValuesMixin, TestCaseMixin, TestCaseProtocol
from django_ca.tests.base.utils import (
    authority_information_access,
    basic_constraints,
    certificate_policies,
    crl_distribution_points,
    distribution_point,
    get_idp,
    idp_full_name,
    issuer_alternative_name,
    override_tmpcadir,
    subject_key_identifier,
    uri,
)
from django_ca.typehints import PolicyQualifier
from django_ca.utils import get_crl_cache_key, get_storage

ChallengeTypeVar = typing.TypeVar("ChallengeTypeVar", bound=challenges.KeyAuthorizationChallenge)
key_backend_options = LoadPrivateKeyOptions(password=None)


class TestWatcher(TestCase):
    """Test :py:class:`django_ca.models.Watcher`."""

    def test_from_addr(self) -> None:
        """Basic test for the ``from_addr()`` function."""
        mail = "user@example.com"
        name = "Firstname Lastname"

        watcher = Watcher.from_addr(f"{name} <{mail}>")
        self.assertEqual(watcher.mail, mail)
        self.assertEqual(watcher.name, name)

    def test_spaces(self) -> None:
        """Test that ``from_addr() is agnostic to spaces."""
        mail = "user@example.com"
        name = "Firstname Lastname"

        watcher = Watcher.from_addr(f"{name}     <{mail}>")
        self.assertEqual(watcher.mail, mail)
        self.assertEqual(watcher.name, name)

        watcher = Watcher.from_addr(f"{name}<{mail}>")
        self.assertEqual(watcher.mail, mail)
        self.assertEqual(watcher.name, name)

    def test_error(self) -> None:
        """Test some validation errors."""
        with self.assertRaises(ValidationError):
            Watcher.from_addr("foobar ")
        with self.assertRaises(ValidationError):
            Watcher.from_addr("foobar @")

    def test_update(self) -> None:
        """Test that from_addr updates the name if passed."""
        mail = "user@example.com"
        name = "Firstname Lastname"
        newname = "Newfirst Newlast"

        Watcher.from_addr(f"{name} <{mail}>")
        watcher = Watcher.from_addr(f"{newname} <{mail}>")
        self.assertEqual(watcher.mail, mail)
        self.assertEqual(watcher.name, newname)

    def test_str(self) -> None:
        """Test the str function."""
        mail = "user@example.com"
        name = "Firstname Lastname"

        watcher = Watcher(mail=mail)
        self.assertEqual(str(watcher), mail)

        watcher.name = name
        self.assertEqual(str(watcher), f"{name} <{mail}>")


class X509CertMixinTestCaseMixin(TestCaseProtocol):
    """Mixin collecting assertion methods for CertificateAuthority and Certificate."""

    def assertBundle(  # pylint: disable=invalid-name
        self, chain: List[X509CertMixin], cert: X509CertMixin
    ) -> None:
        """Assert that a bundle contains the expected certificates."""
        encoded_chain = [c.pub.pem.encode() for c in chain]

        # Make sure that all PEMs end with a newline. RFC 7468 does not mandate a newline at the end, but it
        # seems in practice we always get one. We want to detect if that ever changes
        for member in encoded_chain:
            self.assertTrue(member.endswith(b"\n"))

        bundle = cert.bundle_as_pem
        self.assertIsInstance(bundle, str)
        self.assertTrue(bundle.endswith("\n"))

        # Test the regex used by certbot to make sure certbot finds the expected certificates
        found = CERT_PEM_REGEX.findall(bundle.encode())
        self.assertEqual(encoded_chain, found)


# pylint: disable-next=too-many-public-methods
class CertificateAuthorityTests(TestCaseMixin, X509CertMixinTestCaseMixin, TestCase):
    """Test :py:class:`django_ca.models.CertificateAuthority`."""

    load_cas = "__all__"
    load_certs = ("root-cert", "child-cert")

    @contextmanager
    def generate_ocsp_key(
        self, ca: CertificateAuthority, key_backend_options: BaseModel, *args: Any, **kwargs: Any
    ) -> Iterator[Tuple[CertificateIssuerPrivateKeyTypes, Certificate]]:
        """Context manager to  create an OCSP key and test some basic properties."""
        private_path, cert_path, cert = ca.generate_ocsp_key(  # type: ignore[misc]
            key_backend_options, *args, **kwargs
        )
        assert cert.autogenerated is True

        storage = get_storage()
        with storage.open(private_path) as priv_key_stream:
            key = typing.cast(
                CertificateIssuerPrivateKeyTypes, load_der_private_key(priv_key_stream.read(), password=None)
            )

        yield key, cert

    def test_key_type(self) -> None:
        """Test the key type of CAs."""
        self.assertEqual(self.cas["root"].key_type, "RSA")
        self.assertEqual(self.cas["dsa"].key_type, "DSA")
        self.assertEqual(self.cas["ec"].key_type, "EC")
        self.assertEqual(self.cas["ed25519"].key_type, "Ed25519")
        self.assertEqual(self.cas["ed448"].key_type, "Ed448")

    @override_tmpcadir()
    def test_bundle_as_pem(self) -> None:
        """Test bundles of various CAs."""
        self.assertBundle([self.cas["root"]], self.cas["root"])
        self.assertBundle([self.cas["child"], self.cas["root"]], self.cas["child"])
        self.assertBundle([self.cas["ec"]], self.cas["ec"])
        self.assertBundle([self.cas["ed448"]], self.cas["ed448"])
        self.assertBundle([self.cas["ed25519"]], self.cas["ed25519"])

    def test_path_length(self) -> None:
        """Test the path_length attribute."""
        for name, ca in self.cas.items():
            self.assertEqual(ca.path_length, CERT_DATA[name].get("path_length"))

    def test_root(self) -> None:
        """Test the root attribute."""
        self.assertEqual(self.cas["root"].root, self.cas["root"])
        self.assertEqual(self.cas["child"].root, self.cas["root"])

    @freeze_time(TIMESTAMPS["everything_valid"])
    @override_tmpcadir()
    def test_full_crl(self) -> None:
        """Test getting the CRL for a CertificateAuthority."""
        ca = self.cas["root"]
        child = self.cas["child"]
        cert = self.certs["root-cert"]
        full_name = "http://localhost/crl"
        idp = get_idp(full_name=[uri(full_name)])

        crl = ca.get_crl(key_backend_options, full_name=[uri(full_name)]).public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=idp, signer=ca, algorithm=ca.algorithm)

        ca.sign_crl_distribution_points = crl_distribution_points(distribution_point([uri(full_name)]))
        ca.save()
        crl = ca.get_crl(key_backend_options).public_bytes(Encoding.PEM)
        self.assertCRL(crl, crl_number=1, signer=ca, algorithm=ca.algorithm)

        # revoke a cert
        cert.revoke()
        crl = ca.get_crl(key_backend_options).public_bytes(Encoding.PEM)
        self.assertCRL(crl, expected=[cert], crl_number=2, signer=ca, algorithm=ca.algorithm)

        # also revoke a CA
        child.revoke()
        crl = ca.get_crl(key_backend_options).public_bytes(Encoding.PEM)
        self.assertCRL(crl, expected=[cert, child], crl_number=3, signer=ca, algorithm=ca.algorithm)

        # unrevoke cert (so we have all three combinations)
        cert.revoked = False
        cert.revoked_date = None
        cert.revoked_reason = ""
        cert.save()

        crl = ca.get_crl(key_backend_options).public_bytes(Encoding.PEM)
        self.assertCRL(crl, expected=[child], crl_number=4, signer=ca, algorithm=ca.algorithm)

    @freeze_time(TIMESTAMPS["everything_valid"])
    @override_tmpcadir()
    def test_intermediate_crl(self) -> None:
        """Test getting the CRL of an intermediate CA."""
        child = self.cas["child"]
        cert = self.certs["child-cert"]
        full_name = "http://localhost/crl"
        idp = get_idp(full_name=[uri(full_name)])

        crl = child.get_crl(key_backend_options, full_name=[uri(full_name)]).public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=idp, signer=child, algorithm=child.algorithm)

        # Revoke a cert
        cert.revoke()
        crl = child.get_crl(key_backend_options, full_name=[uri(full_name)]).public_bytes(Encoding.PEM)
        self.assertCRL(crl, expected=[cert], idp=idp, crl_number=1, signer=child, algorithm=child.algorithm)

    @override_settings(USE_TZ=False)
    def test_full_crl_without_timezone_support(self) -> None:
        """Test full CRL but with timezone support disabled."""
        # otherwise we get TZ warnings for preloaded objects
        ca = self.cas["root"]
        child = self.cas["child"]
        cert = self.certs["root-cert"]

        ca.refresh_from_db()
        child.refresh_from_db()
        cert.refresh_from_db()

        self.test_full_crl()

    @override_tmpcadir()
    @freeze_time(TIMESTAMPS["everything_valid"])
    def test_ca_crl(self) -> None:
        """Test getting a CA CRL."""
        ca = self.cas["root"]
        idp = get_idp(only_contains_ca_certs=True)  # root CAs don't have a full name (GitHub issue #64)

        crl = ca.get_crl(key_backend_options, scope="ca").public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=idp, signer=ca, algorithm=ca.algorithm)

        # revoke ca and cert, CRL only contains CA
        child_ca = self.cas["child"]
        child_ca.revoke()
        self.cas["ec"].revoke()
        self.certs["root-cert"].revoke()
        self.certs["child-cert"].revoke()
        crl = ca.get_crl(key_backend_options, scope="ca").public_bytes(Encoding.PEM)
        self.assertCRL(crl, expected=[child_ca], idp=idp, crl_number=1, signer=ca, algorithm=ca.algorithm)

    @override_tmpcadir()
    @freeze_time(TIMESTAMPS["everything_valid"])
    def test_intermediate_ca_crl(self) -> None:
        """Test getting the CRL for an intermediate CA."""
        # Intermediate CAs have a DP in the CRL that has the CA url
        full_name = [uri(f"http://{ca_settings.CA_DEFAULT_HOSTNAME}/django_ca/crl/ca/{self.ca.serial}/")]
        idp = get_idp(full_name=full_name, only_contains_ca_certs=True)

        crl = self.ca.get_crl(key_backend_options, scope="ca").public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=idp, signer=self.ca, algorithm=self.ca.algorithm)

    @freeze_time(TIMESTAMPS["everything_valid"])
    @override_tmpcadir()
    def test_user_crl(self) -> None:
        """Test getting a user CRL."""
        ca = self.cas["root"]
        idp = get_idp(full_name=idp_full_name(ca), only_contains_user_certs=True)

        crl = ca.get_crl(key_backend_options, scope="user").public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=idp, signer=ca, algorithm=ca.algorithm)

        # revoke ca and cert, CRL only contains cert
        cert = self.certs["root-cert"]
        cert.revoke()
        self.certs["child-cert"].revoke()
        self.cas["child"].revoke()
        crl = ca.get_crl(key_backend_options, scope="user").public_bytes(Encoding.PEM)
        self.assertCRL(crl, expected=[cert], idp=idp, crl_number=1, signer=ca, algorithm=ca.algorithm)

    @freeze_time(TIMESTAMPS["everything_valid"])
    @override_tmpcadir()
    def test_attr_crl(self) -> None:
        """Test getting an Attribute CRL (always an empty list)."""
        ca = self.cas["root"]
        idp = get_idp(only_contains_attribute_certs=True)

        crl = ca.get_crl(key_backend_options, scope="attribute").public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=idp, signer=ca, algorithm=ca.algorithm)

        # revoke ca and cert, CRL is empty (we don't know attribute certs)
        self.certs["root-cert"].revoke()
        self.certs["child-cert"].revoke()
        self.cas["child"].revoke()
        crl = ca.get_crl(key_backend_options, scope="attribute").public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=idp, crl_number=1, signer=ca, algorithm=ca.algorithm)

    @override_tmpcadir()
    @freeze_time(TIMESTAMPS["everything_valid"])
    def test_no_idp(self) -> None:
        """Test a CRL with no IDP."""
        # CRLs require a full name (or only_some_reasons) if it's a full CRL
        self.ca.sign_crl_distribution_points = None
        self.ca.save()
        crl = self.ca.get_crl(key_backend_options).public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=None, algorithm=self.ca.algorithm)

    @override_tmpcadir()
    @freeze_time(TIMESTAMPS["everything_valid"])
    def test_counter(self) -> None:
        """Test the counter for CRLs."""
        idp = get_idp(full_name=idp_full_name(self.ca))
        crl = self.ca.get_crl(key_backend_options, counter="test").public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=idp, crl_number=0, algorithm=self.ca.algorithm)
        crl = self.ca.get_crl(key_backend_options, counter="test").public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=idp, crl_number=1, algorithm=self.ca.algorithm)

        crl = self.ca.get_crl(key_backend_options).public_bytes(Encoding.PEM)  # test with no counter
        self.assertCRL(crl, idp=idp, crl_number=0, algorithm=self.ca.algorithm)

    @override_tmpcadir()
    @freeze_time(TIMESTAMPS["everything_valid"])
    def test_no_auth_key_identifier(self) -> None:
        """Test getting the CRL from a CA with no AuthorityKeyIdentifier."""

        # All CAs have an authority key identifier, so we mock that this exception is not present
        def side_effect(cls: Any) -> typing.NoReturn:
            raise x509.ExtensionNotFound("mocked", x509.SubjectKeyIdentifier.oid)

        full_name = "http://localhost/crl"
        idp = get_idp(full_name=[uri(full_name)])

        with mock.patch(
            "cryptography.x509.extensions.Extensions.get_extension_for_oid", side_effect=side_effect
        ):
            crl = self.ca.get_crl(key_backend_options, full_name=[uri(full_name)]).public_bytes(Encoding.PEM)
        # Note that we still get an AKI because the value comes from the public key in this case
        self.assertCRL(crl, idp=idp, signer=self.ca, algorithm=self.ca.algorithm)

    @freeze_time(TIMESTAMPS["everything_valid"])
    def test_get_crl_with_wrong_algorithm(self) -> None:
        """Test that we validate the algorithm if passed by the user."""
        # DSA/RSA/EC keys cannot trigger this condition, as the algorithm would default to the one used by
        # the certificate authority itself.

        with self.assertRaisesRegex(ValueError, r"^Ed25519 keys do not allow an algorithm for signing\.$"):
            self.cas["ed25519"].get_crl(key_backend_options, algorithm=hashes.SHA256())
        with self.assertRaisesRegex(ValueError, r"^Ed448 keys do not allow an algorithm for signing\.$"):
            self.cas["ed448"].get_crl(key_backend_options, algorithm=hashes.SHA256())

    def test_validate_json(self) -> None:
        """Test the json validator."""
        # Validation works if we're not revoked
        self.ca.full_clean()

        self.ca.crl_number = "{"
        # Note: we do not use self.assertValidationError, b/c the JSON message might be system dependent
        with self.assertRaises(ValidationError) as exc_cm:
            self.ca.full_clean()
        self.assertTrue(re.match("Must be valid JSON: ", exc_cm.exception.message_dict["crl_number"][0]))

    def test_crl_invalid_scope(self) -> None:
        """Try getting a CRL with an invalid scope."""
        with self.assertRaisesRegex(ValueError, r'^scope must be either None, "ca", "user" or "attribute"$'):
            self.ca.get_crl(key_backend_options, scope="foobar").public_bytes(Encoding.PEM)  # type: ignore[arg-type]

    @override_tmpcadir()
    @freeze_time(TIMESTAMPS["everything_valid"])
    def test_cache_crls(self) -> None:
        """Test caching of CRLs."""
        crl_profiles = self.crl_profiles
        for config in crl_profiles.values():
            config["encodings"] = [
                "DER",
                "PEM",
            ]

        for name, ca in self.usable_cas:
            ca_private_key_options = LoadPrivateKeyOptions(password=CERT_DATA[name].get("password"))
            der_user_key = get_crl_cache_key(ca.serial, Encoding.DER, "user")
            pem_user_key = get_crl_cache_key(ca.serial, Encoding.PEM, "user")
            der_ca_key = get_crl_cache_key(ca.serial, Encoding.DER, "ca")
            pem_ca_key = get_crl_cache_key(ca.serial, Encoding.PEM, "ca")
            user_idp = get_idp(full_name=idp_full_name(ca), only_contains_user_certs=True)
            if ca.parent is None:
                ca_idp = get_idp(full_name=None, only_contains_ca_certs=True)
            else:
                crl_path = reverse("django_ca:ca-crl", kwargs={"serial": ca.serial})
                full_name = [uri(f"http://{ca_settings.CA_DEFAULT_HOSTNAME}{crl_path}")]
                ca_idp = get_idp(full_name=full_name, only_contains_ca_certs=True)

            self.assertIsNone(cache.get(der_ca_key))
            self.assertIsNone(cache.get(pem_ca_key))
            self.assertIsNone(cache.get(der_user_key))
            self.assertIsNone(cache.get(pem_user_key))

            with self.settings(CA_CRL_PROFILES=crl_profiles):
                ca.cache_crls(ca_private_key_options)

            der_user_crl = cache.get(der_user_key)
            pem_user_crl = cache.get(pem_user_key)
            self.assertCRL(
                der_user_crl,
                idp=user_idp,
                crl_number=0,
                encoding=Encoding.DER,
                signer=ca,
                algorithm=ca.algorithm,
            )
            self.assertCRL(
                pem_user_crl,
                idp=user_idp,
                crl_number=0,
                encoding=Encoding.PEM,
                signer=ca,
                algorithm=ca.algorithm,
            )

            der_ca_crl = cache.get(der_ca_key)
            pem_ca_crl = cache.get(pem_ca_key)
            self.assertCRL(
                der_ca_crl,
                idp=ca_idp,
                crl_number=0,
                encoding=Encoding.DER,
                signer=ca,
                algorithm=ca.algorithm,
            )
            self.assertCRL(
                pem_ca_crl, idp=ca_idp, crl_number=0, encoding=Encoding.PEM, signer=ca, algorithm=ca.algorithm
            )

            # cache again - which will force triggering a new computation
            with self.settings(CA_CRL_PROFILES=crl_profiles):
                ca.cache_crls(ca_private_key_options)

            # Get CRLs from cache - we have a new CRLNumber
            der_user_crl = cache.get(der_user_key)
            pem_user_crl = cache.get(pem_user_key)
            self.assertCRL(
                der_user_crl,
                idp=user_idp,
                crl_number=1,
                encoding=Encoding.DER,
                signer=ca,
                algorithm=ca.algorithm,
            )
            self.assertCRL(
                pem_user_crl,
                idp=user_idp,
                crl_number=1,
                encoding=Encoding.PEM,
                signer=ca,
                algorithm=ca.algorithm,
            )

            der_ca_crl = cache.get(der_ca_key)
            pem_ca_crl = cache.get(pem_ca_key)
            self.assertCRL(
                der_ca_crl,
                idp=ca_idp,
                crl_number=1,
                encoding=Encoding.DER,
                signer=ca,
                algorithm=ca.algorithm,
            )
            self.assertCRL(
                pem_ca_crl,
                idp=ca_idp,
                crl_number=1,
                encoding=Encoding.PEM,
                signer=ca,
                algorithm=ca.algorithm,
            )

            # clear caches and skip generation
            cache.clear()
            crl_profiles["ca"]["OVERRIDES"][ca.serial]["skip"] = True
            crl_profiles["user"]["OVERRIDES"][ca.serial]["skip"] = True

            # set a wrong password, ensuring that any CRL generation would *never* work
            crl_profiles["ca"]["OVERRIDES"][ca.serial]["password"] = b"wrong"
            crl_profiles["user"]["OVERRIDES"][ca.serial]["password"] = b"wrong"

            with self.settings(CA_CRL_PROFILES=crl_profiles):
                ca.cache_crls(ca_private_key_options)

            self.assertIsNone(cache.get(der_ca_key))
            self.assertIsNone(cache.get(pem_ca_key))
            self.assertIsNone(cache.get(der_user_key))
            self.assertIsNone(cache.get(pem_user_key))

    @override_tmpcadir()
    def test_cache_crls_algorithm(self) -> None:
        """Test passing an explicit hash algorithm."""
        crl_profiles = self.crl_profiles
        for config in crl_profiles.values():
            config["encodings"] = ["DER", "PEM"]

        ca = self.cas["root"]
        der_user_key = get_crl_cache_key(ca.serial, Encoding.DER, "user")
        pem_user_key = get_crl_cache_key(ca.serial, Encoding.PEM, "user")
        der_ca_key = get_crl_cache_key(ca.serial, Encoding.DER, "ca")
        pem_ca_key = get_crl_cache_key(ca.serial, Encoding.PEM, "ca")

        self.assertIsNone(cache.get(der_ca_key))
        self.assertIsNone(cache.get(pem_ca_key))
        self.assertIsNone(cache.get(der_user_key))
        self.assertIsNone(cache.get(pem_user_key))

        with self.settings(CA_CRL_PROFILES=crl_profiles):
            ca.cache_crls(key_backend_options)

        der_user_crl = cache.get(der_user_key)
        pem_user_crl = cache.get(pem_user_key)
        self.assertIsInstance(der_user_crl, bytes)
        self.assertIsInstance(pem_user_crl, bytes)

    def test_max_path_length(self) -> None:
        """Test getting the maximum path_length."""
        for name, ca in self.usable_cas:
            self.assertEqual(ca.max_path_length, CERT_DATA[name].get("max_path_length"), name)

    def test_allows_intermediate(self) -> None:
        """Test checking if this CA allows intermediate CAs."""
        self.assertTrue(self.cas["root"].allows_intermediate_ca)
        self.assertTrue(self.cas["ec"].allows_intermediate_ca)
        self.assertFalse(self.cas["child"].allows_intermediate_ca)

    @override_tmpcadir()
    def test_generate_ocsp_key(self) -> None:
        """Test generate_ocsp_key()."""
        for name, ca in self.usable_cas:
            private_key_options = LoadPrivateKeyOptions(password=CERT_DATA[name].get("password"))
            with self.generate_ocsp_key(ca, private_key_options) as (key, cert):
                print(name, ca, private_key_options)
                ca_key = ca.key_backend.get_key(ca, private_key_options)
                assert isinstance(key, type(ca_key))

    @override_tmpcadir(CA_DEFAULT_ELLIPTIC_CURVE="secp192r1")
    def test_generate_ocsp_responder_certificate_for_ec_ca(self) -> None:
        """Test generate_ocsp_key() with elliptic curve based certificate authority."""
        # EC key for an EC based CA should inherit the key
        with self.generate_ocsp_key(self.cas["ec"], key_backend_options, key_type="EC") as (key, cert):
            key = typing.cast(ec.EllipticCurvePrivateKey, key)
            assert isinstance(key, ec.EllipticCurvePrivateKey)

            # Since the CA is EC-based, they curve is inherited from the CA (not from the default setting).
            assert isinstance(key.curve, ec.SECP256R1)

    @override_tmpcadir(CA_DEFAULT_ELLIPTIC_CURVE="secp192r1")
    def test_generate_ocsp_responder_certificate_for_rsa_ca(self) -> None:
        """Test generating an EC-based OCSP responder certificate with an RSA-based certificate authority."""
        with self.generate_ocsp_key(self.cas["root"], key_backend_options, key_type="EC") as (key, cert):
            key = typing.cast(ec.EllipticCurvePrivateKey, key)
            self.assertIsInstance(key, ec.EllipticCurvePrivateKey)

            # Since the CA is not EC-based, it uses the default elliptic curve.
            self.assertIsInstance(key.curve, ca_settings.CA_DEFAULT_ELLIPTIC_CURVE)

    @override_tmpcadir(CA_DEFAULT_ELLIPTIC_CURVE="secp192r1")
    def test_generate_ocsp_responder_certificate_for_rsa_ca_with_custom_curve(self) -> None:
        """Test generating EC-based OCSP responder certificates with a custom elliptic curve."""
        curve = ec.BrainpoolP256R1
        with self.generate_ocsp_key(
            self.cas["root"], key_backend_options, key_type="EC", elliptic_curve=curve()
        ) as (key, cert):
            key = typing.cast(ec.EllipticCurvePrivateKey, key)
            self.assertIsInstance(key, ec.EllipticCurvePrivateKey)
            self.assertIsInstance(key.curve, curve)

    @override_tmpcadir()
    def test_regenerate_ocsp_responder_certificate(self) -> None:
        """Test regenerating an OCSP responder certificate that is due to expire soon."""
        with freeze_time(TIMESTAMPS["everything_valid"]) as frozen_time:
            # TYPEHINT NOTE: We know that the certificate was not yet generated here
            _, _, ocsp_responder_certificate = self.ca.generate_ocsp_key(  # type: ignore[misc]
                key_backend_options
            )

            # OCSP key is not immediately regenerated
            assert self.ca.generate_ocsp_key(key_backend_options) is None
            assert self.ca.ocsp_responder_certificate == ocsp_responder_certificate.pub.loaded

            frozen_time.tick(delta=timedelta(days=2))
            _, _, updated_ocsp_responder_certificate = self.ca.generate_ocsp_key(  # type: ignore[misc]
                key_backend_options
            )
            assert updated_ocsp_responder_certificate.expires > ocsp_responder_certificate.expires

    @override_tmpcadir()
    def test_force_regenerate_ocsp_responder_certificate(self) -> None:
        """Test forcing recreation of OCSP responder certificates."""
        with self.generate_ocsp_key(self.ca, key_backend_options) as (key, cert):
            key = typing.cast(rsa.RSAPrivateKey, key)
            self.assertIsInstance(key, rsa.RSAPrivateKey)

        # force regenerating the OCSP key:
        with self.generate_ocsp_key(self.ca, key_backend_options, force=True) as (key_renewed, cert_renewed):
            self.assertNotEqual(cert_renewed.serial, cert.serial)


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


def _old_serialize_policy_qualifier(qualifier: PolicyQualifier) -> Union[str, Dict[str, Any]]:
    """Duplicate of old CertificatePolicies serialization."""
    if isinstance(qualifier, str):
        return qualifier

    value: Dict[str, Any] = {}
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
) -> Dict[str, Any]:
    """Duplicate of old CertificatePolicies serialization."""
    policy_qualifiers: Optional[List[Union[str, Dict[str, Any]]]] = None
    if policy_information.policy_qualifiers is not None:
        policy_qualifiers = [_old_serialize_policy_qualifier(q) for q in policy_information.policy_qualifiers]

    serialized = {
        "policy_identifier": policy_information.policy_identifier.dotted_string,
        "policy_qualifiers": policy_qualifiers,
    }
    return serialized


def _old_certificate_policies_serialization(
    extension: x509.Extension[x509.CertificatePolicies],
) -> Dict[str, Any]:
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


class CertificateAuthoritySignTests(TestCaseMixin, X509CertMixinTestCaseMixin, TestCase):
    """Test signing a certificiate."""

    load_cas = ("root", "child")
    csr = CERT_DATA["child-cert"]["csr"]["parsed"]

    def assertBasicCert(self, cert: x509.Certificate) -> None:  # pylint: disable=invalid-name
        """Basic assertions about the certificate."""
        now = datetime.now(tz=tz.utc)
        self.assertEqual(cert.issuer, self.ca.subject)
        self.assertEqual(not_valid_before(cert), now)
        self.assertEqual(cert.version, x509.Version.v3)
        self.assertIsInstance(cert.public_key(), rsa.RSAPublicKey)

    def assertExtensionDict(  # pylint: disable=invalid-name
        self, cert: x509.Certificate, expected: Iterable[x509.Extension[x509.ExtensionType]]
    ) -> None:
        """Test that the certificate has the expected extensions."""
        actual = {ext.oid: ext for ext in cert.extensions}
        expected_dict = {ext.oid: ext for ext in expected}
        self.assertEqual(actual, expected_dict)

    @override_tmpcadir()
    @freeze_time(TIMESTAMPS["everything_valid"])
    def test_simple(self) -> None:
        """Test the simplest invocation of the function."""
        now = datetime.now(tz=tz.utc)
        cn = "example.com"
        csr = CERT_DATA["child-cert"]["csr"]["parsed"]
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        with self.assertSignCertSignals():
            cert = self.ca.sign(key_backend_options, csr, subject=subject)

        self.assertBasicCert(cert)
        self.assertEqual(not_valid_after(cert), now + ca_settings.CA_DEFAULT_EXPIRES)
        self.assertEqual(cert.subject, subject)
        self.assertIsInstance(cert.signature_hash_algorithm, type(self.ca.algorithm))
        self.assertExtensionDict(
            cert,
            [
                subject_key_identifier(cert),
                basic_constraints(),
                self.ca.get_authority_key_identifier_extension(),
            ],
        )

    @override_tmpcadir()
    @freeze_time(TIMESTAMPS["everything_valid"])
    def test_non_default_values(self) -> None:
        """Pass non-default parameters."""
        cn = "example.com"
        csr = CERT_DATA["child-cert"]["csr"]["parsed"]
        algorithm = hashes.SHA256()
        expires = datetime.now(tz=tz.utc) + ca_settings.CA_DEFAULT_EXPIRES + timedelta(days=3)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        with self.assertSignCertSignals():
            cert = self.ca.sign(
                key_backend_options, csr, subject=subject, algorithm=algorithm, expires=expires
            )

        self.assertBasicCert(cert)
        self.assertEqual(not_valid_after(cert), expires)
        self.assertIsInstance(cert.signature_hash_algorithm, hashes.SHA256)

    @override_tmpcadir()
    @freeze_time(TIMESTAMPS["everything_valid"])
    def test_non_default_extensions(self) -> None:
        """Pass non-default extensions."""
        cn = "example.com"
        csr = CERT_DATA["child-cert"]["csr"]["parsed"]
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        aki = x509.Extension(
            oid=ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
            critical=True,
            value=x509.AuthorityKeyIdentifier(
                key_identifier=b"1", authority_cert_issuer=None, authority_cert_serial_number=None
            ),
        )
        ski = x509.Extension(
            oid=ExtensionOID.SUBJECT_KEY_IDENTIFIER,
            critical=True,
            value=x509.SubjectKeyIdentifier(digest=b"1"),
        )

        with self.assertSignCertSignals():
            cert = self.ca.sign(
                key_backend_options,
                csr,
                subject=subject,
                extensions=[basic_constraints(critical=False), ski, aki],
            )

        self.assertBasicCert(cert)
        self.assertExtensionDict(cert, [ski, basic_constraints(critical=False), aki])

    def test_create_ca(self) -> None:
        """Try passing a BasicConstraints extension that allows creating a CA."""
        csr = CERT_DATA["child-cert"]["csr"]["parsed"]
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
        msg = r"^This function cannot be used to create a Certificate Authority\.$"
        with self.assertSignCertSignals(pre=False, post=False), self.assertRaisesRegex(ValueError, msg):
            self.ca.sign(key_backend_options, csr, subject=subject, extensions=[basic_constraints(ca=True)])


class CertificateTests(TestCaseMixin, X509CertMixinTestCaseMixin, TestCase):
    """Test :py:class:`django_ca.models.Certificate`."""

    load_cas = "__all__"
    load_certs = "__all__"

    @override_tmpcadir()
    def test_bundle_as_pem(self) -> None:
        """Test bundles of various CAs."""
        self.assertBundle([self.certs["root-cert"], self.cas["root"]], self.certs["root-cert"])
        self.assertBundle(
            [self.certs["child-cert"], self.cas["child"], self.cas["root"]], self.certs["child-cert"]
        )
        self.assertBundle([self.certs["ec-cert"], self.cas["ec"]], self.certs["ec-cert"])
        self.assertBundle([self.certs["ed448-cert"], self.cas["ed448"]], self.certs["ed448-cert"])
        self.assertBundle([self.certs["ed25519-cert"], self.cas["ed25519"]], self.certs["ed25519-cert"])

    def test_dates(self) -> None:
        """Test valid_from/valid_until dates."""
        for name, ca in self.cas.items():
            self.assertEqual(ca.valid_from, CERT_DATA[name]["valid_from"])
            self.assertEqual(ca.expires, CERT_DATA[name]["valid_until"])

        for name, cert in self.certs.items():
            self.assertEqual(cert.valid_from, CERT_DATA[name]["valid_from"])
            self.assertEqual(cert.expires, CERT_DATA[name]["valid_until"])

    def test_revocation(self) -> None:
        """Test getting a revociation for a non-revoked certificate."""
        # Never really happens in real life, but should still be checked
        cert = Certificate(revoked=False)

        with self.assertRaises(ValueError):
            cert.get_revocation()

    def test_root(self) -> None:
        """Test the root property."""
        self.assertEqual(self.certs["root-cert"].root, self.cas["root"])
        self.assertEqual(self.certs["child-cert"].root, self.cas["root"])

    @override_tmpcadir()
    def test_serial(self) -> None:
        """Test getting the serial."""
        for name, ca in self.cas.items():
            self.assertEqual(ca.serial, CERT_DATA[name].get("serial"))

        for name, cert in self.certs.items():
            self.assertEqual(cert.serial, CERT_DATA[name].get("serial"))

    @freeze_time("2019-02-03 15:43:12")
    def test_get_revocation_time(self) -> None:
        """Test getting the revocation time."""
        self.assertIsNone(self.cert.get_revocation_time())
        self.cert.revoke()

        # timestamp does not have a timezone regardless of USE_TZ
        self.cert.revoked_date = timezone.now()
        self.assertEqual(self.cert.get_revocation_time(), datetime(2019, 2, 3, 15, 43, 12))

        self.cert.revoked_date = timezone.now()
        self.assertEqual(self.cert.get_revocation_time(), datetime(2019, 2, 3, 15, 43, 12))

        with self.settings(USE_TZ=False):
            self.cert.refresh_from_db()
            self.assertEqual(self.cert.get_revocation_time(), datetime(2019, 2, 3, 15, 43, 12))

    @freeze_time("2019-02-03 15:43:12")
    def test_get_compromised_time(self) -> None:
        """Test getting the time when the certificate was compromised."""
        self.assertIsNone(self.cert.get_compromised_time())
        self.cert.revoke(compromised=timezone.now())

        # timestamp does not have a timezone regardless of USE_TZ
        self.cert.compromised = timezone.now()
        self.assertEqual(self.cert.get_compromised_time(), datetime(2019, 2, 3, 15, 43, 12))

        with override_settings(USE_TZ=False):
            self.cert.compromised = timezone.now()
            self.assertEqual(self.cert.get_compromised_time(), datetime(2019, 2, 3, 15, 43, 12))

    def test_get_revocation_reason(self) -> None:
        """Test getting the revocation reason."""
        self.assertIsNone(self.cert.get_revocation_reason())

        for reason in ReasonFlags:
            self.cert.revoke(reason)
            got = self.cert.get_revocation_reason()
            self.assertIsInstance(got, x509.ReasonFlags)
            self.assertEqual(got.name, reason.name)  # type: ignore[union-attr] # see check above

    def test_validate_past(self) -> None:
        """Test that model validation blocks revoked_date or revoked_invalidity in the future."""
        now = timezone.now()
        future = now + timedelta(10)
        past = now - timedelta(10)

        # Validation works if we're not revoked
        self.cert.full_clean()

        # Validation works if date is in the past
        self.cert.revoked_date = past
        self.cert.compromised = past
        self.cert.full_clean()

        self.cert.revoked_date = future
        self.cert.compromised = future
        with self.assertValidationError(
            {
                "compromised": ["Date must be in the past!"],
                "revoked_date": ["Date must be in the past!"],
            }
        ):
            self.cert.full_clean()

    def test_get_fingerprint(self) -> None:
        """Test getting the fingerprint value."""
        algorithms = {
            "sha256": hashes.SHA256(),
            "sha512": hashes.SHA512(),
        }
        for name, ca in self.cas.items():
            for algo_name, algorithm in algorithms.items():
                self.assertEqual(ca.get_fingerprint(algorithm), CERT_DATA[name][algo_name])

        for name, cert in self.certs.items():
            for algo_name, algorithm in algorithms.items():
                self.assertEqual(cert.get_fingerprint(algorithm), CERT_DATA[name][algo_name])

    def test_jwk(self) -> None:
        """Test JWK property."""
        for name, ca in self.cas.items():
            # josepy does not support loading DSA/Ed448/Ed25519 keys:
            #   https://github.com/certbot/josepy/pull/98
            if CERT_DATA[name]["key_type"] in ("DSA", "Ed448", "Ed25519"):
                continue

            if CERT_DATA[name]["key_type"] == "EC":
                self.assertIsInstance(ca.jwk, jose.jwk.JWKEC, name)
            else:
                self.assertIsInstance(ca.jwk, jose.jwk.JWKRSA, name)

        for name, cert in self.certs.items():
            # josepy does not support loading DSA/Ed448/Ed25519 keys:
            #   https://github.com/certbot/josepy/pull/98
            if CERT_DATA[name]["key_type"] in ("DSA", "Ed448", "Ed25519"):
                continue

            if CERT_DATA[name]["key_type"] == "EC":
                self.assertIsInstance(cert.jwk, jose.jwk.JWKEC, name)
            else:
                self.assertIsInstance(cert.jwk, jose.jwk.JWKRSA, name)

    def test_jwk_with_unsupported_algorithm(self) -> None:
        """Test the ValueError raised if called with an unsupported algorithm."""
        with self.assertRaisesRegex(ValueError, "Unsupported algorithm"):
            self.certs["ed448-cert"].jwk  # noqa: B018
        with self.assertRaisesRegex(ValueError, "Unsupported algorithm"):
            self.certs["ed25519-cert"].jwk  # noqa: B018
        with self.assertRaisesRegex(ValueError, "Unsupported algorithm"):
            self.certs["dsa-cert"].jwk  # noqa: B018

    def test_get_authority_key_identifier(self) -> None:
        """Test getting the authority key identifier."""
        for name, ca in self.cas.items():
            self.assertEqual(
                ca.get_authority_key_identifier().key_identifier,
                CERT_DATA[name]["subject_key_identifier"].value.key_identifier,
            )

        # All CAs have a subject key identifier, so we mock that this exception is not present
        def side_effect(cls: Any) -> typing.NoReturn:
            raise x509.ExtensionNotFound("mocked", x509.SubjectKeyIdentifier.oid)

        ca = self.cas["child"]
        with mock.patch(
            "cryptography.x509.extensions.Extensions.get_extension_for_class", side_effect=side_effect
        ):
            self.assertEqual(
                ca.get_authority_key_identifier().key_identifier,
                CERT_DATA["child"]["subject_key_identifier"].value.key_identifier,
            )

    def test_get_authority_key_identifier_extension(self) -> None:
        """Test getting the authority key id extension for CAs."""
        for name, ca in self.cas.items():
            ext = ca.get_authority_key_identifier_extension()
            self.assertEqual(
                ext.value.key_identifier, CERT_DATA[name]["subject_key_identifier"].value.key_identifier
            )

    def test_inconsistent_model_states(self) -> None:
        """Test exceptions raised for an inconsistent model state."""
        self.cert.revoked = True
        self.cert.save()

        with self.assertRaisesRegex(ValueError, r"^Certificate has no revocation date$"):
            self.cert.get_revocation()

        with self.assertLogs("django_ca.models", level="WARNING") as logcm:
            self.assertIsNone(self.cert.get_revocation_time())
            self.assertEqual(
                logcm.output,
                ["WARNING:django_ca.models:Inconsistent model state: revoked=True and revoked_date=None."],
            )


class ModelfieldsTests(TestCaseMixin, TestCase):
    """Specialized tests for model fields."""

    csr = CERT_DATA["root-cert"]["csr"]
    pub = CERT_DATA["root-cert"]["pub"]
    load_cas = ("root",)

    def test_create_pem_bytes(self) -> None:
        """Test creating with bytes-encoded PEM."""
        pub = self.pub["pem"].encode()
        csr = self.csr["parsed"].public_bytes(Encoding.PEM)
        cert = Certificate.objects.create(
            pub=pub,
            csr=csr,
            ca=self.ca,
            expires=timezone.now(),
            valid_from=timezone.now(),
        )
        self.assertEqual(cert.pub, pub)
        self.assertEqual(cert.csr, csr)

        # Refresh, so that we get lazy values
        cert.refresh_from_db()

        self.assertEqual(cert.pub.loaded, self.pub["parsed"])
        self.assertEqual(cert.csr.loaded, self.csr["parsed"])

    def test_create_bytearray(self) -> None:
        """Test creating with bytes-encoded PEM."""
        pub = bytearray(self.pub["der"])
        csr = bytearray(self.csr["parsed"].public_bytes(Encoding.DER))
        cert = Certificate.objects.create(
            pub=pub,
            csr=csr,
            ca=self.ca,
            expires=timezone.now(),
            valid_from=timezone.now(),
        )
        self.assertEqual(cert.pub, pub)
        self.assertEqual(cert.csr, csr)

        # Refresh, so that we get lazy values
        cert.refresh_from_db()

        self.assertEqual(cert.pub.loaded, self.pub["parsed"])
        self.assertEqual(cert.csr.loaded, self.csr["parsed"])

    def test_create_memoryview(self) -> None:
        """Test creating with bytes-encoded PEM."""
        pub = memoryview(self.pub["der"])
        csr = memoryview(self.csr["parsed"].public_bytes(Encoding.DER))
        cert = Certificate.objects.create(
            pub=pub,
            csr=csr,
            ca=self.ca,
            expires=timezone.now(),
            valid_from=timezone.now(),
        )
        self.assertEqual(cert.pub, pub)
        self.assertEqual(cert.csr, csr)

        # Refresh, so that we get lazy values
        cert.refresh_from_db()

        self.assertEqual(cert.pub.loaded, self.pub["parsed"])
        self.assertEqual(cert.csr.loaded, self.csr["parsed"])

    def test_create_from_instance(self) -> None:
        """Test creating a certificate from LazyField instances."""
        loaded = self.load_named_cert("root-cert")
        self.assertIsInstance(loaded.pub, LazyCertificate)
        self.assertIsInstance(loaded.csr, LazyCertificateSigningRequest)
        cert = Certificate.objects.create(
            pub=loaded.pub,
            csr=loaded.csr,
            ca=self.ca,
            expires=timezone.now(),
            valid_from=timezone.now(),
        )
        self.assertEqual(loaded.pub, cert.pub)
        self.assertEqual(loaded.csr, cert.csr)

        reloaded = Certificate.objects.get(pk=cert.pk)
        self.assertEqual(loaded.pub, reloaded.pub)
        self.assertEqual(loaded.csr, reloaded.csr)

    def test_repr(self) -> None:
        """Test ``repr()`` for custom modelfields."""
        cert = Certificate.objects.create(
            pub=self.pub["pem"],
            csr=self.csr["parsed"].public_bytes(Encoding.PEM).decode("utf-8"),
            ca=self.ca,
            expires=timezone.now(),
            valid_from=timezone.now(),
        )
        cert.refresh_from_db()

        subject = "CN=root-cert.example.com,OU=Django CA Testsuite,O=Django CA,L=Vienna,ST=Vienna,C=AT"
        self.assertEqual(repr(cert.pub), f"<LazyCertificate: {subject}>")
        self.assertEqual(repr(cert.csr), "<LazyCertificateSigningRequest: CN=csr.root-cert.example.com>")

    def test_none_value(self) -> None:
        """Test that nullable fields work."""
        cert = Certificate.objects.create(
            pub=self.pub["parsed"],
            csr=None,
            ca=self.ca,
            expires=timezone.now(),
            valid_from=timezone.now(),
        )
        self.assertIsNone(cert.csr)
        cert.refresh_from_db()
        self.assertIsNone(cert.csr)

    def test_filter(self) -> None:
        """Test that we can use various representations for filtering."""
        cert = Certificate.objects.create(
            pub=self.pub["parsed"],
            csr=self.csr["parsed"],
            ca=self.ca,
            expires=timezone.now(),
            valid_from=timezone.now(),
        )

        for prop in ["parsed", "pem", "der"]:
            qs = Certificate.objects.filter(pub=self.pub[prop])
            self.assertCountEqual(qs, [cert])
            self.assertEqual(qs[0].pub.der, self.pub["der"])

    def test_full_clean(self) -> None:
        """Test the full_clean() method, which invokes ``to_python()`` on the field."""
        cert = Certificate(
            pub=self.pub["parsed"],
            csr=self.csr["parsed"],
            ca=self.ca,
            expires=timezone.now(),
            valid_from=timezone.now(),
            cn="foo",
            serial="0",
        )
        cert.full_clean()
        self.assertEqual(cert.pub.loaded, self.pub["parsed"])
        self.assertEqual(cert.csr.loaded, self.csr["parsed"])

        cert = Certificate(
            pub=cert.pub,
            csr=cert.csr,
            ca=self.ca,
            expires=timezone.now(),
            valid_from=timezone.now(),
            cn="foo",
            serial="0",
        )
        cert.full_clean()
        self.assertEqual(cert.pub.loaded, self.pub["parsed"])
        self.assertEqual(cert.csr.loaded, self.csr["parsed"])

    def test_empty_csr(self) -> None:
        """Test an empty CSR."""
        cert = Certificate(
            pub=self.pub["parsed"],
            csr="",
            ca=self.ca,
            expires=timezone.now(),
            valid_from=timezone.now(),
            cn="foo",
            serial="0",
        )
        cert.full_clean()
        self.assertEqual(cert.pub.loaded, self.pub["parsed"])
        self.assertIsNone(cert.csr)

    def test_invalid_value(self) -> None:
        """Test passing invalid values."""
        with self.assertRaisesRegex(ValueError, r"^True: Could not parse CertificateSigningRequest$"):
            Certificate.objects.create(
                pub=CERT_DATA["child-cert"]["pub"]["parsed"],
                csr=True,
                ca=self.ca,
                expires=timezone.now(),
                valid_from=timezone.now(),
            )

        with self.assertRaisesRegex(ValueError, r"^True: Could not parse Certificate$"):
            Certificate.objects.create(
                csr=CERT_DATA["child-cert"]["csr"]["parsed"],
                pub=True,
                ca=self.ca,
                expires=timezone.now(),
                valid_from=timezone.now(),
            )


class AcmeAccountTestCase(TestCaseMixin, AcmeValuesMixin, TestCase):
    """Test :py:class:`django_ca.models.AcmeAccount`."""

    load_cas = ("root", "child")

    def setUp(self) -> None:
        super().setUp()

        self.kid1 = self.absolute_uri(":acme-account", serial=self.cas["root"].serial, slug=self.ACME_SLUG_1)
        self.account1 = AcmeAccount.objects.create(
            ca=self.cas["root"],
            contact="mailto:user@example.com",
            terms_of_service_agreed=True,
            status=AcmeAccount.STATUS_VALID,
            pem=self.ACME_PEM_1,
            thumbprint=self.ACME_THUMBPRINT_1,
            slug=self.ACME_SLUG_1,
            kid=self.kid1,
        )
        self.kid2 = self.absolute_uri(":acme-account", serial=self.cas["child"].serial, slug=self.ACME_SLUG_2)
        self.account2 = AcmeAccount.objects.create(
            ca=self.cas["child"],
            contact="mailto:user@example.net",
            terms_of_service_agreed=False,
            status=AcmeAccount.STATUS_REVOKED,
            pem=self.ACME_PEM_2,
            thumbprint=self.ACME_THUMBPRINT_2,
            slug=self.ACME_SLUG_2,
            kid=self.kid2,
        )

    def test_str(self) -> None:
        """Test str() function."""
        self.assertEqual(str(self.account1), "user@example.com")
        self.assertEqual(str(self.account2), "user@example.net")
        self.assertEqual(str(AcmeAccount()), "")

    def test_serial(self) -> None:
        """Test the ``serial`` property."""
        self.assertEqual(self.account1.serial, self.cas["root"].serial)
        self.assertEqual(self.account2.serial, self.cas["child"].serial)

        # pylint: disable=no-member; false positive: pylint does not detect RelatedObjectDoesNotExist member
        with self.assertRaisesRegex(AcmeAccount.ca.RelatedObjectDoesNotExist, r"^AcmeAccount has no ca\.$"):
            AcmeAccount().serial  # noqa: B018

    @freeze_time(TIMESTAMPS["everything_valid"])
    def test_usable(self) -> None:
        """Test the ``usable`` property."""
        self.assertTrue(self.account1.usable)
        self.assertFalse(self.account2.usable)

        # Try states that make an account **unusable**
        self.account1.status = AcmeAccount.STATUS_DEACTIVATED
        self.assertFalse(self.account1.usable)
        self.account1.status = AcmeAccount.STATUS_REVOKED
        self.assertFalse(self.account1.usable)

        # Make the account usable again
        self.account1.status = AcmeAccount.STATUS_VALID
        self.assertTrue(self.account1.usable)

        # TOS not agreed, but CA does not have any
        self.account1.terms_of_service_agreed = False
        self.assertTrue(self.account1.usable)

        # TOS not agreed, but CA does have them, so account is now unusable
        self.cas["root"].terms_of_service = "http://tos.example.com"
        self.cas["root"].save()
        self.assertFalse(self.account1.usable)

        # Make the account usable again
        self.account1.terms_of_service_agreed = True
        self.assertTrue(self.account1.usable)

        # If the CA is not usable, neither is the account
        self.account1.ca.enabled = False
        self.assertFalse(self.account1.usable)

    def test_unique_together(self) -> None:
        """Test that a thumbprint must be unique for the given CA."""
        msg = r"^UNIQUE constraint failed: django_ca_acmeaccount\.ca_id, django_ca_acmeaccount\.thumbprint$"
        with transaction.atomic(), self.assertRaisesRegex(IntegrityError, msg):
            AcmeAccount.objects.create(ca=self.account1.ca, thumbprint=self.account1.thumbprint)

        # Works, because CA is different
        AcmeAccount.objects.create(ca=self.account2.ca, thumbprint=self.account1.thumbprint)

    @override_settings(ALLOWED_HOSTS=["kid-test.example.net"])
    def test_set_kid(self) -> None:
        """Test set_kid()."""
        hostname = settings.ALLOWED_HOSTS[0]
        req = RequestFactory().get("/foobar", HTTP_HOST=hostname)
        self.account1.set_kid(req)
        self.assertEqual(
            self.account1.kid,
            f"http://{hostname}/django_ca/acme/{self.account1.serial}/acct/{self.account1.slug}/",
        )

    def test_validate_pem(self) -> None:
        """Test the PEM validator."""
        self.account1.full_clean()

        # So far we only test first and last line, so we just append/prepend a character
        self.account1.pem = f"x{self.account1.pem}"
        with self.assertValidationError({"pem": ["Not a valid PEM."]}):
            self.account1.full_clean()

        self.account1.pem = f"{self.account1.pem}x"[1:]
        with self.assertValidationError({"pem": ["Not a valid PEM."]}):
            self.account1.full_clean()


class AcmeOrderTestCase(TestCaseMixin, AcmeValuesMixin, TestCase):
    """Test :py:class:`django_ca.models.AcmeOrder`."""

    load_cas = ("root",)

    def setUp(self) -> None:
        super().setUp()
        self.account = AcmeAccount.objects.create(
            ca=self.cas["root"],
            contact="mailto:user@example.com",
            terms_of_service_agreed=True,
            status=AcmeAccount.STATUS_VALID,
            pem=self.ACME_PEM_1,
            thumbprint=self.ACME_THUMBPRINT_1,
        )
        self.order1 = AcmeOrder.objects.create(account=self.account)

    def test_str(self) -> None:
        """Test the str function."""
        self.assertEqual(str(self.order1), f"{self.order1.slug} ({self.account})")

    def test_acme_url(self) -> None:
        """Test the acme url function."""
        self.assertEqual(
            self.order1.acme_url, f"/django_ca/acme/{self.account.ca.serial}/order/{self.order1.slug}/"
        )

    def test_acme_finalize_url(self) -> None:
        """Test the acme finalize url function."""
        self.assertEqual(
            self.order1.acme_finalize_url,
            f"/django_ca/acme/{self.account.ca.serial}/order/{self.order1.slug}/finalize/",
        )

    def test_add_authorizations(self) -> None:
        """Test the add_authorizations method."""
        identifier = messages.Identifier(typ=messages.IDENTIFIER_FQDN, value="example.com")
        auths = self.order1.add_authorizations([identifier])
        self.assertEqual(auths[0].type, "dns")
        self.assertEqual(auths[0].value, "example.com")

        msg = r"^UNIQUE constraint failed: django_ca_acmeauthorization\.order_id, django_ca_acmeauthorization\.type, django_ca_acmeauthorization\.value$"  # NOQA: E501
        with transaction.atomic(), self.assertRaisesRegex(IntegrityError, msg):
            self.order1.add_authorizations([identifier])

    def test_serial(self) -> None:
        """Test getting the serial of the associated CA."""
        self.assertEqual(self.order1.serial, self.cas["root"].serial)


class AcmeAuthorizationTestCase(TestCaseMixin, AcmeValuesMixin, TestCase):
    """Test :py:class:`django_ca.models.AcmeAuthorization`."""

    load_cas = ("root",)

    def setUp(self) -> None:
        super().setUp()
        self.account = AcmeAccount.objects.create(
            ca=self.cas["root"],
            contact="user@example.com",
            terms_of_service_agreed=True,
            status=AcmeAccount.STATUS_VALID,
            pem=self.ACME_PEM_1,
            thumbprint=self.ACME_THUMBPRINT_1,
        )
        self.order = AcmeOrder.objects.create(account=self.account)
        self.auth1 = AcmeAuthorization.objects.create(
            order=self.order, type=AcmeAuthorization.TYPE_DNS, value="example.com"
        )
        self.auth2 = AcmeAuthorization.objects.create(
            order=self.order, type=AcmeAuthorization.TYPE_DNS, value="example.net"
        )

    def test_str(self) -> None:
        """Test the __str__ method."""
        self.assertEqual(str(self.auth1), "dns: example.com")
        self.assertEqual(str(self.auth2), "dns: example.net")

    def test_account_property(self) -> None:
        """Test the account property."""
        self.assertEqual(self.auth1.account, self.account)
        self.assertEqual(self.auth2.account, self.account)

    def test_acme_url(self) -> None:
        """Test acme_url property."""
        self.assertEqual(
            self.auth1.acme_url,
            f"/django_ca/acme/{self.cas['root'].serial}/authz/{self.auth1.slug}/",
        )
        self.assertEqual(
            self.auth2.acme_url,
            f"/django_ca/acme/{self.cas['root'].serial}/authz/{self.auth2.slug}/",
        )

    def test_expires(self) -> None:
        """Test the expires property."""
        self.assertEqual(self.auth1.expires, self.order.expires)
        self.assertEqual(self.auth2.expires, self.order.expires)

    def test_identifier(self) -> None:
        """Test the identifier property."""
        self.assertEqual(
            self.auth1.identifier, messages.Identifier(typ=messages.IDENTIFIER_FQDN, value=self.auth1.value)
        )
        self.assertEqual(
            self.auth2.identifier, messages.Identifier(typ=messages.IDENTIFIER_FQDN, value=self.auth2.value)
        )

    def test_identifier_unknown_type(self) -> None:
        """Test that an identifier with an unknown type raises a ValueError."""
        self.auth1.type = "foo"
        with self.assertRaisesRegex(ValueError, r"^Unknown identifier type: foo$"):
            self.auth1.identifier  # noqa: B018

    def test_subject_alternative_name(self) -> None:
        """Test the subject_alternative_name property."""
        self.assertEqual(self.auth1.subject_alternative_name, "dns:example.com")
        self.assertEqual(self.auth2.subject_alternative_name, "dns:example.net")

    def test_get_challenges(self) -> None:
        """Test the get_challenges() method."""
        chall_qs = self.auth1.get_challenges()
        self.assertIsInstance(chall_qs[0], AcmeChallenge)
        self.assertIsInstance(chall_qs[1], AcmeChallenge)

        self.assertEqual(self.auth1.get_challenges(), chall_qs)
        self.assertEqual(AcmeChallenge.objects.all().count(), 2)


class AcmeChallengeTestCase(TestCaseMixin, AcmeValuesMixin, TestCase):
    """Test :py:class:`django_ca.models.AcmeChallenge`."""

    load_cas = ("root",)

    def setUp(self) -> None:
        super().setUp()
        self.account = AcmeAccount.objects.create(
            ca=self.cas["root"],
            contact="user@example.com",
            terms_of_service_agreed=True,
            status=AcmeAccount.STATUS_VALID,
            pem=self.ACME_PEM_1,
            thumbprint=self.ACME_THUMBPRINT_1,
        )
        self.order = AcmeOrder.objects.create(account=self.account)
        self.auth = AcmeAuthorization.objects.create(
            order=self.order, type=AcmeAuthorization.TYPE_DNS, value=self.hostname
        )
        self.chall = AcmeChallenge.objects.create(auth=self.auth, type=AcmeChallenge.TYPE_HTTP_01)

    def assertChallenge(  # pylint: disable=invalid-name
        self, challenge: ChallengeTypeVar, typ: str, token: bytes, cls: Type[ChallengeTypeVar]
    ) -> None:
        """Test that the ACME challenge is of the given type."""
        self.assertIsInstance(challenge, cls)
        self.assertEqual(challenge.typ, typ)
        self.assertEqual(challenge.token, token)

    def test_str(self) -> None:
        """Test the __str__ method."""
        self.assertEqual(str(self.chall), f"{self.hostname} ({self.chall.type})")

    def test_acme_url(self) -> None:
        """Test acme_url property."""
        self.assertEqual(self.chall.acme_url, f"/django_ca/acme/{self.chall.serial}/chall/{self.chall.slug}/")

    def test_acme_challenge(self) -> None:
        """Test acme_challenge property."""
        self.assertChallenge(
            self.chall.acme_challenge, "http-01", self.chall.token.encode(), challenges.HTTP01
        )

        self.chall.type = AcmeChallenge.TYPE_DNS_01
        self.assertChallenge(self.chall.acme_challenge, "dns-01", self.chall.token.encode(), challenges.DNS01)

        self.chall.type = AcmeChallenge.TYPE_TLS_ALPN_01
        self.assertChallenge(
            self.chall.acme_challenge, "tls-alpn-01", self.chall.token.encode(), challenges.TLSALPN01
        )

        self.chall.type = "foo"
        with self.assertRaisesRegex(ValueError, r"^foo: Unsupported challenge type\.$"):
            self.chall.acme_challenge  # noqa: B018

    @freeze_time(TIMESTAMPS["everything_valid"])
    def test_acme_validated(self) -> None:
        """Test acme_validated property."""
        # preconditions for checks (might change them in setUp without realising it might affect this test)
        self.assertNotEqual(self.chall.status, AcmeChallenge.STATUS_VALID)
        self.assertIsNone(self.chall.validated)

        self.assertIsNone(self.chall.acme_validated)

        self.chall.status = AcmeChallenge.STATUS_VALID
        self.assertIsNone(self.chall.acme_validated)  # still None (no validated timestamp)

        self.chall.validated = timezone.now()
        self.assertEqual(self.chall.acme_validated, TIMESTAMPS["everything_valid"])

        # We return a UTC timestamp, even if timezone support is disabled.
        with self.settings(USE_TZ=False):
            self.chall.validated = timezone.now()
            self.assertEqual(self.chall.acme_validated, TIMESTAMPS["everything_valid"])

    def test_encoded(self) -> None:
        """Test the encoded property."""
        self.chall.token = "ADwFxCAXrnk47rcCnnbbtGYSo_l61MCYXqtBziPt26mk7-QzpYNNKnTsKjbBYPzD"
        self.chall.save()
        self.assertEqual(
            self.chall.encoded_token,
            b"QUR3RnhDQVhybms0N3JjQ25uYmJ0R1lTb19sNjFNQ1lYcXRCemlQdDI2bWs3LVF6cFlOTktuVHNLamJCWVB6RA",
        )

    def test_expected(self) -> None:
        """Test the expected property."""
        self.chall.token = "ADwFxCAXrnk47rcCnnbbtGYSo_l61MCYXqtBziPt26mk7-QzpYNNKnTsKjbBYPzD"
        self.chall.save()
        self.assertEqual(
            self.chall.expected, self.chall.encoded_token + b"." + self.account.thumbprint.encode("utf-8")
        )

        self.chall.type = AcmeChallenge.TYPE_DNS_01
        self.chall.save()
        self.assertEqual(self.chall.expected, b"LoNgngEeuLw4rWDFpplPA0XBp9dd9spzuuqbsRFcKug")

        self.chall.type = AcmeChallenge.TYPE_TLS_ALPN_01
        self.chall.save()
        with self.assertRaisesRegex(ValueError, r"^tls-alpn-01: Unsupported challenge type\.$"):
            self.chall.expected  # noqa: B018

    def test_get_challenge(self) -> None:
        """Test the get_challenge() function."""
        body = self.chall.get_challenge(RequestFactory().get("/"))
        self.assertIsInstance(body, messages.ChallengeBody)
        self.assertEqual(body.chall, self.chall.acme_challenge)
        self.assertEqual(body.status, self.chall.status)
        self.assertEqual(body.validated, self.chall.acme_validated)
        self.assertEqual(body.uri, f"http://testserver{self.chall.acme_url}")

    def test_serial(self) -> None:
        """Test the serial property."""
        self.assertEqual(self.chall.serial, self.chall.auth.order.account.ca.serial)


class AcmeCertificateTestCase(TestCaseMixin, AcmeValuesMixin, TestCase):
    """Test :py:class:`django_ca.models.AcmeCertificate`."""

    load_cas = ("root",)

    def setUp(self) -> None:
        super().setUp()
        self.account = AcmeAccount.objects.create(
            ca=self.cas["root"],
            contact="mailto:user@example.com",
            terms_of_service_agreed=True,
            status=AcmeAccount.STATUS_VALID,
            pem=self.ACME_PEM_1,
            thumbprint=self.ACME_THUMBPRINT_1,
        )
        self.order = AcmeOrder.objects.create(account=self.account)
        self.acme_cert = AcmeCertificate.objects.create(order=self.order)

    def test_acme_url(self) -> None:
        """Test the acme_url property."""
        self.assertEqual(
            self.acme_cert.acme_url, f"/django_ca/acme/{self.order.serial}/cert/{self.acme_cert.slug}/"
        )

    def test_parse_csr(self) -> None:
        """Test the parse_csr property."""
        self.acme_cert.csr = (
            CERT_DATA["root-cert"]["csr"]["parsed"].public_bytes(Encoding.PEM).decode("utf-8")
        )
        self.assertIsInstance(self.acme_cert.parse_csr(), x509.CertificateSigningRequest)

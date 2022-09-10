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

"""Test Django model classes."""

import os
import re
import typing
from contextlib import contextmanager
from datetime import datetime, timedelta
from datetime import timezone as tz
from unittest import mock

import josepy as jose
from acme import challenges, messages

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import PRIVATE_KEY_TYPES
from cryptography.hazmat.primitives.serialization import Encoding, load_pem_private_key
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.utils import IntegrityError
from django.test import RequestFactory, TestCase
from django.urls import reverse
from django.utils import timezone

from freezegun import freeze_time

from .. import ca_settings
from ..constants import ReasonFlags
from ..extensions import (
    KEY_TO_EXTENSION,
    Extension,
    PrecertificateSignedCertificateTimestamps,
    SubjectAlternativeName,
)
from ..modelfields import LazyCertificate, LazyCertificateSigningRequest
from ..models import (
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
from ..utils import ca_storage, get_crl_cache_key
from .base import CERT_PEM_REGEX, certs, override_settings, override_tmpcadir, timestamps
from .base.mixins import AcmeValuesMixin, TestCaseMixin, TestCaseProtocol

ChallengeTypeVar = typing.TypeVar("ChallengeTypeVar", bound=challenges.KeyAuthorizationChallenge)


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
    """Mixin collection  assection methods for CertificateAuthority and Certificate."""

    def assertBundle(  # pylint: disable=invalid-name
        self, chain: typing.List[X509CertMixin], cert: X509CertMixin
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


class CertificateAuthorityTests(TestCaseMixin, X509CertMixinTestCaseMixin, TestCase):
    """Test :py:class:`django_ca.models.CertificateAuthority`."""

    load_cas = "__all__"
    load_certs = ("root-cert", "child-cert")

    @contextmanager
    def generate_ocsp_key(
        self, ca: CertificateAuthority, *args: typing.Any, **kwargs: typing.Any
    ) -> typing.Iterator[typing.Tuple[PRIVATE_KEY_TYPES, Certificate]]:
        """Context manager to  create an OCSP key and test some basic properties."""
        private_path, cert_path, cert = ca.generate_ocsp_key(*args, **kwargs)
        self.assertTrue(cert.autogenerated)

        with ca_storage.open(private_path) as priv_key_stream:
            key = load_pem_private_key(priv_key_stream.read(), password=None)

        yield key, cert

    @override_tmpcadir()
    def test_key(self) -> None:
        """Test access to the private key."""
        for name, ca in self.usable_cas:
            self.assertTrue(ca.key_exists)
            self.assertIsNotNone(ca.key(certs[name]["password"]))

            # test a second tome to make sure we reload the key
            with mock.patch("django_ca.utils.read_file") as patched:
                self.assertIsNotNone(ca.key(None))
            patched.assert_not_called()

            ca._key = None  # pylint: disable=protected-access; so the key is reloaded
            ca.private_key_path = os.path.join(ca_settings.CA_DIR, ca.private_key_path)
            self.assertTrue(ca.key_exists)

            self.assertIsNotNone(ca.key(certs[name]["password"]))

            # Check again - here we have an already loaded key (also: no logging here anymore)
            # NOTE: assertLogs() fails if there are *no* log messages, so we cannot test that
            self.assertTrue(ca.key_exists)

    @override_tmpcadir()
    def test_bundle_as_pem(self) -> None:
        """Test bundles of various CAs."""
        self.assertBundle([self.cas["root"]], self.cas["root"])
        self.assertBundle([self.cas["child"], self.cas["root"]], self.cas["child"])
        self.assertBundle([self.cas["ecc"]], self.cas["ecc"])

    @override_tmpcadir()
    def test_key_str_password(self) -> None:
        """Test accessing the private key with a string password."""
        ca = self.cas["pwd"]
        pwd = certs["pwd"]["password"].decode("utf-8")

        self.assertIsNotNone(ca.key(pwd))

    def test_pathlen(self) -> None:
        """Test the pathlen attribute."""
        for name, ca in self.cas.items():
            self.assertEqual(ca.pathlen, certs[name].get("pathlen"))

    def test_root(self) -> None:
        """Test the root attribute."""
        self.assertEqual(self.cas["root"].root, self.cas["root"])
        self.assertEqual(self.cas["child"].root, self.cas["root"])

    @freeze_time(timestamps["everything_valid"])
    @override_tmpcadir()
    def test_full_crl(self) -> None:
        """Test getting the CRL for a CertificateAuthority."""
        ca = self.cas["root"]
        child = self.cas["child"]
        cert = self.certs["root-cert"]
        full_name = "http://localhost/crl"
        idp = self.get_idp(full_name=[x509.UniformResourceIdentifier(value=full_name)])

        crl = ca.get_crl(full_name=[self.uri(full_name)]).public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=idp, signer=ca)

        ca.crl_url = full_name
        ca.save()
        crl = ca.get_crl().public_bytes(Encoding.PEM)
        self.assertCRL(crl, crl_number=1, signer=ca)

        # revoke a cert
        cert.revoke()
        crl = ca.get_crl().public_bytes(Encoding.PEM)
        self.assertCRL(crl, expected=[cert], crl_number=2, signer=ca)

        # also revoke a CA
        child.revoke()
        crl = ca.get_crl().public_bytes(Encoding.PEM)
        self.assertCRL(crl, expected=[cert, child], crl_number=3, signer=ca)

        # unrevoke cert (so we have all three combinations)
        cert.revoked = False
        cert.revoked_date = None
        cert.revoked_reason = ""
        cert.save()

        crl = ca.get_crl().public_bytes(Encoding.PEM)
        self.assertCRL(crl, expected=[child], crl_number=4, signer=ca)

    @freeze_time(timestamps["everything_valid"])
    @override_tmpcadir()
    def test_intermediate_crl(self) -> None:
        """Test getting the CRL of an intermediate CA."""
        child = self.cas["child"]
        cert = self.certs["child-cert"]
        full_name = "http://localhost/crl"
        idp = self.get_idp(full_name=[x509.UniformResourceIdentifier(value=full_name)])

        crl = child.get_crl(full_name=[self.uri(full_name)]).public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=idp, signer=child)

        # Revoke a cert
        cert.revoke()
        crl = child.get_crl(full_name=[self.uri(full_name)]).public_bytes(Encoding.PEM)
        self.assertCRL(crl, expected=[cert], idp=idp, crl_number=1, signer=child)

    @override_settings(USE_TZ=True)
    def test_full_crl_tz(self) -> None:
        """Test full CRL but with timezone support enabled."""
        # otherwise we get TZ warnings for preloaded objects
        ca = self.cas["root"]
        child = self.cas["child"]
        cert = self.certs["root-cert"]

        ca.refresh_from_db()
        child.refresh_from_db()
        cert.refresh_from_db()

        self.test_full_crl()

    @override_tmpcadir()
    @freeze_time(timestamps["everything_valid"])
    def test_ca_crl(self) -> None:
        """Test getting a CA CRL."""
        ca = self.cas["root"]
        idp = self.get_idp(only_contains_ca_certs=True)  # root CAs don't have a full name (github issue #64)

        crl = ca.get_crl(scope="ca").public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=idp, signer=ca)

        # revoke ca and cert, CRL only contains CA
        child_ca = self.cas["child"]
        child_ca.revoke()
        self.cas["ecc"].revoke()
        self.certs["root-cert"].revoke()
        self.certs["child-cert"].revoke()
        crl = ca.get_crl(scope="ca").public_bytes(Encoding.PEM)
        self.assertCRL(crl, expected=[child_ca], idp=idp, crl_number=1, signer=ca)

    @override_tmpcadir()
    @freeze_time(timestamps["everything_valid"])
    def test_intermediate_ca_crl(self) -> None:
        """Test getting the CRL for an intermediate CA."""
        # Intermediate CAs have a DP in the CRL that has the CA url
        full_name = [
            x509.UniformResourceIdentifier(
                f"http://{ca_settings.CA_DEFAULT_HOSTNAME}/django_ca/crl/ca/{self.ca.serial}/"
            )
        ]
        idp = self.get_idp(full_name=full_name, only_contains_ca_certs=True)

        crl = self.ca.get_crl(scope="ca").public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=idp, signer=self.ca)

    @freeze_time(timestamps["everything_valid"])
    @override_tmpcadir()
    def test_user_crl(self) -> None:
        """Test getting a user CRL."""
        ca = self.cas["root"]
        idp = self.get_idp(full_name=self.get_idp_full_name(ca), only_contains_user_certs=True)

        crl = ca.get_crl(scope="user").public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=idp, signer=ca)

        # revoke ca and cert, CRL only contains cert
        cert = self.certs["root-cert"]
        cert.revoke()
        self.certs["child-cert"].revoke()
        self.cas["child"].revoke()
        crl = ca.get_crl(scope="user").public_bytes(Encoding.PEM)
        self.assertCRL(crl, expected=[cert], idp=idp, crl_number=1, signer=ca)

    @freeze_time(timestamps["everything_valid"])
    @override_tmpcadir()
    def test_attr_crl(self) -> None:
        """Test getting an Attribute CRL (always an empty list)."""
        ca = self.cas["root"]
        idp = self.get_idp(only_contains_attribute_certs=True)

        crl = ca.get_crl(scope="attribute").public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=idp, signer=ca)

        # revoke ca and cert, CRL is empty (we don't know attribute certs)
        self.certs["root-cert"].revoke()
        self.certs["child-cert"].revoke()
        self.cas["child"].revoke()
        crl = ca.get_crl(scope="attribute").public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=idp, crl_number=1, signer=ca)

    @override_tmpcadir()
    @freeze_time(timestamps["everything_valid"])
    def test_no_idp(self) -> None:
        """Test a CRL with no IDP."""
        # CRLs require a full name (or only_some_reasons) if it's a full CRL
        self.ca.crl_url = ""
        self.ca.save()
        crl = self.ca.get_crl().public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=None)

    @override_tmpcadir()
    @freeze_time(timestamps["everything_valid"])
    def test_counter(self) -> None:
        """Test the counter for CRLs."""
        idp = self.get_idp(full_name=self.get_idp_full_name(self.ca))
        crl = self.ca.get_crl(counter="test").public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=idp, crl_number=0)
        crl = self.ca.get_crl(counter="test").public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=idp, crl_number=1)

        crl = self.ca.get_crl().public_bytes(Encoding.PEM)  # test with no counter
        self.assertCRL(crl, idp=idp, crl_number=0)

    @override_tmpcadir()
    @freeze_time(timestamps["everything_valid"])
    def test_no_auth_key_identifier(self) -> None:
        """Test an getting the CRL from a CA with no AuthorityKeyIdentifier."""
        # All CAs have a authority key identifier, so we mock that this exception is not present
        def side_effect(cls: typing.Any) -> typing.NoReturn:
            raise x509.ExtensionNotFound("mocked", x509.SubjectKeyIdentifier.oid)

        full_name = "http://localhost/crl"
        idp = self.get_idp(full_name=[x509.UniformResourceIdentifier(value=full_name)])

        with mock.patch(
            "cryptography.x509.extensions.Extensions.get_extension_for_oid", side_effect=side_effect
        ):
            crl = self.ca.get_crl(full_name=[self.uri(full_name)]).public_bytes(Encoding.PEM)
        # Note that we still get an AKI because the value comes from the public key in this case
        self.assertCRL(crl, idp=idp, signer=self.ca)

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
        """ "Try getting a CRL with an invalid scope."""
        with self.assertRaisesRegex(ValueError, r'^scope must be either None, "ca", "user" or "attribute"$'):
            self.ca.get_crl(scope="foobar").public_bytes(Encoding.PEM)  # type: ignore[arg-type]

    @override_tmpcadir()
    @freeze_time(timestamps["everything_valid"])
    def test_cache_crls(self) -> None:
        """Test caching of CRLs."""
        crl_profiles = self.crl_profiles
        for config in crl_profiles.values():
            config["encodings"] = [
                "DER",
                "PEM",
            ]

        for _name, ca in self.usable_cas:
            der_user_key = get_crl_cache_key(ca.serial, hashes.SHA512(), Encoding.DER, "user")
            pem_user_key = get_crl_cache_key(ca.serial, hashes.SHA512(), Encoding.PEM, "user")
            der_ca_key = get_crl_cache_key(ca.serial, hashes.SHA512(), Encoding.DER, "ca")
            pem_ca_key = get_crl_cache_key(ca.serial, hashes.SHA512(), Encoding.PEM, "ca")
            user_idp = self.get_idp(full_name=self.get_idp_full_name(ca), only_contains_user_certs=True)
            if ca.parent is None:
                ca_idp = self.get_idp(full_name=None, only_contains_ca_certs=True)
            else:
                crl_path = reverse("django_ca:ca-crl", kwargs={"serial": ca.serial})
                full_name = [
                    x509.UniformResourceIdentifier(f"http://{ca_settings.CA_DEFAULT_HOSTNAME}{crl_path}")
                ]
                ca_idp = self.get_idp(full_name=full_name, only_contains_ca_certs=True)

            self.assertIsNone(cache.get(der_ca_key))
            self.assertIsNone(cache.get(pem_ca_key))
            self.assertIsNone(cache.get(der_user_key))
            self.assertIsNone(cache.get(pem_user_key))

            with self.settings(CA_CRL_PROFILES=crl_profiles):
                ca.cache_crls()

            der_user_crl = cache.get(der_user_key)
            pem_user_crl = cache.get(pem_user_key)
            self.assertCRL(der_user_crl, idp=user_idp, crl_number=0, encoding=Encoding.DER, signer=ca)
            self.assertCRL(pem_user_crl, idp=user_idp, crl_number=0, encoding=Encoding.PEM, signer=ca)

            der_ca_crl = cache.get(der_ca_key)
            pem_ca_crl = cache.get(pem_ca_key)
            self.assertCRL(der_ca_crl, idp=ca_idp, crl_number=0, encoding=Encoding.DER, signer=ca)
            self.assertCRL(pem_ca_crl, idp=ca_idp, crl_number=0, encoding=Encoding.PEM, signer=ca)

            # cache again - which will force triggering a new computation
            with self.settings(CA_CRL_PROFILES=crl_profiles):
                ca.cache_crls()

            # Get CRLs from cache - we have a new CRLNumber
            der_user_crl = cache.get(der_user_key)
            pem_user_crl = cache.get(pem_user_key)
            self.assertCRL(der_user_crl, idp=user_idp, crl_number=1, encoding=Encoding.DER, signer=ca)
            self.assertCRL(pem_user_crl, idp=user_idp, crl_number=1, encoding=Encoding.PEM, signer=ca)

            der_ca_crl = cache.get(der_ca_key)
            pem_ca_crl = cache.get(pem_ca_key)
            self.assertCRL(der_ca_crl, idp=ca_idp, crl_number=1, encoding=Encoding.DER, signer=ca)
            self.assertCRL(pem_ca_crl, idp=ca_idp, crl_number=1, encoding=Encoding.PEM, signer=ca)

            # clear caches and skip generation
            cache.clear()
            crl_profiles["ca"]["OVERRIDES"][ca.serial]["skip"] = True
            crl_profiles["user"]["OVERRIDES"][ca.serial]["skip"] = True

            # set a wrong password, ensuring that any CRL generation would *never* work
            crl_profiles["ca"]["OVERRIDES"][ca.serial]["password"] = b"wrong"
            crl_profiles["user"]["OVERRIDES"][ca.serial]["password"] = b"wrong"

            with self.settings(CA_CRL_PROFILES=crl_profiles):
                ca.cache_crls()

            self.assertIsNone(cache.get(der_ca_key))
            self.assertIsNone(cache.get(pem_ca_key))
            self.assertIsNone(cache.get(der_user_key))
            self.assertIsNone(cache.get(pem_user_key))

    @override_tmpcadir()
    def test_cache_crls_algorithm(self) -> None:
        """Test passing an explicit hash algorithm."""

        crl_profiles = self.crl_profiles
        for config in crl_profiles.values():
            config["encodings"] = [
                "DER",
                "PEM",
            ]

        ca = self.cas["root"]
        algo = hashes.SHA256()
        der_user_key = get_crl_cache_key(ca.serial, algo, Encoding.DER, "user")
        pem_user_key = get_crl_cache_key(ca.serial, algo, Encoding.PEM, "user")
        der_ca_key = get_crl_cache_key(ca.serial, algo, Encoding.DER, "ca")
        pem_ca_key = get_crl_cache_key(ca.serial, algo, Encoding.PEM, "ca")

        self.assertIsNone(cache.get(der_ca_key))
        self.assertIsNone(cache.get(pem_ca_key))
        self.assertIsNone(cache.get(der_user_key))
        self.assertIsNone(cache.get(pem_user_key))

        with self.settings(CA_CRL_PROFILES=crl_profiles):
            ca.cache_crls(algorithm=algo)

        der_user_crl = cache.get(der_user_key)
        pem_user_crl = cache.get(pem_user_key)
        self.assertIsInstance(der_user_crl, bytes)
        self.assertIsInstance(pem_user_crl, bytes)

    def test_max_pathlen(self) -> None:
        """Test getting the maximum pathlen."""
        for name, ca in self.usable_cas:
            self.assertEqual(ca.max_pathlen, certs[name].get("max_pathlen"))

    def test_allows_intermediate(self) -> None:
        """Test checking if this CA allows intermediate CAs."""
        self.assertTrue(self.cas["root"].allows_intermediate_ca)
        self.assertTrue(self.cas["ecc"].allows_intermediate_ca)
        self.assertFalse(self.cas["child"].allows_intermediate_ca)

    @override_tmpcadir()
    def test_generate_ocsp_key(self) -> None:
        """Test generate_ocsp_key()."""

        for name, ca in self.usable_cas:
            with self.generate_ocsp_key(ca) as (key, cert):
                self.assertIsInstance(key, rsa.RSAPrivateKey)

    @override_tmpcadir(CA_DEFAULT_ECC_CURVE="SECP192R1")
    def test_generate_ocsp_key_ecc(self) -> None:
        """Test generate_ocsp_key() with ECC keys."""

        for name, ca in self.usable_cas:
            with self.generate_ocsp_key(ca, key_type="ECC") as (key, cert):
                key = typing.cast(ec.EllipticCurvePrivateKey, key)
                self.assertIsInstance(key, ec.EllipticCurvePrivateKey)
                self.assertIsInstance(key.curve, ec.SECP192R1)

            # pass a custom ecc curve
            with self.generate_ocsp_key(ca, key_type="ECC", ecc_curve=ec.BrainpoolP256R1()) as (key, cert):
                key = typing.cast(ec.EllipticCurvePrivateKey, key)
                self.assertIsInstance(key, ec.EllipticCurvePrivateKey)
                self.assertIsInstance(key.curve, ec.BrainpoolP256R1)


class CertificateTests(TestCaseMixin, X509CertMixinTestCaseMixin, TestCase):
    """Test :py:class:`django_ca.models.Certificate`."""

    load_cas = "__all__"
    load_certs = "__all__"

    def assertExtension(  # pylint: disable=invalid-name; unittest style
        self,
        cert: X509CertMixin,
        name: str,
        key: str,
        cls: typing.Type[Extension[typing.Any, typing.Any, typing.Any]],
    ) -> None:
        """Assert that an extension for the given certificate is equal to what we have on record.

        Parameters
        ----------

        cert : :py:class:`django_ca.models.Certificate`
        name : str
        Name of the certificate
        key : str
        Extension name
        cls : class
        Expected extension class
        """
        ext = getattr(cert, key)

        if ext is None:
            self.assertNotIn(key, certs[name])
        else:
            self.assertIsInstance(ext, cls)
            self.assertEqual(ext, certs[name].get(key))

    @override_tmpcadir()
    def test_bundle_as_pem(self) -> None:
        """Test bundles of various CAs."""
        self.assertBundle([self.certs["root-cert"], self.cas["root"]], self.certs["root-cert"])
        self.assertBundle(
            [self.certs["child-cert"], self.cas["child"], self.cas["root"]], self.certs["child-cert"]
        )
        self.assertBundle([self.certs["ecc-cert"], self.cas["ecc"]], self.certs["ecc-cert"])

    def test_dates(self) -> None:
        """Test valid_from/valid_until dates."""
        for name, ca in self.cas.items():
            self.assertEqual(ca.valid_from, certs[name]["valid_from"])
            self.assertEqual(ca.expires, certs[name]["valid_until"])

        for name, cert in self.certs.items():
            self.assertEqual(cert.valid_from, certs[name]["valid_from"])
            self.assertEqual(cert.expires, certs[name]["valid_until"])

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
            self.assertEqual(ca.serial, certs[ca.name].get("serial"))

        for name, cert in self.certs.items():
            self.assertEqual(cert.serial, certs[name].get("serial"))

    @override_tmpcadir()
    def test_subject_alternative_name(self) -> None:
        """Test getting the subjectAlternativeName extension."""
        for name, ca in self.cas.items():
            self.assertEqual(ca.subject_alternative_name, certs[ca.name].get("subject_alternative_name"))

        for name, cert in self.certs.items():
            self.assertEqual(cert.subject_alternative_name, certs[name].get("subject_alternative_name"))

        # Create a cert with some weirder SANs to test that too
        weird_cert = self.create_cert(
            self.cas["child"],
            certs["child-cert"]["csr"]["parsed"],
            subject=self.subject,
            extensions=[
                SubjectAlternativeName(
                    {
                        "value": ["dirname:/C=AT/CN=example.com", "email:user@example.com", "fd00::1"],
                    }
                )
            ],
        )

        expected = SubjectAlternativeName(
            {
                "value": [
                    "dirname:/C=AT/CN=example.com",
                    "email:user@example.com",
                    "IP:fd00::1",
                    f"DNS:{self.hostname}",
                ]
            }
        )
        self.assertEqual(weird_cert.subject_alternative_name, expected)

    @freeze_time("2019-02-03 15:43:12")
    def test_get_revocation_time(self) -> None:
        """Test getting the revocation time."""
        self.assertIsNone(self.cert.get_revocation_time())
        self.cert.revoke()

        # timestamp does not have a timezone regardless of USE_TZ
        with override_settings(USE_TZ=True):
            self.cert.revoked_date = timezone.now()
            self.assertEqual(self.cert.get_revocation_time(), datetime(2019, 2, 3, 15, 43, 12))

        with override_settings(USE_TZ=False):
            self.cert.revoked_date = timezone.now()
            self.assertEqual(self.cert.get_revocation_time(), datetime(2019, 2, 3, 15, 43, 12))

    @freeze_time("2019-02-03 15:43:12")
    def test_get_compromised_time(self) -> None:
        """Test getting the time when the certificate was compromised."""
        self.assertIsNone(self.cert.get_compromised_time())
        self.cert.revoke(compromised=timezone.now())

        # timestamp does not have a timezone regardless of USE_TZ
        with override_settings(USE_TZ=True):
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
            "md5": hashes.MD5(),
            "sha1": hashes.SHA1(),
            "sha256": hashes.SHA256(),
            "sha512": hashes.SHA512(),
        }
        for name, ca in self.cas.items():
            for algo_name, algorithm in algorithms.items():
                self.assertEqual(ca.get_fingerprint(algorithm), certs[name][algo_name])

        for name, cert in self.certs.items():
            for algo_name, algorithm in algorithms.items():
                self.assertEqual(cert.get_fingerprint(algorithm), certs[name][algo_name])

    def test_hpkp_pin(self) -> None:
        """Test getting a HPKP pin for a certificate."""
        # get hpkp pins using
        #   openssl x509 -in cert1.pem -pubkey -noout \
        #       | openssl rsa -pubin -outform der \
        #       | openssl dgst -sha256 -binary | base64
        for name, ca in self.cas.items():
            self.assertEqual(ca.hpkp_pin, certs[name]["hpkp"])
            self.assertIsInstance(ca.hpkp_pin, str)

        for name, cert in self.certs.items():
            self.assertEqual(cert.hpkp_pin, certs[name]["hpkp"])
            self.assertIsInstance(cert.hpkp_pin, str)

    def test_jwk(self) -> None:
        """Test JWK property."""
        for name, ca in self.cas.items():
            if certs[name]["key_type"] == "ECC":
                self.assertIsInstance(ca.jwk, jose.jwk.JWKEC, name)
            else:
                self.assertIsInstance(ca.jwk, jose.jwk.JWKRSA)

        for name, cert in self.certs.items():
            if certs[name]["key_type"] == "ECC":
                self.assertIsInstance(cert.jwk, jose.jwk.JWKEC, name)
            else:
                self.assertIsInstance(cert.jwk, jose.jwk.JWKRSA, name)

    def test_get_authority_information_access_extension(self) -> None:
        """Test getting the AuthorityInformationAccess extension for a CA."""
        self.assertIsNone(CertificateAuthority().get_authority_information_access_extension())

        ca = CertificateAuthority(issuer_url="https://example.com")
        actual = ca.get_authority_information_access_extension()
        expected = x509.Extension(
            oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
            critical=False,
            value=x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                        access_location=x509.UniformResourceIdentifier("https://example.com"),
                    )
                ]
            ),
        )
        self.assertEqual(actual, expected)

        ca = CertificateAuthority(ocsp_url="https://example.com")
        actual = ca.get_authority_information_access_extension()
        expected = x509.Extension(
            oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
            critical=False,
            value=x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        access_method=AuthorityInformationAccessOID.OCSP,
                        access_location=x509.UniformResourceIdentifier("https://example.com"),
                    )
                ]
            ),
        )
        self.assertEqual(actual, expected)

    def test_get_authority_key_identifier(self) -> None:
        """Test getting the authority key identifier."""
        for name, ca in self.cas.items():
            self.assertEqual(
                ca.get_authority_key_identifier().key_identifier, certs[name]["subject_key_identifier"].value
            )

        # All CAs have a subject key identifier, so we mock that this exception is not present
        def side_effect(cls: typing.Any) -> typing.NoReturn:
            raise x509.ExtensionNotFound("mocked", x509.SubjectKeyIdentifier.oid)

        ca = self.cas["child"]
        with mock.patch(
            "cryptography.x509.extensions.Extensions.get_extension_for_class", side_effect=side_effect
        ):
            self.assertEqual(
                ca.get_authority_key_identifier().key_identifier,
                certs["child"]["subject_key_identifier"].value,
            )

    def test_get_authority_key_identifier_extension(self) -> None:
        """Test getting the authority key id extension for CAs."""
        for name, ca in self.cas.items():
            ext = ca.get_authority_key_identifier_extension()
            self.assertEqual(ext.value.key_identifier, certs[name]["subject_key_identifier"].value)

    ###############################################
    # Test extensions for all loaded certificates #
    ###############################################
    def test_extensions(self) -> None:
        """Test getting extensions."""
        for key, cls in KEY_TO_EXTENSION.items():
            if key == PrecertificateSignedCertificateTimestamps.key:
                # These extensions are never equal:
                # Since we cannot instantiate this extension, the value is stored internally as cryptography
                # object if it comes from the extension (or there would be no way back), but as serialized
                # data if instantiated from dict (b/c we cannot create the cryptography objects).
                continue

            for name, ca in self.cas.items():
                self.assertExtension(ca, name, key, cls)

            for name, cert in self.certs.items():
                self.assertExtension(cert, name, key, cls)

    # @unittest.skip('Cannot currently instantiate extensions, so no sense in testing this.')
    def test_precertificate_signed_certificate_timestamps(self) -> None:
        """Test getting the SCT timestamp extension."""
        for name, cert in self.certs.items():
            ext = getattr(cert, PrecertificateSignedCertificateTimestamps.key)

            if PrecertificateSignedCertificateTimestamps.key in certs[name]:
                self.assertIsInstance(ext, PrecertificateSignedCertificateTimestamps)
            else:
                self.assertIsNone(ext)

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

    csr = certs["root-cert"]["csr"]
    pub = certs["root-cert"]["pub"]
    load_cas = ("root",)

    def test_create(self) -> None:
        """Test create() for the models."""
        for prop in ["parsed", "pem", "der"]:
            cert = Certificate.objects.create(
                pub=self.pub[prop],
                csr=self.csr[prop],
                ca=self.ca,
                expires=timezone.now(),
                valid_from=timezone.now(),
            )
            self.assertEqual(cert.pub, self.pub[prop])
            self.assertEqual(cert.csr, self.csr[prop])

            # Refresh, so that we get lazy values
            cert.refresh_from_db()

            self.assertEqual(cert.pub.loaded, self.pub["parsed"])
            self.assertEqual(cert.csr.loaded, self.csr["parsed"])

            cert.delete()  # for next loop iteration

    def test_create_pem_bytes(self) -> None:
        """Test creating with bytes-encoded PEM."""
        pub = self.pub["pem"].encode()
        csr = self.csr["pem"].encode()
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
        csr = bytearray(self.csr["der"])
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
        csr = memoryview(self.csr["der"])
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
            csr=self.csr["pem"],
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
                pub=certs["child-cert"]["pub"]["parsed"],
                csr=True,
                ca=self.ca,
                expires=timezone.now(),
                valid_from=timezone.now(),
            )

        with self.assertRaisesRegex(ValueError, r"^True: Could not parse Certificate$"):
            Certificate.objects.create(
                csr=certs["child-cert"]["csr"]["parsed"],
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
            AcmeAccount().serial  # pylint: disable=expression-not-assigned

    @freeze_time(timestamps["everything_valid"])
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

        # TOS must be agreed
        self.account1.terms_of_service_agreed = False
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
            self.auth1.identifier  # pylint: disable=pointless-statement; access to prop raises exception

    def test_subject_alternative_name(self) -> None:
        """Test the subject_alternative_name property."""

        self.assertEqual(self.auth1.subject_alternative_name, "dns:example.com")
        self.assertEqual(self.auth2.subject_alternative_name, "dns:example.net")

        self.assertEqual(
            SubjectAlternativeName({"value": [self.auth1.subject_alternative_name]}).extension_type,
            x509.SubjectAlternativeName([x509.DNSName("example.com")]),
        )
        self.assertEqual(
            SubjectAlternativeName({"value": [self.auth2.subject_alternative_name]}).extension_type,
            x509.SubjectAlternativeName([x509.DNSName("example.net")]),
        )

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
        self, challenge: ChallengeTypeVar, typ: str, token: bytes, cls: typing.Type[ChallengeTypeVar]
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
            self.chall.acme_challenge  # pylint: disable=pointless-statement

    @freeze_time(timestamps["everything_valid"])
    def test_acme_validated(self) -> None:
        """Test acme_calidated property."""

        # preconditions for checks (might change them in setUp without realising it might affect this test)
        self.assertNotEqual(self.chall.status, AcmeChallenge.STATUS_VALID)
        self.assertIsNone(self.chall.validated)

        self.assertIsNone(self.chall.acme_validated)

        self.chall.status = AcmeChallenge.STATUS_VALID
        self.assertIsNone(self.chall.acme_validated)  # still None (no validated timestamp)

        self.chall.validated = timezone.now()
        self.assertEqual(self.chall.acme_validated, timezone.make_aware(timezone.now(), timezone=tz.utc))

        with self.settings(USE_TZ=True):
            self.chall.validated = timezone.now()
            self.assertEqual(self.chall.acme_validated, timezone.now())

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
            self.chall.expected  # pylint: disable=pointless-statement  # this is a computed property

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
        self.acme_cert.csr = certs["root-cert"]["csr"]["pem"]
        self.assertIsInstance(self.acme_cert.parse_csr(), x509.CertificateSigningRequest)

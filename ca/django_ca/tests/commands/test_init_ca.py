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

"""Test the init_ca management command."""

import io
import re
import typing
from datetime import timedelta
from typing import Any, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from freezegun import freeze_time

from django_ca import ca_settings
from django_ca.constants import ExtendedKeyUsageOID
from django_ca.models import Certificate, CertificateAuthority
from django_ca.tests.base.assertions import assert_authority_key_identifier, assert_create_ca_signals
from django_ca.tests.base.constants import TIMESTAMPS
from django_ca.tests.base.mixins import TestCaseMixin
from django_ca.tests.base.utils import (
    authority_information_access,
    basic_constraints,
    certificate_policies,
    crl_distribution_points,
    distribution_point,
    dns,
    extended_key_usage,
    issuer_alternative_name,
    key_usage,
    name_constraints,
    ocsp_no_check,
    override_tmpcadir,
    subject_alternative_name,
    uri,
)
from django_ca.utils import get_crl_cache_key, int_to_hex


class InitCATest(TestCaseMixin, TestCase):
    """Test the init_ca management command."""

    def init_ca(self, **kwargs: Any) -> Tuple[str, str]:
        """Run a basic init_ca command."""
        stdout = io.StringIO()
        stderr = io.StringIO()
        name = kwargs.pop("name", "Test CA")
        if kwargs.get("key_type", "RSA") in ("RSA", "DSA"):
            kwargs.setdefault("key_size", ca_settings.CA_MIN_KEY_SIZE)

        return self.cmd(
            "init_ca",
            name,
            f"C=AT,ST=Vienna,L=Vienna,O=Org,OU=OrgUnit,CN={name}",
            subject_format="rfc4514",
            stdout=stdout,
            stderr=stderr,
            **kwargs,
        )

    def init_ca_e2e(
        self, name: str, *args: str, chain: Optional[List[CertificateAuthority]] = None
    ) -> CertificateAuthority:
        """Run a init_ca command via cmd_e2e()."""
        if chain is None:
            chain = []

        with assert_create_ca_signals() as (pre, post):
            out, err = self.cmd_e2e(["init_ca", name, *args])
        self.assertEqual(out, "")
        self.assertEqual(err, "")

        ca = CertificateAuthority.objects.get(name=name)
        self.assertPostCreateCa(post, ca)
        self.assertPrivateKey(ca)
        ca.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([*chain, ca], ca)

        return ca

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    @freeze_time(TIMESTAMPS["everything_valid"])
    def test_basic(self) -> None:
        """Basic tests for the command."""
        name = "test_basic"
        with assert_create_ca_signals() as (pre, post):
            out, err = self.init_ca(name=name)
        self.assertEqual(out, "")
        self.assertEqual(err, "")

        ca: CertificateAuthority = CertificateAuthority.objects.get(name=name)
        self.assertPostCreateCa(post, ca)
        self.assertPrivateKey(ca)
        self.assertSignature([ca], ca)
        ca.full_clean()  # assert e.g. max_length in serials
        self.assertBasic(ca.pub.loaded, algo=hashes.SHA512)

        # test the private key
        key = typing.cast(RSAPrivateKey, ca.key(None))
        self.assertIsInstance(key, RSAPrivateKey)
        self.assertEqual(key.key_size, 1024)

        self.assertEqual(
            ca.pub.loaded.subject,
            x509.Name(
                [
                    x509.NameAttribute(oid=NameOID.COUNTRY_NAME, value="AT"),
                    x509.NameAttribute(oid=NameOID.STATE_OR_PROVINCE_NAME, value="Vienna"),
                    x509.NameAttribute(oid=NameOID.LOCALITY_NAME, value="Vienna"),
                    x509.NameAttribute(oid=NameOID.ORGANIZATION_NAME, value="Org"),
                    x509.NameAttribute(oid=NameOID.ORGANIZATIONAL_UNIT_NAME, value="OrgUnit"),
                    x509.NameAttribute(oid=NameOID.COMMON_NAME, value=name),
                ]
            ),
        )
        self.assertIssuer(ca, ca)
        assert_authority_key_identifier(ca, ca)
        self.assertEqual(ca.serial, int_to_hex(ca.pub.loaded.serial_number))

        # Test that extensions that do not work for root CAs are NOT present
        self.assertNotIn(ExtensionOID.AUTHORITY_INFORMATION_ACCESS, ca.extensions)
        self.assertNotIn(ExtensionOID.CRL_DISTRIBUTION_POINTS, ca.extensions)

        # Test extensions for signing
        self.assertIsNotNone(ca.sign_authority_information_access)
        self.assertIsNone(ca.sign_certificate_policies)
        self.assertIsNotNone(ca.sign_crl_distribution_points)
        self.assertIsNone(ca.sign_issuer_alternative_name)

        # Check the OCSP responder certificate
        cert: Certificate = Certificate.objects.get(ca=ca, autogenerated=True)
        expected_subject = x509.Name(
            [x509.NameAttribute(oid=NameOID.COMMON_NAME, value=f"{name} OCSP authorized responder")]
        )
        self.assertEqual(cert.subject, expected_subject)
        expected_authority_information_access = x509.Extension(
            oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
            critical=ca.sign_authority_information_access.critical,  # type: ignore[union-attr]
            value=x509.AuthorityInformationAccess(
                [
                    ad
                    for ad in ca.sign_authority_information_access.value  # type: ignore[union-attr]
                    if ad.access_method == AuthorityInformationAccessOID.CA_ISSUERS
                ]
            ),
        )
        self.assertExtensions(
            cert,
            [
                ocsp_no_check(),
                extended_key_usage(ExtendedKeyUsageOID.OCSP_SIGNING),
                key_usage(digital_signature=True, content_commitment=True, key_encipherment=True),
                expected_authority_information_access,
            ],
            signer=ca,
        )

        # Validate the CRL from the cache
        cache_key = get_crl_cache_key(ca.serial, Encoding.PEM, scope="user")
        user_idp = self.get_idp(full_name=self.get_idp_full_name(ca), only_contains_user_certs=True)
        crl = cache.get(cache_key)
        self.assertCRL(crl, signer=ca, algorithm=ca.algorithm, idp=user_idp)

        cache_key = get_crl_cache_key(ca.serial, Encoding.PEM, scope="ca")
        ca_idp = self.get_idp(full_name=None, only_contains_ca_certs=True)
        crl = cache.get(cache_key)
        self.assertCRL(crl, signer=ca, algorithm=ca.algorithm, idp=ca_idp)

    @override_settings(USE_TZ=False)
    def test_basic_without_timezone_support(self) -> None:
        """Basic test without timezone support."""
        return self.test_basic()

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_arguments(self) -> None:
        """Test most arguments."""
        hostname = "example.com"
        website = f"https://{hostname}"
        tos = f"{website}/tos/"
        caa = f"caa.{hostname}"
        name = "test_arguments"

        ca = self.init_ca_e2e(
            name,
            "CN={self.hostname}",
            "--subject-format=rfc4514",
            "--algorithm=SHA-256",  # hashes.SHA256(),
            "--key-type=EC",
            "--expires=720",
            "--sign-ca-issuer=http://issuer.ca.example.com",
            "--sign-issuer-alternative-name=http://ian.ca.example.com",
            "--sign-crl-full-name=http://crl.example.com",
            "--sign-ocsp-responder=http://ocsp.example.com",
            f"--caa={caa}",
            f"--website={website}",
            f"--tos={tos}",
        )

        actual = ca.extensions
        self.assertNotIn(ExtensionOID.CRL_DISTRIBUTION_POINTS, actual)

        # test the private key
        key = typing.cast(ec.EllipticCurvePrivateKey, ca.key(None))
        self.assertIsInstance(key, ec.EllipticCurvePrivateKey)
        self.assertEqual(key.key_size, 256)

        self.assertIsInstance(ca.pub.loaded.signature_hash_algorithm, hashes.SHA256)
        self.assertIsInstance(ca.pub.loaded.public_key(), ec.EllipticCurvePublicKey)
        self.assertEqual(ca.path_length, 0)
        self.assertEqual(ca.max_path_length, 0)
        self.assertFalse(ca.allows_intermediate_ca)
        self.assertEqual(
            ca.sign_authority_information_access,
            authority_information_access(
                ca_issuers=[uri("http://issuer.ca.example.com")], ocsp=[uri("http://ocsp.example.com")]
            ),
        )
        self.assertEqual(
            ca.sign_issuer_alternative_name, issuer_alternative_name(uri("http://ian.ca.example.com"))
        )
        self.assertEqual(
            ca.sign_crl_distribution_points,
            crl_distribution_points(distribution_point([uri("http://crl.example.com")])),
        )
        self.assertIssuer(ca, ca)
        assert_authority_key_identifier(ca, ca)

        # test non-extension properties
        self.assertEqual(ca.caa_identity, caa)
        self.assertEqual(ca.website, website)
        self.assertEqual(ca.terms_of_service, tos)

        # test acme properties
        self.assertFalse(ca.acme_enabled)
        self.assertTrue(ca.acme_registration)
        self.assertTrue(ca.acme_requires_contact)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_add_extensions(self) -> None:
        """Test adding various extensions."""
        ca = self.init_ca_e2e(
            "extensions",
            f"CN={self.hostname}",
            "--subject-format=rfc4514",
            # Basic Constraints extension
            "--path-length=3",
            # Certificate Policies extension
            "--policy-identifier=anyPolicy",
            "--certification-practice-statement=https://example.com/cps1/",
            "--user-notice=user notice text one",
            "--policy-identifier=1.2.3",
            "--user-notice=user notice text two",
            "--certification-practice-statement=https://example.com/cps2/",
            # Extended Key Usage extension
            "--extended-key-usage",
            "clientAuth",
            "1.3.6.1.5.5.7.3.1",  # == serverAuth, to test custom OIDs
            # Inhibit anyPolicy extension
            "--inhibit-any-policy",
            "1",
            # Issuer Alternative Name extension
            "--issuer-alternative-name",
            "DNS:ian.example.com",
            # Key Usage extension
            "--key-usage",
            "keyCertSign",
            "digitalSignature",
            # Name Constraints extension
            "--permit-name=DNS:.com",
            "--exclude-name=DNS:.net",
            # Policy Constraints extension
            "--inhibit-policy-mapping",
            "1",
            "--require-explicit-policy",
            "2",
            # Subject Alternative Name extension
            "--subject-alternative-name",
            "DNS:san.example.com",
            "--subject-alternative-name",
            "URI:https://san.example.net",
        )

        extensions = ca.extensions

        # Test BasicConstraints extension
        self.assertEqual(extensions[ExtensionOID.BASIC_CONSTRAINTS], basic_constraints(True, 3))
        self.assertEqual(ca.path_length, 3)
        self.assertEqual(ca.max_path_length, 3)
        self.assertTrue(ca.allows_intermediate_ca)

        # Test Certificate Policies extension
        self.assertEqual(
            extensions[ExtensionOID.CERTIFICATE_POLICIES],
            certificate_policies(
                x509.PolicyInformation(
                    policy_identifier=x509.ObjectIdentifier("2.5.29.32.0"),
                    policy_qualifiers=[
                        "https://example.com/cps1/",
                        x509.UserNotice(notice_reference=None, explicit_text="user notice text one"),
                    ],
                ),
                x509.PolicyInformation(
                    policy_identifier=x509.ObjectIdentifier("1.2.3"),
                    policy_qualifiers=[
                        x509.UserNotice(notice_reference=None, explicit_text="user notice text two"),
                        "https://example.com/cps2/",
                    ],
                ),
            ),
        )

        # Test Extended Key Usage extension
        self.assertEqual(
            extensions[ExtensionOID.EXTENDED_KEY_USAGE],
            extended_key_usage(ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH),
        )

        # Test Inhibit anyPolicy extension
        self.assertEqual(
            extensions[ExtensionOID.INHIBIT_ANY_POLICY],
            x509.Extension(
                oid=ExtensionOID.INHIBIT_ANY_POLICY, critical=True, value=x509.InhibitAnyPolicy(1)
            ),
        )

        # Test Issuer Alternative Name extension
        self.assertEqual(
            extensions[ExtensionOID.ISSUER_ALTERNATIVE_NAME],
            issuer_alternative_name(dns("ian.example.com")),
        )

        # Test Key Usage extension
        self.assertEqual(
            extensions[ExtensionOID.KEY_USAGE],
            key_usage(key_cert_sign=True, digital_signature=True),
        )

        # Test Name Constraints extension
        self.assertEqual(
            extensions[ExtensionOID.NAME_CONSTRAINTS],
            name_constraints(permitted=[dns(".com")], excluded=[dns(".net")], critical=True),
        )

        # Test Policy Constraints extension
        self.assertEqual(
            extensions[ExtensionOID.POLICY_CONSTRAINTS],
            x509.Extension(
                oid=ExtensionOID.POLICY_CONSTRAINTS,
                critical=True,
                value=x509.PolicyConstraints(inhibit_policy_mapping=1, require_explicit_policy=2),
            ),
        )

        # Test Subject Alternative Name extension
        self.assertEqual(
            extensions[ExtensionOID.SUBJECT_ALTERNATIVE_NAME],
            subject_alternative_name(dns("san.example.com"), uri("https://san.example.net")),
        )

    @override_tmpcadir()
    def test_add_extensions_with_non_default_critical(self) -> None:
        """Test setting non-default critical values."""
        ca = self.init_ca_e2e(
            "extensions",
            "CN=extensions.example.com",
            "--subject-format=rfc4514",
            # Certificate Policies extension:
            "--policy-identifier=anyPolicy",
            "--certificate-policies-critical",
            # Extended Key Usage extension
            "--extended-key-usage",
            "clientAuth",
            "1.3.6.1.5.5.7.3.1",  # == serverAuth, to test custom OIDs
            "--extended-key-usage-critical",
            # Key Usage extension
            "--key-usage",
            "keyCertSign",
            "digitalSignature",
            "--key-usage-non-critical",
            # Subject Alternative Name extension
            "--subject-alternative-name",
            "DNS:san.example.com",
            "--subject-alternative-name",
            "URI:https://san.example.net",
            "--subject-alternative-name-critical",
        )

        extensions = ca.extensions

        # Test Certificate Policies extension
        self.assertEqual(
            extensions[ExtensionOID.CERTIFICATE_POLICIES],
            self.certificate_policies(
                x509.PolicyInformation(
                    policy_identifier=x509.ObjectIdentifier("2.5.29.32.0"), policy_qualifiers=None
                ),
                critical=True,
            ),
        )

        # Test Extended Key Usage extension
        self.assertEqual(
            extensions[ExtensionOID.EXTENDED_KEY_USAGE],
            extended_key_usage(
                ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH, critical=True
            ),
        )

        # Test KeyUsage extension
        self.assertEqual(
            extensions[ExtensionOID.KEY_USAGE],
            key_usage(key_cert_sign=True, digital_signature=True, critical=False),
        )

        # Test Subject Alternative Name extension
        self.assertEqual(
            extensions[ExtensionOID.SUBJECT_ALTERNATIVE_NAME],
            subject_alternative_name(dns("san.example.com"), uri("https://san.example.net"), critical=True),
        )

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_add_extensions_with_formatting(self) -> None:
        """Test adding various extensions."""
        root = self.load_ca("root")

        ca = self.init_ca_e2e(
            "extensions_with_formatting",
            "CN={self.hostname}",
            "--subject-format=rfc4514",
            f"--parent={root.serial}",
            "--ocsp-responder=https://example.com/ocsp/{OCSP_PATH}",
            "--ca-issuer=https://example.com/ca-issuer/{CA_ISSUER_PATH}",
            "--crl-full-name=http://example.com/crl/{CRL_PATH}",
            "--crl-full-name=http://example.net/crl/{CRL_PATH}",
            chain=[root],
        )

        extensions = ca.extensions
        ca_issuer_path = reverse("django_ca:issuer", kwargs={"serial": root.serial})
        ocsp_path = reverse("django_ca:ocsp-ca-post", kwargs={"serial": root.serial})
        crl_path = reverse("django_ca:ca-crl", kwargs={"serial": root.serial})

        # Test AuthorityInformationAccess extension
        self.assertEqual(
            extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS],
            authority_information_access(
                ca_issuers=[uri(f"https://example.com/ca-issuer{ca_issuer_path}")],
                ocsp=[uri(f"https://example.com/ocsp{ocsp_path}")],
            ),
        )

        # Test CRL Distribution Points extension
        self.assertEqual(
            extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS],
            crl_distribution_points(
                distribution_point(
                    [uri(f"http://example.com/crl{crl_path}"), uri(f"http://example.net/crl{crl_path}")]
                )
            ),
        )

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_add_extensions_with_formatting_without_uri(self) -> None:
        """Test adding various extensions."""
        root = self.load_ca("root")

        ca = self.init_ca_e2e(
            "extensions_with_formatting",
            "CN={self.hostname}",
            "--subject-format=rfc4514",
            f"--parent={root.serial}",
            "--ocsp-responder=DNS:example.com",
            "--ca-issuer=DNS:example.net",
            "--crl-full-name=DNS:crl.example.com",
            "--crl-full-name=DNS:crl.example.net",
            chain=[root],
        )

        extensions = ca.extensions

        # Test AuthorityInformationAccess extension
        self.assertEqual(
            extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS],
            x509.Extension(
                oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
                critical=False,
                value=x509.AuthorityInformationAccess(
                    [
                        x509.AccessDescription(
                            access_method=AuthorityInformationAccessOID.OCSP,
                            access_location=dns("example.com"),
                        ),
                        x509.AccessDescription(
                            access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                            access_location=dns("example.net"),
                        ),
                    ]
                ),
            ),
        )

        # Test CRL Distribution Points extension
        self.assertEqual(
            extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS],
            self.crl_distribution_points([dns("crl.example.com"), dns("crl.example.net")]),
        )

    @override_tmpcadir()
    def test_sign_extensions(self) -> None:
        """Test adding extensions for signed certificates."""
        root = self.load_ca("root")

        ca = self.init_ca_e2e(
            "extensions_with_formatting",
            "CN=extensions_with_formatting.example.com",
            f"--parent={root.serial}",
            "--subject-format=rfc4514",
            # Certificate Policies extension
            "--sign-policy-identifier=anyPolicy",
            "--sign-certification-practice-statement=https://example.com/cps1/",
            "--sign-user-notice=user notice text one",
            "--sign-policy-identifier=1.2.3",
            "--sign-user-notice=user notice text two",
            "--sign-certification-practice-statement=https://example.com/cps2/",
            chain=[root],
        )

        # Test Certificate Policies extension
        self.assertNotIn(ExtensionOID.CERTIFICATE_POLICIES, ca.extensions)
        self.assertEqual(
            ca.sign_certificate_policies,
            self.certificate_policies(
                x509.PolicyInformation(
                    policy_identifier=x509.ObjectIdentifier("2.5.29.32.0"),
                    policy_qualifiers=[
                        "https://example.com/cps1/",
                        x509.UserNotice(notice_reference=None, explicit_text="user notice text one"),
                    ],
                ),
                x509.PolicyInformation(
                    policy_identifier=x509.ObjectIdentifier("1.2.3"),
                    policy_qualifiers=[
                        x509.UserNotice(notice_reference=None, explicit_text="user notice text two"),
                        "https://example.com/cps2/",
                    ],
                ),
            ),
        )

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_multiple_ians(self) -> None:
        """Test that we can set multiple IssuerAlternativeName values."""
        name = "test_multiple_ians"
        ca = self.init_ca_e2e(
            name,
            "--sign-issuer-alternative-name=example.com",
            "--sign-issuer-alternative-name=https://example.com",
            "--subject-format=rfc4514",
            f"CN={name}",
        )
        self.assertEqual(
            ca.sign_issuer_alternative_name,
            issuer_alternative_name(dns("example.com"), uri("https://example.com")),
        )

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_acme_arguments(self) -> None:
        """Test ACME arguments."""
        ca = self.init_ca_e2e(
            "Test CA",
            "CN=acme.example.com",
            "--subject-format=rfc4514",
            "--acme-enable",
            "--acme-disable-account-registration",
            "--acme-contact-optional",
            "--acme-profile=client",
        )

        self.assertIs(ca.acme_enabled, True)
        self.assertIs(ca.acme_registration, False)
        self.assertEqual(ca.acme_profile, "client")
        self.assertIs(ca.acme_requires_contact, False)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024, CA_ENABLE_REST_API=True)
    def test_api_arguments(self) -> None:
        """Test REST API arguments."""
        ca = self.init_ca_e2e(
            "Test CA",
            f"CN={self.hostname}",
            "--api-enable",
            "--subject-format=rfc4514",
        )

        self.assertIs(ca.api_enabled, True)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024, CA_ENABLE_ACME=False, CA_ENABLE_REST_API=False)
    def test_disabled_arguments(self) -> None:
        """Test that ACME/REST API options don't work when feature is disabled."""
        command = ["init_ca", "Test CA", "--subject-format=rfc4514", "CN=example.com"]
        with self.assertSystemExit(2):
            self.cmd_e2e([*command, "--acme-enable"])

        with self.assertSystemExit(2):
            self.cmd_e2e([*command, "--acme-disable"])

        with self.assertSystemExit(2):
            self.cmd_e2e([*command, "--acme-disable-account-registration"])

        with self.assertSystemExit(2):
            self.cmd_e2e([*command, "--acme-enable-account-registration"])

        with self.assertSystemExit(2):
            self.cmd_e2e([*command, "--acme-contact-optional"])

        with self.assertSystemExit(2):
            self.cmd_e2e([*command, "--acme-profile=client"])

        with self.assertSystemExit(2):
            self.cmd_e2e([*command, "--api-enable"])

    @override_tmpcadir()
    def test_unknown_acme_profile(self) -> None:
        """Test naming an unknown profile."""
        with self.assertCommandError(r"^unknown-profile: Profile is not defined\.$"):
            self.init_ca(name="test", acme_profile="unknown-profile")

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_ocsp_responder_arguments(self) -> None:
        """Test ACME arguments."""
        ca = self.init_ca_e2e(
            "Test CA",
            f"CN={self.hostname}",
            "--subject-format=rfc4514",
            "--ocsp-responder-key-validity=10",
            "--ocsp-response-validity=3600",
        )

        self.assertEqual(ca.ocsp_responder_key_validity, 10)
        self.assertEqual(ca.ocsp_response_validity, 3600)

    @override_tmpcadir()
    def test_invalid_ocsp_responder_arguments(self) -> None:
        """Test naming an unknown profile."""
        self.assertE2EError(
            ["init_ca", "--subject-format=rfc4514", "CN=example.com", "--ocsp-responder-key-validity=0"],
            stderr=re.compile(r"--ocsp-responder-key-validity: DAYS must be equal or greater then 1\."),
        )

        self.assertE2EError(
            ["init_ca", "--subject-format=rfc4514", "CN=example.com", "--ocsp-response-validity=10"],
            stderr=re.compile(r"--ocsp-response-validity: SECONDS must be equal or greater then 600\."),
        )

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_ec(self) -> None:
        """Test creating an ECC CA."""
        name = "test_ec"
        with assert_create_ca_signals() as (pre, post):
            out, err = self.init_ca(
                name=name, algorithm=hashes.SHA256(), key_type="EC", expires=self.expires(720)
            )
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        ca = CertificateAuthority.objects.get(name=name)
        self.assertPostCreateCa(post, ca)
        self.assertIsInstance(ca.key(None), ec.EllipticCurvePrivateKey)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_dsa_private_key(self) -> None:
        """Test creating a certificate authority with a DSA private key."""
        name = "test_dsa"
        with assert_create_ca_signals() as (pre, post):
            out, err = self.init_ca(
                name=name, algorithm=hashes.SHA256(), key_type="DSA", expires=self.expires(720), path_length=3
            )
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        ca = CertificateAuthority.objects.get(name=name)
        self.assertPostCreateCa(post, ca)
        ca_key = typing.cast(dsa.DSAPrivateKey, ca.key())
        self.assertIsInstance(ca_key, dsa.DSAPrivateKey)
        self.assertEqual(ca_key.key_size, 1024)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_permitted(self) -> None:
        """Test the NameConstraints extension with 'permitted'."""
        name = "test_permitted"
        ca = self.init_ca_e2e(name, "--subject-format=rfc4514", "--permit-name", "DNS:.com", f"CN={name}")
        self.assertEqual(
            ca.extensions[ExtensionOID.NAME_CONSTRAINTS],
            name_constraints(permitted=[dns(".com")], critical=True),
        )

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_excluded(self) -> None:
        """Test the NameConstraints extension with 'excluded'."""
        name = "test_excluded"
        ca = self.init_ca_e2e(name, "--subject-format=rfc4514", "--exclude-name", "DNS:.com", f"CN={name}")
        self.assertEqual(
            ca.extensions[ExtensionOID.NAME_CONSTRAINTS],
            name_constraints(excluded=[dns(".com")], critical=True),
        )

    @override_settings(USE_TZ=False)
    def test_arguments_without_timezone_support(self) -> None:
        """Test arguments without timezone support."""
        self.test_arguments()

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_no_path_length(self) -> None:
        """Test creating a CA with no path length."""
        name = "test_no_path_length"
        with assert_create_ca_signals() as (pre, post):
            out, err = self.init_ca(name=name, path_length=None)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        ca = CertificateAuthority.objects.get(name=name)
        self.assertPostCreateCa(post, ca)
        ca.full_clean()  # assert e.g. max_length in serials
        self.assertPrivateKey(ca)
        self.assertSignature([ca], ca)
        self.assertEqual(ca.max_path_length, None)
        self.assertEqual(ca.path_length, None)
        self.assertTrue(ca.allows_intermediate_ca)
        self.assertIssuer(ca, ca)
        assert_authority_key_identifier(ca, ca)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_empty_subject_fields(self) -> None:
        """Test creating a CA with empty subject fields."""
        name = "test_empty_subject_fields"
        with assert_create_ca_signals() as (pre, post):
            out, err = self.cmd("init_ca", name, f"L=,CN={self.hostname}", subject_format="rfc4514")
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        ca = CertificateAuthority.objects.get(name=name)
        self.assertPostCreateCa(post, ca)
        ca.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([ca], ca)
        self.assertEqual(
            ca.pub.loaded.subject,
            x509.Name(
                [
                    x509.NameAttribute(NameOID.LOCALITY_NAME, ""),
                    x509.NameAttribute(NameOID.COMMON_NAME, self.hostname),
                ]
            ),
        )
        self.assertIssuer(ca, ca)
        assert_authority_key_identifier(ca, ca)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_no_cn(self) -> None:
        """Test creating a CA with no CommonName."""
        name = "test_no_cn"
        subject = "C=AT,ST=Vienna,L=Vienna,O=Org,OU=OrgUnit"
        error = r"^Subject must contain a common name \(CN=\.\.\.\)\.$"
        with assert_create_ca_signals(False, False), self.assertCommandError(error):
            self.cmd("init_ca", name, subject, subject_format="rfc4514")

        error = r"CommonName must not be an empty value"
        subject = "C=AT,ST=Vienna,L=Vienna,O=Org,OU=OrgUnit,CN="
        with assert_create_ca_signals(False, False), self.assertCommandError(error):
            self.cmd("init_ca", name, subject, subject_format="rfc4514")

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_parent(self) -> None:
        """Test creating a CA and an intermediate CA."""
        with assert_create_ca_signals() as (pre, post):
            out, err = self.init_ca(name="Parent", path_length=1)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        parent = CertificateAuthority.objects.get(name="Parent")
        self.assertPostCreateCa(post, parent)
        parent.full_clean()  # assert e.g. max_length in serials
        self.assertPrivateKey(parent)
        self.assertSignature([parent], parent)

        # test that the default is not a child-relationship
        with assert_create_ca_signals() as (pre, post):
            out, err = self.init_ca(name="Second")
        self.assertEqual(out, "")
        self.assertEqual(err, "")

        second = CertificateAuthority.objects.get(name="Second")
        self.assertPostCreateCa(post, second)
        second.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([second], second)
        self.assertIsNone(second.parent)

        crl_full_name = uri("http://ca.crl.example.com")
        with assert_create_ca_signals() as (pre, post):
            out, err = self.init_ca(
                name="Child",
                parent=parent,
                crl_full_names=[crl_full_name],
                authority_information_access=authority_information_access(
                    ocsp=[uri("http://passed.ca.ocsp.example.com")]
                ).value,
            )
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        child = CertificateAuthority.objects.get(name="Child")
        self.assertPostCreateCa(post, child)
        child.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([parent], child)
        self.assertPrivateKey(child)

        self.assertIsNone(parent.parent)
        self.assertEqual(child.parent, parent)
        self.assertEqual(list(child.children.all()), [])
        self.assertEqual(list(parent.children.all()), [child])
        self.assertIssuer(parent, child)
        assert_authority_key_identifier(parent, child)
        self.assertEqual(
            child.extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS],
            self.crl_distribution_points([crl_full_name]),
        )
        ca_issuer_path = reverse("django_ca:issuer", kwargs={"serial": parent.serial})
        self.assertEqual(
            child.extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS],
            authority_information_access(
                ca_issuers=[uri(f"http://{ca_settings.CA_DEFAULT_HOSTNAME}{ca_issuer_path}")],
                ocsp=[uri("http://passed.ca.ocsp.example.com")],
            ),
        )

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_intermediate_check(self) -> None:  # noqa: PLR0915
        """Test intermediate path length checks."""
        with assert_create_ca_signals() as (pre, post):
            out, err = self.init_ca(name="default")
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        parent = CertificateAuthority.objects.get(name="default")
        self.assertPostCreateCa(post, parent)
        self.assertPrivateKey(parent)
        parent.full_clean()  # assert e.g. max_length in serials
        self.assertEqual(parent.path_length, 0)
        self.assertEqual(parent.max_path_length, 0)
        self.assertFalse(parent.allows_intermediate_ca)

        with assert_create_ca_signals() as (pre, post):
            out, err = self.init_ca(name="path-length-1", path_length=1)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        path_length_1 = CertificateAuthority.objects.get(name="path-length-1")
        self.assertPostCreateCa(post, path_length_1)
        path_length_1.full_clean()  # assert e.g. max_length in serials
        self.assertPrivateKey(path_length_1)
        self.assertEqual(path_length_1.path_length, 1)
        self.assertEqual(path_length_1.max_path_length, 1)
        self.assertTrue(path_length_1.allows_intermediate_ca)

        with assert_create_ca_signals() as (pre, post):
            out, err = self.init_ca(name="path-length-1-none", path_length=None, parent=path_length_1)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        path_length_1_none = CertificateAuthority.objects.get(name="path-length-1-none")
        self.assertPostCreateCa(post, path_length_1_none)
        path_length_1_none.full_clean()  # assert e.g. max_length in serials
        self.assertPrivateKey(path_length_1_none)

        # path_length_1_none cannot have an intermediate CA because parent has path_length=1
        self.assertIsNone(path_length_1_none.path_length)
        self.assertEqual(path_length_1_none.max_path_length, 0)
        self.assertFalse(path_length_1_none.allows_intermediate_ca)
        with self.assertCommandError(
            r"^Parent CA cannot create intermediate CA due to path length restrictions\.$"
        ), assert_create_ca_signals(False, False):
            out, err = self.init_ca(name="wrong", parent=path_length_1_none)
        self.assertEqual(out, "")
        self.assertEqual(err, "")

        with assert_create_ca_signals() as (pre, post):
            out, err = self.init_ca(name="path-length-1-three", path_length=3, parent=path_length_1)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        path_length_1_three = CertificateAuthority.objects.get(name="path-length-1-three")
        self.assertPostCreateCa(post, path_length_1_three)
        path_length_1_three.full_clean()  # assert e.g. max_length in serials
        self.assertPrivateKey(path_length_1_three)

        # path_length_1_none cannot have an intermediate CA because parent has path_length=1
        self.assertEqual(path_length_1_three.path_length, 3)
        self.assertEqual(path_length_1_three.max_path_length, 0)
        self.assertFalse(path_length_1_three.allows_intermediate_ca)
        with self.assertCommandError(
            r"^Parent CA cannot create intermediate CA due to path length restrictions\.$"
        ), assert_create_ca_signals(False, False):
            out, _err = self.init_ca(name="wrong", parent=path_length_1_none)
        self.assertEqual(out, "")

        with assert_create_ca_signals() as (pre, post):
            out, err = self.init_ca(name="path-length-none", path_length=None)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        path_length_none = CertificateAuthority.objects.get(name="path-length-none")
        self.assertPostCreateCa(post, path_length_none)
        path_length_none.full_clean()  # assert e.g. max_length in serials
        self.assertPrivateKey(path_length_none)
        self.assertIsNone(path_length_none.path_length)
        self.assertIsNone(path_length_none.max_path_length, None)
        self.assertTrue(path_length_none.allows_intermediate_ca)

        with assert_create_ca_signals() as (pre, post):
            out, err = self.init_ca(name="path-length-none-none", path_length=None, parent=path_length_none)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        path_length_none_none = CertificateAuthority.objects.get(name="path-length-none-none")
        self.assertPostCreateCa(post, path_length_none_none)
        path_length_none_none.full_clean()  # assert e.g. max_length in serials
        self.assertIsNone(path_length_none_none.path_length)
        self.assertIsNone(path_length_none_none.max_path_length)

        with assert_create_ca_signals() as (pre, post):
            out, err = self.init_ca(name="path-length-none-1", path_length=1, parent=path_length_none)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        path_length_none_1 = CertificateAuthority.objects.get(name="path-length-none-1")
        self.assertPostCreateCa(post, path_length_none_1)
        path_length_none_1.full_clean()  # assert e.g. max_length in serials
        self.assertEqual(path_length_none_1.path_length, 1)
        self.assertEqual(path_length_none_1.max_path_length, 1)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_expires_override(self) -> None:
        """Test that if we request an expiry after that of the parent, we override to that of the parent."""
        with assert_create_ca_signals() as (pre, post):
            out, err = self.init_ca(name="Parent", path_length=1)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        parent = CertificateAuthority.objects.get(name="Parent")
        self.assertPostCreateCa(post, parent)
        parent.full_clean()  # assert e.g. max_length in serials
        self.assertPrivateKey(parent)
        self.assertSignature([parent], parent)

        # test that the default is not a child-relationship
        with assert_create_ca_signals() as (pre, post):
            out, err = self.init_ca(name="Second")
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        second = CertificateAuthority.objects.get(name="Second")
        self.assertPostCreateCa(post, second)
        second.full_clean()  # assert e.g. max_length in serials
        self.assertIsNone(second.parent)
        self.assertSignature([second], second)

        expires = parent.expires - timezone.now() + timedelta(days=10)
        with assert_create_ca_signals() as (pre, post):
            out, err = self.init_ca(name="Child", parent=parent, expires=expires)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        child = CertificateAuthority.objects.get(name="Child")
        self.assertPostCreateCa(post, child)
        child.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([parent], child)

        self.assertEqual(parent.expires, child.expires)
        self.assertIsNone(parent.parent)
        self.assertEqual(child.parent, parent)
        self.assertEqual(list(child.children.all()), [])
        self.assertEqual(list(parent.children.all()), [child])
        self.assertIssuer(parent, child)
        assert_authority_key_identifier(parent, child)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024, USE_TZ=False)
    def test_expires_override_with_use_tz_false(self) -> None:
        """Test silently limiting expiry if USE_TZ=False."""
        self.init_ca(name="Parent", path_length=1, expires=timedelta(days=100))
        parent = CertificateAuthority.objects.get(name="Parent")

        self.init_ca(name="Child", expires=timedelta(days=300), parent=parent)
        ca = CertificateAuthority.objects.get(name="Child")
        self.assertIsNone(ca.expires.tzinfo)
        self.assertEqual(ca.expires, parent.expires)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_password(self) -> None:
        """Test creating a CA with a password."""
        password = b"testpassword"
        with assert_create_ca_signals() as (pre, post):
            out, err = self.init_ca(name="Parent", password=password, path_length=1)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        parent = CertificateAuthority.objects.get(name="Parent")
        self.assertPostCreateCa(post, parent)
        parent.full_clean()  # assert e.g. max_length in serials
        self.assertPrivateKey(parent, password=password)
        self.assertSignature([parent], parent)

        # Assert that we cannot access this without a password
        msg = "^Password was not given but private key is encrypted$"
        parent = CertificateAuthority.objects.get(name="Parent")
        with self.assertRaisesRegex(TypeError, msg):
            parent.key(None)

        # Wrong password doesn't work either
        with self.assertRaises(ValueError):
            # NOTE: cryptography is notoriously unstable when it comes to the error message here, so we only
            # check the exception class.
            parent.key(b"wrong")

        # test the private key
        key = typing.cast(RSAPrivateKey, parent.key(password))
        self.assertIsInstance(key, RSAPrivateKey)
        self.assertEqual(key.key_size, 1024)

        # create a child ca, also password protected
        child_password = b"childpassword"
        parent = CertificateAuthority.objects.get(name="Parent")  # Get again, key is cached

        with self.assertCommandError(
            r"^Password was not given but private key is encrypted$"
        ), assert_create_ca_signals(False, False):
            out, err = self.init_ca(name="Child", parent=parent, password=child_password)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        self.assertIsNone(CertificateAuthority.objects.filter(name="Child").first())

        # Create again with parent ca
        with assert_create_ca_signals() as (pre, post):
            out, err = self.init_ca(
                name="Child", parent=parent, password=child_password, parent_password=password
            )
        self.assertEqual(out, "")
        self.assertEqual(err, "")

        child = CertificateAuthority.objects.get(name="Child")
        self.assertPostCreateCa(post, child)
        child.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([parent], child)

        # test the private key
        key = typing.cast(RSAPrivateKey, child.key(child_password))
        self.assertIsInstance(key, RSAPrivateKey)
        self.assertEqual(key.key_size, 1024)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    @freeze_time(TIMESTAMPS["everything_valid"])
    def test_default_hostname(self) -> None:
        """Test manually passing a default hostname.

        Note: freeze time b/c this test uses root CA as a parent.
        """
        root = self.load_ca("root")

        name = "ca"
        hostname = "test-default-hostname.com"
        with assert_create_ca_signals() as (pre, post):
            out, err = self.init_ca(name=name, parent=root, default_hostname=hostname)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        ca = CertificateAuthority.objects.get(name=name)
        self.assertPostCreateCa(post, ca)

        # Test signing extensions
        self.assertEqual(
            ca.sign_authority_information_access,
            authority_information_access(
                ca_issuers=[uri(f"http://{hostname}/django_ca/issuer/{root.serial}.der")],
                ocsp=[uri(f"http://{hostname}/django_ca/ocsp/{ca.serial}/cert/")],
            ),
        )
        crl_urlpath = self.reverse("crl", serial=ca.serial)
        self.assertEqual(
            ca.sign_crl_distribution_points,
            crl_distribution_points(distribution_point([uri(f"http://{hostname}{crl_urlpath}")])),
        )

        ca_crl_urlpath = self.reverse("ca-crl", serial=root.serial)
        self.assertEqual(
            ca.extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS],
            crl_distribution_points(distribution_point([uri(f"http://{hostname}{ca_crl_urlpath}")])),
        )
        self.assertEqual(
            ca.extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS],
            authority_information_access(
                ca_issuers=[uri(f"http://{hostname}/django_ca/issuer/{root.serial}.der")],
                ocsp=[uri(f"http://{hostname}/django_ca/ocsp/{root.serial}/ca/")],
            ),
        )

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_no_default_hostname(self) -> None:
        """Disable default hostname via the command line."""
        name = "ca"
        with assert_create_ca_signals() as (pre, post):
            out, err = self.init_ca(name=name, default_hostname=False)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        ca = CertificateAuthority.objects.get(name=name)
        self.assertPostCreateCa(post, ca)

        self.assertNotIn(ExtensionOID.AUTHORITY_INFORMATION_ACCESS, ca.extensions)
        self.assertNotIn(ExtensionOID.CRL_DISTRIBUTION_POINTS, ca.extensions)
        self.assertIsNone(ca.sign_authority_information_access)
        self.assertIsNone(ca.sign_crl_distribution_points)
        self.assertIsNone(ca.sign_issuer_alternative_name)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_multiple_ocsp_and_ca_issuers(self) -> None:
        """Test using multiple OCSP responders and CA issuers."""
        root = self.load_ca("root")
        name = self._testMethodName[:32]

        ocsp_uri_one = "http://ocsp.example.com/one"
        ocsp_uri_two = "http://ocsp.example.net/two"
        issuer_uri_one = "http://issuer.example.com/one"
        issuer_uri_two = "http://issuer.example.com/two"
        ca = self.init_ca_e2e(
            name,
            f"CN={name}",
            "--subject-format=rfc4514",
            f"--parent={root.serial}",
            # NOTE: mixing the order of arguments here. This way we make sure that the values are properly
            # sorted (by method) in the assertion for the extension.
            f"--ocsp-responder={ocsp_uri_one}",
            f"--ca-issuer={issuer_uri_one}",
            f"--ocsp-responder={ocsp_uri_two}",
            f"--ca-issuer={issuer_uri_two}",
            chain=[root],
        )

        actual = ca.extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS]
        expected = authority_information_access(
            [uri(issuer_uri_one), uri(issuer_uri_two)], [uri(ocsp_uri_one), uri(ocsp_uri_two)]
        )
        self.assertEqual(actual, expected)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_invalid_public_key_parameters(self) -> None:
        """Test passing invalid public key parameters."""
        msg = r"^Ed25519 keys do not allow an algorithm for signing\.$"
        with self.assertCommandError(msg), assert_create_ca_signals(False, False):
            self.init_ca(name="invalid-public-key-parameters", key_type="Ed25519", algorithm=hashes.SHA256())

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_root_ca_crl_url(self) -> None:
        """Test that you cannot create a CA with a CRL URL."""
        with self.assertCommandError(r"^CRLs cannot be used to revoke root CAs\.$"), assert_create_ca_signals(
            False, False
        ):
            self.init_ca(name="foobar", crl_full_name="https://example.com")

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_root_ca_ocsp_responder(self) -> None:
        """Test that you cannot create a root CA with a OCSP responder."""
        aia = authority_information_access(ocsp=[uri("http://example.com")])
        with self.assertCommandError(
            r"^URI:http://example.com: OCSP responder cannot be added to root CAs\.$"
        ), assert_create_ca_signals(False, False):
            self.init_ca(name="foobar", authority_information_access=aia.value)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_root_ca_issuer(self) -> None:
        """Test that you cannot create a root CA with a CA issuer field."""
        aia = authority_information_access(ca_issuers=[uri("http://example.com")])
        with self.assertCommandError(
            r"^URI:http://example.com: CA issuer cannot be added to root CAs\.$"
        ), assert_create_ca_signals(False, False):
            self.init_ca(name="foobar", authority_information_access=aia.value)

    @override_tmpcadir()
    def test_small_key_size(self) -> None:
        """Test creating a key with a key size that is too small."""
        with self.assertCommandError(r"^256: Key size must be least 1024 bits$"), assert_create_ca_signals(
            False, False
        ):
            self.init_ca(key_size=256)

    @override_tmpcadir()
    def test_key_not_power_of_two(self) -> None:
        """Test creating a key with invalid key size."""
        with self.assertCommandError(r"^2049: Key size must be a power of two$"), assert_create_ca_signals(
            False, False
        ):
            self.init_ca(key_size=2049)

    @override_tmpcadir()
    def test_deprecated_subject_format(self) -> None:
        """Test passing a subject in the deprecated OpenSSL-style format."""
        stdout = io.StringIO()
        stderr = io.StringIO()
        name = "Test CA"

        with assert_create_ca_signals() as (pre, post):
            out, err = self.cmd("init_ca", name, f"/CN={name}", stdout=stdout, stderr=stderr)
        self.assertEqual(out, "")
        # message is too long, just make sure it's there:
        self.assertIn(f"WARNING: /CN={name}: openssl-style format is deprecated", err)

        ca: CertificateAuthority = CertificateAuthority.objects.get(name=name)
        self.assertEqual(ca.cn, name)
        self.assertEqual(ca.pub.loaded.subject, x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))

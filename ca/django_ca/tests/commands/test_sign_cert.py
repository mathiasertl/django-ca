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

"""Test the sign_cert management command."""

import io
import os
from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import CertificatePoliciesOID, ExtendedKeyUsageOID, ExtensionOID, NameOID

from django.core.files.storage import storages
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from freezegun import freeze_time

from django_ca import ca_settings
from django_ca.models import Certificate, CertificateAuthority
from django_ca.tests.base.constants import CERT_DATA, TIMESTAMPS
from django_ca.tests.base.mixins import TestCaseMixin
from django_ca.tests.base.utils import (
    authority_information_access,
    certificate_policies,
    crl_distribution_points,
    distribution_point,
    dns,
    extended_key_usage,
    issuer_alternative_name,
    key_usage,
    ocsp_no_check,
    override_tmpcadir,
    subject_alternative_name,
    tls_feature,
    uri,
)

csr: bytes = CERT_DATA["root-cert"]["csr"]["parsed"].public_bytes(Encoding.PEM)


@override_settings(CA_MIN_KEY_SIZE=1024, CA_PROFILES={}, CA_DEFAULT_SUBJECT=tuple())
@freeze_time(TIMESTAMPS["everything_valid"])
class SignCertTestCase(TestCaseMixin, TestCase):  # pylint: disable=too-many-public-methods
    """Main test class for this command."""

    default_ca = "root"
    load_cas = "__usable__"

    @override_tmpcadir()
    def test_from_stdin(self) -> None:
        """Test reading CSR from stdin."""
        with self.assertCreateCertSignals() as (pre, post):
            stdout, stderr = self.cmd(
                "sign_cert",
                ca=self.ca,
                subject=self.subject.rfc4514_string(),
                subject_format="rfc4514",
                stdin=csr,
            )
        self.assertEqual(stderr, "")

        cert = Certificate.objects.get(cn=self.hostname)
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertEqual(cert.pub.loaded.subject, self.subject)
        self.assertEqual(stdout, f"Please paste the CSR:\n{cert.pub.pem}")

        actual = cert.extensions
        self.assertEqual(
            actual[ExtensionOID.KEY_USAGE],
            key_usage(digital_signature=True, key_agreement=True, key_encipherment=True),
        )
        self.assertEqual(
            actual[ExtensionOID.EXTENDED_KEY_USAGE], extended_key_usage(ExtendedKeyUsageOID.SERVER_AUTH)
        )
        self.assertNotIn(ExtensionOID.SUBJECT_ALTERNATIVE_NAME, actual)
        self.assertIssuer(self.ca, cert)
        self.assertAuthorityKeyIdentifier(self.ca, cert)

    @override_tmpcadir()
    def test_with_bundle(self) -> None:
        """Test outputting the whole certificate bundle."""
        stdout, stderr = self.cmd(
            "sign_cert",
            bundle=True,
            ca=self.ca,
            subject=self.subject.rfc4514_string(),
            subject_format="rfc4514",
            stdin=csr,
        )
        cert = Certificate.objects.get()
        self.assertEqual(stdout, f"Please paste the CSR:\n{cert.bundle_as_pem}")
        self.assertEqual(stderr, "")

    @override_tmpcadir()
    def test_usable_cas(self) -> None:
        """Test signing with all usable CAs."""
        for name, ca in self.cas.items():
            stdin = CERT_DATA[f"{name}-cert"]["csr"]["parsed"].public_bytes(Encoding.PEM)
            password = CERT_DATA[name].get("password")

            with self.assertCreateCertSignals() as (pre, post):
                stdout, stderr = self.cmd(
                    "sign_cert",
                    ca=ca,
                    subject=self.subject.rfc4514_string(),
                    subject_format="rfc4514",
                    password=password,
                    stdin=stdin,
                )

            self.assertEqual(stderr, "")

            cert = Certificate.objects.get(ca=ca, cn=self.hostname)
            self.assertPostIssueCert(post, cert)
            self.assertSignature(tuple(reversed(ca.bundle)), cert)
            self.assertEqual(cert.pub.loaded.subject, self.subject)
            self.assertEqual(stdout, f"Please paste the CSR:\n{cert.pub.pem}")

            actual = cert.extensions

            self.assertEqual(
                actual[ExtensionOID.KEY_USAGE],
                key_usage(digital_signature=True, key_agreement=True, key_encipherment=True),
            )
            self.assertEqual(
                actual[ExtensionOID.EXTENDED_KEY_USAGE], extended_key_usage(ExtendedKeyUsageOID.SERVER_AUTH)
            )
            self.assertIssuer(ca, cert)
            self.assertAuthorityKeyIdentifier(ca, cert)

    @override_tmpcadir()
    def test_from_file(self) -> None:
        """Test reading CSR from file."""
        csr_path = os.path.join(ca_settings.CA_DIR, f"{self.hostname}.csr")
        with open(csr_path, "wb") as csr_stream:
            csr_stream.write(csr)

        with self.assertCreateCertSignals() as (pre, post):
            stdout, stderr = self.cmd(
                "sign_cert",
                ca=self.ca,
                subject=self.subject.rfc4514_string(),
                subject_format="rfc4514",
                csr=csr_path,
            )
        self.assertEqual(stderr, "")

        cert = Certificate.objects.get()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)

        self.assertEqual(cert.pub.loaded.subject, self.subject)
        self.assertEqual(stdout, cert.pub.pem)
        actual = cert.extensions
        self.assertEqual(
            actual[ExtensionOID.KEY_USAGE],
            key_usage(digital_signature=True, key_agreement=True, key_encipherment=True),
        )
        self.assertEqual(
            actual[ExtensionOID.EXTENDED_KEY_USAGE], extended_key_usage(ExtendedKeyUsageOID.SERVER_AUTH)
        )
        self.assertNotIn(ExtensionOID.SUBJECT_ALTERNATIVE_NAME, actual)

    @override_tmpcadir()
    def test_to_file(self) -> None:
        """Test writing PEM to file."""
        out_path = os.path.join(ca_settings.CA_DIR, "test.pem")

        try:
            with self.assertCreateCertSignals() as (pre, post):
                stdout, stderr = self.cmd(
                    "sign_cert",
                    ca=self.ca,
                    subject=self.subject.rfc4514_string(),
                    subject_format="rfc4514",
                    out=out_path,
                    stdin=csr,
                )

            cert = Certificate.objects.get()
            self.assertPostIssueCert(post, cert)
            self.assertSignature([self.ca], cert)
            self.assertEqual(stdout, "Please paste the CSR:\n")
            self.assertEqual(stderr, "")

            self.assertIssuer(self.ca, cert)
            self.assertAuthorityKeyIdentifier(self.ca, cert)

            with open(out_path, encoding="ascii") as out_stream:
                from_file = out_stream.read()

            self.assertEqual(cert.pub.pem, from_file)
        finally:
            if os.path.exists(out_path):
                os.remove(out_path)

    @override_tmpcadir()
    def test_with_rsa_with_algorithm(self) -> None:
        """Test creating a CA with a custom algorithm."""
        self.cmd(
            "sign_cert",
            ca=self.ca,
            subject=self.subject.rfc4514_string(),
            subject_format="rfc4514",
            stdin=csr,
            algorithm=hashes.SHA256(),
        )
        cert = Certificate.objects.get()
        self.assertIsInstance(cert.algorithm, hashes.SHA256)

    @override_tmpcadir(CA_DEFAULT_SUBJECT=(("ST", "Vienna"),))
    def test_subject_sort_with_profile_subject(self) -> None:
        """Test that subject is sorted on the command line.

        The subject given in the profile must be updated with the given subject, and the order would not be
        clear otherwise.
        """
        cname = "subject-sort.example.com"
        subject = f"CN={cname},C=AT"  # not the default order
        cmdline = [
            "sign_cert",
            f"--subject={subject}",
            "--subject-format=rfc4514",
            f"--ca={self.ca.serial}",
        ]

        with self.assertCreateCertSignals() as (pre, post):
            stdout, stderr = self.cmd_e2e(cmdline, stdin=csr)

        self.assertEqual(stderr, "")

        cert = Certificate.objects.get()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertEqual(
            cert.pub.loaded.subject,
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "AT"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Vienna"),
                    x509.NameAttribute(NameOID.COMMON_NAME, cname),
                ]
            ),
        )

    @override_tmpcadir(CA_DEFAULT_SUBJECT=None)
    def test_subject_sort_with_no_common_name(self) -> None:
        """Test that the subject is sorted when the CommonName is added via SubjectAlternativeName.

        The subject must be ordered if the CommonName is coming from the SubjectAlternativeName extension, as
        the position of the CommonName would otherwise not be clear.
        """
        subject = "emailAddress=user@example.com,C=AT"  # not the default order
        cmdline = [
            "sign_cert",
            f"--subject={subject}",
            "--subject-format=rfc4514",
            f"--ca={self.ca.serial}",
            f"--alt={self.hostname}",
        ]

        with self.assertCreateCertSignals() as (pre, post):
            stdout, stderr = self.cmd_e2e(cmdline, stdin=csr)

        self.assertEqual(stderr, "")

        cert = Certificate.objects.get()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertEqual(
            cert.pub.loaded.subject,
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "AT"),
                    x509.NameAttribute(NameOID.COMMON_NAME, self.hostname),
                    x509.NameAttribute(NameOID.EMAIL_ADDRESS, "user@example.com"),
                ]
            ),
        )

    @override_tmpcadir()
    def test_no_san(self) -> None:
        """Test signing without passing any SANs."""
        with self.assertCreateCertSignals() as (pre, post):
            stdout, stderr = self.cmd(
                "sign_cert",
                ca=self.ca,
                subject=self.subject.rfc4514_string(),
                subject_format="rfc4514",
                stdin=csr,
            )

        cert = Certificate.objects.get()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertEqual(cert.pub.loaded.subject, self.subject)
        self.assertIssuer(self.ca, cert)
        self.assertAuthorityKeyIdentifier(self.ca, cert)
        self.assertEqual(stdout, f"Please paste the CSR:\n{cert.pub.pem}")
        self.assertEqual(stderr, "")
        self.assertNotIn(ExtensionOID.SUBJECT_ALTERNATIVE_NAME, cert.extensions)

    @override_tmpcadir(
        CA_DEFAULT_SUBJECT=(
            ("C", "AT"),
            ("ST", "Vienna"),
            ("L", "Vienna"),
            ("O", "MyOrg"),
            ("OU", "MyOrgUnit"),
            ("CN", "CommonName"),
            ("emailAddress", "user@example.com"),
        )
    )
    def test_profile_subject(self) -> None:
        """Test signing with a subject in the profile."""
        # first, we only pass an subjectAltName, meaning that even the CommonName is used.
        san = subject_alternative_name(dns(self.hostname))
        with self.assertCreateCertSignals() as (pre, post):
            stdout, stderr = self.cmd("sign_cert", ca=self.ca, subject_alternative_name=san.value, stdin=csr)
        self.assertEqual(stderr, "")

        cert = Certificate.objects.get()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertEqual(cert.pub.loaded.subject, ca_settings.CA_DEFAULT_SUBJECT)
        self.assertIssuer(self.ca, cert)
        self.assertAuthorityKeyIdentifier(self.ca, cert)
        self.assertEqual(stdout, f"Please paste the CSR:\n{cert.pub.pem}")
        self.assertEqual(cert.extensions[ExtensionOID.SUBJECT_ALTERNATIVE_NAME], san)

        # replace subject fields via command-line argument:
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyOrg2"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "MyOrg2Unit2"),
                x509.NameAttribute(NameOID.COMMON_NAME, "CommonName2"),
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, "user@example.net"),
            ]
        )
        with self.assertCreateCertSignals() as (pre, post):
            self.cmd(
                "sign_cert",
                ca=self.ca,
                subject_alternative_name=san.value,
                stdin=csr,
                subject=subject.rfc4514_string(),
                subject_format="rfc4514",
            )

        cert = Certificate.objects.get(cn="CommonName2")
        self.assertPostIssueCert(post, cert)
        self.assertEqual(cert.pub.loaded.subject, subject)
        self.assertEqual(cert.extensions[ExtensionOID.SUBJECT_ALTERNATIVE_NAME], san)

    @override_tmpcadir()
    def test_extensions(self) -> None:
        """Test setting extensions for the signed certificate."""
        self.ca.sign_authority_information_access = authority_information_access(
            ca_issuers=[uri("http://issuer.ca.example.com")], ocsp=[uri("http://ocsp.ca.example.com")]
        )
        self.ca.sign_certificate_policies = certificate_policies(
            x509.PolicyInformation(
                policy_identifier=CertificatePoliciesOID.CPS_QUALIFIER, policy_qualifiers=None
            )
        )
        self.ca.sign_crl_distribution_points = crl_distribution_points(
            distribution_point([uri("http://crl.ca.example.com")])
        )
        self.ca.sign_issuer_alternative_name = issuer_alternative_name(uri("http://ian.example.com"))
        self.ca.save()

        cmdline = [
            "sign_cert",
            f"--subject=CN={self.hostname}",
            "--subject-format=rfc4514",
            f"--ca={self.ca.serial}",
            # Authority Information Access extension
            "--ocsp-responder=http://ocsp.example.com/1",
            "--ca-issuer=http://issuer.example.com/1",
            "--ocsp-responder=http://ocsp.example.com/2",
            "--ca-issuer=http://issuer.example.com/2",
            # Certificate Policies extension
            "--policy-identifier=1.2.3",
            "--certification-practice-statement=https://example.com/cps/",
            "--user-notice=user notice text",
            # CRL Distribution Points
            "--crl-full-name=http://crl.example.com",
            "--crl-full-name=http://crl.example.net",
            # Extended Key Usage extension
            "--extended-key-usage=clientAuth",
            # Issuer Alternative Name extension
            "--issuer-alternative-name",
            "DNS:ian-cert.example.com",
            "--issuer-alternative-name",
            "URI:http://ian-cert.example.com",
            # Key Usage extension
            "--key-usage=keyCertSign",
            # OCSP No Check extension
            "--ocsp-no-check",
            # Subject Alternative Name extension
            "--subject-alternative-name=URI:https://example.net",
            # TLS Feature extension
            "--tls-feature=status_request",
        ]

        with self.assertCreateCertSignals() as (pre, post):
            stdout, stderr = self.cmd_e2e(cmdline, stdin=csr)
        self.assertEqual(stderr, "")

        cert = Certificate.objects.get()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertEqual(cert.pub.loaded.subject, self.subject)
        self.assertEqual(stdout, f"Please paste the CSR:\n{cert.pub.pem}")

        extensions = cert.extensions

        # Test Authority Information Access extension
        self.assertEqual(
            extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS],
            authority_information_access(
                ocsp=[uri("http://ocsp.example.com/1"), uri("http://ocsp.example.com/2")],
                ca_issuers=[uri("http://issuer.example.com/1"), uri("http://issuer.example.com/2")],
            ),
        )

        # Test Certificate Policies extension
        self.assertEqual(
            extensions[ExtensionOID.CERTIFICATE_POLICIES],
            certificate_policies(
                x509.PolicyInformation(
                    policy_identifier=x509.ObjectIdentifier("1.2.3"),
                    policy_qualifiers=[
                        "https://example.com/cps/",
                        x509.UserNotice(notice_reference=None, explicit_text="user notice text"),
                    ],
                )
            ),
        )

        # Test CRL Distribution Points extension
        self.assertEqual(
            extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS],
            self.crl_distribution_points([uri("http://crl.example.com"), uri("http://crl.example.net")]),
        )

        # Test Extended Key Usage extension
        self.assertEqual(
            extensions[ExtensionOID.EXTENDED_KEY_USAGE],
            extended_key_usage(ExtendedKeyUsageOID.CLIENT_AUTH),
        )

        # Test Issuer Alternative Name extension
        self.assertEqual(
            extensions[ExtensionOID.ISSUER_ALTERNATIVE_NAME],
            issuer_alternative_name(dns("ian-cert.example.com"), uri("http://ian-cert.example.com")),
        )

        # Test Key Usage extension
        self.assertEqual(extensions[ExtensionOID.KEY_USAGE], key_usage(key_cert_sign=True))

        # Test OCSP No Check extension
        self.assertEqual(extensions[ExtensionOID.OCSP_NO_CHECK], ocsp_no_check())

        # Test Subject Alternative Name extension
        self.assertEqual(
            extensions[x509.SubjectAlternativeName.oid], subject_alternative_name(uri("https://example.net"))
        )

        # Test TLSFeature extension
        self.assertEqual(
            extensions[ExtensionOID.TLS_FEATURE], tls_feature(x509.TLSFeatureType.status_request)
        )

    @override_tmpcadir()
    def test_extensions_with_non_default_critical(self) -> None:
        """Test setting extensions with non-default critical values."""
        self.assertIsNotNone(self.ca.sign_crl_distribution_points)
        self.ca.save()

        cmdline = [
            "sign_cert",
            f"--subject=CN={self.hostname}",
            "--subject-format=rfc4514",
            f"--ca={self.ca.serial}",
            # Certificate Policies extension
            "--policy-identifier=1.2.3",
            "--certification-practice-statement=https://example.com/cps/",
            "--user-notice=user notice text",
            "--certificate-policies-critical",
            # CRL Distribution Points
            "--crl-full-name=http://crl.example.com",
            "--crl-full-name=http://crl.example.net",
            "--crl-distribution-points-critical",
            # Extended Key Usage extension
            "--extended-key-usage=clientAuth",
            "--extended-key-usage-critical",
            # Key Usage extension
            "--key-usage=keyCertSign",
            "--key-usage-non-critical",
            # OCSP No Check extension
            "--ocsp-no-check",
            "--ocsp-no-check-critical",
            # Subject Alternative Name extension
            "--subject-alternative-name=URI:https://example.net",
            "--subject-alternative-name-critical",
            # TLS Feature extension: OpenSSL fails validation of certificates, but the RFC explicitly says
            # it is possible for this to be critical. This means we cannot test this extension with a critical
            # flag here.
            # "--tls-feature=status_request",
            # "--tls-feature-critical",
        ]

        with self.assertCreateCertSignals() as (pre, post):
            stdout, stderr = self.cmd_e2e(cmdline, stdin=csr)
        self.assertEqual(stderr, "")

        cert = Certificate.objects.get()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertEqual(cert.pub.loaded.subject, self.subject)
        self.assertEqual(stdout, f"Please paste the CSR:\n{cert.pub.pem}")

        extensions = cert.extensions

        # Test Certificate Policies extension
        self.assertEqual(
            extensions[ExtensionOID.CERTIFICATE_POLICIES],
            certificate_policies(
                x509.PolicyInformation(
                    policy_identifier=x509.ObjectIdentifier("1.2.3"),
                    policy_qualifiers=[
                        "https://example.com/cps/",
                        x509.UserNotice(notice_reference=None, explicit_text="user notice text"),
                    ],
                ),
                critical=True,
            ),
        )

        # Test CRL Distribution Points extension
        self.assertEqual(
            extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS],
            self.crl_distribution_points(
                [uri("http://crl.example.com"), uri("http://crl.example.net")], critical=True
            ),
        )

        # Test Extended Key Usage extension
        self.assertEqual(
            extensions[ExtensionOID.EXTENDED_KEY_USAGE],
            extended_key_usage(ExtendedKeyUsageOID.CLIENT_AUTH, critical=True),
        )

        # Test Key Usage extension
        self.assertEqual(extensions[ExtensionOID.KEY_USAGE], key_usage(key_cert_sign=True, critical=False))

        # Test OCSP No Check extension
        self.assertEqual(extensions[ExtensionOID.OCSP_NO_CHECK], ocsp_no_check(critical=True))

        # Test Subject Alternative Name extension (NOTE: Common Name is automatically appended).
        self.assertEqual(
            cert.extensions[x509.SubjectAlternativeName.oid],
            subject_alternative_name(uri("https://example.net"), critical=True),
        )

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_add_extensions_with_formatting(self) -> None:
        """Test adding various extensions."""
        cmdline = [
            "sign_cert",
            f"--subject=CN={self.hostname}",
            "--subject-format=rfc4514",
            f"--ca={self.ca.serial}",
            "--ocsp-responder=https://example.com/ocsp/{OCSP_PATH}",
            "--ca-issuer=https://example.com/ca-issuer/{CA_ISSUER_PATH}",
            "--crl-full-name=http://example.com/crl/{CRL_PATH}",
            "--crl-full-name=http://example.net/crl/{CRL_PATH}",
        ]

        with self.assertCreateCertSignals() as (pre, post):
            stdout, stderr = self.cmd_e2e(cmdline, stdin=csr)
        self.assertEqual(stderr, "")

        cert = Certificate.objects.get()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertEqual(cert.pub.loaded.subject, self.subject)
        self.assertEqual(stdout, f"Please paste the CSR:\n{cert.pub.pem}")

        extensions = cert.extensions
        ca_issuer_path = reverse("django_ca:issuer", kwargs={"serial": self.ca.serial})
        ocsp_path = reverse("django_ca:ocsp-cert-post", kwargs={"serial": self.ca.serial})
        crl_path = reverse("django_ca:crl", kwargs={"serial": self.ca.serial})

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

    @override_tmpcadir()
    def test_multiple_sans(self) -> None:
        """Test passing multiple SubjectAlternativeName instances."""
        cmdline = [
            "sign_cert",
            f"--subject=CN={self.hostname}",
            "--subject-format=rfc4514",
            f"--ca={self.ca.serial}",
            "--subject-alternative-name=URI:https://example.net",
            "--subject-alternative-name=DNS:example.org",
        ]
        with self.assertCreateCertSignals() as (pre, post):
            stdout, stderr = self.cmd_e2e(cmdline, stdin=csr)
        self.assertEqual(stderr, "")

        cert = Certificate.objects.get()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertEqual(cert.pub.loaded.subject, self.subject)
        self.assertEqual(stdout, f"Please paste the CSR:\n{cert.pub.pem}")
        self.assertEqual(
            cert.extensions[x509.SubjectAlternativeName.oid],
            subject_alternative_name(uri("https://example.net"), dns("example.org")),
        )

    @override_tmpcadir(CA_DEFAULT_SUBJECT=tuple())
    def test_no_subject(self) -> None:
        """Test signing without a subject (but SANs)."""
        with self.assertCreateCertSignals() as (pre, post):
            stdout, stderr = self.cmd(
                "sign_cert",
                ca=self.ca,
                subject_alternative_name=subject_alternative_name(dns(self.hostname)).value,
                stdin=csr,
            )

        cert = Certificate.objects.get()

        self.assertEqual(pre.call_count, 1)
        self.assertSignature([self.ca], cert)
        self.assertEqual(cert.pub.loaded.subject, self.subject)
        self.assertEqual(stdout, f"Please paste the CSR:\n{cert.pub.pem}")
        self.assertEqual(stderr, "")
        actual = cert.extensions
        self.assertEqual(
            actual[ExtensionOID.SUBJECT_ALTERNATIVE_NAME], subject_alternative_name(dns(self.hostname))
        )

    @override_tmpcadir(CA_DEFAULT_SUBJECT=tuple())
    def test_with_password(self) -> None:
        """Test signing with a CA that is protected with a password."""
        password = b"testpassword"
        ca = self.cas["pwd"]
        self.assertIsNotNone(ca.key(password=password))

        ca = CertificateAuthority.objects.get(pk=ca.pk)

        # Giving no password raises a CommandError
        san = subject_alternative_name(dns("example.com"))
        with self.assertCommandError(
            "^Password was not given but private key is encrypted$"
        ), self.assertCreateCertSignals(False, False):
            self.cmd("sign_cert", ca=ca, subject_alternative_name=san.value, stdin=csr)

        # Pass a password
        ca = CertificateAuthority.objects.get(pk=ca.pk)
        with self.assertCreateCertSignals():
            self.cmd("sign_cert", ca=ca, subject_alternative_name=san.value, stdin=csr, password=password)

        # Pass the wrong password
        ca = CertificateAuthority.objects.get(pk=ca.pk)
        with self.assertCommandError(self.re_false_password), self.assertCreateCertSignals(False, False):
            self.cmd("sign_cert", ca=ca, subject_alternative_name=san.value, stdin=csr, password=b"wrong")

    @override_tmpcadir(CA_DEFAULT_SUBJECT=tuple())
    def test_unparsable_private_key(self) -> None:
        """Test creating a cert where the CA private key contains bogus data."""
        # NOTE: we assert storage class in skipUnless() above

        path = storages["django-ca"].path(self.ca.private_key_path)
        with open(path, "wb") as stream:
            stream.write(b"bogus")

        san = subject_alternative_name(dns("example.com"))
        with self.assertCommandError(self.re_false_password), self.assertCreateCertSignals(False, False):
            self.cmd("sign_cert", ca=self.ca, subject_alternative_name=san.value, stdin=csr)

    @override_tmpcadir()
    def test_der_csr(self) -> None:
        """Test using a DER CSR."""
        csr_path = os.path.join(ca_settings.CA_DIR, "test.csr")
        with open(csr_path, "wb") as csr_stream:
            csr_stream.write(CERT_DATA["child-cert"]["csr"]["parsed"].public_bytes(Encoding.DER))

        with self.assertCreateCertSignals() as (pre, post):
            stdout, stderr = self.cmd(
                "sign_cert",
                ca=self.ca,
                subject=self.subject.rfc4514_string(),
                subject_format="rfc4514",
                csr=csr_path,
            )
        self.assertEqual(stderr, "")

        cert = Certificate.objects.get()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)

        self.assertEqual(cert.pub.loaded.subject, self.subject)
        self.assertEqual(stdout, cert.pub.pem)
        actual = cert.extensions
        self.assertEqual(
            actual[ExtensionOID.KEY_USAGE],
            key_usage(digital_signature=True, key_agreement=True, key_encipherment=True),
        )
        self.assertEqual(
            actual[ExtensionOID.EXTENDED_KEY_USAGE], extended_key_usage(ExtendedKeyUsageOID.SERVER_AUTH)
        )

    @override_tmpcadir(CA_DEFAULT_SUBJECT=None)
    def test_unsortable_subject_with_no_profile_subject(self) -> None:
        """Test passing a subject that cannot be sorted.

        The subject of the certificate will be identical to the given subject, with no sorting applied. This
        requires that the profile does **not** define a subject (as given and profile subject would have to be
        merged) and the passed subject already contains a CommonName (as it would have to be added in the
        "correct" location from the SubjectAlternativeName extension).
        """
        with self.assertCreateCertSignals() as (pre, post):
            stdout, stderr = self.cmd(
                "sign_cert",
                ca=self.ca,
                subject_format="rfc4514",
                subject=f"inn=weird,CN={self.hostname}",
                stdin=csr,
            )
        self.assertEqual(stderr, "")

        cert = Certificate.objects.get(cn=self.hostname)
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertEqual(
            cert.pub.loaded.subject,
            x509.Name(
                [
                    x509.NameAttribute(NameOID.INN, "weird"),
                    x509.NameAttribute(NameOID.COMMON_NAME, self.hostname),
                ]
            ),
        )
        self.assertEqual(stdout, f"Please paste the CSR:\n{cert.pub.pem}")

    @override_tmpcadir(CA_DEFAULT_SUBJECT=(("C", "AT"),))
    def test_unsortable_subject_with_profile_subject(self) -> None:
        """Test passing a subject that cannot be sorted, but the profile also defines a subject.

        The given subject and subject in the profile cannot be merged in any predictable order, so this is an
        error.
        """
        subject = f"inn=weird,CN={self.hostname}"
        with self.assertCommandError(rf"^{subject}: Unsortable name$"), self.assertCreateCertSignals(
            False, False
        ):
            self.cmd("sign_cert", ca=self.ca, subject_format="rfc4514", subject=subject, stdin=csr)

    @override_tmpcadir(CA_DEFAULT_SUBJECT=None)
    def test_unsortable_subject_with_no_common_name(self) -> None:
        """Test passing a subject that cannot be sorted and has no CommonName.

        The position of the CommonName added via the SubjectAlternativeName extension cannot be determined.
        """
        subject = "inn=weird"
        with self.assertCommandError(rf"^{subject}: Unsortable name$"), self.assertCreateCertSignals(
            False, False
        ):
            self.cmd(
                "sign_cert",
                ca=self.ca,
                subject_format="rfc4514",
                subject=subject,
                subject_alternative_name=subject_alternative_name(dns(self.hostname)).value,
                stdin=csr,
            )

    @override_tmpcadir()
    def test_expiry_too_late(self) -> None:
        """Test signing with an expiry after the CA expires."""
        time_left = (self.ca.expires - timezone.now()).days
        expires = timedelta(days=time_left + 3)

        with self.assertCommandError(
            rf"^Certificate would outlive CA, maximum expiry for this CA is {time_left} days\.$"
        ), self.assertCreateCertSignals(False, False):
            self.cmd(
                "sign_cert",
                ca=self.ca,
                subject_format="rfc4514",
                subject=f"CN={self.hostname}",
                expires=expires,
                stdin=csr,
            )

    @override_tmpcadir()
    def test_revoked_ca(self) -> None:
        """Test signing with a revoked CA."""
        self.ca.revoke()

        with self.assertCommandError(r"^Certificate Authority is revoked\.$"), self.assertCreateCertSignals(
            False, False
        ):
            self.cmd(
                "sign_cert", ca=self.ca, subject_format="rfc4514", subject=f"CN={self.hostname}", stdin=csr
            )

    def test_invalid_algorithm(self) -> None:
        """Test passing an invalid algorithm."""
        with self.assertCommandError(r"^Ed448 keys do not allow an algorithm for signing\.$"):
            self.cmd(
                "sign_cert",
                ca=self.cas["ed448"],
                subject_format="rfc4514",
                subject=f"CN={self.hostname}",
                algorithm=hashes.SHA512(),
            )

    @override_tmpcadir()
    def test_no_cn_or_san(self) -> None:
        """Test signing a cert that has neither CN nor SAN."""
        subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.hostname)])
        with self.assertCommandError(
            r"^Must give at least a Common Name in --subject or one or more "
            r"--subject-alternative-name/--name arguments\.$"
        ), self.assertCreateCertSignals(False, False):
            self.cmd("sign_cert", ca=self.ca, subject=subject.rfc4514_string(), subject_format="rfc4514")

    @override_tmpcadir()
    def test_unusable_ca(self) -> None:
        """Test signing with an unusable CA."""
        path = storages["django-ca"].path(self.ca.private_key_path)
        os.remove(path)
        msg = rf"^\[Errno 2\] No such file or directory: '{path}'"

        with self.assertCommandError(msg), self.assertCreateCertSignals(False, False):
            self.cmd(
                "sign_cert",
                ca=self.ca,
                subject=self.subject.rfc4514_string(),
                subject_format="rfc4514",
                stdin=csr,
            )

    @override_tmpcadir()
    @freeze_time(TIMESTAMPS["everything_expired"])
    def test_expired_ca(self) -> None:
        """Test signing with an expired CA."""
        msg = r"^Certificate Authority has expired\.$"
        with self.assertCommandError(msg), self.assertCreateCertSignals(False, False):
            self.cmd(
                "sign_cert", ca=self.ca, subject_format="rfc4514", subject=f"CN={self.hostname}", stdin=csr
            )

    @override_tmpcadir()
    def test_add_any_policy(self) -> None:
        """Test adding the anyPolicy, which is an error for end-entity certificates."""
        cmdline = [
            "sign_cert",
            "--subject=/CN=example.com",
            f"--ca={self.ca.serial}",
            "--policy-identifier=anyPolicy",
        ]

        actual_stdout = io.StringIO()
        actual_stderr = io.StringIO()
        with self.assertSystemExit(2):
            self.cmd_e2e(cmdline, stdout=actual_stdout, stderr=actual_stderr)

        self.assertEqual("", actual_stdout.getvalue())
        self.assertIn("anyPolicy is not allowed in this context.", actual_stderr.getvalue())

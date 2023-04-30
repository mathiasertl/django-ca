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
import re
import stat
import unittest
from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

from django.core.files.storage import FileSystemStorage
from django.test import TestCase, override_settings
from django.utils import timezone

from freezegun import freeze_time

from django_ca import ca_settings
from django_ca.models import Certificate, CertificateAuthority
from django_ca.tests.base import certs, dns, override_tmpcadir, timestamps, uri
from django_ca.tests.base.mixins import TestCaseMixin
from django_ca.utils import ca_storage


@override_settings(CA_MIN_KEY_SIZE=1024, CA_PROFILES={}, CA_DEFAULT_SUBJECT=tuple())
@freeze_time(timestamps["everything_valid"])
class SignCertTestCase(TestCaseMixin, TestCase):  # pylint: disable=too-many-public-methods
    """Main test class for this command."""

    default_ca = "root"
    load_cas = "__usable__"

    def setUp(self) -> None:
        super().setUp()
        self.csr_pem = certs["root-cert"]["csr"]["pem"]

    @override_tmpcadir()
    def test_from_stdin(self) -> None:
        """Test reading CSR from stdin."""
        stdin = self.csr_pem.encode()
        with self.assertCreateCertSignals() as (pre, post):
            stdout, stderr = self.cmd("sign_cert", ca=self.ca, subject=self.subject, stdin=stdin)
        self.assertEqual(stderr, "")

        cert = Certificate.objects.get(cn=self.hostname)
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertEqual(cert.pub.loaded.subject, self.subject)
        self.assertEqual(stdout, f"Please paste the CSR:\n{cert.pub.pem}")

        actual = cert.x509_extensions
        self.assertEqual(
            actual[ExtensionOID.KEY_USAGE],
            self.key_usage(digital_signature=True, key_agreement=True, key_encipherment=True),
        )
        self.assertEqual(
            actual[ExtensionOID.EXTENDED_KEY_USAGE], self.extended_key_usage(ExtendedKeyUsageOID.SERVER_AUTH)
        )
        self.assertEqual(
            actual[ExtensionOID.SUBJECT_ALTERNATIVE_NAME], self.subject_alternative_name(dns(self.hostname))
        )
        self.assertIssuer(self.ca, cert)
        self.assertAuthorityKeyIdentifier(self.ca, cert)

    @override_tmpcadir()
    def test_with_bundle(self) -> None:
        """Test outputting the whole certificate bundle."""

        stdin = self.csr_pem.encode()
        stdout, stderr = self.cmd("sign_cert", bundle=True, ca=self.ca, subject=self.subject, stdin=stdin)
        cert = Certificate.objects.get()
        self.assertEqual(stdout, f"Please paste the CSR:\n{cert.bundle_as_pem}")
        self.assertEqual(stderr, "")

    @override_tmpcadir()
    def test_usable_cas(self) -> None:
        """Test signing with all usable CAs."""

        for name, ca in self.cas.items():
            stdin = certs[f"{name}-cert"]["csr"]["pem"].encode()

            password = certs[name].get("password")

            with self.assertCreateCertSignals() as (pre, post):
                stdout, stderr = self.cmd(
                    "sign_cert", ca=ca, subject=self.subject, password=password, stdin=stdin
                )

            self.assertEqual(stderr, "")

            cert = Certificate.objects.get(ca=ca, cn=self.hostname)
            self.assertPostIssueCert(post, cert)
            self.assertSignature(tuple(reversed(ca.bundle)), cert)
            self.assertEqual(cert.pub.loaded.subject, self.subject)
            self.assertEqual(stdout, f"Please paste the CSR:\n{cert.pub.pem}")

            actual = cert.x509_extensions

            self.assertEqual(
                actual[ExtensionOID.KEY_USAGE],
                self.key_usage(digital_signature=True, key_agreement=True, key_encipherment=True),
            )
            self.assertEqual(
                actual[ExtensionOID.EXTENDED_KEY_USAGE],
                self.extended_key_usage(ExtendedKeyUsageOID.SERVER_AUTH),
            )
            self.assertEqual(
                actual[ExtensionOID.SUBJECT_ALTERNATIVE_NAME],
                self.subject_alternative_name(dns(self.hostname)),
            )
            self.assertIssuer(ca, cert)
            self.assertAuthorityKeyIdentifier(ca, cert)

    @override_tmpcadir()
    def test_from_file(self) -> None:
        """Test reading CSR from file."""
        csr_path = os.path.join(ca_settings.CA_DIR, f"{self.hostname}.csr")
        with open(csr_path, "w", encoding="ascii") as csr_stream:
            csr_stream.write(self.csr_pem)

        with self.assertCreateCertSignals() as (pre, post):
            stdout, stderr = self.cmd("sign_cert", ca=self.ca, subject=self.subject, csr=csr_path)
        self.assertEqual(stderr, "")

        cert = Certificate.objects.get()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)

        self.assertEqual(cert.pub.loaded.subject, self.subject)
        self.assertEqual(stdout, cert.pub.pem)
        actual = cert.x509_extensions
        self.assertEqual(
            actual[ExtensionOID.KEY_USAGE],
            self.key_usage(digital_signature=True, key_agreement=True, key_encipherment=True),
        )
        self.assertEqual(
            actual[ExtensionOID.EXTENDED_KEY_USAGE], self.extended_key_usage(ExtendedKeyUsageOID.SERVER_AUTH)
        )
        self.assertEqual(
            actual[ExtensionOID.SUBJECT_ALTERNATIVE_NAME], self.subject_alternative_name(dns(self.hostname))
        )

    @override_tmpcadir()
    def test_to_file(self) -> None:
        """Test writing PEM to file."""
        out_path = os.path.join(ca_settings.CA_DIR, "test.pem")
        stdin = self.csr_pem.encode()

        try:
            with self.assertCreateCertSignals() as (pre, post):
                stdout, stderr = self.cmd(
                    "sign_cert", ca=self.ca, subject=self.subject, out=out_path, stdin=stdin
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
        stdin = self.csr_pem.encode()
        self.cmd("sign_cert", ca=self.ca, subject=self.subject, stdin=stdin, algorithm=hashes.SHA256())
        cert = Certificate.objects.get()
        self.assertIsInstance(cert.algorithm, hashes.SHA256)

    @override_tmpcadir()
    def test_subject_sort(self) -> None:
        """Test that subject is sorted on the command line."""

        cname = "subject-sort.example.com"
        subject = f"/CN={cname}/C=AT"
        stdin = self.csr_pem.encode()
        cmdline = [
            "sign_cert",
            f"--subject={subject}",
            f"--ca={self.ca.serial}",
        ]

        with self.assertCreateCertSignals() as (pre, post):
            stdout, stderr = self.cmd_e2e(cmdline, stdin=stdin)

        self.assertEqual(stderr, "")

        cert = Certificate.objects.get()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertEqual(
            cert.pub.loaded.subject,
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "AT"),
                    x509.NameAttribute(NameOID.COMMON_NAME, cname),
                ]
            ),
        )

    @override_tmpcadir()
    def test_no_dns_cn(self) -> None:
        """Test using a CN that is not a valid DNS name."""
        # Use a CommonName that is *not* a valid DNSName. By default, this is added as a subjectAltName, which
        # should fail.

        stdin = self.csr_pem.encode()
        cname = "foo bar"
        msg = rf"^{cname}: Could not parse CommonName as subjectAlternativeName\.$"
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cname)])

        with self.assertCommandError(msg), self.assertCreateCertSignals(False, False):
            self.cmd("sign_cert", ca=self.ca, subject=subject, cn_in_san=True, stdin=stdin)

    @override_tmpcadir()
    def test_cn_not_in_san(self) -> None:
        """Test adding a CN that is not in the SAN."""
        stdin = self.csr_pem.encode()
        with self.assertCreateCertSignals() as (pre, post):
            stdout, stderr = self.cmd(
                "sign_cert",
                ca=self.ca,
                subject=self.subject,
                cn_in_san=False,
                alt=self.subject_alternative_name(dns("example.com")),
                stdin=stdin,
            )

        cert = Certificate.objects.get()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertIssuer(self.ca, cert)
        self.assertAuthorityKeyIdentifier(self.ca, cert)
        self.assertEqual(cert.pub.loaded.subject, self.subject)
        self.assertEqual(stdout, f"Please paste the CSR:\n{cert.pub.pem}")
        self.assertEqual(stderr, "")
        self.assertEqual(
            cert.x509_extensions[ExtensionOID.SUBJECT_ALTERNATIVE_NAME],
            self.subject_alternative_name(dns("example.com")),
        )

    @override_tmpcadir()
    def test_no_san(self) -> None:
        """Test signing without passing any SANs."""
        stdin = self.csr_pem.encode()
        with self.assertCreateCertSignals() as (pre, post):
            stdout, stderr = self.cmd(
                "sign_cert",
                ca=self.ca,
                subject=self.subject,
                cn_in_san=False,
                stdin=stdin,
            )

        cert = Certificate.objects.get()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertEqual(cert.pub.loaded.subject, self.subject)
        self.assertIssuer(self.ca, cert)
        self.assertAuthorityKeyIdentifier(self.ca, cert)
        self.assertEqual(stdout, f"Please paste the CSR:\n{cert.pub.pem}")
        self.assertEqual(stderr, "")
        self.assertNotIn(ExtensionOID.SUBJECT_ALTERNATIVE_NAME, cert.x509_extensions)

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
        stdin = self.csr_pem.encode()
        with self.assertCreateCertSignals() as (pre, post):
            stdout, stderr = self.cmd(
                "sign_cert",
                ca=self.ca,
                cn_in_san=False,
                alt=self.subject_alternative_name(dns(self.hostname)),
                stdin=stdin,
            )
        self.assertEqual(stderr, "")

        cert = Certificate.objects.get()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertEqual(cert.pub.loaded.subject, ca_settings.CA_DEFAULT_SUBJECT)
        self.assertIssuer(self.ca, cert)
        self.assertAuthorityKeyIdentifier(self.ca, cert)
        self.assertEqual(stdout, f"Please paste the CSR:\n{cert.pub.pem}")

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
                cn_in_san=False,
                alt=self.subject_alternative_name(dns(self.hostname)),
                stdin=stdin,
                subject=subject,
            )

        cert = Certificate.objects.get(cn="CommonName2")
        self.assertPostIssueCert(post, cert)
        self.assertEqual(cert.pub.loaded.subject, subject)

    @override_tmpcadir()
    def test_extensions(self) -> None:
        """Test setting extensions for the signed certificate."""

        self.ca.issuer_alt_name = "http://ian.example.com"
        self.ca.save()

        stdin = self.csr_pem.encode()
        cmdline = [
            "sign_cert",
            f"--subject=/CN={self.hostname}",
            f"--ca={self.ca.serial}",
            "--key-usage=keyCertSign",
            "--ocsp-no-check",
            "--extended-key-usage=clientAuth",
            "--alt=URI:https://example.net",
            "--tls-feature=OCSPMustStaple",
        ]

        with self.assertCreateCertSignals() as (pre, post):
            stdout, stderr = self.cmd_e2e(cmdline, stdin=stdin)
        self.assertEqual(stderr, "")

        cert = Certificate.objects.get()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertEqual(cert.pub.loaded.subject, self.subject)
        self.assertEqual(stdout, f"Please paste the CSR:\n{cert.pub.pem}")

        actual = cert.x509_extensions
        self.assertEqual(
            actual[ExtensionOID.EXTENDED_KEY_USAGE], self.extended_key_usage(ExtendedKeyUsageOID.CLIENT_AUTH)
        )
        self.assertEqual(actual[ExtensionOID.KEY_USAGE], self.key_usage(key_cert_sign=True))
        self.assertEqual(actual[ExtensionOID.OCSP_NO_CHECK], self.ocsp_no_check())
        self.assertEqual(
            cert.x509_extensions[x509.SubjectAlternativeName.oid],
            self.subject_alternative_name(uri("https://example.net"), dns(self.hostname)),
        )
        self.assertEqual(
            actual[ExtensionOID.TLS_FEATURE], self.tls_feature(x509.TLSFeatureType.status_request)
        )
        self.assertEqual(
            actual[ExtensionOID.ISSUER_ALTERNATIVE_NAME],
            self.issuer_alternative_name(uri(self.ca.issuer_alt_name)),
        )

    @override_tmpcadir()
    def test_extensions_with_non_default_critical(self) -> None:
        """Test setting extensions with non-default critical values."""
        stdin = self.csr_pem.encode()
        cmdline = [
            "sign_cert",
            f"--subject=/CN={self.hostname}",
            f"--ca={self.ca.serial}",
            "--key-usage=keyCertSign",
            "--key-usage-non-critical",
            "--ocsp-no-check",
            "--ocsp-no-check-critical",
            "--extended-key-usage=clientAuth",
            "--extended-key-usage-critical",
            "--alt=URI:https://example.net",
            "--tls-feature=OCSPMustStaple",
        ]

        with self.assertCreateCertSignals() as (pre, post):
            stdout, stderr = self.cmd_e2e(cmdline, stdin=stdin)
        self.assertEqual(stderr, "")

        cert = Certificate.objects.get()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertEqual(cert.pub.loaded.subject, self.subject)
        self.assertEqual(stdout, f"Please paste the CSR:\n{cert.pub.pem}")

        actual = cert.x509_extensions
        self.assertEqual(
            actual[ExtensionOID.EXTENDED_KEY_USAGE],
            self.extended_key_usage(ExtendedKeyUsageOID.CLIENT_AUTH, critical=True),
        )
        self.assertEqual(actual[ExtensionOID.KEY_USAGE], self.key_usage(key_cert_sign=True, critical=False))
        self.assertEqual(actual[ExtensionOID.OCSP_NO_CHECK], self.ocsp_no_check(critical=True))

    @override_tmpcadir()
    def test_multiple_sans(self) -> None:
        """Test passing multiple SubjectAlternativeName instances."""

        stdin = self.csr_pem.encode()
        cmdline = [
            "sign_cert",
            f"--subject=/CN={self.hostname}",
            f"--ca={self.ca.serial}",
            "--alt=URI:https://example.net",
            "--alt=DNS:example.org",
        ]
        with self.assertCreateCertSignals() as (pre, post):
            stdout, stderr = self.cmd_e2e(cmdline, stdin=stdin)
        self.assertEqual(stderr, "")

        cert = Certificate.objects.get()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertEqual(cert.pub.loaded.subject, self.subject)
        self.assertEqual(stdout, f"Please paste the CSR:\n{cert.pub.pem}")
        self.assertEqual(
            cert.x509_extensions[x509.SubjectAlternativeName.oid],
            self.subject_alternative_name(uri("https://example.net"), dns("example.org"), dns(self.hostname)),
        )

    @override_tmpcadir(CA_DEFAULT_SUBJECT=tuple())
    def test_no_subject(self) -> None:
        """Test signing without a subject (but SANs)."""
        stdin = self.csr_pem.encode()
        with self.assertCreateCertSignals() as (pre, post):
            stdout, stderr = self.cmd(
                "sign_cert",
                ca=self.ca,
                alt=self.subject_alternative_name(dns(self.hostname)),
                stdin=stdin,
            )

        cert = Certificate.objects.get()

        self.assertEqual(pre.call_count, 1)
        self.assertSignature([self.ca], cert)
        self.assertEqual(cert.pub.loaded.subject, self.subject)
        self.assertEqual(stdout, f"Please paste the CSR:\n{cert.pub.pem}")
        self.assertEqual(stderr, "")
        actual = cert.x509_extensions
        self.assertEqual(
            actual[ExtensionOID.SUBJECT_ALTERNATIVE_NAME], self.subject_alternative_name(dns(self.hostname))
        )

    @override_tmpcadir(CA_DEFAULT_SUBJECT=tuple())
    def test_with_password(self) -> None:
        """Test signing with a CA that is protected with a password."""
        password = b"testpassword"
        ca = self.cas["pwd"]
        self.assertIsNotNone(ca.key(password=password))

        ca = CertificateAuthority.objects.get(pk=ca.pk)

        # Giving no password raises a CommandError
        stdin = self.csr_pem.encode()
        san = self.subject_alternative_name(dns("example.com"))
        with self.assertCommandError(
            "^Password was not given but private key is encrypted$"
        ), self.assertCreateCertSignals(False, False):
            self.cmd("sign_cert", ca=ca, alt=san, stdin=stdin)

        # Pass a password
        ca = CertificateAuthority.objects.get(pk=ca.pk)
        with self.assertCreateCertSignals():
            self.cmd("sign_cert", ca=ca, alt=san, stdin=stdin, password=password)

        # Pass the wrong password
        ca = CertificateAuthority.objects.get(pk=ca.pk)
        with self.assertCommandError(self.re_false_password), self.assertCreateCertSignals(False, False):
            self.cmd("sign_cert", ca=ca, alt=san, stdin=stdin, password=b"wrong")

    @override_tmpcadir(CA_DEFAULT_SUBJECT=tuple())
    @unittest.skipUnless(
        isinstance(ca_storage, FileSystemStorage), "Test only makes sense with local filesystem storage."
    )
    def test_unparsable(self) -> None:
        """Test creating a cert where the CA private key contains bogus data."""
        # NOTE: we assert ca_storage class in skipUnless() above
        key_path = os.path.join(ca_storage.location, self.ca.private_key_path)  # type: ignore[attr-defined]

        os.chmod(key_path, stat.S_IWUSR | stat.S_IRUSR)
        with open(key_path, "w", encoding="ascii") as stream:
            stream.write("bogus")
        os.chmod(key_path, stat.S_IRUSR)

        # Giving no password raises a CommandError
        stdin = io.StringIO(self.csr_pem)
        with self.assertCommandError(self.re_false_password), self.assertCreateCertSignals(False, False):
            self.cmd("sign_cert", ca=self.ca, alt=["example.com"], stdin=stdin)

    @override_tmpcadir()
    def test_der_csr(self) -> None:
        """Test using a DER CSR."""
        csr_path = os.path.join(ca_settings.CA_DIR, "test.csr")
        with open(csr_path, "wb") as csr_stream:
            csr_stream.write(certs["child-cert"]["csr"]["parsed"].public_bytes(Encoding.DER))

        with self.assertCreateCertSignals() as (pre, post):
            stdout, stderr = self.cmd("sign_cert", ca=self.ca, subject=self.subject, csr=csr_path)
        self.assertEqual(stderr, "")

        cert = Certificate.objects.get()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)

        self.assertEqual(cert.pub.loaded.subject, self.subject)
        self.assertEqual(stdout, cert.pub.pem)
        actual = cert.x509_extensions
        self.assertEqual(
            actual[ExtensionOID.KEY_USAGE],
            self.key_usage(digital_signature=True, key_agreement=True, key_encipherment=True),
        )
        self.assertEqual(
            actual[ExtensionOID.EXTENDED_KEY_USAGE], self.extended_key_usage(ExtendedKeyUsageOID.SERVER_AUTH)
        )
        self.assertEqual(
            actual[ExtensionOID.SUBJECT_ALTERNATIVE_NAME], self.subject_alternative_name(dns(self.hostname))
        )

    @override_tmpcadir()
    def test_expiry_too_late(self) -> None:
        """Test signing with an expiry after the CA expires."""
        time_left = (self.ca.expires - timezone.now()).days
        expires = timedelta(days=time_left + 3)
        stdin = io.StringIO(self.csr_pem)

        with self.assertCommandError(
            rf"^Certificate would outlive CA, maximum expiry for this CA is {time_left} days\.$"
        ), self.assertCreateCertSignals(False, False):
            self.cmd("sign_cert", ca=self.ca, alt={"value": ["example.com"]}, expires=expires, stdin=stdin)

    @override_tmpcadir()
    def test_revoked_ca(self) -> None:
        """Test signing with a revoked CA."""
        self.ca.revoke()
        stdin = io.StringIO(self.csr_pem)

        with self.assertCommandError(r"^Certificate Authority is revoked\.$"), self.assertCreateCertSignals(
            False, False
        ):
            self.cmd("sign_cert", ca=self.ca, subject=self.subject, stdin=stdin)

    def test_invalid_algorithm(self) -> None:
        """Test passing an invalid algorithm."""
        with self.assertCommandError(r"^Ed448 keys do not allow an algorithm for signing\.$"):
            self.cmd("sign_cert", ca=self.cas["ed448"], subject=self.subject, algorithm=hashes.SHA512())

    @override_tmpcadir()
    def test_no_cn_or_san(self) -> None:
        """Test signing a cert that has neither CN nor SAN."""
        subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.hostname)])
        with self.assertCommandError(
            r"^Must give at least a CN in --subject or one or more --alt arguments\.$"
        ), self.assertCreateCertSignals(False, False):
            self.cmd("sign_cert", ca=self.ca, subject=subject)

    @override_tmpcadir()
    def test_unusable_ca(self) -> None:
        """Test signing with an unusable CA."""
        path = ca_storage.path(self.ca.private_key_path)
        os.remove(path)
        msg = rf"^\[Errno 2\] No such file or directory: '{path}'"
        stdin = io.StringIO(self.csr_pem)

        with self.assertCommandError(msg), self.assertCreateCertSignals(False, False):
            self.cmd("sign_cert", ca=self.ca, subject=self.subject, stdin=stdin)

    @override_tmpcadir()
    @freeze_time(timestamps["everything_expired"])
    def test_expired_ca(self) -> None:
        """Test signing with an expired CA."""
        stdin = io.StringIO(self.csr_pem)

        msg = r"^Certificate Authority has expired\.$"
        with self.assertCommandError(msg), self.assertCreateCertSignals(False, False):
            self.cmd("sign_cert", ca=self.ca, subject=self.subject, stdin=stdin)

    @override_tmpcadir()
    def test_help_text(self) -> None:
        """Test the help text."""
        with self.assertCreateCertSignals(False, False):
            help_text = self.cmd_help_text("sign_cert")

        # Remove newlines and multiple spaces from text for matching independent of terminal width
        help_text = re.sub(r"\s+", " ", help_text.replace("\n", ""))

        self.assertIn("Do not add the CommonName as subjectAlternativeName.", help_text)
        self.assertIn("Add the CommonName as subjectAlternativeName (default).", help_text)

        with self.assertCreateCertSignals(False, False), self.settings(
            CA_PROFILES={"webserver": {"cn_in_san": False}}
        ):
            help_text = self.cmd_help_text("sign_cert")
        help_text = re.sub(r"\s+", " ", help_text.replace("\n", ""))

        self.assertIn("Do not add the CommonName as subjectAlternativeName (default).", help_text)
        self.assertIn("Add the CommonName as subjectAlternativeName.", help_text)

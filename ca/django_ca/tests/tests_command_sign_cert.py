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
# see <http://www.gnu.org/licenses/>

"""Test the sign_cert management command."""

import io
import os
import re
import stat
import unittest
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

from django.core.files.storage import FileSystemStorage
from django.test import TestCase

from freezegun import freeze_time

from django_ca import ca_settings
from django_ca.models import Certificate, CertificateAuthority
from django_ca.signals import post_issue_cert, pre_issue_cert
from django_ca.tests.base import certs, dns, override_settings, override_tmpcadir, timestamps, uri
from django_ca.tests.base.mixins import TestCaseMixin
from django_ca.utils import ca_storage, x509_name


@override_settings(CA_MIN_KEY_SIZE=1024, CA_PROFILES={}, CA_DEFAULT_SUBJECT=tuple())
@freeze_time(timestamps["everything_valid"])
class SignCertTestCase(TestCaseMixin, TestCase):
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
        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd("sign_cert", ca=self.ca, subject=self.subject, stdin=stdin)
        self.assertEqual(stderr, "")
        self.assertEqual(pre.call_count, 1)

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
            stdin = self.csr_pem.encode()

            with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
                stdout, stderr = self.cmd(
                    "sign_cert", ca=ca, subject=self.subject, password=certs[name]["password"], stdin=stdin
                )

            self.assertEqual(stderr, "")
            self.assertEqual(pre.call_count, 1)

            cert = Certificate.objects.get(ca=ca, cn=self.hostname)
            self.assertPostIssueCert(post, cert)
            self.assertSignature(reversed(ca.bundle), cert)
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

        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd("sign_cert", ca=self.ca, subject=self.subject, csr=csr_path)
        self.assertEqual(stderr, "")
        self.assertEqual(pre.call_count, 1)

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
            with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
                stdout, stderr = self.cmd(
                    "sign_cert", ca=self.ca, subject=self.subject, out=out_path, stdin=stdin
                )
            self.assertEqual(pre.call_count, 1)

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

        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd_e2e(cmdline, stdin=stdin)

        self.assertEqual(pre.call_count, 1)
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
        """Test using a CN that is not a vlaid DNS name."""
        # Use a CommonName that is *not* a valid DNSName. By default, this is added as a subjectAltName, which
        # should fail.

        stdin = self.csr_pem.encode()
        cname = "foo bar"
        msg = rf"^{cname}: Could not parse CommonName as subjectAlternativeName\.$"
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cname)])

        with self.assertCommandError(msg), self.mockSignal(pre_issue_cert) as pre, self.mockSignal(
            post_issue_cert
        ) as post:
            self.cmd("sign_cert", ca=self.ca, subject=subject, cn_in_san=True, stdin=stdin)
        self.assertFalse(pre.called)
        self.assertFalse(post.called)

    @override_tmpcadir()
    def test_cn_not_in_san(self) -> None:
        """Test adding a CN that is not in the SAN."""
        stdin = self.csr_pem.encode()
        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd(
                "sign_cert",
                ca=self.ca,
                subject=self.subject,
                cn_in_san=False,
                alt=self.subject_alternative_name(dns("example.com")),
                stdin=stdin,
            )
        self.assertEqual(pre.call_count, 1)

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
        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd(
                "sign_cert",
                ca=self.ca,
                subject=self.subject,
                cn_in_san=False,
                stdin=stdin,
            )
        self.assertEqual(pre.call_count, 1)

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
        self.assertEqual(next(t[1] for t in ca_settings.CA_DEFAULT_SUBJECT if t[0] == "O"), "MyOrg")
        self.assertEqual(next(t[1] for t in ca_settings.CA_DEFAULT_SUBJECT if t[0] == "OU"), "MyOrgUnit")

        # first, we only pass an subjectAltName, meaning that even the CommonName is used.
        stdin = self.csr_pem.encode()
        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd(
                "sign_cert",
                ca=self.ca,
                cn_in_san=False,
                alt=self.subject_alternative_name(dns(self.hostname)),
                stdin=stdin,
            )
        self.assertEqual(stderr, "")
        self.assertEqual(pre.call_count, 1)

        cert = Certificate.objects.get()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertEqual(cert.pub.loaded.subject, x509_name(ca_settings.CA_DEFAULT_SUBJECT))
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
        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            self.cmd(
                "sign_cert",
                ca=self.ca,
                cn_in_san=False,
                alt=self.subject_alternative_name(dns(self.hostname)),
                stdin=stdin,
                subject=subject,
            )
        self.assertEqual(pre.call_count, 1)

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
            "--key-usage=critical,keyCertSign",
            "--ext-key-usage=clientAuth",
            "--alt=URI:https://example.net",
            "--tls-feature=OCSPMustStaple",
        ]

        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd_e2e(cmdline, stdin=stdin)
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(stderr, "")

        cert = Certificate.objects.get()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertEqual(cert.pub.loaded.subject, self.subject)
        self.assertEqual(stdout, f"Please paste the CSR:\n{cert.pub.pem}")

        actual = cert.x509_extensions
        self.assertEqual(actual[ExtensionOID.KEY_USAGE], self.key_usage(key_cert_sign=True))
        self.assertEqual(
            actual[ExtensionOID.EXTENDED_KEY_USAGE], self.extended_key_usage(ExtendedKeyUsageOID.CLIENT_AUTH)
        )
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
        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd_e2e(cmdline, stdin=stdin)
        self.assertEqual(pre.call_count, 1)
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
        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd(
                "sign_cert",
                ca=self.ca,
                alt=self.subject_alternative_name(dns(self.hostname)),
                stdin=stdin,
            )

        cert = Certificate.objects.get()

        self.assertEqual(pre.call_count, 1)
        self.assertPostIssueCert(post, cert)
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
        ), self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            self.cmd("sign_cert", ca=ca, alt=san, stdin=stdin)
        self.assertEqual(pre.call_count, 0)
        self.assertEqual(post.call_count, 0)

        # Pass a password
        ca = CertificateAuthority.objects.get(pk=ca.pk)
        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            self.cmd("sign_cert", ca=ca, alt=san, stdin=stdin, password=password)
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(post.call_count, 1)

        # Pass the wrong password
        ca = CertificateAuthority.objects.get(pk=ca.pk)
        with self.assertCommandError(self.re_false_password), self.mockSignal(
            pre_issue_cert
        ) as pre, self.mockSignal(post_issue_cert) as post:
            self.cmd("sign_cert", ca=ca, alt=san, stdin=stdin, password=b"wrong")
        self.assertFalse(pre.called)
        self.assertFalse(post.called)

    @override_tmpcadir(CA_DEFAULT_SUBJECT=tuple())
    @unittest.skipUnless(
        isinstance(ca_storage, FileSystemStorage), "Test only makes sense with local filesystem storage."
    )
    def test_unparseable(self) -> None:
        """Test creating a cert where the CA private key contains bogus data."""
        # NOTE: we assert ca_storage class in skipUnless() above
        key_path = os.path.join(ca_storage.location, self.ca.private_key_path)  # type: ignore[attr-defined]

        os.chmod(key_path, stat.S_IWUSR | stat.S_IRUSR)
        with open(key_path, "w", encoding="ascii") as stream:
            stream.write("bogus")
        os.chmod(key_path, stat.S_IRUSR)

        # Giving no password raises a CommandError
        stdin = io.StringIO(self.csr_pem)
        with self.assertCommandError(self.re_false_password), self.mockSignal(
            pre_issue_cert
        ) as pre, self.mockSignal(post_issue_cert) as post:
            self.cmd("sign_cert", ca=self.ca, alt=["example.com"], stdin=stdin)
        self.assertEqual(pre.call_count, 0)
        self.assertEqual(post.call_count, 0)

    @override_tmpcadir()
    def test_der_csr(self) -> None:
        """Test using a DER CSR."""
        csr_path = os.path.join(ca_settings.CA_DIR, "test.csr")
        with open(csr_path, "wb") as csr_stream:
            csr_stream.write(certs["child-cert"]["csr"]["der"])

        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd("sign_cert", ca=self.ca, subject=self.subject, csr=csr_path)
        self.assertEqual(pre.call_count, 1)
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
        time_left = (self.ca.expires - datetime.now()).days
        expires = timedelta(days=time_left + 3)
        stdin = io.StringIO(self.csr_pem)

        with self.assertCommandError(
            rf"^Certificate would outlive CA, maximum expiry for this CA is {time_left} days\.$"
        ), self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            self.cmd("sign_cert", ca=self.ca, alt={"value": ["example.com"]}, expires=expires, stdin=stdin)
        self.assertFalse(pre.called)
        self.assertFalse(post.called)

    @override_tmpcadir()
    def test_no_cn_or_san(self) -> None:
        """Test signing a cert that has neither CN nor SAN."""
        subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.hostname)])
        with self.assertCommandError(
            r"^Must give at least a CN in --subject or one or more --alt arguments\.$"
        ), self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            self.cmd("sign_cert", ca=self.ca, subject=subject)
        self.assertFalse(pre.called)
        self.assertFalse(post.called)

    @override_tmpcadir()
    @freeze_time(timestamps["everything_valid"])
    def test_revoked_ca(self) -> None:
        """Test signing with a revoked CA."""
        self.ca.revoke()
        stdin = io.StringIO(self.csr_pem)

        with self.assertCommandError(r"^Certificate Authority is revoked\.$"), self.mockSignal(
            pre_issue_cert
        ) as pre, self.mockSignal(post_issue_cert) as post:
            self.cmd("sign_cert", ca=self.ca, subject=self.subject, stdin=stdin)
        self.assertFalse(pre.called)
        self.assertFalse(post.called)

    @override_tmpcadir()
    @freeze_time(timestamps["everything_valid"])
    def test_unusable_ca(self) -> None:
        """Test signing with an unusable CA."""
        path = ca_storage.path(self.ca.private_key_path)
        os.remove(path)
        msg = rf"^\[Errno 2\] No such file or directory: '{path}'"
        stdin = io.StringIO(self.csr_pem)

        with self.assertCommandError(msg), self.mockSignal(pre_issue_cert) as pre, self.mockSignal(
            post_issue_cert
        ) as post:
            self.cmd("sign_cert", ca=self.ca, subject=self.subject, stdin=stdin)
        self.assertFalse(pre.called)
        self.assertFalse(post.called)

    @override_tmpcadir()
    @freeze_time(timestamps["everything_expired"])
    def test_expired_ca(self) -> None:
        """Test signing with an expired CA."""
        stdin = io.StringIO(self.csr_pem)

        with self.assertCommandError(r"^Certificate Authority has expired\.$"), self.mockSignal(
            pre_issue_cert
        ) as pre, self.mockSignal(post_issue_cert) as post:
            self.cmd("sign_cert", ca=self.ca, subject=self.subject, stdin=stdin)
        self.assertFalse(pre.called)
        self.assertFalse(post.called)

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


@override_settings(USE_TZ=True)
class SignCertWithTZTestCase(SignCertTestCase):
    """Same but with timezone support."""

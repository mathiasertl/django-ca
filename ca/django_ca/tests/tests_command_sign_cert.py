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
from datetime import datetime
from datetime import timedelta

from django.core.files.storage import FileSystemStorage
from django.test import TestCase

from freezegun import freeze_time

from .. import ca_settings
from ..deprecation import RemovedInDjangoCA120Warning
from ..extensions import ExtendedKeyUsage
from ..extensions import IssuerAlternativeName
from ..extensions import KeyUsage
from ..extensions import SubjectAlternativeName
from ..extensions import TLSFeature
from ..models import Certificate
from ..models import CertificateAuthority
from ..signals import post_issue_cert
from ..signals import pre_issue_cert
from ..subject import Subject
from ..utils import ca_storage
from .base import certs
from .base import override_settings
from .base import override_tmpcadir
from .base import timestamps
from .base.mixins import TestCaseMixin


@override_settings(CA_MIN_KEY_SIZE=1024, CA_PROFILES={}, CA_DEFAULT_SUBJECT={})
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
        subject = Subject([("CN", "example.com")])
        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd("sign_cert", ca=self.ca, subject=subject, stdin=stdin)
        self.assertEqual(stderr, "")
        self.assertEqual(pre.call_count, 1)

        cert = Certificate.objects.get()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertSubject(cert.pub.loaded, subject)
        self.assertEqual(stdout, f"Please paste the CSR:\n{cert.pub.pem}")

        self.assertEqual(
            cert.key_usage,
            KeyUsage({"critical": True, "value": ["digitalSignature", "keyAgreement", "keyEncipherment"]}),
        )
        self.assertEqual(cert.extended_key_usage, ExtendedKeyUsage({"value": ["serverAuth"]}))
        self.assertEqual(
            cert.subject_alternative_name, SubjectAlternativeName({"value": ["DNS:example.com"]})
        )
        self.assertIssuer(self.ca, cert)
        self.assertAuthorityKeyIdentifier(self.ca, cert)

    @override_tmpcadir()
    def test_usable_cas(self) -> None:
        """Test signing with all usable CAs."""

        for name, ca in self.cas.items():
            cname = f"{name}-signed.example.com"
            stdin = self.csr_pem.encode()
            subject = Subject([("CN", cname)])

            with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
                stdout, stderr = self.cmd(
                    "sign_cert", ca=ca, subject=subject, password=certs[name]["password"], stdin=stdin
                )

            self.assertEqual(stderr, "")
            self.assertEqual(pre.call_count, 1)

            cert = Certificate.objects.get(ca=ca, cn=cname)
            self.assertPostIssueCert(post, cert)
            self.assertSignature(reversed(ca.bundle), cert)
            self.assertSubject(cert.pub.loaded, subject)
            self.assertEqual(stdout, f"Please paste the CSR:\n{cert.pub.pem}")

            self.assertEqual(
                cert.key_usage,
                KeyUsage(
                    {"critical": True, "value": ["digitalSignature", "keyAgreement", "keyEncipherment"]}
                ),
            )
            self.assertEqual(cert.extended_key_usage, ExtendedKeyUsage({"value": ["serverAuth"]}))
            self.assertEqual(
                cert.subject_alternative_name, SubjectAlternativeName({"value": [f"DNS:{cname}"]})
            )
            self.assertIssuer(ca, cert)
            self.assertAuthorityKeyIdentifier(ca, cert)

    @override_tmpcadir()
    def test_from_file(self) -> None:
        """Test reading CSR from file."""
        csr_path = os.path.join(ca_settings.CA_DIR, "test.csr")
        with open(csr_path, "w", encoding="ascii") as csr_stream:
            csr_stream.write(self.csr_pem)

        try:
            subject = Subject([("CN", "example.com"), ("emailAddress", "user@example.com")])
            with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
                stdout, stderr = self.cmd("sign_cert", ca=self.ca, subject=subject, csr=csr_path)
            self.assertEqual(stderr, "")
            self.assertEqual(pre.call_count, 1)

            cert = Certificate.objects.get()
            self.assertPostIssueCert(post, cert)
            self.assertSignature([self.ca], cert)

            self.assertSubject(cert.pub.loaded, subject)
            self.assertEqual(stdout, cert.pub.pem)
            self.assertEqual(
                cert.key_usage,
                KeyUsage(
                    {"critical": True, "value": ["digitalSignature", "keyAgreement", "keyEncipherment"]}
                ),
            )
            self.assertEqual(cert.extended_key_usage, ExtendedKeyUsage({"value": ["serverAuth"]}))
            self.assertEqual(
                cert.subject_alternative_name, SubjectAlternativeName({"value": ["DNS:example.com"]})
            )
        finally:
            os.remove(csr_path)

    @override_tmpcadir()
    def test_to_file(self) -> None:
        """Test writing PEM to file."""
        out_path = os.path.join(ca_settings.CA_DIR, "test.pem")
        stdin = self.csr_pem.encode()

        try:
            with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
                stdout, stderr = self.cmd(
                    "sign_cert",
                    ca=self.ca,
                    subject=Subject([("CN", "example.com")]),
                    out=out_path,
                    stdin=stdin,
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
    def test_no_dns_cn(self) -> None:
        """Test using a CN that is not a vlaid DNS name."""
        # Use a CommonName that is *not* a valid DNSName. By default, this is added as a subjectAltName, which
        # should fail.

        stdin = self.csr_pem.encode()
        cname = "foo bar"
        msg = rf"^{cname}: Could not parse CommonName as subjectAlternativeName\.$"

        with self.assertCommandError(msg), self.mockSignal(pre_issue_cert) as pre, self.mockSignal(
            post_issue_cert
        ) as post:
            self.cmd("sign_cert", ca=self.ca, subject=Subject([("CN", cname)]), cn_in_san=True, stdin=stdin)
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
                subject=Subject([("CN", "example.net")]),
                cn_in_san=False,
                alt=SubjectAlternativeName({"value": ["example.com"]}),
                stdin=stdin,
            )
        self.assertEqual(pre.call_count, 1)

        cert = Certificate.objects.get()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertIssuer(self.ca, cert)
        self.assertAuthorityKeyIdentifier(self.ca, cert)
        self.assertSubject(cert.pub.loaded, [("CN", "example.net")])
        self.assertEqual(stdout, f"Please paste the CSR:\n{cert.pub.pem}")
        self.assertEqual(stderr, "")
        self.assertEqual(
            cert.subject_alternative_name, SubjectAlternativeName({"value": ["DNS:example.com"]})
        )

    @override_tmpcadir()
    def test_no_san(self) -> None:
        """Test signing without passing any SANs."""
        stdin = self.csr_pem.encode()
        subject = Subject([("CN", "example.net")])
        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd(
                "sign_cert",
                ca=self.ca,
                subject=subject,
                cn_in_san=False,
                alt=SubjectAlternativeName(),
                stdin=stdin,
            )
        self.assertEqual(pre.call_count, 1)

        cert = Certificate.objects.get()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertSubject(cert.pub.loaded, subject)
        self.assertIssuer(self.ca, cert)
        self.assertAuthorityKeyIdentifier(self.ca, cert)
        self.assertEqual(stdout, f"Please paste the CSR:\n{cert.pub.pem}")
        self.assertEqual(stderr, "")
        self.assertIsNone(cert.subject_alternative_name)

    @override_tmpcadir(
        CA_DEFAULT_SUBJECT=[
            ("C", "AT"),
            ("ST", "Vienna"),
            ("L", "Vienna"),
            ("O", "MyOrg"),
            ("OU", "MyOrgUnit"),
            ("CN", "CommonName"),
            ("emailAddress", "user@example.com"),
        ]
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
                alt=SubjectAlternativeName({"value": ["example.net"]}),
                stdin=stdin,
            )
        self.assertEqual(stderr, "")
        self.assertEqual(pre.call_count, 1)

        cert = Certificate.objects.get()
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertSubject(cert.pub.loaded, ca_settings.CA_DEFAULT_SUBJECT)
        self.assertIssuer(self.ca, cert)
        self.assertAuthorityKeyIdentifier(self.ca, cert)
        self.assertEqual(stdout, f"Please paste the CSR:\n{cert.pub.pem}")

        # replace subject fields via command-line argument:
        subject = Subject(
            [
                ("C", "US"),
                ("ST", "California"),
                ("L", "San Francisco"),
                ("O", "MyOrg2"),
                ("OU", "MyOrg2Unit2"),
                ("CN", "CommonName2"),
                ("emailAddress", "user@example.net"),
            ]
        )
        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            self.cmd(
                "sign_cert",
                ca=self.ca,
                cn_in_san=False,
                alt=SubjectAlternativeName({"value": ["example.net"]}),
                stdin=stdin,
                subject=subject,
            )
        self.assertEqual(pre.call_count, 1)

        cert = Certificate.objects.get(cn="CommonName2")
        self.assertPostIssueCert(post, cert)
        self.assertSubject(cert.pub.loaded, subject)

    @override_tmpcadir()
    def test_extensions(self) -> None:
        """Test setting extensions for the signed certificate."""

        self.ca.issuer_alt_name = "DNS:ian.example.com"
        self.ca.save()

        stdin = self.csr_pem.encode()
        cmdline = [
            "sign_cert",
            f"--subject={Subject([('CN', 'example.com')])}",
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
        self.assertSubject(cert.pub.loaded, [("CN", "example.com")])
        self.assertEqual(stdout, f"Please paste the CSR:\n{cert.pub.pem}")
        self.assertEqual(cert.key_usage, KeyUsage({"critical": True, "value": ["keyCertSign"]}))
        self.assertEqual(cert.extended_key_usage, ExtendedKeyUsage({"value": ["clientAuth"]}))
        self.assertEqual(
            cert.subject_alternative_name,
            SubjectAlternativeName({"value": ["URI:https://example.net", "DNS:example.com"]}),
        )
        self.assertEqual(cert.tls_feature, TLSFeature({"value": ["OCSPMustStaple"]}))
        self.assertEqual(
            cert.issuer_alternative_name, IssuerAlternativeName({"value": [self.ca.issuer_alt_name]})
        )

    @override_tmpcadir(CA_DEFAULT_SUBJECT={})
    def test_no_subject(self) -> None:
        """Test signing without a subject (but SANs)."""
        stdin = self.csr_pem.encode()
        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd(
                "sign_cert", ca=self.ca, alt=SubjectAlternativeName({"value": ["example.com"]}), stdin=stdin
            )

        cert = Certificate.objects.get()

        self.assertEqual(pre.call_count, 1)
        self.assertPostIssueCert(post, cert)
        self.assertSignature([self.ca], cert)
        self.assertSubject(cert.pub.loaded, [("CN", "example.com")])
        self.assertEqual(stdout, f"Please paste the CSR:\n{cert.pub.pem}")
        self.assertEqual(stderr, "")
        self.assertEqual(
            cert.subject_alternative_name, SubjectAlternativeName({"value": ["DNS:example.com"]})
        )

    @override_tmpcadir(CA_DEFAULT_SUBJECT={})
    def test_with_password(self) -> None:
        """Test signing with a CA that is protected with a password."""
        password = b"testpassword"
        ca = self.cas["pwd"]
        self.assertIsNotNone(ca.key(password=password))

        ca = CertificateAuthority.objects.get(pk=ca.pk)

        # Giving no password raises a CommandError
        stdin = self.csr_pem.encode()
        with self.assertCommandError(
            "^Password was not given but private key is encrypted$"
        ), self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            self.cmd("sign_cert", ca=ca, alt=SubjectAlternativeName({"value": ["example.com"]}), stdin=stdin)
        self.assertEqual(pre.call_count, 0)
        self.assertEqual(post.call_count, 0)

        # Pass a password
        ca = CertificateAuthority.objects.get(pk=ca.pk)
        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            self.cmd(
                "sign_cert",
                ca=ca,
                alt=SubjectAlternativeName({"value": ["example.com"]}),
                stdin=stdin,
                password=password,
            )
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(post.call_count, 1)

        # Pass the wrong password
        ca = CertificateAuthority.objects.get(pk=ca.pk)
        with self.assertCommandError(self.re_false_password), self.mockSignal(
            pre_issue_cert
        ) as pre, self.mockSignal(post_issue_cert) as post:
            self.cmd(
                "sign_cert",
                ca=ca,
                alt=SubjectAlternativeName({"value": ["example.com"]}),
                stdin=stdin,
                password=b"wrong",
            )
        self.assertFalse(pre.called)
        self.assertFalse(post.called)

    @override_tmpcadir(CA_DEFAULT_SUBJECT={})
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
        # NOTE: cryptography>=35.0 returns a tuple with OpenSSL internals as second element. We thus match
        #       without '^' and '$' as this would not match otherwise.
        msg = r"Could not deserialize key data\. The data may be in an incorrect format or it may be encrypted with an unsupported algorithm\."  # NOQA: E501

        stdin = io.StringIO(self.csr_pem)
        with self.assertCommandError(msg), self.mockSignal(pre_issue_cert) as pre, self.mockSignal(
            post_issue_cert
        ) as post:
            self.cmd("sign_cert", ca=self.ca, alt=["example.com"], stdin=stdin)
        self.assertEqual(pre.call_count, 0)
        self.assertEqual(post.call_count, 0)

    @override_tmpcadir()
    def test_der_csr(self) -> None:
        """Test using a DER CSR."""
        csr_path = os.path.join(ca_settings.CA_DIR, "test.csr")
        with open(csr_path, "wb") as csr_stream:
            csr_stream.write(certs["child-cert"]["csr"]["der"])

        try:
            subject = Subject([("CN", "example.com"), ("emailAddress", "user@example.com")])
            with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
                stdout, stderr = self.cmd("sign_cert", ca=self.ca, subject=subject, csr=csr_path)
            self.assertEqual(pre.call_count, 1)
            self.assertEqual(stderr, "")

            cert = Certificate.objects.get()
            self.assertPostIssueCert(post, cert)
            self.assertSignature([self.ca], cert)

            self.assertSubject(cert.pub.loaded, subject)
            self.assertEqual(stdout, cert.pub.pem)
            self.assertEqual(
                cert.key_usage,
                KeyUsage(
                    {"critical": True, "value": ["digitalSignature", "keyAgreement", "keyEncipherment"]}
                ),
            )
            self.assertEqual(cert.extended_key_usage, ExtendedKeyUsage({"value": ["serverAuth"]}))
            self.assertEqual(
                cert.subject_alternative_name, SubjectAlternativeName({"value": ["DNS:example.com"]})
            )
        finally:
            os.remove(csr_path)

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
        with self.assertCommandError(
            r"^Must give at least a CN in --subject or one or more --alt arguments\.$"
        ), self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            self.cmd("sign_cert", ca=self.ca, subject=Subject([("C", "AT")]))
        self.assertFalse(pre.called)
        self.assertFalse(post.called)

    @override_tmpcadir()
    def test_pass_format(self) -> None:
        """Test passing a format, which is deprecated."""
        common_name = "pass-format.example.com"
        warning_msg = r"^--csr-format option is deprecated and will be removed in django-ca 1\.20\.0\.$"
        with self.assertCreateCertSignals() as (pre, post), self.assertWarnsRegex(
            RemovedInDjangoCA120Warning, warning_msg
        ):
            stdout, stderr = self.cmd_e2e(
                [
                    "sign_cert",
                    f"--subject=CN={common_name}",
                    "--csr-format=PEM",
                ],
                stdin=self.csr_pem.encode(),
            )

        cert = Certificate.objects.get(cn=common_name)
        self.assertEqual(stdout, f"Please paste the CSR:\n{cert.pub.pem}")
        self.assertEqual(stderr, "")

    @override_tmpcadir()
    def test_unparsable_format(self) -> None:
        """Test signing with an invalid CSR format."""
        stdout = io.StringIO()
        stderr = io.StringIO()

        # with self.assertCreateCertSignals(False, False) as (pre, post),
        # with self.assertWarnsRegex(
        #    RemovedInDjangoCA120Warning, warning_msg
        # ):
        with self.assertSystemExit(2), self.assertCreateCertSignals(False, False) as (pre, post):
            self.cmd_e2e(
                [
                    "sign_cert",
                    "--alt=example.com",
                    "--csr-format=foo",
                ],
                stdin=self.csr_pem.encode(),
                stdout=stdout,
                stderr=stderr,
            )
        self.assertEqual(stdout.getvalue(), "")
        self.assertTrue(
            stderr.getvalue()
            .strip()
            .endswith("sign_cert: error: argument --csr-format: Unknown encoding: foo")
        )

    @override_tmpcadir()
    @freeze_time(timestamps["everything_valid"])
    def test_revoked_ca(self) -> None:
        """Test signing with a revoked CA."""
        self.ca.revoke()
        stdin = io.StringIO(self.csr_pem)
        subject = Subject([("CN", "example.com")])

        with self.assertCommandError(r"^Certificate Authority is revoked\.$"), self.mockSignal(
            pre_issue_cert
        ) as pre, self.mockSignal(post_issue_cert) as post:
            self.cmd("sign_cert", ca=self.ca, subject=subject, stdin=stdin)
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
        subject = Subject([("CN", "example.com")])

        with self.assertCommandError(msg), self.mockSignal(pre_issue_cert) as pre, self.mockSignal(
            post_issue_cert
        ) as post:
            self.cmd("sign_cert", ca=self.ca, subject=subject, stdin=stdin)
        self.assertFalse(pre.called)
        self.assertFalse(post.called)

    @override_tmpcadir()
    @freeze_time(timestamps["everything_expired"])
    def test_expired_ca(self) -> None:
        """Test signing with an expired CA."""
        stdin = io.StringIO(self.csr_pem)
        subject = Subject([("CN", "example.com")])

        with self.assertCommandError(r"^Certificate Authority has expired\.$"), self.mockSignal(
            pre_issue_cert
        ) as pre, self.mockSignal(post_issue_cert) as post:
            self.cmd("sign_cert", ca=self.ca, subject=subject, stdin=stdin)
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

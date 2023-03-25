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

"""Test the resign_cert management command."""

import os
from datetime import timedelta
from typing import Optional
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

from django.test import TestCase
from django.utils import timezone

from freezegun import freeze_time

from django_ca import ca_settings
from django_ca.models import Certificate, CertificateAuthority, Watcher
from django_ca.tests.base import dns, override_tmpcadir, timestamps, uri
from django_ca.tests.base.mixins import TestCaseMixin


@freeze_time(timestamps["everything_valid"])
class ResignCertTestCase(TestCaseMixin, TestCase):
    """Main test class for this command."""

    default_cert = "root-cert"
    load_cas = ("root", "child", "dsa")
    load_certs = ("root-cert", "dsa-cert", "no-extensions")

    def assertResigned(  # pylint: disable=invalid-name
        self, old: Certificate, new: Certificate, new_ca: Optional[CertificateAuthority] = None
    ) -> None:
        """Assert that the resigned certificate matches the old cert."""
        new_ca = new_ca or old.ca
        issuer = new_ca.subject

        self.assertNotEqual(old.pk, new.pk)  # make sure we're not comparing the same cert

        # assert various properties
        self.assertEqual(new_ca, new.ca)
        self.assertEqual(issuer, new.issuer)
        self.assertEqual(old.hpkp_pin, new.hpkp_pin)

    def assertEqualExt(  # pylint: disable=invalid-name
        self, old: Certificate, new: Certificate, new_ca: Optional[CertificateAuthority] = None
    ) -> None:
        """Assert that the extensions in both certs are equal."""
        new_ca = new_ca or old.ca
        self.assertEqual(old.subject, new.subject)

        # assert extensions that should be equal
        aki = new_ca.get_authority_key_identifier_extension()
        self.assertEqual(aki, new.x509_extensions[ExtensionOID.AUTHORITY_KEY_IDENTIFIER])
        for oid in [
            ExtensionOID.EXTENDED_KEY_USAGE,
            ExtensionOID.KEY_USAGE,
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
            ExtensionOID.TLS_FEATURE,
        ]:
            self.assertEqual(old.x509_extensions.get(oid), new.x509_extensions.get(oid))

        # Test extensions that don't come from the old cert but from the signing CA
        self.assertEqual(new.x509_extensions[ExtensionOID.BASIC_CONSTRAINTS], self.basic_constraints())
        self.assertNotIn(
            ExtensionOID.ISSUER_ALTERNATIVE_NAME, new.x509_extensions
        )  # signing CA does not have this set

        # Some properties come from the ca
        if new_ca.crl_url:
            self.assertEqual(
                new.x509_extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS],
                self.crl_distribution_points([uri(new_ca.crl_url)]),
            )
        else:
            self.assertNotIn(ExtensionOID.CRL_DISTRIBUTION_POINTS, new.x509_extensions)

    @override_tmpcadir()
    def test_basic(self) -> None:
        """Simplest test while resigning a cert."""
        with self.assertCreateCertSignals():
            stdout, stderr = self.cmd("resign_cert", self.cert.serial)
        self.assertEqual(stderr, "")

        new = Certificate.objects.get(pub=stdout)
        self.assertResigned(self.cert, new)
        self.assertEqualExt(self.cert, new)
        self.assertIsInstance(new.algorithm, type(self.cert.algorithm))

    @override_tmpcadir()
    def test_dsa_ca_resign(self) -> None:
        """Resign a certificate from a DSA CA."""
        with self.assertCreateCertSignals():
            stdout, stderr = self.cmd("resign_cert", self.certs["dsa-cert"].serial)
        self.assertEqual(stderr, "")

        new = Certificate.objects.get(pub=stdout)
        self.assertResigned(self.certs["dsa-cert"], new)
        self.assertEqualExt(self.certs["dsa-cert"], new)
        self.assertIsInstance(new.algorithm, hashes.SHA256)

    @override_tmpcadir()
    def test_custom_algorithm(self) -> None:
        """Test resigning a cert with a new algorithm."""
        with self.assertCreateCertSignals():
            stdout, stderr = self.cmd("resign_cert", self.cert.serial, algorithm=hashes.SHA512())
        self.assertEqual(stderr, "")

        new = Certificate.objects.get(pub=stdout)
        self.assertResigned(self.cert, new)
        self.assertEqualExt(self.cert, new)
        self.assertIsInstance(new.algorithm, hashes.SHA512)

    @override_tmpcadir()
    def test_different_ca(self) -> None:
        """Test writing with a different CA."""
        with self.assertCreateCertSignals():
            stdout, stderr = self.cmd("resign_cert", self.cert.serial, ca=self.cas["child"])

        self.assertEqual(stderr, "")

        new = Certificate.objects.get(pub=stdout)
        self.assertResigned(self.cert, new, new_ca=self.cas["child"])
        self.assertEqualExt(self.cert, new, new_ca=self.cas["child"])

    @override_tmpcadir(CA_DEFAULT_SUBJECT=tuple())
    def test_overwrite(self) -> None:
        """Test overwriting extensions."""
        cname = "new.example.com"
        key_usage = "cRLSign"
        ext_key_usage = "critical,emailProtection"
        tls_feature = "critical,MultipleCertStatusRequest"
        watcher = "new@example.com"
        alt = "new-alt-name.example.com"

        # resign a cert, but overwrite all options
        with self.assertCreateCertSignals():
            stdout, stderr = self.cmd_e2e(
                [
                    "resign_cert",
                    self.cert.serial,
                    "--key-usage",
                    key_usage,
                    "--key-usage-non-critical",
                    "--ext-key-usage",
                    ext_key_usage,
                    "--tls-feature",
                    tls_feature,
                    "--subject",
                    f"/CN={cname}",
                    "--watch",
                    watcher,
                    "--alt",
                    alt,
                ]
            )
        self.assertEqual(stderr, "")

        new = Certificate.objects.get(pub=stdout)
        self.assertResigned(self.cert, new)
        self.assertEqual(new.subject, x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cname)]))

        # assert overwritten extensions
        actual = new.x509_extensions
        self.assertEqual(
            actual[ExtensionOID.SUBJECT_ALTERNATIVE_NAME], self.subject_alternative_name(dns(alt))
        )
        self.assertEqual(actual[ExtensionOID.KEY_USAGE], self.key_usage(crl_sign=True, critical=False))
        self.assertEqual(
            actual[ExtensionOID.EXTENDED_KEY_USAGE],
            self.extended_key_usage(ExtendedKeyUsageOID.EMAIL_PROTECTION, critical=True),
        )
        self.assertEqual(
            actual[ExtensionOID.TLS_FEATURE],
            self.tls_feature(x509.TLSFeatureType.status_request_v2, critical=True),
        )
        self.assertEqual(list(new.watchers.all()), [Watcher.objects.get(mail=watcher)])

    @override_tmpcadir(
        CA_PROFILES={"server": {"expires": 200}, "webserver": {}},
        CA_DEFAULT_EXPIRES=31,
    )
    def test_set_profile(self) -> None:
        """Test getting the certificate from the profile."""

        with self.assertCreateCertSignals():
            stdout, stderr = self.cmd_e2e(["resign_cert", self.cert.serial, "--server"])
        self.assertEqual(stderr, "")

        new = Certificate.objects.get(pub=stdout)
        self.assertEqual(new.expires.date(), timezone.now().date() + timedelta(days=200))
        self.assertResigned(self.cert, new)
        self.assertEqualExt(self.cert, new)

    @override_tmpcadir(
        CA_PROFILES={"server": {"expires": 200}, "webserver": {}},
        CA_DEFAULT_EXPIRES=31,
    )
    def test_cert_profile(self) -> None:
        """Test passing a profile."""

        self.cert.profile = "server"
        self.cert.save()

        with self.assertCreateCertSignals():
            stdout, stderr = self.cmd_e2e(["resign_cert", self.cert.serial])
        self.assertEqual(stderr, "")

        new = Certificate.objects.get(pub=stdout)
        self.assertEqual(new.expires.date(), timezone.now().date() + timedelta(days=200))
        self.assertResigned(self.cert, new)
        self.assertEqualExt(self.cert, new)

    @override_tmpcadir()
    def test_to_file(self) -> None:
        """Test writing output to file."""
        out_path = os.path.join(ca_settings.CA_DIR, "test.pem")

        with self.assertCreateCertSignals():
            stdout, stderr = self.cmd("resign_cert", self.cert.serial, out=out_path)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")

        with open(out_path, encoding="ascii") as stream:
            pub = stream.read()

        new = Certificate.objects.get(pub=pub)
        self.assertResigned(self.cert, new)
        self.assertEqualExt(self.cert, new)

    @override_tmpcadir()
    def test_no_cn(self) -> None:
        """Test resigning with a subject that has no CN."""
        cert = self.certs["no-extensions"]
        subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.hostname)])

        msg = r"^Must give at least a CN in --subject or one or more --alt arguments\."
        with self.assertCreateCertSignals(False, False), self.assertCommandError(msg):
            self.cmd("resign_cert", cert, subject=subject)

    @override_tmpcadir()
    def test_error(self) -> None:
        """Test resign function throwing a random exception."""
        msg = "foobar"
        msg_re = rf"^{msg}$"
        with self.assertCreateCertSignals(False, False), patch(
            "django_ca.managers.CertificateManager.create_cert", side_effect=Exception(msg)
        ), self.assertCommandError(msg_re):
            self.cmd("resign_cert", self.cert.serial)

    @override_tmpcadir()
    def test_invalid_algorithm(self) -> None:
        """Test manually specifying an invalid algorithm."""

        ed448_ca = self.load_ca("ed448")
        with self.assertCommandError(r"^Ed448 keys do not allow an algorithm for signing\.$"):
            self.cmd("resign_cert", self.cert.serial, ca=ed448_ca, algorithm=hashes.SHA512())

    @override_tmpcadir(
        CA_PROFILES={"server": {"expires": 200}, "webserver": {}},
        CA_DEFAULT_EXPIRES=31,
    )
    def test_missing_cert_profile(self) -> None:
        """Test resigning a certificate with a profile that doesn't exist."""

        self.cert.profile = "profile-gone"
        self.cert.save()

        msg_re = rf'^Profile "{self.cert.profile}" for original certificate is no longer defined, please set one via the command line\.$'  # NOQA: E501
        with self.assertCommandError(msg_re):
            self.cmd("resign_cert", self.cert.serial)

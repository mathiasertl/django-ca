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
from typing import Any, Optional
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    CertificatePoliciesOID,
    ExtendedKeyUsageOID,
    ExtensionOID,
    NameOID,
)

from django.conf import settings
from django.test import TestCase
from django.utils import timezone

import pytest

from django_ca.models import Certificate, CertificateAuthority, Watcher
from django_ca.tests.base.assertions import assert_command_error, assert_create_cert_signals
from django_ca.tests.base.constants import TIMESTAMPS
from django_ca.tests.base.mixins import TestCaseMixin
from django_ca.tests.base.utils import (
    basic_constraints,
    certificate_policies,
    cmd,
    cmd_e2e,
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

pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])]


def resign_cert(serial: str, **kwargs: Any) -> tuple[str, str]:
    """Execute the regenerate_ocsp_keys command."""
    return cmd("resign_cert", serial, **kwargs)


class ResignCertTestCase(TestCaseMixin, TestCase):
    """Main test class for this command."""

    default_cert = "root-cert"
    load_cas = ("root", "child", "dsa")
    load_certs = ("root-cert", "dsa-cert", "no-extensions", "all-extensions")

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

    def assertEqualExt(  # pylint: disable=invalid-name
        self, old: Certificate, new: Certificate, new_ca: Optional[CertificateAuthority] = None
    ) -> None:
        """Assert that the extensions in both certs are equal."""
        new_ca = new_ca or old.ca
        self.assertEqual(old.subject, new.subject)

        # assert extensions that should be equal
        aki = new_ca.get_authority_key_identifier_extension()
        self.assertEqual(aki, new.extensions[ExtensionOID.AUTHORITY_KEY_IDENTIFIER])
        for oid in [
            ExtensionOID.EXTENDED_KEY_USAGE,
            ExtensionOID.KEY_USAGE,
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
            ExtensionOID.TLS_FEATURE,
        ]:
            self.assertEqual(old.extensions.get(oid), new.extensions.get(oid))

        # Test extensions that don't come from the old cert but from the signing CA
        self.assertEqual(new.extensions[ExtensionOID.BASIC_CONSTRAINTS], basic_constraints())
        self.assertNotIn(
            ExtensionOID.ISSUER_ALTERNATIVE_NAME, new.extensions
        )  # signing CA does not have this set

        # Some properties come from the ca
        if new_ca.sign_crl_distribution_points:
            self.assertEqual(
                new.extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS], new_ca.sign_crl_distribution_points
            )
        else:
            self.assertNotIn(ExtensionOID.CRL_DISTRIBUTION_POINTS, new.extensions)

    @override_tmpcadir()
    def test_basic(self) -> None:
        """Simplest test while resigning a cert."""
        with assert_create_cert_signals():
            stdout, stderr = cmd("resign_cert", self.cert.serial)
        self.assertEqual(stderr, "")

        new = Certificate.objects.get(pub=stdout)
        self.assertResigned(self.cert, new)
        self.assertEqualExt(self.cert, new)
        self.assertIsInstance(new.algorithm, type(self.cert.algorithm))

    @override_tmpcadir()
    def test_dsa_ca_resign(self) -> None:
        """Resign a certificate from a DSA CA."""
        with assert_create_cert_signals():
            stdout, stderr = cmd("resign_cert", self.certs["dsa-cert"].serial)
        self.assertEqual(stderr, "")

        new = Certificate.objects.get(pub=stdout)
        self.assertResigned(self.certs["dsa-cert"], new)
        self.assertEqualExt(self.certs["dsa-cert"], new)
        self.assertIsInstance(new.algorithm, hashes.SHA256)

    @override_tmpcadir()
    def test_all_extensions_certificate(self) -> None:
        """Test resigning the all-extensions certificate."""
        orig = self.certs["all-extensions"]
        with assert_create_cert_signals():
            stdout, stderr = cmd("resign_cert", orig.serial)
        self.assertEqual(stderr, "")

        new = Certificate.objects.get(pub=stdout)
        self.assertResigned(orig, new)
        self.assertIsInstance(new.algorithm, hashes.SHA256)

        expected = orig.extensions
        actual = new.extensions
        self.assertEqual(
            sorted(expected.values(), key=lambda e: e.oid.dotted_string),
            sorted(actual.values(), key=lambda e: e.oid.dotted_string),
        )

    @override_tmpcadir()
    def test_test_all_extensions_cert_with_overrides(self) -> None:
        """Test resigning a certificate with adding new extensions."""
        self.assertIsNotNone(self.ca.sign_authority_information_access)
        self.assertIsNotNone(self.ca.sign_crl_distribution_points)
        self.ca.sign_certificate_policies = certificate_policies(
            x509.PolicyInformation(
                policy_identifier=CertificatePoliciesOID.CPS_QUALIFIER, policy_qualifiers=None
            )
        )
        self.ca.sign_issuer_alternative_name = issuer_alternative_name(
            uri("http://issuer-alt-name.test-only-ca.example.com")
        )
        self.ca.save()

        orig = self.certs["all-extensions"]
        with assert_create_cert_signals():
            stdout, stderr = cmd(
                "resign_cert",
                orig.serial,
                # Authority Information Access extension
                "--ocsp-responder=http://ocsp.example.com/1",
                "--ca-issuer=http://issuer.example.com/1",
                "--ocsp-responder=http://ocsp.example.com/2",
                "--ca-issuer=http://issuer.example.com/2",
                # Certificate Policies extension
                "--policy-identifier=1.2.3",
                "--certification-practice-statement=https://example.com/overwritten/",
                "--user-notice=overwritten user notice text",
                # CRL Distribution Points
                "--crl-full-name=http://crl.example.com",
                "--crl-full-name=http://crl.example.net",
                # Extended Key Usage extension
                "--extended-key-usage",
                "clientAuth",
                "serverAuth",
                # Issuer Alternative Name extension
                "--issuer-alternative-name",
                "DNS:ian-override.example.com",
                "--issuer-alternative-name",
                "URI:http://ian-override.example.com",
                # Key Usage extension
                "--key-usage",
                "keyAgreement",
                "keyEncipherment",
                "--key-usage-non-critical",
                # OCSP No Check extension
                "--ocsp-no-check",
                "--ocsp-no-check-critical",
                # Subject Alternative Name extension
                "--subject-alternative-name=DNS:override.example.net",
                # TLS Feature extension
                "--tls-feature",
                "status_request",
            )
        self.assertEqual(stderr, "")

        new = Certificate.objects.get(pub=stdout)
        self.assertResigned(orig, new)
        self.assertIsInstance(new.algorithm, hashes.SHA256)

        extensions = new.extensions

        # Test Authority Information Access extension
        self.assertEqual(
            extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS],
            x509.Extension(
                oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
                critical=False,
                value=x509.AuthorityInformationAccess(
                    [
                        x509.AccessDescription(
                            access_method=AuthorityInformationAccessOID.OCSP,
                            access_location=uri("http://ocsp.example.com/1"),
                        ),
                        x509.AccessDescription(
                            access_method=AuthorityInformationAccessOID.OCSP,
                            access_location=uri("http://ocsp.example.com/2"),
                        ),
                        x509.AccessDescription(
                            access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                            access_location=uri("http://issuer.example.com/1"),
                        ),
                        x509.AccessDescription(
                            access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                            access_location=uri("http://issuer.example.com/2"),
                        ),
                    ]
                ),
            ),
        )

        # Test Certificate Policies extension
        self.assertEqual(
            extensions[ExtensionOID.CERTIFICATE_POLICIES],
            x509.Extension(
                oid=ExtensionOID.CERTIFICATE_POLICIES,
                critical=False,
                value=x509.CertificatePolicies(
                    policies=[
                        x509.PolicyInformation(
                            policy_identifier=x509.ObjectIdentifier("1.2.3"),
                            policy_qualifiers=[
                                "https://example.com/overwritten/",
                                x509.UserNotice(
                                    notice_reference=None, explicit_text="overwritten user notice text"
                                ),
                            ],
                        )
                    ]
                ),
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
            extended_key_usage(ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH),
        )

        # Test Issuer Alternative Name extension
        self.assertEqual(
            extensions[ExtensionOID.ISSUER_ALTERNATIVE_NAME],
            issuer_alternative_name(dns("ian-override.example.com"), uri("http://ian-override.example.com")),
        )

        # Test KeyUsage extension
        self.assertEqual(
            extensions[ExtensionOID.KEY_USAGE],
            key_usage(key_agreement=True, key_encipherment=True, critical=False),
        )

        # Test OCSP No Check extension
        self.assertEqual(extensions[ExtensionOID.OCSP_NO_CHECK], ocsp_no_check(critical=True))

        # Test Subject Alternative Name extension
        self.assertEqual(
            extensions[x509.SubjectAlternativeName.oid],
            subject_alternative_name(dns("override.example.net")),
        )

        # Test TLSFeature extension
        self.assertEqual(
            extensions[ExtensionOID.TLS_FEATURE], tls_feature(x509.TLSFeatureType.status_request)
        )

    @override_tmpcadir()
    def test_test_no_extensions_cert_with_overrides(self) -> None:
        """Test resigning a certificate with adding new extensions."""
        self.assertIsNotNone(self.ca.sign_authority_information_access)
        self.assertIsNotNone(self.ca.sign_crl_distribution_points)
        self.ca.sign_certificate_policies = certificate_policies(
            x509.PolicyInformation(
                policy_identifier=CertificatePoliciesOID.CPS_QUALIFIER, policy_qualifiers=None
            )
        )
        self.ca.sign_issuer_alternative_name = issuer_alternative_name(
            uri("http://issuer-alt-name.test-only-ca.example.com")
        )
        self.ca.save()

        orig = self.certs["no-extensions"]
        with assert_create_cert_signals():
            stdout, stderr = cmd(
                "resign_cert",
                orig.serial,
                # Certificate Policies extension
                "--policy-identifier=1.2.3",
                "--certification-practice-statement=https://example.com/overwritten/",
                "--user-notice=overwritten user notice text",
                # CRL Distribution Points
                "--crl-full-name=http://crl.example.com",
                "--crl-full-name=http://crl.example.net",
                # Extended Key Usage extension
                "--extended-key-usage",
                "clientAuth",
                "serverAuth",
                # Issuer Alternative Name extension
                "--issuer-alternative-name",
                "DNS:ian-override.example.com",
                "--issuer-alternative-name",
                "URI:http://ian-override.example.com",
                # Key Usage extension
                "--key-usage",
                "keyAgreement",
                "keyEncipherment",
                # OCSP No Check extension
                "--ocsp-no-check",
                # Subject Alternative Name extension
                "--subject-alternative-name=DNS:override.example.net",
                # TLS Feature extension
                "--tls-feature",
                "status_request",
            )
        self.assertEqual(stderr, "")

        new = Certificate.objects.get(pub=stdout)
        self.assertResigned(orig, new)
        self.assertIsInstance(new.algorithm, hashes.SHA256)

        extensions = new.extensions

        # Test Certificate Policies extension
        self.assertEqual(
            extensions[ExtensionOID.CERTIFICATE_POLICIES],
            certificate_policies(
                x509.PolicyInformation(
                    policy_identifier=x509.ObjectIdentifier("1.2.3"),
                    policy_qualifiers=[
                        "https://example.com/overwritten/",
                        x509.UserNotice(notice_reference=None, explicit_text="overwritten user notice text"),
                    ],
                )
            ),
        )

        # Test CRL Distribution Points extension
        self.assertEqual(
            extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS],
            crl_distribution_points(
                distribution_point([uri("http://crl.example.com"), uri("http://crl.example.net")])
            ),
        )

        # Test Extended Key Usage extension
        self.assertEqual(
            extensions[ExtensionOID.EXTENDED_KEY_USAGE],
            extended_key_usage(ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH),
        )

        # Test Issuer Alternative Name extension
        self.assertEqual(
            extensions[ExtensionOID.ISSUER_ALTERNATIVE_NAME],
            issuer_alternative_name(dns("ian-override.example.com"), uri("http://ian-override.example.com")),
        )

        # Test Key Usage extension
        self.assertEqual(
            extensions[ExtensionOID.KEY_USAGE], key_usage(key_agreement=True, key_encipherment=True)
        )

        # Test OCSP No Check extension
        self.assertEqual(extensions[ExtensionOID.OCSP_NO_CHECK], ocsp_no_check())

        # Test Subject Alternative Name extension
        self.assertEqual(
            extensions[x509.SubjectAlternativeName.oid],
            subject_alternative_name(dns("override.example.net")),
        )

        # Test TLSFeature extension
        self.assertEqual(
            extensions[ExtensionOID.TLS_FEATURE], tls_feature(x509.TLSFeatureType.status_request)
        )

    @override_tmpcadir()
    def test_test_no_extensions_cert_with_overrides_with_non_default_critical(self) -> None:
        """Test resigning a certificate with adding new extensions with non-default critical values."""
        self.assertIsNotNone(self.ca.sign_authority_information_access)
        self.assertIsNotNone(self.ca.sign_crl_distribution_points)
        self.ca.sign_certificate_policies = certificate_policies(
            x509.PolicyInformation(
                policy_identifier=CertificatePoliciesOID.CPS_QUALIFIER, policy_qualifiers=None
            )
        )
        self.ca.save()

        orig = self.certs["no-extensions"]
        with assert_create_cert_signals():
            stdout, stderr = cmd(
                "resign_cert",
                orig.serial,
                # Certificate Policies extension
                "--policy-identifier=1.2.3",
                "--certification-practice-statement=https://example.com/overwritten/",
                "--user-notice=overwritten user notice text",
                "--certificate-policies-critical",
                # CRL Distribution Points
                "--crl-full-name=http://crl.example.com",
                "--crl-full-name=http://crl.example.net",
                "--crl-distribution-points-critical",
                # Extended Key Usage extension
                "--extended-key-usage",
                "clientAuth",
                "serverAuth",
                "--extended-key-usage-critical",
                # Key Usage extension
                "--key-usage",
                "keyAgreement",
                "keyEncipherment",
                "--key-usage-non-critical",
                # OCSP No Check extension
                "--ocsp-no-check",
                "--ocsp-no-check-critical",
                # Subject Alternative Name extension
                "--subject-alternative-name=DNS:override.example.net",
                "--subject-alternative-name-critical",
                # TLS Feature extension
                "--tls-feature",
                "status_request",
                "--tls-feature-critical",
            )
        self.assertEqual(stderr, "")

        new = Certificate.objects.get(pub=stdout)
        self.assertResigned(orig, new)
        self.assertIsInstance(new.algorithm, hashes.SHA256)

        extensions = new.extensions

        # Test Certificate Policies extension
        self.assertEqual(
            extensions[ExtensionOID.CERTIFICATE_POLICIES],
            x509.Extension(
                oid=ExtensionOID.CERTIFICATE_POLICIES,
                critical=True,
                value=x509.CertificatePolicies(
                    policies=[
                        x509.PolicyInformation(
                            policy_identifier=x509.ObjectIdentifier("1.2.3"),
                            policy_qualifiers=[
                                "https://example.com/overwritten/",
                                x509.UserNotice(
                                    notice_reference=None, explicit_text="overwritten user notice text"
                                ),
                            ],
                        )
                    ]
                ),
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
            extended_key_usage(
                ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH, critical=True
            ),
        )

        # Test Key Usage extension
        self.assertEqual(
            extensions[ExtensionOID.KEY_USAGE],
            key_usage(key_agreement=True, key_encipherment=True, critical=False),
        )

        # Test OCSP No Check extension
        self.assertEqual(extensions[ExtensionOID.OCSP_NO_CHECK], ocsp_no_check(True))

        # Test Subject Alternative Name extension
        self.assertEqual(
            extensions[x509.SubjectAlternativeName.oid],
            subject_alternative_name(dns("override.example.net"), critical=True),
        )

        # Test TLSFeature extension
        self.assertEqual(
            extensions[ExtensionOID.TLS_FEATURE],
            tls_feature(x509.TLSFeatureType.status_request, critical=True),
        )

    @override_tmpcadir()
    def test_custom_algorithm(self) -> None:
        """Test resigning a cert with a new algorithm."""
        with assert_create_cert_signals():
            stdout, stderr = cmd("resign_cert", self.cert.serial, algorithm=hashes.SHA512())
        self.assertEqual(stderr, "")

        new = Certificate.objects.get(pub=stdout)
        self.assertResigned(self.cert, new)
        self.assertEqualExt(self.cert, new)
        self.assertIsInstance(new.algorithm, hashes.SHA512)

    @override_tmpcadir()
    def test_different_ca(self) -> None:
        """Test writing with a different CA."""
        with assert_create_cert_signals():
            stdout, stderr = cmd("resign_cert", self.cert.serial, ca=self.cas["child"])

        self.assertEqual(stderr, "")

        new = Certificate.objects.get(pub=stdout)
        self.assertResigned(self.cert, new, new_ca=self.cas["child"])
        self.assertEqualExt(self.cert, new, new_ca=self.cas["child"])

    @override_tmpcadir(CA_DEFAULT_SUBJECT=tuple())
    def test_overwrite(self) -> None:
        """Test overwriting extensions."""
        cname = "new.example.com"
        ext_key_usage = "emailProtection"
        watcher = "new@example.com"

        # resign a cert, but overwrite all options
        with assert_create_cert_signals():
            stdout, stderr = cmd_e2e(
                [
                    "resign_cert",
                    self.cert.serial,
                    "--key-usage",
                    "cRLSign",
                    "--key-usage-non-critical",
                    f"--extended-key-usage={ext_key_usage}",
                    "--extended-key-usage-critical",
                    "--tls-feature",
                    "status_request_v2",
                    "--tls-feature-critical",
                    "--subject-format=rfc4514",
                    "--subject",
                    f"CN={cname}",
                    "--watch",
                    watcher,
                    "--subject-alternative-name",
                    "subject-alternative-name.example.com",
                ]
            )
        self.assertEqual(stderr, "")

        new = Certificate.objects.get(pub=stdout)
        self.assertResigned(self.cert, new)
        self.assertEqual(new.subject, x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cname)]))
        self.assertEqual(list(new.watchers.all()), [Watcher.objects.get(mail=watcher)])

        # assert overwritten extensions
        extensions = new.extensions

        # Test Extended Key Usage extension
        self.assertEqual(
            extensions[ExtensionOID.EXTENDED_KEY_USAGE],
            extended_key_usage(ExtendedKeyUsageOID.EMAIL_PROTECTION, critical=True),
        )

        # Test Key Usage extension
        self.assertEqual(extensions[ExtensionOID.KEY_USAGE], key_usage(crl_sign=True, critical=False))

        # Test Subject Alternative Name extension
        self.assertEqual(
            extensions[ExtensionOID.SUBJECT_ALTERNATIVE_NAME],
            subject_alternative_name(dns("subject-alternative-name.example.com")),
        )

        # Test TLSFeature extension
        self.assertEqual(
            extensions[ExtensionOID.TLS_FEATURE],
            tls_feature(x509.TLSFeatureType.status_request_v2, critical=True),
        )

    @override_tmpcadir(
        CA_PROFILES={"server": {"expires": 200}, "webserver": {}},
        CA_DEFAULT_EXPIRES=31,
    )
    def test_set_profile(self) -> None:
        """Test getting the certificate from the profile."""
        with assert_create_cert_signals():
            stdout, stderr = cmd_e2e(["resign_cert", self.cert.serial, "--server"])
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

        with assert_create_cert_signals():
            stdout, stderr = cmd_e2e(["resign_cert", self.cert.serial])
        self.assertEqual(stderr, "")

        new = Certificate.objects.get(pub=stdout)
        self.assertEqual(new.expires.date(), timezone.now().date() + timedelta(days=200))
        self.assertResigned(self.cert, new)
        self.assertEqualExt(self.cert, new)

    @override_tmpcadir()
    def test_to_file(self) -> None:
        """Test writing output to file."""
        out_path = os.path.join(settings.CA_DIR, "test.pem")

        with assert_create_cert_signals():
            stdout, stderr = cmd("resign_cert", self.cert.serial, out=out_path)
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

        msg = (
            r"^Must give at least a Common Name in --subject or one or more "
            r"--subject-alternative-name/--name arguments\.$"
        )
        with assert_create_cert_signals(False, False), assert_command_error(msg):
            cmd("resign_cert", cert, subject_format="rfc4514", subject=subject.rfc4514_string())

    @override_tmpcadir()
    def test_error(self) -> None:
        """Test resign function throwing a random exception."""
        msg = "foobar"
        msg_re = rf"^{msg}$"
        with (
            assert_create_cert_signals(False, False),
            patch("django_ca.managers.CertificateManager.create_cert", side_effect=Exception(msg)),
            assert_command_error(msg_re),
        ):
            cmd("resign_cert", self.cert.serial)

    @override_tmpcadir()
    def test_invalid_algorithm(self) -> None:
        """Test manually specifying an invalid algorithm."""
        ed448_ca = self.load_ca("ed448")
        with assert_command_error(r"^Ed448 keys do not allow an algorithm for signing\.$"):
            cmd("resign_cert", self.cert.serial, ca=ed448_ca, algorithm=hashes.SHA512())

    @override_tmpcadir(
        CA_PROFILES={"server": {"expires": 200}, "webserver": {}},
        CA_DEFAULT_EXPIRES=31,
    )
    def test_missing_cert_profile(self) -> None:
        """Test resigning a certificate with a profile that doesn't exist."""
        self.cert.profile = "profile-gone"
        self.cert.save()

        msg_re = rf'^Profile "{self.cert.profile}" for original certificate is no longer defined, please set one via the command line\.$'  # NOQA: E501
        with assert_command_error(msg_re):
            cmd("resign_cert", self.cert.serial)


@pytest.mark.freeze_time(TIMESTAMPS["everything_expired"])
def test_expired_certificate_authority(root_cert: Certificate) -> None:
    """Test resigning with a CA that has expired."""
    with assert_command_error(r"^Certificate authority has expired\.$"):
        resign_cert(root_cert.serial)


@pytest.mark.usefixtures("usable_root")
def test_disabled_certificate_authority(usable_root: CertificateAuthority, root_cert: Certificate) -> None:
    """Test resigning with a CA that is disabled."""
    assert usable_root == root_cert.ca
    usable_root.enabled = False
    usable_root.save()
    with assert_command_error(r"^Certificate authority is disabled\.$"):
        resign_cert(root_cert.serial)


@pytest.mark.usefixtures("usable_root")
def test_revoked_certificate_authority(usable_root: CertificateAuthority, root_cert: Certificate) -> None:
    """Test resigning with a CA that is revoked."""
    assert usable_root == root_cert.ca
    usable_root.revoke()
    with assert_command_error(r"^Certificate authority is revoked\.$"):
        resign_cert(root_cert.serial)


def test_unusable_private_key(root_cert: Certificate) -> None:
    """Test resigning with an unusable CA."""
    with assert_command_error(r"root.key: Private key file not found\.$"):
        resign_cert(root_cert.serial)


def test_model_validation_error(root_cert: Certificate) -> None:
    """Test model validation is tested properly.

    NOTE: This example is contrived for the default backend, as the type of the password would already be
    checked by argparse. Other backends however might have other validation mechanisms.
    """
    with assert_command_error(r"^password: Input should be a valid bytes$"):
        resign_cert(root_cert.serial, password=123)

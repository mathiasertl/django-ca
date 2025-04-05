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

from datetime import timedelta
from pathlib import Path
from typing import Any
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

from django.test import TestCase
from django.utils import timezone

import pytest
from pytest_django.fixtures import SettingsWrapper

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
    subject_alternative_name,
    tls_feature,
    uri,
)

pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])]


def resign_cert(serial: str, **kwargs: Any) -> Certificate:
    """Execute the regenerate_ocsp_keys command."""
    with assert_create_cert_signals():
        stdout, stderr = cmd("resign_cert", serial, **kwargs)
    assert stderr == ""
    return Certificate.objects.get(pub=stdout)


def assert_resigned(old: Certificate, new: Certificate, new_ca: CertificateAuthority | None = None) -> None:
    """Assert that the resigned certificate matches the old cert."""
    new_ca = new_ca or old.ca
    issuer = new_ca.subject

    assert old.pk != new.pk  # make sure we're not comparing the same cert

    # assert various properties
    assert new_ca == new.ca
    assert issuer == new.issuer


def assert_equal_ext(old: Certificate, new: Certificate, new_ca: CertificateAuthority | None = None) -> None:
    """Assert that the extensions in both certs are equal."""
    new_ca = new_ca or old.ca
    assert old.subject == new.subject

    # assert extensions that should be equal
    aki = new_ca.get_authority_key_identifier_extension()
    assert aki == new.extensions[ExtensionOID.AUTHORITY_KEY_IDENTIFIER]
    for oid in [
        ExtensionOID.EXTENDED_KEY_USAGE,
        ExtensionOID.KEY_USAGE,
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
        ExtensionOID.TLS_FEATURE,
    ]:
        assert old.extensions.get(oid) == new.extensions.get(oid)

    # Test extensions that don't come from the old cert but from the signing CA
    assert new.extensions[ExtensionOID.BASIC_CONSTRAINTS] == basic_constraints()
    assert ExtensionOID.ISSUER_ALTERNATIVE_NAME not in new.extensions  # signing CA does not have this set

    # Some properties come from the ca
    if new_ca.sign_crl_distribution_points:
        assert new.extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS] == new_ca.sign_crl_distribution_points
    else:
        assert ExtensionOID.CRL_DISTRIBUTION_POINTS not in new.extensions


@pytest.mark.usefixtures("usable_root")
def test_with_rsa(root_cert: Certificate) -> None:
    """Simplest test while resigning a cert."""
    new = resign_cert(root_cert.serial)
    assert_resigned(root_cert, new)
    assert_equal_ext(root_cert, new)
    assert isinstance(new.algorithm, type(root_cert.algorithm))


@pytest.mark.usefixtures("usable_dsa")
def test_with_dsa(dsa_cert: Certificate) -> None:
    """Resign a certificate from a DSA CA."""
    new = resign_cert(dsa_cert.serial)
    assert_resigned(dsa_cert, new)
    assert_equal_ext(dsa_cert, new)
    assert isinstance(new.algorithm, hashes.SHA256)


@pytest.mark.usefixtures("usable_child")
def test_all_extensions_certificate(all_extensions: Certificate) -> None:
    """Test resigning the all-extensions certificate."""
    with assert_create_cert_signals():
        new = resign_cert(all_extensions.serial)

    assert_resigned(all_extensions, new)
    assert isinstance(new.algorithm, hashes.SHA256)

    expected = all_extensions.extensions
    actual = new.extensions
    assert sorted(expected.values(), key=lambda e: e.oid.dotted_string) == sorted(
        actual.values(), key=lambda e: e.oid.dotted_string
    )


def test_all_extensions_cert_with_overrides(
    usable_child: CertificateAuthority, all_extensions: Certificate
) -> None:
    """Test resigning a certificate with adding new extensions."""
    assert usable_child.sign_authority_information_access is not None
    assert usable_child.sign_crl_distribution_points is not None
    usable_child.sign_certificate_policies = certificate_policies(
        x509.PolicyInformation(policy_identifier=CertificatePoliciesOID.CPS_QUALIFIER, policy_qualifiers=None)
    )
    usable_child.sign_issuer_alternative_name = issuer_alternative_name(
        uri("http://issuer-alt-name.test-only-ca.example.com")
    )
    usable_child.save()

    with assert_create_cert_signals():
        stdout, stderr = cmd(
            "resign_cert",
            all_extensions.serial,
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
    assert stderr == ""

    new = Certificate.objects.get(pub=stdout)
    assert_resigned(all_extensions, new)
    assert isinstance(new.algorithm, hashes.SHA256)

    extensions = new.extensions

    # Test Authority Information Access extension
    assert extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS] == x509.Extension(
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
    )

    # Test Certificate Policies extension
    assert extensions[ExtensionOID.CERTIFICATE_POLICIES] == x509.Extension(
        oid=ExtensionOID.CERTIFICATE_POLICIES,
        critical=False,
        value=x509.CertificatePolicies(
            policies=[
                x509.PolicyInformation(
                    policy_identifier=x509.ObjectIdentifier("1.2.3"),
                    policy_qualifiers=[
                        "https://example.com/overwritten/",
                        x509.UserNotice(notice_reference=None, explicit_text="overwritten user notice text"),
                    ],
                )
            ]
        ),
    )

    # Test CRL Distribution Points extension
    assert extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS] == crl_distribution_points(
        distribution_point([uri("http://crl.example.com"), uri("http://crl.example.net")])
    )

    # Test Extended Key Usage extension
    assert extensions[ExtensionOID.EXTENDED_KEY_USAGE] == extended_key_usage(
        ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH
    )

    # Test Issuer Alternative Name extension
    assert extensions[ExtensionOID.ISSUER_ALTERNATIVE_NAME] == issuer_alternative_name(
        dns("ian-override.example.com"), uri("http://ian-override.example.com")
    )

    # Test KeyUsage extension
    assert extensions[ExtensionOID.KEY_USAGE] == key_usage(
        key_agreement=True, key_encipherment=True, critical=False
    )

    # Test OCSP No Check extension
    assert extensions[ExtensionOID.OCSP_NO_CHECK] == ocsp_no_check(critical=True)

    # Test Subject Alternative Name extension
    assert extensions[x509.SubjectAlternativeName.oid] == subject_alternative_name(
        dns("override.example.net")
    )

    # Test TLSFeature extension
    assert extensions[ExtensionOID.TLS_FEATURE] == tls_feature(x509.TLSFeatureType.status_request)


def test_no_extensions_cert_with_overrides(
    usable_child: CertificateAuthority, no_extensions: Certificate
) -> None:
    """Test resigning a certificate with adding new extensions."""
    assert usable_child.sign_authority_information_access is not None
    assert usable_child.sign_crl_distribution_points is not None
    usable_child.sign_certificate_policies = certificate_policies(
        x509.PolicyInformation(policy_identifier=CertificatePoliciesOID.CPS_QUALIFIER, policy_qualifiers=None)
    )
    usable_child.sign_issuer_alternative_name = issuer_alternative_name(
        uri("http://issuer-alt-name.test-only-ca.example.com")
    )
    usable_child.save()

    with assert_create_cert_signals():
        stdout, stderr = cmd(
            "resign_cert",
            no_extensions.serial,
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
    assert stderr == ""

    new = Certificate.objects.get(pub=stdout)
    assert_resigned(no_extensions, new)
    assert isinstance(new.algorithm, hashes.SHA256)

    extensions = new.extensions

    # Test Certificate Policies extension
    assert extensions[ExtensionOID.CERTIFICATE_POLICIES] == certificate_policies(
        x509.PolicyInformation(
            policy_identifier=x509.ObjectIdentifier("1.2.3"),
            policy_qualifiers=[
                "https://example.com/overwritten/",
                x509.UserNotice(notice_reference=None, explicit_text="overwritten user notice text"),
            ],
        )
    )

    # Test CRL Distribution Points extension
    assert extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS] == crl_distribution_points(
        distribution_point([uri("http://crl.example.com"), uri("http://crl.example.net")])
    )

    # Test Extended Key Usage extension
    assert extensions[ExtensionOID.EXTENDED_KEY_USAGE] == extended_key_usage(
        ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH
    )

    # Test Issuer Alternative Name extension
    assert extensions[ExtensionOID.ISSUER_ALTERNATIVE_NAME] == issuer_alternative_name(
        dns("ian-override.example.com"), uri("http://ian-override.example.com")
    )

    # Test Key Usage extension
    assert extensions[ExtensionOID.KEY_USAGE] == key_usage(key_agreement=True, key_encipherment=True)

    # Test OCSP No Check extension
    assert extensions[ExtensionOID.OCSP_NO_CHECK] == ocsp_no_check()

    # Test Subject Alternative Name extension
    assert extensions[x509.SubjectAlternativeName.oid] == subject_alternative_name(
        dns("override.example.net")
    )

    # Test TLSFeature extension
    assert extensions[ExtensionOID.TLS_FEATURE] == tls_feature(x509.TLSFeatureType.status_request)


def test_no_extensions_cert_with_overrides_with_non_default_critical(
    usable_child: CertificateAuthority, no_extensions: Certificate
) -> None:
    """Test resigning a certificate with adding new extensions with non-default critical values."""
    assert usable_child.sign_authority_information_access is not None
    assert usable_child.sign_crl_distribution_points is not None
    usable_child.sign_certificate_policies = certificate_policies(
        x509.PolicyInformation(policy_identifier=CertificatePoliciesOID.CPS_QUALIFIER, policy_qualifiers=None)
    )
    usable_child.save()

    with assert_create_cert_signals():
        stdout, stderr = cmd(
            "resign_cert",
            no_extensions.serial,
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
    assert stderr == ""

    new = Certificate.objects.get(pub=stdout)
    assert_resigned(no_extensions, new)
    assert isinstance(new.algorithm, hashes.SHA256)

    extensions = new.extensions

    # Test Certificate Policies extension
    assert extensions[ExtensionOID.CERTIFICATE_POLICIES] == x509.Extension(
        oid=ExtensionOID.CERTIFICATE_POLICIES,
        critical=True,
        value=x509.CertificatePolicies(
            policies=[
                x509.PolicyInformation(
                    policy_identifier=x509.ObjectIdentifier("1.2.3"),
                    policy_qualifiers=[
                        "https://example.com/overwritten/",
                        x509.UserNotice(notice_reference=None, explicit_text="overwritten user notice text"),
                    ],
                )
            ]
        ),
    )

    # Test CRL Distribution Points extension
    assert extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS] == crl_distribution_points(
        distribution_point([uri("http://crl.example.com"), uri("http://crl.example.net")]), critical=True
    )

    # Test Extended Key Usage extension
    assert extensions[ExtensionOID.EXTENDED_KEY_USAGE] == extended_key_usage(
        ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH, critical=True
    )

    # Test Key Usage extension
    assert extensions[ExtensionOID.KEY_USAGE] == key_usage(
        key_agreement=True, key_encipherment=True, critical=False
    )

    # Test OCSP No Check extension
    assert extensions[ExtensionOID.OCSP_NO_CHECK] == ocsp_no_check(True)

    # Test Subject Alternative Name extension
    assert extensions[x509.SubjectAlternativeName.oid] == subject_alternative_name(
        dns("override.example.net"), critical=True
    )

    # Test TLSFeature extension
    assert extensions[ExtensionOID.TLS_FEATURE] == tls_feature(
        x509.TLSFeatureType.status_request, critical=True
    )


@pytest.mark.usefixtures("usable_root")
def test_custom_algorithm(root_cert: Certificate) -> None:
    """Test resigning a cert with a new algorithm."""
    new = resign_cert(root_cert.serial, algorithm=hashes.SHA512())
    assert_resigned(root_cert, new)
    assert_equal_ext(root_cert, new)
    assert isinstance(new.algorithm, hashes.SHA512)


def test_different_ca(usable_child: CertificateAuthority, root_cert: Certificate) -> None:
    """Test writing with a different CA."""
    new = resign_cert(root_cert.serial, ca=usable_child)
    assert_resigned(root_cert, new, new_ca=usable_child)
    assert_equal_ext(root_cert, new, new_ca=usable_child)


@pytest.mark.usefixtures("usable_root")
def test_overwrite(settings: SettingsWrapper, root_cert: Certificate) -> None:
    """Test overwriting extensions."""
    settings.CA_DEFAULT_SUBJECT = tuple()
    cname = "new.example.com"
    ext_key_usage = "emailProtection"
    watcher = "new@example.com"

    # resign a cert, but overwrite all options
    with assert_create_cert_signals():
        stdout, stderr = cmd_e2e(
            [
                "resign_cert",
                root_cert.serial,
                "--key-usage",
                "cRLSign",
                "--key-usage-non-critical",
                f"--extended-key-usage={ext_key_usage}",
                "--extended-key-usage-critical",
                "--tls-feature",
                "status_request_v2",
                "--tls-feature-critical",
                "--subject",
                f"CN={cname}",
                "--watch",
                watcher,
                "--subject-alternative-name",
                "subject-alternative-name.example.com",
            ]
        )
    assert stderr == ""

    new = Certificate.objects.get(pub=stdout)
    assert_resigned(root_cert, new)
    assert new.subject == x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cname)])
    assert list(new.watchers.all()) == [Watcher.objects.get(mail=watcher)]

    # assert overwritten extensions
    extensions = new.extensions

    # Test Extended Key Usage extension
    assert extensions[ExtensionOID.EXTENDED_KEY_USAGE] == extended_key_usage(
        ExtendedKeyUsageOID.EMAIL_PROTECTION, critical=True
    )

    # Test Key Usage extension
    assert extensions[ExtensionOID.KEY_USAGE] == key_usage(crl_sign=True, critical=False)

    # Test Subject Alternative Name extension
    assert extensions[ExtensionOID.SUBJECT_ALTERNATIVE_NAME] == subject_alternative_name(
        dns("subject-alternative-name.example.com")
    )

    # Test TLSFeature extension
    assert extensions[ExtensionOID.TLS_FEATURE] == tls_feature(
        x509.TLSFeatureType.status_request_v2, critical=True
    )


@pytest.mark.usefixtures("usable_root")
def test_set_profile(settings: SettingsWrapper, root_cert: Certificate) -> None:
    """Test getting the certificate from the profile."""
    settings.CA_PROFILES = {"server": {"expires": 200}, "webserver": {}}
    settings.CA_DEFAULT_EXPIRES = 31
    with assert_create_cert_signals():
        stdout, stderr = cmd_e2e(["resign_cert", root_cert.serial, "--server"])
    assert stderr == ""

    new = Certificate.objects.get(pub=stdout)
    assert new.not_after.date() == timezone.now().date() + timedelta(days=200)
    assert_resigned(root_cert, new)
    assert_equal_ext(root_cert, new)


@pytest.mark.usefixtures("usable_root")
def test_cert_profile(settings: SettingsWrapper, root_cert: Certificate) -> None:
    """Test passing a profile."""
    settings.CA_PROFILES = {"server": {"expires": 200}, "webserver": {}}
    settings.CA_DEFAULT_EXPIRES = 31
    root_cert.profile = "server"
    root_cert.save()

    with assert_create_cert_signals():
        stdout, stderr = cmd_e2e(["resign_cert", root_cert.serial])
    assert stderr == ""

    new = Certificate.objects.get(pub=stdout)
    assert new.not_after.date() == timezone.now().date() + timedelta(days=200)
    assert_resigned(root_cert, new)
    assert_equal_ext(root_cert, new)


@pytest.mark.usefixtures("usable_root")
def test_to_file(tmpcadir: Path, root_cert: Certificate) -> None:
    """Test writing output to file."""
    out_path = tmpcadir / "test.pem"

    with assert_create_cert_signals():
        stdout, stderr = cmd("resign_cert", root_cert.serial, out=out_path)
    assert stdout == ""
    assert stderr == ""

    with open(out_path, encoding="ascii") as stream:
        pub = stream.read()

    new = Certificate.objects.get(pub=pub)
    assert_resigned(root_cert, new)
    assert_equal_ext(root_cert, new)


@pytest.mark.usefixtures("usable_child")
def test_no_cn(hostname: str, no_extensions: Certificate) -> None:
    """Test resigning with a subject that has no CN."""
    subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, hostname)])

    msg = (
        r"^Must give at least a Common Name in --subject or one or more "
        r"--subject-alternative-name/--name arguments\.$"
    )
    with assert_create_cert_signals(False, False), assert_command_error(msg):
        cmd("resign_cert", no_extensions, subject=subject)


@pytest.mark.usefixtures("usable_root")
def test_error(root_cert: Certificate) -> None:
    """Test resign function throwing a random exception."""
    msg = "foobar"
    msg_re = rf"^{msg}$"
    with (
        assert_create_cert_signals(False, False),
        patch("django_ca.managers.CertificateManager.create_cert", side_effect=Exception(msg)),
        assert_command_error(msg_re),
    ):
        cmd("resign_cert", root_cert.serial)


@pytest.mark.usefixtures("usable_root")
def test_invalid_algorithm(usable_ed448: CertificateAuthority, root_cert: Certificate) -> None:
    """Test manually specifying an invalid algorithm."""
    with assert_command_error(r"^Ed448 keys do not allow an algorithm for signing\.$"):
        cmd("resign_cert", root_cert.serial, ca=usable_ed448, algorithm=hashes.SHA512())


@pytest.mark.usefixtures("usable_root")
def test_missing_cert_profile(root_cert: Certificate) -> None:
    """Test resigning a certificate with a profile that doesn't exist."""
    root_cert.profile = "profile-gone"
    root_cert.save()

    msg_re = rf'^Profile "{root_cert.profile}" for original certificate is no longer defined, please set one via the command line\.$'  # NOQA: E501
    with assert_command_error(msg_re):
        cmd("resign_cert", root_cert.serial)


@pytest.mark.hsm
def test_hsm_backend(usable_hsm_ca: CertificateAuthority, root_cert: Certificate) -> None:
    """Test signing a certificate with a CA that is in a HSM."""
    # Fake the ca of an existing cert (this way we don't have to sign it)
    root_cert.ca = usable_hsm_ca
    root_cert.save()

    with assert_create_cert_signals():
        stdout, stderr = cmd("resign_cert", root_cert.serial)
    assert stderr == ""
    new = Certificate.objects.exclude(pk=root_cert.pk).get()
    assert_resigned(root_cert, new)
    assert_equal_ext(root_cert, new)


@pytest.mark.freeze_time(TIMESTAMPS["everything_expired"])
def test_expired_certificate_authority(root_cert: Certificate) -> None:
    """Test resigning with a CA that has expired."""
    with assert_command_error(r"^Certificate authority has expired\.$"):
        cmd("resign_cert", root_cert.serial)


@pytest.mark.usefixtures("usable_root")
def test_disabled_certificate_authority(usable_root: CertificateAuthority, root_cert: Certificate) -> None:
    """Test resigning with a CA that is disabled."""
    assert usable_root == root_cert.ca
    usable_root.enabled = False
    usable_root.save()
    with assert_command_error(r"^Certificate authority is disabled\.$"):
        cmd("resign_cert", root_cert.serial)


@pytest.mark.usefixtures("usable_root")
def test_revoked_certificate_authority(usable_root: CertificateAuthority, root_cert: Certificate) -> None:
    """Test resigning with a CA that is revoked."""
    assert usable_root == root_cert.ca
    usable_root.revoke()
    with assert_command_error(r"^Certificate authority is revoked\.$"):
        cmd("resign_cert", root_cert.serial)


def test_unusable_private_key(root_cert: Certificate) -> None:
    """Test resigning with an unusable CA."""
    with assert_command_error(r"root.key: Private key file not found\.$"):
        cmd("resign_cert", root_cert.serial)


def test_model_validation_error(root_cert: Certificate) -> None:
    """Test model validation is tested properly.

    NOTE: This example is contrived for the default backend, as the type of the password would already be
    checked by argparse. Other backends however might have other validation mechanisms.
    """
    with assert_command_error(r"^password: Input should be a valid bytes$"):
        cmd("resign_cert", root_cert.serial, password=123)

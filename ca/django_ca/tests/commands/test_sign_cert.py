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
import shutil
from datetime import timedelta
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import CertificatePoliciesOID, ExtendedKeyUsageOID, ExtensionOID, NameOID

from django.core.files.storage import storages
from django.urls import reverse
from django.utils import timezone

import pytest
from pytest_django.fixtures import SettingsWrapper

from django_ca.conf import model_settings
from django_ca.models import Certificate, CertificateAuthority
from django_ca.tests.base.assertions import (
    assert_authority_key_identifier,
    assert_command_error,
    assert_create_cert_signals,
    assert_post_issue_cert,
    assert_signature,
    assert_system_exit,
)
from django_ca.tests.base.constants import CERT_DATA, FIXTURES_DIR, TIMESTAMPS
from django_ca.tests.base.utils import (
    authority_information_access,
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

csr: bytes = CERT_DATA["root-cert"]["csr"]["parsed"].public_bytes(Encoding.PEM)

# All tests in this module require a valid time (so that the CA is valid)
pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])]


def sign_cert(ca: CertificateAuthority, subject: str, **kwargs: Any) -> tuple[str, str]:
    """Shortcut for the sign_cert command."""
    return cmd("sign_cert", ca=ca, subject=subject, **kwargs)


def test_usable_cas(usable_ca: CertificateAuthority, subject: x509.Name, rfc4514_subject: str) -> None:
    """Test signing with all usable CAs."""
    password = CERT_DATA[usable_ca.name].get("password")

    with assert_create_cert_signals() as (pre, post):
        stdout, stderr = sign_cert(usable_ca, rfc4514_subject, password=password, stdin=csr)
    assert stderr == ""

    cert = Certificate.objects.get(ca=usable_ca)
    assert cert.pub.loaded.issuer == usable_ca.subject
    assert cert.pub.loaded.subject == subject
    assert_post_issue_cert(post, cert)
    assert_signature(tuple(reversed(usable_ca.bundle)), cert)
    assert stdout == f"Please paste the CSR:\n{cert.pub.pem}"

    actual = cert.extensions

    assert actual[ExtensionOID.KEY_USAGE] == key_usage(
        digital_signature=True, key_agreement=True, key_encipherment=True
    )
    assert actual[ExtensionOID.EXTENDED_KEY_USAGE] == extended_key_usage(ExtendedKeyUsageOID.SERVER_AUTH)
    assert_authority_key_identifier(usable_ca, cert)


def test_with_bundle(usable_root: CertificateAuthority, rfc4514_subject: str) -> None:
    """Test outputting the whole certificate bundle."""
    stdout, stderr = sign_cert(usable_root, rfc4514_subject, bundle=True, stdin=csr)
    cert = Certificate.objects.get()
    assert stdout == f"Please paste the CSR:\n{cert.bundle_as_pem}"
    assert stderr == ""
    assert isinstance(cert.algorithm, hashes.SHA256)


def test_from_file(usable_root: CertificateAuthority, subject: x509.Name, rfc4514_subject: str) -> None:
    """Test reading CSR from file."""
    csr_path = FIXTURES_DIR / CERT_DATA["root-cert"]["csr_filename"]
    with assert_create_cert_signals() as (pre, post):
        stdout, stderr = sign_cert(usable_root, rfc4514_subject, csr=csr_path)
    assert stderr == ""

    cert = Certificate.objects.get()
    assert cert.pub.loaded.issuer == usable_root.subject
    assert cert.pub.loaded.subject == subject
    assert stdout == cert.pub.pem
    assert_post_issue_cert(post, cert)
    assert_signature([usable_root], cert)

    actual = cert.extensions
    assert actual[ExtensionOID.KEY_USAGE] == key_usage(
        digital_signature=True, key_agreement=True, key_encipherment=True
    )
    assert actual[ExtensionOID.EXTENDED_KEY_USAGE] == extended_key_usage(ExtendedKeyUsageOID.SERVER_AUTH)
    assert ExtensionOID.SUBJECT_ALTERNATIVE_NAME not in actual


def test_to_file(tmp_path: Path, usable_root: CertificateAuthority, rfc4514_subject: str) -> None:
    """Test writing PEM to file."""
    out_path = os.path.join(tmp_path, "test.pem")
    with assert_create_cert_signals() as (pre, post):
        stdout, stderr = sign_cert(usable_root, rfc4514_subject, out=out_path, stdin=csr)
    assert stdout == "Please paste the CSR:\n"
    assert stderr == ""

    cert = Certificate.objects.get()
    assert_post_issue_cert(post, cert)
    assert_signature([usable_root], cert)

    with open(out_path, encoding="ascii") as out_stream:
        from_file = out_stream.read()

    assert cert.pub.pem == from_file


def test_with_rsa_with_algorithm(usable_root: CertificateAuthority, rfc4514_subject: str) -> None:
    """Test creating a CA with a custom algorithm."""
    assert isinstance(usable_root.algorithm, hashes.SHA256)  # make sure that default is different
    sign_cert(usable_root, rfc4514_subject, stdin=csr, algorithm=hashes.SHA3_256())
    cert = Certificate.objects.get()
    assert isinstance(cert.algorithm, hashes.SHA3_256)


def test_subject_sort_with_profile_subject(
    settings: SettingsWrapper, usable_root: CertificateAuthority, hostname: str
) -> None:
    """Test that subject is sorted on the command line.

    The subject given in the profile must be updated with the given subject, and the order would not be
    clear otherwise.
    """
    settings.CA_PROFILES = {}
    settings.CA_DEFAULT_SUBJECT = ({"oid": "ST", "value": "Vienna"},)
    subject = f"CN={hostname},C=DE"  # not the default order
    cmdline = ["sign_cert", f"--subject={subject}", f"--ca={usable_root.serial}"]

    with assert_create_cert_signals() as (pre, post):
        stdout, stderr = cmd_e2e(cmdline, stdin=csr)

    assert stderr == ""

    cert = Certificate.objects.get()
    assert_post_issue_cert(post, cert)
    assert_signature([usable_root], cert)
    assert cert.pub.loaded.subject == x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Vienna"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ]
    )


def test_subject_sort_with_no_common_name(
    settings: SettingsWrapper, usable_root: CertificateAuthority, hostname: str
) -> None:
    """Test that the subject is sorted when the CommonName is added via SubjectAlternativeName.

    The subject must be ordered if the CommonName is coming from the SubjectAlternativeName extension, as
    the position of the CommonName would otherwise not be clear.
    """
    settings.CA_PROFILES = {}
    settings.CA_DEFAULT_SUBJECT = None
    subject = "emailAddress=user@example.com,C=AT"  # not the default order
    cmdline = ["sign_cert", f"--subject={subject}", f"--ca={usable_root.serial}", f"--alt={hostname}"]

    with assert_create_cert_signals() as (pre, post):
        stdout, stderr = cmd_e2e(cmdline, stdin=csr)
    assert stderr == ""

    cert = Certificate.objects.get()
    assert_post_issue_cert(post, cert)
    assert_signature([usable_root], cert)
    assert cert.pub.loaded.subject == x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "AT"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, "user@example.com"),
        ]
    )


def test_no_san(usable_root: CertificateAuthority, subject: x509.Name, rfc4514_subject: str) -> None:
    """Test signing without passing any SANs."""
    with assert_create_cert_signals() as (pre, post):
        stdout, stderr = sign_cert(usable_root, rfc4514_subject, stdin=csr)
    cert = Certificate.objects.get()
    assert cert.pub.loaded.subject == subject
    assert_post_issue_cert(post, cert)
    assert_signature([usable_root], cert)
    assert_authority_key_identifier(usable_root, cert)
    assert ExtensionOID.SUBJECT_ALTERNATIVE_NAME not in cert.extensions

    assert stdout == f"Please paste the CSR:\n{cert.pub.pem}"
    assert stderr == ""


def test_profile_subject(settings: SettingsWrapper, usable_root: CertificateAuthority, hostname: str) -> None:
    """Test signing with a subject in the profile."""
    # first, we only pass an subjectAltName, meaning that even the CommonName is used.
    settings.CA_PROFILES = {}
    settings.CA_DEFAULT_SUBJECT = (
        {"oid": "C", "value": "AT"},
        {"oid": "ST", "value": "Vienna"},
        {"oid": "L", "value": "Vienna"},
        {"oid": "O", "value": "MyOrg"},
        {"oid": "OU", "value": "MyOrgUnit"},
        {"oid": "CN", "value": "CommonName"},
        {"oid": "emailAddress", "value": "user@example.com"},
    )
    san = subject_alternative_name(dns(hostname))
    with assert_create_cert_signals() as (pre, post):
        stdout, stderr = cmd("sign_cert", ca=usable_root, subject_alternative_name=san.value, stdin=csr)
    assert stderr == ""

    cert = Certificate.objects.get()
    assert_post_issue_cert(post, cert)
    assert_signature([usable_root], cert)
    assert cert.pub.loaded.subject == model_settings.CA_DEFAULT_SUBJECT
    assert_authority_key_identifier(usable_root, cert)
    assert stdout == f"Please paste the CSR:\n{cert.pub.pem}"
    assert cert.extensions[ExtensionOID.SUBJECT_ALTERNATIVE_NAME] == san

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
    with assert_create_cert_signals() as (pre, post):
        sign_cert(
            usable_root,
            subject_alternative_name=san.value,
            stdin=csr,
            subject=subject.rfc4514_string(),
        )

    cert = Certificate.objects.get(cn="CommonName2")
    assert_post_issue_cert(post, cert)
    assert cert.pub.loaded.subject == subject
    assert cert.extensions[ExtensionOID.SUBJECT_ALTERNATIVE_NAME] == san


def test_extensions(usable_root: CertificateAuthority, subject: x509.Name, rfc4514_subject: str) -> None:
    """Test setting extensions for the signed certificate."""
    usable_root.sign_authority_information_access = authority_information_access(
        ca_issuers=[uri("http://issuer.ca.example.com")], ocsp=[uri("http://ocsp.ca.example.com")]
    )
    usable_root.sign_certificate_policies = certificate_policies(
        x509.PolicyInformation(policy_identifier=CertificatePoliciesOID.CPS_QUALIFIER, policy_qualifiers=None)
    )
    usable_root.sign_crl_distribution_points = crl_distribution_points(
        distribution_point([uri("http://crl.ca.example.com")])
    )
    usable_root.sign_issuer_alternative_name = issuer_alternative_name(uri("http://ian.example.com"))
    usable_root.save()

    cmdline = [
        "sign_cert",
        f"--subject={rfc4514_subject}",
        f"--ca={usable_root.serial}",
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

    with assert_create_cert_signals() as (pre, post):
        stdout, stderr = cmd_e2e(cmdline, stdin=csr)
    assert stderr == ""

    cert = Certificate.objects.get()
    assert_post_issue_cert(post, cert)
    assert_signature([usable_root], cert)
    assert cert.pub.loaded.subject == subject

    extensions = cert.extensions

    # Test Authority Information Access extension
    assert extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS] == authority_information_access(
        ocsp=[uri("http://ocsp.example.com/1"), uri("http://ocsp.example.com/2")],
        ca_issuers=[uri("http://issuer.example.com/1"), uri("http://issuer.example.com/2")],
    )

    # Test Certificate Policies extension
    assert extensions[ExtensionOID.CERTIFICATE_POLICIES] == certificate_policies(
        x509.PolicyInformation(
            policy_identifier=x509.ObjectIdentifier("1.2.3"),
            policy_qualifiers=[
                "https://example.com/cps/",
                x509.UserNotice(notice_reference=None, explicit_text="user notice text"),
            ],
        )
    )

    # Test CRL Distribution Points extension
    assert extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS] == crl_distribution_points(
        distribution_point([uri("http://crl.example.com"), uri("http://crl.example.net")])
    )

    # Test Extended Key Usage extension
    assert extensions[ExtensionOID.EXTENDED_KEY_USAGE] == extended_key_usage(ExtendedKeyUsageOID.CLIENT_AUTH)

    # Test Issuer Alternative Name extension
    assert extensions[ExtensionOID.ISSUER_ALTERNATIVE_NAME] == issuer_alternative_name(
        dns("ian-cert.example.com"), uri("http://ian-cert.example.com")
    )

    # Test Key Usage extension
    assert extensions[ExtensionOID.KEY_USAGE] == key_usage(key_cert_sign=True)
    # Test OCSP No Check extension
    assert extensions[ExtensionOID.OCSP_NO_CHECK] == ocsp_no_check()
    # Test Subject Alternative Name extension
    assert extensions[x509.SubjectAlternativeName.oid] == subject_alternative_name(uri("https://example.net"))
    # Test TLSFeature extension
    assert extensions[ExtensionOID.TLS_FEATURE] == tls_feature(x509.TLSFeatureType.status_request)


def test_extensions_with_non_default_critical(
    usable_root: CertificateAuthority, subject: x509.Name, rfc4514_subject: str
) -> None:
    """Test setting extensions with non-default critical values."""
    assert usable_root.sign_crl_distribution_points is not None

    cmdline = [
        "sign_cert",
        f"--subject={rfc4514_subject}",
        f"--ca={usable_root.serial}",
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

    with assert_create_cert_signals() as (pre, post):
        stdout, stderr = cmd_e2e(cmdline, stdin=csr)
    assert stderr == ""

    cert = Certificate.objects.get()
    assert_post_issue_cert(post, cert)
    assert_signature([usable_root], cert)
    assert cert.pub.loaded.subject == subject
    assert stdout == f"Please paste the CSR:\n{cert.pub.pem}"

    extensions = cert.extensions

    # Test Certificate Policies extension
    assert extensions[ExtensionOID.CERTIFICATE_POLICIES] == certificate_policies(
        x509.PolicyInformation(
            policy_identifier=x509.ObjectIdentifier("1.2.3"),
            policy_qualifiers=[
                "https://example.com/cps/",
                x509.UserNotice(notice_reference=None, explicit_text="user notice text"),
            ],
        ),
        critical=True,
    )

    # Test CRL Distribution Points extension
    assert extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS] == crl_distribution_points(
        distribution_point([uri("http://crl.example.com"), uri("http://crl.example.net")]), critical=True
    )

    # Test Extended Key Usage extension
    assert extensions[ExtensionOID.EXTENDED_KEY_USAGE] == extended_key_usage(
        ExtendedKeyUsageOID.CLIENT_AUTH, critical=True
    )

    # Test Key Usage extension
    assert extensions[ExtensionOID.KEY_USAGE] == key_usage(key_cert_sign=True, critical=False)

    # Test OCSP No Check extension
    assert extensions[ExtensionOID.OCSP_NO_CHECK] == ocsp_no_check(critical=True)

    # Test Subject Alternative Name extension (NOTE: Common Name is automatically appended).
    assert cert.extensions[x509.SubjectAlternativeName.oid] == subject_alternative_name(
        uri("https://example.net"), critical=True
    )


def test_extensions_with_formatting(
    usable_root: CertificateAuthority, subject: x509.Name, rfc4514_subject: str
) -> None:
    """Test adding various extensions."""
    cmdline = [
        "sign_cert",
        f"--subject={rfc4514_subject}",
        f"--ca={usable_root.serial}",
        "--ocsp-responder=https://example.com/ocsp/{OCSP_PATH}",
        "--ca-issuer=https://example.com/ca-issuer/{CA_ISSUER_PATH}",
        "--crl-full-name=http://example.com/crl/{CRL_PATH}",
        "--crl-full-name=http://example.net/crl/{CRL_PATH}",
    ]

    with assert_create_cert_signals() as (pre, post):
        stdout, stderr = cmd_e2e(cmdline, stdin=csr)
    assert stderr == ""

    cert = Certificate.objects.get()
    assert_post_issue_cert(post, cert)
    assert_signature([usable_root], cert)
    assert cert.pub.loaded.subject == subject
    assert stdout == f"Please paste the CSR:\n{cert.pub.pem}"

    extensions = cert.extensions
    ca_issuer_path = reverse("django_ca:issuer", kwargs={"serial": usable_root.serial})
    ocsp_path = reverse("django_ca:ocsp-cert-post", kwargs={"serial": usable_root.serial})
    crl_path = reverse("django_ca:crl", kwargs={"serial": usable_root.serial})

    # Test AuthorityInformationAccess extension
    assert extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS] == authority_information_access(
        ca_issuers=[uri(f"https://example.com/ca-issuer{ca_issuer_path}")],
        ocsp=[uri(f"https://example.com/ocsp{ocsp_path}")],
    )

    # Test CRL Distribution Points extension
    assert extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS] == crl_distribution_points(
        distribution_point(
            [uri(f"http://example.com/crl{crl_path}"), uri(f"http://example.net/crl{crl_path}")]
        )
    )


def test_multiple_sans(usable_root: CertificateAuthority, subject: x509.Name, rfc4514_subject: str) -> None:
    """Test passing multiple SubjectAlternativeName instances."""
    cmdline = [
        "sign_cert",
        f"--subject={rfc4514_subject}",
        f"--ca={usable_root.serial}",
        "--subject-alternative-name=URI:https://example.net",
        "--subject-alternative-name=DNS:example.org",
    ]
    with assert_create_cert_signals() as (pre, post):
        stdout, stderr = cmd_e2e(cmdline, stdin=csr)
    assert stderr == ""

    cert = Certificate.objects.get()
    assert_post_issue_cert(post, cert)
    assert_signature([usable_root], cert)
    assert cert.pub.loaded.subject == subject
    assert stdout == f"Please paste the CSR:\n{cert.pub.pem}"
    assert cert.extensions[x509.SubjectAlternativeName.oid] == subject_alternative_name(
        uri("https://example.net"), dns("example.org")
    )


def test_no_subject(settings: SettingsWrapper, usable_root: CertificateAuthority, hostname: str) -> None:
    """Test signing without a subject (but SANs)."""
    settings.CA_PROFILES = {}
    settings.CA_DEFAULT_SUBJECT = tuple()
    san = subject_alternative_name(dns(hostname)).value
    with assert_create_cert_signals():
        cmd("sign_cert", ca=usable_root, subject_alternative_name=san, stdin=csr)

    cert = Certificate.objects.get()
    assert_signature([usable_root], cert)
    assert cert.pub.loaded.subject == x509.Name([x509.NameAttribute(oid=NameOID.COMMON_NAME, value=hostname)])
    assert cert.extensions[ExtensionOID.SUBJECT_ALTERNATIVE_NAME] == subject_alternative_name(dns(hostname))


@pytest.mark.usefixtures("tmpcadir")
def test_secondary_backend(pwd: CertificateAuthority, rfc4514_subject: str) -> None:
    """Sign a certificate with a CA in the secondary backend."""
    # Prepare root so that it is usable with the secondary backend.
    secondary_location = storages["secondary"].location  # type: ignore[attr-defined]
    shutil.copy(os.path.join(FIXTURES_DIR, CERT_DATA["pwd"]["key_filename"]), secondary_location)
    pwd.key_backend_alias = "secondary"
    pwd.save()

    with assert_create_cert_signals() as (pre, post):
        sign_cert(pwd, rfc4514_subject, secondary_password=CERT_DATA["pwd"]["password"], stdin=csr)
    cert = Certificate.objects.get()
    assert_signature([pwd], cert)


@pytest.mark.hsm
def test_hsm_backend(usable_hsm_ca: CertificateAuthority, rfc4514_subject: str) -> None:
    """Test signing a certificate with a CA that is in a HSM."""
    with assert_create_cert_signals() as (pre, post):
        sign_cert(usable_hsm_ca, rfc4514_subject, stdin=csr)
    cert = Certificate.objects.get()
    assert_signature([usable_hsm_ca], cert)


def test_encrypted_ca_with_settings(
    usable_pwd: CertificateAuthority, rfc4514_subject: str, settings: SettingsWrapper
) -> None:
    """Sign a certificate with an encrypted CA, with the password in CA_PASSWORDS."""
    settings.CA_PASSWORDS = {usable_pwd.serial: CERT_DATA[usable_pwd.name]["password"]}
    with assert_create_cert_signals():
        sign_cert(usable_pwd, rfc4514_subject, stdin=csr)
    cert = Certificate.objects.get()
    assert_signature([usable_pwd], cert)


def test_unencrypted_ca_with_password(usable_root: CertificateAuthority, rfc4514_subject: str) -> None:
    """Test signing with a CA that is not protected with a password, but giving a password."""
    with (
        assert_command_error(r"^Password was given but private key is not encrypted\.$"),
        assert_create_cert_signals(False, False),
    ):
        sign_cert(usable_root, rfc4514_subject, password=b"there-is-no-password", stdin=csr)
    assert Certificate.objects.exists() is False


def test_encrypted_ca_with_no_password(
    usable_pwd: CertificateAuthority, rfc4514_subject: str, settings: SettingsWrapper
) -> None:
    """Test signing with a CA that is protected with a password, but not giving a password."""
    settings.CA_PASSWORDS = {}
    with (
        assert_command_error(r"^Password was not given but private key is encrypted$"),
        assert_create_cert_signals(False, False),
    ):
        sign_cert(usable_pwd, rfc4514_subject, stdin=csr)
    assert Certificate.objects.exists() is False


def test_encrypted_ca_with_wrong_password(usable_pwd: CertificateAuthority, rfc4514_subject: str) -> None:
    """Test that passing the wrong password raises an error."""
    with (
        assert_command_error(r"^Could not decrypt private key - bad password\?$"),
        assert_create_cert_signals(False, False),
    ):
        sign_cert(usable_pwd, rfc4514_subject, stdin=csr, password=b"wrong")
    assert Certificate.objects.exists() is False


def test_unparsable_private_key(usable_root: CertificateAuthority, rfc4514_subject: str) -> None:
    """Test creating a cert where the CA private key contains bogus data."""
    path = storages["django-ca"].path(usable_root.key_backend_options["path"])
    with open(path, "wb") as stream:
        stream.write(b"bogus")

    with (
        assert_command_error(r"^Could not decrypt private key - bad password\?$"),
        assert_create_cert_signals(False, False),
    ):
        sign_cert(usable_root, rfc4514_subject, stdin=csr)


def test_unsortable_subject_with_no_profile_subject(
    settings: SettingsWrapper, usable_root: CertificateAuthority, hostname: str
) -> None:
    """Test passing a subject that cannot be sorted.

    The subject of the certificate will be identical to the given subject, with no sorting applied. This
    requires that the profile does **not** define a subject (as given and profile subject would have to be
    merged) and the passed subject already contains a CommonName (as it would have to be added in the
    "correct" location from the SubjectAlternativeName extension).
    """
    settings.CA_PROFILES = {model_settings.CA_DEFAULT_PROFILE: {"subject": False}}
    with assert_create_cert_signals() as (pre, post):
        stdout, stderr = sign_cert(
            usable_root,
            subject=f"inn=weird,CN={hostname}",
            stdin=csr,
        )
    assert stderr == ""

    cert = Certificate.objects.get(cn=hostname)
    assert_post_issue_cert(post, cert)
    assert_signature([usable_root], cert)
    assert cert.pub.loaded.subject == x509.Name(
        [
            x509.NameAttribute(NameOID.INN, "weird"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ]
    )
    assert stdout == f"Please paste the CSR:\n{cert.pub.pem}"


def test_unsortable_subject_with_profile_subject(
    settings: SettingsWrapper, usable_root: CertificateAuthority, hostname: str
) -> None:
    """Test passing a subject that cannot be sorted, but the profile also defines a subject.

    The given subject and subject in the profile cannot be merged in any predictable order, so this is an
    error.
    """
    settings.CA_PROFILES = {}
    settings.CA_DEFAULT_SUBJECT = ({"oid": "C", "value": "AT"},)
    subject = f"inn=weird,CN={hostname}"
    with assert_command_error(rf"^{subject}: Unsortable name$"), assert_create_cert_signals(False, False):
        sign_cert(usable_root, subject, stdin=csr)


def test_unsortable_subject_with_no_common_name(
    settings: SettingsWrapper, usable_root: CertificateAuthority, hostname: str
) -> None:
    """Test passing a subject that cannot be sorted and has no CommonName.

    The position of the CommonName added via the SubjectAlternativeName extension cannot be determined.
    """
    settings.CA_PROFILES = {}
    settings.CA_DEFAULT_SUBJECT = None
    subject = "inn=weird"
    san = subject_alternative_name(dns(hostname)).value
    with assert_command_error(rf"^{subject}: Unsortable name$"), assert_create_cert_signals(False, False):
        # NOTE: pass SAN as otherwise check for missing common name or san would fire
        sign_cert(usable_root, subject, subject_alternative_name=san, stdin=csr)


def test_expiry_too_late(usable_root: CertificateAuthority, rfc4514_subject: str) -> None:
    """Test signing with an expiry after the CA expires."""
    time_left = (usable_root.not_after - timezone.now()).days
    expires = timedelta(days=time_left + 3)

    with (
        assert_command_error(
            rf"^Certificate would outlive CA, maximum expiry for this CA is {time_left} days\.$"
        ),
        assert_create_cert_signals(False, False),
    ):
        sign_cert(usable_root, rfc4514_subject, expires=expires, stdin=csr)


def test_revoked_ca(root: CertificateAuthority, rfc4514_subject: str) -> None:
    """Test signing with a revoked CA."""
    root.revoke()

    with (
        assert_command_error(r"^Certificate authority is revoked\.$"),
        assert_create_cert_signals(False, False),
    ):
        sign_cert(root, rfc4514_subject, stdin=csr)


def test_invalid_algorithm(usable_ed448: CertificateAuthority, rfc4514_subject: str) -> None:
    """Test passing an invalid algorithm."""
    with assert_command_error(r"^Ed448 keys do not allow an algorithm for signing\.$"):
        sign_cert(usable_ed448, rfc4514_subject, algorithm=hashes.SHA512())


def test_no_cn_or_san(usable_root: CertificateAuthority, hostname: str) -> None:
    """Test signing a cert that has neither CN nor SAN."""
    subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, hostname)])
    with (
        assert_command_error(
            r"^Must give at least a Common Name in --subject or one or more "
            r"--subject-alternative-name/--name arguments\.$"
        ),
        assert_create_cert_signals(False, False),
    ):
        sign_cert(usable_root, subject.rfc4514_string())


def test_unusable_ca(root: CertificateAuthority, rfc4514_subject: str) -> None:
    """Test signing with an unusable CA."""
    msg = r"root.key: Private key file not found\.$"
    with assert_command_error(msg), assert_create_cert_signals(False, False):
        sign_cert(root, rfc4514_subject, stdin=csr)


@pytest.mark.freeze_time(TIMESTAMPS["everything_expired"])
def test_expired_ca(root: CertificateAuthority, rfc4514_subject: str) -> None:
    """Test signing with an expired CA."""
    msg = r"^Certificate authority has expired\.$"
    with assert_command_error(msg), assert_create_cert_signals(False, False):
        sign_cert(root, rfc4514_subject, stdin=csr)


def test_add_any_policy(root: CertificateAuthority) -> None:
    """Test adding the anyPolicy, which is an error for end-entity certificates."""
    cmdline = [
        "sign_cert",
        "--subject=/CN=example.com",
        f"--ca={root.serial}",
        "--policy-identifier=anyPolicy",
    ]

    actual_stdout = io.StringIO()
    actual_stderr = io.StringIO()
    with assert_system_exit(2):
        cmd_e2e(cmdline, stdout=actual_stdout, stderr=actual_stderr)

    assert "" == actual_stdout.getvalue()
    assert "anyPolicy is not allowed in this context." in actual_stderr.getvalue()


def test_model_validation_error(root: CertificateAuthority, rfc4514_subject: str) -> None:
    """Test model validation is tested properly.

    NOTE: This example is contrived for the default backend, as the type of the password would already be
    checked by argparse. Other backends however might have other validation mechanisms.
    """
    with assert_command_error(r"^password: Input should be a valid bytes$"):
        sign_cert(root, rfc4514_subject, password=123)

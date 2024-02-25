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

"""TestCases for various model managers."""

import unittest
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.x509.oid import ExtensionOID, NameOID

from django.test import TestCase, override_settings
from django.urls import reverse

import pytest
from freezegun import freeze_time

from django_ca import ca_settings
from django_ca.backends.storages import StoragesBackend
from django_ca.constants import ExtendedKeyUsageOID
from django_ca.models import Certificate, CertificateAuthority
from django_ca.profiles import profiles
from django_ca.querysets import CertificateAuthorityQuerySet, CertificateQuerySet
from django_ca.tests.base.assertions import assert_certificate_authority_properties, assert_create_ca_signals
from django_ca.tests.base.constants import CERT_DATA, TIMESTAMPS
from django_ca.tests.base.mixins import TestCaseMixin
from django_ca.tests.base.utils import (
    authority_information_access,
    basic_constraints,
    crl_distribution_points,
    distribution_point,
    dns,
    extended_key_usage,
    key_usage,
    name_constraints,
    ocsp_no_check,
    override_tmpcadir,
    precert_poison,
    tls_feature,
    uri,
)


@pytest.mark.django_db
def test_init(ca_name: str, subject: x509.Name, storages_backend: StoragesBackend) -> None:
    """Test creating the most basic possible CA."""
    with assert_create_ca_signals():
        ca = CertificateAuthority.objects.init(ca_name, subject, key_backend=storages_backend)
    assert_certificate_authority_properties(ca, ca_name, subject)


@pytest.mark.django_db
def test_init_with_dsa(ca_name: str, subject: x509.Name, storages_backend: StoragesBackend) -> None:
    """Test creating a DSA-based CA."""
    with assert_create_ca_signals():
        ca = CertificateAuthority.objects.init(ca_name, subject, key_type="DSA", key_backend=storages_backend)
    assert_certificate_authority_properties(
        ca, ca_name, subject, private_key_type=dsa.DSAPrivateKey, algorithm=hashes.SHA256
    )


@override_settings(CA_PROFILES={}, CA_DEFAULT_SUBJECT=tuple())
class CertificateAuthorityManagerInitTestCase(TestCaseMixin, TestCase):
    """Tests for :py:func:`django_ca.managers.CertificateAuthorityManager.init` (create a new CA)."""

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_password_bytes(self) -> None:
        """Create a CA with bytes as password."""
        name = "password_bytes"
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
        with assert_create_ca_signals():
            ca = CertificateAuthority.objects.init(name, subject, password=b"foobar")
        ca.key("foobar").public_key()
        ca.key(b"foobar").public_key()

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_password_str(self) -> None:
        """Create a CA with a str as password."""
        name = "password_bytes"
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
        with assert_create_ca_signals():
            ca = CertificateAuthority.objects.init(name, subject, password="foobar")
        ca.key("foobar").public_key()
        ca.key(b"foobar").public_key()

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_intermediate(self) -> None:
        """Test creating intermediate CAs."""
        # test a few properties of intermediate CAs, with multiple levels
        host = ca_settings.CA_DEFAULT_HOSTNAME  # shortcut
        name = "root"
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "root.example.com")])
        with assert_create_ca_signals():
            ca = CertificateAuthority.objects.init(name, subject, path_length=2)
        assert_certificate_authority_properties(ca, name, subject)
        self.assertNotIn(ExtensionOID.AUTHORITY_INFORMATION_ACCESS, ca.extensions)
        self.assertNotIn(ExtensionOID.CRL_DISTRIBUTION_POINTS, ca.extensions)

        name = "child"
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "child.example.com")])
        with assert_create_ca_signals():
            child = CertificateAuthority.objects.init(name, subject, parent=ca)
        assert_certificate_authority_properties(child, name, subject, parent=ca)

        expected_issuers = [uri(f"http://{host}{self.reverse('issuer', serial=ca.serial)}")]
        expected_ocsp = [uri(f"http://{host}{self.reverse('ocsp-ca-post', serial=ca.serial)}")]

        self.assertEqual(
            child.extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS],
            authority_information_access(ca_issuers=expected_issuers, ocsp=expected_ocsp),
        )
        self.assertEqual(
            child.extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS],
            crl_distribution_points(
                distribution_point([uri(f"http://{host}{self.reverse('ca-crl', serial=ca.serial)}")])
            ),
        )

        name = "grandchild"
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "grandchild.example.com")])
        with assert_create_ca_signals():
            grandchild = CertificateAuthority.objects.init(name, subject, parent=child)
        assert_certificate_authority_properties(grandchild, name, subject, parent=child)

        expected_ocsp = [uri(f"http://{host}{self.reverse('ocsp-ca-post', serial=child.serial)}")]
        expected_issuers = [uri(f"http://{host}{self.reverse('issuer', serial=child.serial)}")]
        self.assertEqual(
            grandchild.extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS],
            authority_information_access(ca_issuers=expected_issuers, ocsp=expected_ocsp),
        )
        self.assertEqual(
            grandchild.extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS],
            crl_distribution_points(
                distribution_point([uri(f"http://{host}{self.reverse('ca-crl', serial=child.serial)}")])
            ),
        )

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_no_default_hostname(self) -> None:
        """Test creating a CA with no default hostname."""
        name = "ndh"
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ndh.example.com")])
        with assert_create_ca_signals():
            ca = CertificateAuthority.objects.init(name, subject, default_hostname=False)
        self.assertEqual(ca.crl_number, '{"scope": {}}')
        self.assertIsNone(ca.sign_authority_information_access)
        self.assertIsNone(ca.sign_certificate_policies)
        self.assertIsNone(ca.sign_crl_distribution_points)
        self.assertIsNone(ca.sign_issuer_alternative_name)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_extra_extensions(self) -> None:
        """Test creating a CA with extra extensions."""
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
        extensions: List[x509.Extension[x509.ExtensionType]] = [
            tls_feature(x509.TLSFeatureType.status_request),
            ocsp_no_check(),
            name_constraints(permitted=[dns(".com")]),
            precert_poison(),
            self.ext(x509.InhibitAnyPolicy(3)),
        ]

        with assert_create_ca_signals():
            ca = CertificateAuthority.objects.init("with-extra", subject, extensions=extensions)

        self.assertEqual(ca.subject, subject)

        expected = [
            *extensions,
            basic_constraints(ca=True),
            key_usage(crl_sign=True, key_cert_sign=True),
            self.ext(x509.InhibitAnyPolicy(3)),
        ]
        self.assertExtensions(ca, expected)

    @override_tmpcadir()
    def test_partial_authority_information_access(self) -> None:
        """Test passing a partial Authority Information Access extension."""
        parent = self.load_ca("root")
        host = ca_settings.CA_DEFAULT_HOSTNAME  # shortcut
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
        ca_issuer_path = reverse("django_ca:issuer", kwargs={"serial": parent.serial})
        ocsp_path = reverse("django_ca:ocsp-ca-post", kwargs={"serial": parent.serial})

        # Pass no OCSP URIs
        passed_extensions: List[x509.Extension[x509.ExtensionType]] = [
            authority_information_access(ca_issuers=[uri("https://example.com/ca-issuer/{CA_ISSUER_PATH}")]),
        ]

        with assert_create_ca_signals():
            ca = CertificateAuthority.objects.init(
                "auto-ocsp", subject, parent=parent, extensions=passed_extensions
            )

        extensions = ca.extensions

        self.assertEqual(
            extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS],
            authority_information_access(
                ca_issuers=[uri(f"https://example.com/ca-issuer{ca_issuer_path}")],
                ocsp=[uri(f"http://{host}{ocsp_path}")],
            ),
        )

        # Pass no CA Issuers
        passed_extensions = [
            authority_information_access(
                ocsp=[uri("https://example.com/ocsp/{OCSP_PATH}")],
            ),
        ]

        with assert_create_ca_signals():
            ca = CertificateAuthority.objects.init(
                "auto-ca-issuers", subject, parent=parent, extensions=passed_extensions
            )

        extensions = ca.extensions

        self.assertEqual(
            extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS],
            authority_information_access(
                ca_issuers=[uri(f"http://{host}{ca_issuer_path}")],
                ocsp=[uri(f"https://example.com/ocsp{ocsp_path}")],
            ),
        )

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_formatting(self) -> None:
        """Test passing extensions that are formatted."""
        parent = self.load_ca("root")
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
        passed_extensions: List[x509.Extension[x509.ExtensionType]] = [
            authority_information_access(
                [uri("https://example.com/ca-issuer/{CA_ISSUER_PATH}")],
                [uri("https://example.com/ocsp/{OCSP_PATH}")],
            ),
            crl_distribution_points(distribution_point([uri("http://example.com/crl/{CRL_PATH}")])),
        ]

        with assert_create_ca_signals():
            ca = CertificateAuthority.objects.init(
                "formatting", subject, parent=parent, extensions=passed_extensions
            )

        extensions = ca.extensions
        ca_issuer_path = reverse("django_ca:issuer", kwargs={"serial": parent.serial})
        ocsp_path = reverse("django_ca:ocsp-ca-post", kwargs={"serial": parent.serial})
        crl_path = reverse("django_ca:ca-crl", kwargs={"serial": parent.serial})

        self.assertEqual(
            extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS],
            authority_information_access(
                [uri(f"https://example.com/ca-issuer{ca_issuer_path}")],
                [uri(f"https://example.com/ocsp{ocsp_path}")],
            ),
        )

        self.assertEqual(
            extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS],
            crl_distribution_points(distribution_point([uri(f"http://example.com/crl{crl_path}")])),
        )

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_formatting_no_uri(self) -> None:
        """Test passing extensions with values that cannot be formatted."""
        parent = self.load_ca("root")

        aia = authority_information_access([dns("ca-issuer.example.com")], [dns("ocsp.example.com")])
        crldp = crl_distribution_points(distribution_point([dns("crl.example.com")]))
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
        passed_extensions: List[x509.Extension[x509.ExtensionType]] = [aia, crldp]

        with assert_create_ca_signals():
            ca = CertificateAuthority.objects.init(
                "formatting", subject, parent=parent, extensions=passed_extensions
            )

        extensions = ca.extensions
        self.assertEqual(extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS], aia)
        self.assertEqual(extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS], crldp)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_formatting_with_rdn_in_crldp(self) -> None:
        """Test passing a relative distinguished name in the CRL Distribution Points extension."""
        parent = self.load_ca("root")

        crldp = self.crl_distribution_points(
            relative_name=x509.RelativeDistinguishedName(
                [x509.NameAttribute(NameOID.COMMON_NAME, "example.com")]
            )
        )
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
        passed_extensions: List[x509.Extension[x509.ExtensionType]] = [crldp]

        with assert_create_ca_signals():
            ca = CertificateAuthority.objects.init(
                "formatting-rdn", subject, parent=parent, extensions=passed_extensions
            )

        extensions = ca.extensions
        self.assertEqual(extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS], crldp)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_no_extensions(self) -> None:
        """Test passing no extensions."""
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
        with assert_create_ca_signals():
            ca = CertificateAuthority.objects.init("with-extra", subject, extensions=None)
        self.assertEqual(ca.subject, subject)
        self.assertExtensions(ca, [basic_constraints(ca=True), key_usage(crl_sign=True, key_cert_sign=True)])

    @override_tmpcadir()
    def test_acme_parameters(self) -> None:
        """Test parameters for ACMEv2."""
        name = "acme"
        with assert_create_ca_signals():
            ca = CertificateAuthority.objects.init(
                name, self.subject, acme_enabled=True, acme_profile="client", acme_requires_contact=False
            )
        assert_certificate_authority_properties(ca, name, self.subject)
        self.assertTrue(ca.acme_enabled)
        self.assertEqual(ca.acme_profile, "client")
        self.assertFalse(ca.acme_requires_contact)

    @override_tmpcadir()
    def test_api_parameters(self) -> None:
        """Test parameters for the REST API."""
        name = "api"
        with assert_create_ca_signals():
            ca = CertificateAuthority.objects.init(name, self.subject, api_enabled=True)
        assert_certificate_authority_properties(ca, name, self.subject)
        self.assertTrue(ca.api_enabled)

    def test_unknown_profile(self) -> None:
        """Test creating a certificate authority with a profile that doesn't exist."""
        with self.assertRaisesRegex(ValueError, r"^foobar: Profile is not defined\.$"):
            CertificateAuthority.objects.init("wrong", self.subject, acme_profile="foobar")

    def test_unknown_extension_type(self) -> None:
        """Test that creating a CA with an unknown extension throws an error."""
        name = "unknown-extension-type"
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{name}.example.com")])
        with self.assertRaisesRegex(ValueError, r"^Cannot add extension of type bool$"):
            CertificateAuthority.objects.init(name, subject, extensions=[True])  # type: ignore[list-item]
        self.assertEqual(CertificateAuthority.objects.filter(name=name).count(), 0)


@override_settings(CA_PROFILES={}, CA_DEFAULT_SUBJECT=tuple(), CA_DEFAULT_CA=CERT_DATA["child"]["serial"])
@freeze_time(TIMESTAMPS["everything_valid"])
class CertificateAuthorityManagerDefaultTestCase(TestCaseMixin, TestCase):
    """Tests for :py:func:`django_ca.managers.CertificateAuthorityManager.default`."""

    load_cas = (
        "root",
        "child",
    )

    def test_default(self) -> None:
        """Test the correct CA is returned if CA_DEFAULT_CA is set."""
        self.assertEqual(CertificateAuthority.objects.default(), self.ca)

    def test_disabled(self) -> None:
        """Test that an exception is raised if the CA is disabled."""
        self.ca.enabled = False
        self.ca.save()

        with self.assertImproperlyConfigured(rf"^CA_DEFAULT_CA: {self.ca.serial} is disabled\.$"):
            CertificateAuthority.objects.default()

    @freeze_time(TIMESTAMPS["everything_expired"])
    def test_expired(self) -> None:
        """Test that an exception is raised if CA is expired."""
        with self.assertImproperlyConfigured(rf"^CA_DEFAULT_CA: {self.ca.serial} is expired\.$"):
            CertificateAuthority.objects.default()

    @freeze_time(TIMESTAMPS["before_everything"])
    def test_not_yet_valid(self) -> None:
        """Test that an exception is raised if CA is not yet valid."""
        with self.assertImproperlyConfigured(rf"^CA_DEFAULT_CA: {self.ca.serial} is not yet valid\.$"):
            CertificateAuthority.objects.default()

    @override_settings(CA_DEFAULT_CA="")
    def test_default_ca(self) -> None:
        """Test what is returned when **no** CA is configured as default."""
        self.load_named_cas("__all__")
        ca = sorted(self.cas.values(), key=lambda ca: (ca.expires, ca.serial))[-1]
        self.assertEqual(CertificateAuthority.objects.default(), ca)

    @override_settings(CA_DEFAULT_CA="")
    @freeze_time(TIMESTAMPS["everything_expired"])
    def test_default_ca_expired(self) -> None:
        """Test that exception is raised if no CA is currently valid."""
        with self.assertImproperlyConfigured(r"^No CA is currently usable\.$"):
            CertificateAuthority.objects.default()

    @override_settings(CA_DEFAULT_CA="ABC")
    def test_unknown_ca_configured(self) -> None:
        """Test behavior when an unknown CA is manually configured."""
        with self.assertImproperlyConfigured(r"^CA_DEFAULT_CA: ABC: CA not found\.$"):
            CertificateAuthority.objects.default()


@override_settings(CA_DEFAULT_SUBJECT=tuple())
class CreateCertTestCase(TestCaseMixin, TestCase):
    """Test :py:class:`django_ca.managers.CertificateManager.create_cert` (create a new cert)."""

    csr = CERT_DATA["root-cert"]["csr"]["parsed"]
    load_cas = ("root",)

    @override_tmpcadir(CA_PROFILES={ca_settings.CA_DEFAULT_PROFILE: {"extensions": {}}})
    def test_basic(self) -> None:
        """Test creating the most basic cert possible."""
        with self.assertCreateCertSignals():
            cert = Certificate.objects.create_cert(self.ca, self.csr, subject=self.subject)
        self.assertEqual(cert.subject, self.subject)
        self.assertExtensions(cert, [])

    @override_tmpcadir(CA_PROFILES={ca_settings.CA_DEFAULT_PROFILE: {"extensions": {}}})
    def test_explicit_profile(self) -> None:
        """Test creating a cert with a profile."""
        with self.assertCreateCertSignals():
            cert = Certificate.objects.create_cert(
                self.ca, self.csr, subject=self.subject, profile=profiles[ca_settings.CA_DEFAULT_PROFILE]
            )
        self.assertEqual(cert.subject, self.subject)
        self.assertExtensions(cert, [])

    @override_tmpcadir()
    def test_cryptography_extensions(self) -> None:
        """Test passing readable extensions."""
        expected_key_usage = key_usage(key_cert_sign=True, key_encipherment=True)
        with self.assertCreateCertSignals():
            cert = Certificate.objects.create_cert(
                self.ca, self.csr, subject=self.subject, extensions=[expected_key_usage]
            )
        self.assertEqual(cert.subject, self.subject)
        self.assertExtensions(
            cert,
            [
                expected_key_usage,
                extended_key_usage(ExtendedKeyUsageOID.SERVER_AUTH),
            ],
        )

    @override_tmpcadir()
    def test_no_cn_or_san(self) -> None:
        """Test that creating a cert with no CommonName or SubjectAlternativeName is an error."""
        subject = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "AT")])

        msg = r"^Must name at least a CN or a subjectAlternativeName\.$"
        with self.assertRaisesRegex(ValueError, msg), self.assertCreateCertSignals(False, False):
            Certificate.objects.create_cert(self.ca, self.csr, subject=subject)

    @override_tmpcadir()
    def test_profile_unsupported_type(self) -> None:
        """Test passing a profile with an unsupported type."""
        common_name = "csr-profile-bad-type.example.com"
        msg = r"^profile must be of type django_ca\.profiles\.Profile\.$"
        with self.assertCreateCertSignals(False, False), self.assertRaisesRegex(TypeError, msg):
            Certificate.objects.create_cert(
                self.ca,
                csr=CERT_DATA["root-cert"]["csr"]["parsed"],
                profile=False,  # type: ignore[arg-type] # what we're testing
                subject=self.subject,
                add_crl_url=False,
                add_ocsp_url=False,
                add_issuer_url=False,
            )
        self.assertFalse(Certificate.objects.filter(cn=common_name).exists())


@unittest.skip("Only for type checkers.")
class TypingTestCase(unittest.TestCase):
    """Test case to create some code that would show an error in type checkers if type hinting is wrong.

    Note that none of these tests are designed to ever be executed.
    """

    # pylint: disable=missing-function-docstring

    def test_get(self) -> CertificateAuthority:
        return CertificateAuthority.objects.get(pk=1)

    def test_first(self) -> Optional[CertificateAuthority]:
        return CertificateAuthority.objects.first()

    def test_get_queryset(self) -> CertificateAuthorityQuerySet:
        return CertificateAuthority.objects.get_queryset()

    def test_all(self) -> CertificateAuthorityQuerySet:
        return CertificateAuthority.objects.all()

    def test_filter(self) -> CertificateAuthorityQuerySet:
        return CertificateAuthority.objects.filter()

    def test_order_by(self) -> CertificateAuthorityQuerySet:
        return CertificateAuthority.objects.order_by()

    def test_exclude(self) -> CertificateAuthorityQuerySet:
        return CertificateAuthority.objects.exclude()

    def test_acme(self) -> CertificateAuthorityQuerySet:
        return CertificateAuthority.objects.acme()

    def test_get_by_serial_or_cn(self) -> CertificateAuthority:
        return CertificateAuthority.objects.get_by_serial_or_cn("foo")

    def test_default(self) -> CertificateAuthority:
        return CertificateAuthority.objects.default()

    def test_disabled(self) -> CertificateAuthorityQuerySet:
        return CertificateAuthority.objects.disabled()

    def test_enabled(self) -> CertificateAuthorityQuerySet:
        return CertificateAuthority.objects.enabled()

    def test_invalid(self) -> CertificateAuthorityQuerySet:
        return CertificateAuthority.objects.invalid()

    def test_usable(self) -> CertificateAuthorityQuerySet:
        return CertificateAuthority.objects.usable()

    def test_valid(self) -> CertificateAuthorityQuerySet:
        return CertificateAuthority.objects.valid()

    # Tests for Certificate
    def test_cert_get(self) -> Certificate:
        return Certificate.objects.get(pk=1)

    def test_cert_first(self) -> Optional[Certificate]:
        return Certificate.objects.first()

    def test_cert_get_queryset(self) -> CertificateQuerySet:
        return Certificate.objects.get_queryset()

    def test_cert_all(self) -> CertificateQuerySet:
        return Certificate.objects.all()

    def test_cert_filter(self) -> CertificateQuerySet:
        return Certificate.objects.filter()

    def test_cert_order_by(self) -> CertificateQuerySet:
        return Certificate.objects.order_by()

    def test_cert_revoked(self) -> CertificateQuerySet:
        return Certificate.objects.revoked()

    def test_cert_expired(self) -> CertificateQuerySet:
        return Certificate.objects.expired()

    def test_cert_not_yet_valid(self) -> CertificateQuerySet:
        return Certificate.objects.not_yet_valid()

    def test_cert_valid(self) -> CertificateQuerySet:
        return Certificate.objects.valid()

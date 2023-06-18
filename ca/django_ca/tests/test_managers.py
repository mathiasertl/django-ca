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
from cryptography.x509.oid import ExtensionOID, NameOID

from django.test import TestCase, override_settings
from django.urls import reverse

from freezegun import freeze_time

from django_ca import ca_settings
from django_ca.constants import ExtendedKeyUsageOID
from django_ca.models import Certificate, CertificateAuthority
from django_ca.profiles import profiles
from django_ca.querysets import CertificateAuthorityQuerySet, CertificateQuerySet
from django_ca.tests.base import certs, dns, override_tmpcadir, timestamps, uri
from django_ca.tests.base.mixins import TestCaseMixin


@override_settings(CA_PROFILES={}, CA_DEFAULT_SUBJECT=tuple())
class CertificateAuthorityManagerInitTestCase(TestCaseMixin, TestCase):
    """Tests for :py:func:`django_ca.managers.CertificateAuthorityManager.init` (create a new CA)."""

    def assertProperties(  # pylint: disable=invalid-name
        self,
        ca: CertificateAuthority,
        name: str,
        subject: x509.Name,
        parent: Optional[CertificateAuthority] = None,
    ) -> None:
        """Assert some basic properties of a CA."""
        parent_ca = parent or ca
        parent_serial = parent_ca.serial
        issuer = parent_ca.subject

        base_url = f"http://{ca_settings.CA_DEFAULT_HOSTNAME}/django_ca/"
        self.assertEqual(ca.name, name)
        self.assertEqual(ca.issuer, issuer)
        self.assertEqual(ca.subject, subject)
        self.assertTrue(ca.enabled)
        self.assertEqual(ca.parent, parent)
        self.assertEqual(ca.crl_url, f"{base_url}crl/{ca.serial}/")
        self.assertEqual(ca.crl_number, '{"scope": {}}')
        self.assertEqual(ca.issuer_url, f"{base_url}issuer/{parent_serial}.der")
        self.assertEqual(ca.ocsp_url, f"{base_url}ocsp/{ca.serial}/cert/")
        self.assertEqual(ca.issuer_alt_name, "")
        self.assertAuthorityKeyIdentifier(parent_ca, ca)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_basic(self) -> None:
        """Test creating the most basic possible CA."""
        name = "basic"
        with self.assertCreateCASignals():
            ca = CertificateAuthority.objects.init(name, self.subject)
        self.assertProperties(ca, name, self.subject)
        self.assertEqual(ca.acme_profile, ca_settings.CA_DEFAULT_PROFILE)
        self.assertIsInstance(ca.algorithm, hashes.SHA512)
        ca.key().public_key()  # just access private key to make sure we can load it

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_dsa_key(self) -> None:
        """Test creating the most basic possible CA."""
        name = "dsa-ca"
        with self.assertCreateCASignals():
            ca = CertificateAuthority.objects.init(name, self.subject, key_type="DSA")
        self.assertProperties(ca, name, self.subject)
        self.assertEqual(ca.acme_profile, ca_settings.CA_DEFAULT_PROFILE)
        self.assertIsInstance(ca.algorithm, hashes.SHA256)
        ca.key().public_key()  # just access private key to make sure we can load it

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_password_bytes(self) -> None:
        """Create a CA with bytes as password."""
        name = "password_bytes"
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
        with self.assertCreateCASignals():
            ca = CertificateAuthority.objects.init(name, subject, password=b"foobar")
        ca.key("foobar").public_key()
        ca.key(b"foobar").public_key()

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_password_str(self) -> None:
        """Create a CA with a str as password."""
        name = "password_bytes"
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
        with self.assertCreateCASignals():
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
        with self.assertCreateCASignals():
            ca = CertificateAuthority.objects.init(name, subject, path_length=2)
        self.assertProperties(ca, name, subject)
        self.assertNotIn(ExtensionOID.AUTHORITY_INFORMATION_ACCESS, ca.x509_extensions)
        self.assertNotIn(ExtensionOID.CRL_DISTRIBUTION_POINTS, ca.x509_extensions)

        name = "child"
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "child.example.com")])
        with self.assertCreateCASignals():
            child = CertificateAuthority.objects.init(name, subject, parent=ca)
        self.assertProperties(child, name, subject, parent=ca)

        expected_issuers = [uri(f"http://{host}{self.reverse('issuer', serial=ca.serial)}")]
        expected_ocsp = [uri(f"http://{host}{self.reverse('ocsp-ca-post', serial=ca.serial)}")]

        self.assertEqual(
            child.x509_extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS],
            self.authority_information_access(ca_issuers=expected_issuers, ocsp=expected_ocsp),
        )
        self.assertEqual(
            child.x509_extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS],
            self.crl_distribution_points([uri(f"http://{host}{self.reverse('ca-crl', serial=ca.serial)}")]),
        )

        name = "grandchild"
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "grandchild.example.com")])
        with self.assertCreateCASignals():
            grandchild = CertificateAuthority.objects.init(name, subject, parent=child)
        self.assertProperties(grandchild, name, subject, parent=child)

        expected_ocsp = [uri(f"http://{host}{self.reverse('ocsp-ca-post', serial=child.serial)}")]
        expected_issuers = [uri(f"http://{host}{self.reverse('issuer', serial=child.serial)}")]
        self.assertEqual(
            grandchild.x509_extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS],
            self.authority_information_access(ca_issuers=expected_issuers, ocsp=expected_ocsp),
        )
        self.assertEqual(
            grandchild.x509_extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS],
            self.crl_distribution_points(
                [uri(f"http://{host}{self.reverse('ca-crl', serial=child.serial)}")]
            ),
        )

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_no_default_hostname(self) -> None:
        """Test creating a CA with no default hostname."""
        name = "ndh"
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ndh.example.com")])
        with self.assertCreateCASignals():
            ca = CertificateAuthority.objects.init(name, subject, default_hostname=False)
        self.assertEqual(ca.crl_url, "")
        self.assertEqual(ca.crl_number, '{"scope": {}}')
        self.assertIsNone(ca.issuer_url)
        self.assertIsNone(ca.ocsp_url)
        self.assertEqual(ca.issuer_alt_name, "")

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_extra_extensions(self) -> None:
        """Test creating a CA with extra extensions."""
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
        tls_feature = self.tls_feature(x509.TLSFeatureType.status_request)
        name_constraints = self.name_constraints(permitted=[dns(".com")])
        extensions: List[x509.Extension[x509.ExtensionType]] = [
            tls_feature,
            self.ocsp_no_check(),
            name_constraints,
            self.precert_poison(),
            self.ext(x509.InhibitAnyPolicy(3)),
        ]

        with self.assertCreateCASignals():
            ca = CertificateAuthority.objects.init("with-extra", subject, extensions=extensions)

        self.assertEqual(ca.subject, subject)

        expected = extensions + [
            self.basic_constraints(ca=True),
            self.key_usage(crl_sign=True, key_cert_sign=True),
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
            self.authority_information_access(
                ca_issuers=[uri("https://example.com/ca-issuer/{CA_ISSUER_PATH}")]
            ),
        ]

        with self.assertCreateCASignals():
            ca = CertificateAuthority.objects.init(
                "auto-ocsp", subject, parent=parent, extensions=passed_extensions
            )

        extensions = ca.x509_extensions

        self.assertEqual(
            extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS],
            self.authority_information_access(
                ca_issuers=[uri(f"https://example.com/ca-issuer{ca_issuer_path}")],
                ocsp=[uri(f"http://{host}{ocsp_path}")],
            ),
        )

        # Pass no CA Issuers
        passed_extensions = [
            self.authority_information_access(
                ocsp=[uri("https://example.com/ocsp/{OCSP_PATH}")],
            ),
        ]

        with self.assertCreateCASignals():
            ca = CertificateAuthority.objects.init(
                "auto-ca-issuers", subject, parent=parent, extensions=passed_extensions
            )

        extensions = ca.x509_extensions

        self.assertEqual(
            extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS],
            self.authority_information_access(
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
            self.authority_information_access(
                [uri("https://example.com/ca-issuer/{CA_ISSUER_PATH}")],
                [uri("https://example.com/ocsp/{OCSP_PATH}")],
            ),
            self.crl_distribution_points([uri("http://example.com/crl/{CRL_PATH}")]),
        ]

        with self.assertCreateCASignals():
            ca = CertificateAuthority.objects.init(
                "formatting", subject, parent=parent, extensions=passed_extensions
            )

        extensions = ca.x509_extensions
        ca_issuer_path = reverse("django_ca:issuer", kwargs={"serial": parent.serial})
        ocsp_path = reverse("django_ca:ocsp-ca-post", kwargs={"serial": parent.serial})
        crl_path = reverse("django_ca:ca-crl", kwargs={"serial": parent.serial})

        self.assertEqual(
            extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS],
            self.authority_information_access(
                [uri(f"https://example.com/ca-issuer{ca_issuer_path}")],
                [uri(f"https://example.com/ocsp{ocsp_path}")],
            ),
        )

        self.assertEqual(
            extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS],
            self.crl_distribution_points([uri(f"http://example.com/crl{crl_path}")]),
        )

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_formatting_no_uri(self) -> None:
        """Test passing extensions with values that cannot be formatted."""
        parent = self.load_ca("root")

        aia = self.authority_information_access([dns("ca-issuer.example.com")], [dns("ocsp.example.com")])
        crldp = self.crl_distribution_points([dns("crl.example.com")])
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
        passed_extensions: List[x509.Extension[x509.ExtensionType]] = [aia, crldp]

        with self.assertCreateCASignals():
            ca = CertificateAuthority.objects.init(
                "formatting", subject, parent=parent, extensions=passed_extensions
            )

        extensions = ca.x509_extensions
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

        with self.assertCreateCASignals():
            ca = CertificateAuthority.objects.init(
                "formatting-rdn", subject, parent=parent, extensions=passed_extensions
            )

        extensions = ca.x509_extensions
        self.assertEqual(extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS], crldp)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_no_extensions(self) -> None:
        """Test passing no extensions."""

        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
        with self.assertCreateCASignals():
            ca = CertificateAuthority.objects.init("with-extra", subject, extensions=None)
        self.assertEqual(ca.subject, subject)
        self.assertExtensions(
            ca, [self.basic_constraints(ca=True), self.key_usage(crl_sign=True, key_cert_sign=True)]
        )

    @override_tmpcadir()
    def test_acme_parameters(self) -> None:
        """Test parameters for ACMEv2."""
        name = "acme"
        with self.assertCreateCASignals():
            ca = CertificateAuthority.objects.init(
                name, self.subject, acme_enabled=False, acme_profile="client", acme_requires_contact=False
            )
        self.assertProperties(ca, name, self.subject)
        self.assertFalse(ca.acme_enabled)
        self.assertEqual(ca.acme_profile, "client")
        self.assertFalse(ca.acme_requires_contact)
        ca.key().public_key()  # just access private key to make sure we can load it

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


@override_settings(CA_PROFILES={}, CA_DEFAULT_SUBJECT=tuple(), CA_DEFAULT_CA=certs["child"]["serial"])
@freeze_time(timestamps["everything_valid"])
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

    @freeze_time(timestamps["everything_expired"])
    def test_expired(self) -> None:
        """Test that an exception is raised if CA is expired."""
        with self.assertImproperlyConfigured(rf"^CA_DEFAULT_CA: {self.ca.serial} is expired\.$"):
            CertificateAuthority.objects.default()

    @freeze_time(timestamps["before_everything"])
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
    @freeze_time(timestamps["everything_expired"])
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

    csr = certs["root-cert"]["csr"]["parsed"]
    load_cas = ("root",)

    @override_tmpcadir(CA_PROFILES={ca_settings.CA_DEFAULT_PROFILE: {"extensions": {}}})
    def test_basic(self) -> None:
        """Test creating the most basic cert possible."""
        with self.assertCreateCertSignals():
            cert = Certificate.objects.create_cert(self.ca, self.csr, subject=self.subject)
        self.assertEqual(cert.subject, self.subject)
        self.assertExtensions(cert, [self.subject_alternative_name(dns(self.hostname))])

    @override_tmpcadir(CA_PROFILES={ca_settings.CA_DEFAULT_PROFILE: {"extensions": {}}})
    def test_explicit_profile(self) -> None:
        """Test creating a cert with a profile."""
        with self.assertCreateCertSignals():
            cert = Certificate.objects.create_cert(
                self.ca, self.csr, subject=self.subject, profile=profiles[ca_settings.CA_DEFAULT_PROFILE]
            )
        self.assertEqual(cert.subject, self.subject)
        self.assertExtensions(cert, [self.subject_alternative_name(dns(self.hostname))])

    @override_tmpcadir()
    def test_cryptography_extensions(self) -> None:
        """Test passing readable extensions."""
        key_usage = self.key_usage(key_cert_sign=True, key_encipherment=True)
        with self.assertCreateCertSignals():
            cert = Certificate.objects.create_cert(
                self.ca, self.csr, subject=self.subject, extensions=[key_usage]
            )
        self.assertEqual(cert.subject, self.subject)
        self.assertExtensions(
            cert,
            [
                self.subject_alternative_name(dns(self.hostname)),
                key_usage,
                self.extended_key_usage(ExtendedKeyUsageOID.SERVER_AUTH),
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
                csr=certs["root-cert"]["csr"]["parsed"],
                profile=False,  # type: ignore[arg-type] # what we're testing
                subject=f"CN={common_name}",
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

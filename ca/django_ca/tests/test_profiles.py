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

"""Test :py:mod:`django_ca.profiles`."""

import doctest
from datetime import timedelta
from typing import Any, Dict

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID

from django.test import TestCase, override_settings

import pytest

from django_ca import ca_settings
from django_ca.constants import EXTENSION_DEFAULT_CRITICAL, EXTENSION_KEYS
from django_ca.deprecation import RemovedInDjangoCA128Warning
from django_ca.key_backends.storages import UsePrivateKeyOptions
from django_ca.models import Certificate, CertificateAuthority
from django_ca.profiles import Profile, get_profile, profile, profiles
from django_ca.signals import pre_sign_cert
from django_ca.tests.base.assertions import assert_extensions
from django_ca.tests.base.constants import CERT_DATA
from django_ca.tests.base.mixins import TestCaseMixin
from django_ca.tests.base.mocks import mock_signal
from django_ca.tests.base.utils import (
    authority_information_access,
    basic_constraints,
    crl_distribution_points,
    distribution_point,
    dns,
    issuer_alternative_name,
    ocsp_no_check,
    override_tmpcadir,
    subject_alternative_name,
    subject_key_identifier,
    uri,
)

key_backend_options = UsePrivateKeyOptions(password=None)


class DocumentationTestCase(TestCaseMixin, TestCase):
    """Test sphinx docs."""

    def setUp(self) -> None:
        super().setUp()
        self.ca = self.load_ca(name=CERT_DATA["root"]["name"], parsed=CERT_DATA["root"]["pub"]["parsed"])

    def get_globs(self) -> Dict[str, Any]:
        """Get globals for doctests."""
        return {
            "Profile": Profile,
            "get_profile": get_profile,
            "ca": self.ca,
            "ca_serial": self.ca.serial,
            "csr": CERT_DATA["root-cert"]["csr"]["parsed"],
        }

    @override_tmpcadir()
    def test_module(self) -> None:
        """Test doctests from main module."""
        # pylint: disable=import-outside-toplevel; we need the top-level module
        from django_ca import profiles as profiles_mod

        failures, _tests = doctest.testmod(profiles_mod, globs=self.get_globs())
        self.assertEqual(failures, 0, f"{failures} doctests failed, see above for output.")

    @override_tmpcadir()
    def test_docs(self) -> None:
        """Test python/profiles.rst."""
        failures, _tests = doctest.testfile(
            "../../../docs/source/python/profiles.rst", globs=self.get_globs()
        )
        self.assertEqual(failures, 0, f"{failures} doctests failed, see above for output.")


class ProfileTestCase(TestCaseMixin, TestCase):
    """Main tests for the profile class."""

    def create_cert(
        self,
        prof: Profile,
        ca: CertificateAuthority,
        csr: x509.CertificateSigningRequest,
        *args: Any,
        **kwargs: Any,
    ) -> Certificate:
        """Shortcut to create a cert with the given profile."""
        cert = Certificate(ca=ca)
        cert.update_certificate(prof.create_cert(ca, key_backend_options, csr, *args, **kwargs))
        return cert

    @override_tmpcadir()
    def test_create_cert_minimal(self) -> None:
        """Create a certificate with minimal parameters."""
        ca = self.load_ca(name="root", parsed=CERT_DATA["root"]["pub"]["parsed"])
        csr = CERT_DATA["child-cert"]["csr"]["parsed"]

        prof = Profile("example")
        with mock_signal(pre_sign_cert) as pre:
            cert = self.create_cert(prof, ca, csr, subject=self.subject, add_issuer_alternative_name=False)
        self.assertEqual(pre.call_count, 1)
        assert_extensions(cert, [ca.get_authority_key_identifier_extension()])

    @override_tmpcadir()
    def test_alternative_values(self) -> None:
        """Test overriding most values."""
        ca = self.load_ca(name="root", parsed=CERT_DATA["root"]["pub"]["parsed"])
        ca.sign_issuer_alternative_name = issuer_alternative_name(uri("https://example.com"))
        ca.save()
        csr = CERT_DATA["child-cert"]["csr"]["parsed"]
        country_name = x509.NameAttribute(NameOID.COUNTRY_NAME, "AT")
        subject = x509.Name([country_name, x509.NameAttribute(NameOID.COMMON_NAME, self.hostname)])

        prof = Profile("example", subject=False)

        with mock_signal(pre_sign_cert) as pre:
            cert = self.create_cert(
                prof,
                ca,
                csr,
                subject=x509.Name([country_name]),
                algorithm=hashes.SHA256(),
                expires=timedelta(days=30),
                extensions=[subject_alternative_name(dns(self.hostname))],
            )
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(cert.cn, self.hostname)
        self.assertEqual(cert.subject, subject)
        assert_extensions(
            cert,
            [
                ca.get_authority_key_identifier_extension(),
                ca.sign_issuer_alternative_name,
                subject_alternative_name(dns(self.hostname)),
            ],
        )

    @override_tmpcadir()
    def test_overrides(self) -> None:
        """Test other overrides."""
        ca = self.load_ca(name="root", parsed=CERT_DATA["root"]["pub"]["parsed"])
        csr = CERT_DATA["child-cert"]["csr"]["parsed"]
        country_name = x509.NameAttribute(NameOID.COUNTRY_NAME, "AT")
        expected_subject = x509.Name([country_name, x509.NameAttribute(NameOID.COMMON_NAME, self.hostname)])

        prof = Profile(
            "example",
            subject=x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "AT")]),
            add_crl_url=False,
            add_ocsp_url=False,
            add_issuer_url=False,
            add_issuer_alternative_name=False,
        )
        with mock_signal(pre_sign_cert) as pre:
            cert = self.create_cert(prof, ca, csr, subject=self.subject)
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(cert.subject, expected_subject)
        self.assertEqual(cert.ca, ca)

        assert_extensions(
            cert,
            [
                subject_key_identifier(cert),
                ca.get_authority_key_identifier_extension(),
                basic_constraints(),
            ],
            expect_defaults=False,
        )

        with mock_signal(pre_sign_cert) as pre:
            cert = self.create_cert(
                prof,
                ca,
                csr,
                subject=self.subject,
                add_crl_url=True,
                add_ocsp_url=True,
                add_issuer_url=True,
                add_issuer_alternative_name=True,
            )
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(cert.subject, expected_subject)
        self.assertEqual(cert.ca, ca)
        assert_extensions(
            cert,
            [
                ca.get_authority_key_identifier_extension(),
                basic_constraints(),
            ],
        )

    @override_tmpcadir()
    def test_none_extension(self) -> None:
        """Test passing an extension that is removed by the profile."""
        ca = self.load_ca(name="root", parsed=CERT_DATA["root"]["pub"]["parsed"])
        csr = CERT_DATA["child-cert"]["csr"]["parsed"]
        prof = Profile("example", extensions={"ocsp_no_check": None})

        with mock_signal(pre_sign_cert) as pre:
            cert = self.create_cert(prof, ca, csr, subject=self.subject, extensions=[ocsp_no_check()])
        self.assertEqual(pre.call_count, 1)
        self.assertNotIn(ExtensionOID.OCSP_NO_CHECK, cert.extensions)

    @override_tmpcadir()
    def test_override_ski(self) -> None:
        """Test overriding the subject key identifier."""
        ca = self.load_ca(name="root", parsed=CERT_DATA["root"]["pub"]["parsed"])
        csr = CERT_DATA["child-cert"]["csr"]["parsed"]
        ski = x509.Extension(
            oid=ExtensionOID.SUBJECT_KEY_IDENTIFIER,
            critical=False,
            value=x509.SubjectKeyIdentifier(b"custom value"),
        )

        prof = Profile("example")
        with mock_signal(pre_sign_cert) as pre:
            cert = self.create_cert(
                prof,
                ca,
                csr,
                subject=self.subject,
                add_crl_url=False,
                add_ocsp_url=False,
                add_issuer_url=False,
                add_issuer_alternative_name=False,
                extensions=[ski],
            )
        self.assertEqual(pre.call_count, 1)
        assert_extensions(
            cert,
            [ca.get_authority_key_identifier_extension(), basic_constraints(), ski],
            expect_defaults=False,
        )

    @override_tmpcadir()
    def test_add_distribution_point_with_ca_crldp(self) -> None:
        """Pass a custom distribution point when creating the cert, which matches ca.crl_url."""
        prof = Profile("example")
        ca = self.load_ca(name="root", parsed=CERT_DATA["root"]["pub"]["parsed"])
        csr = CERT_DATA["child-cert"]["csr"]["parsed"]

        # Add CRL Distribution Points extension to CA
        crl_url = "https://crl.ca.example.com"
        ca.sign_crl_distribution_points = crl_distribution_points(distribution_point([uri(crl_url)]))
        ca.save()

        added_crldp = self.crl_distribution_points([uri(crl_url)])

        with mock_signal(pre_sign_cert) as pre:
            cert = self.create_cert(
                prof,
                ca,
                csr,
                subject=self.subject,
                add_crl_url=True,
                add_ocsp_url=False,
                add_issuer_url=False,
                add_issuer_alternative_name=False,
                extensions=[added_crldp],
            )
        self.assertEqual(pre.call_count, 1)
        ski = x509.SubjectKeyIdentifier.from_public_key(cert.pub.loaded.public_key())

        assert_extensions(
            cert,
            [
                ca.get_authority_key_identifier_extension(),
                basic_constraints(),
                x509.Extension(oid=ExtensionOID.SUBJECT_KEY_IDENTIFIER, critical=False, value=ski),
                added_crldp,
            ],
            expect_defaults=False,
        )

    @override_tmpcadir()
    def test_with_algorithm(self) -> None:
        """Test a profile that manually overrides the algorithm."""
        root = self.load_ca(name="root", parsed=CERT_DATA["root"]["pub"]["parsed"])
        csr = CERT_DATA["child-cert"]["csr"]["parsed"]

        prof = Profile("example", algorithm="SHA-512")

        # Make sure that algorithm does not match what is the default profile above, so that we can test it
        self.assertIsInstance(root.algorithm, hashes.SHA256)

        with mock_signal(pre_sign_cert) as pre:
            cert = self.create_cert(
                prof,
                root,
                csr,
                subject=self.subject,
                add_crl_url=True,
                add_ocsp_url=False,
                add_issuer_url=False,
                add_issuer_alternative_name=False,
            )
        self.assertEqual(pre.call_count, 1)
        self.assertIsInstance(cert.algorithm, hashes.SHA512)

    @override_tmpcadir()
    def test_issuer_alternative_name_override(self) -> None:
        """Pass a custom Issuer Alternative Name which overwrites the CA value."""
        prof = Profile("example")
        ca = self.load_ca(name="root", parsed=CERT_DATA["root"]["pub"]["parsed"])
        csr = CERT_DATA["child-cert"]["csr"]["parsed"]

        # Add CRL url to CA
        ca.sign_issuer_alternative_name = issuer_alternative_name(uri("https://ian.ca.example.com"))
        ca.save()

        added_ian_uri = uri("https://ian.cert.example.com")

        with mock_signal(pre_sign_cert) as pre:
            cert = self.create_cert(
                prof,
                ca,
                csr,
                subject=self.subject,
                add_crl_url=False,
                add_ocsp_url=False,
                add_issuer_url=False,
                add_issuer_alternative_name=True,
                extensions=[issuer_alternative_name(added_ian_uri)],
            )
        self.assertEqual(pre.call_count, 1)
        ski = x509.SubjectKeyIdentifier.from_public_key(cert.pub.loaded.public_key())

        assert_extensions(
            cert,
            [
                ca.get_authority_key_identifier_extension(),
                basic_constraints(),
                x509.Extension(oid=ExtensionOID.SUBJECT_KEY_IDENTIFIER, critical=False, value=ski),
                issuer_alternative_name(added_ian_uri),
            ],
            expect_defaults=False,
        )

    @override_tmpcadir()
    def test_merge_authority_information_access_existing_values(self) -> None:
        """Pass a custom distribution point when creating the cert, which matches ca.crl_url."""
        prof = Profile("example")
        ca = self.load_ca(name="root", parsed=CERT_DATA["root"]["pub"]["parsed"])
        csr = CERT_DATA["child-cert"]["csr"]["parsed"]

        # Set Authority Information Access extesion
        ca.sign_authority_information_access = authority_information_access(
            ca_issuers=[uri("https://issuer.ca.example.com")], ocsp=[uri("https://ocsp.ca.example.com")]
        )
        ca.save()

        cert_issuers = uri("https://issuer.cert.example.com")
        cert_issuers2 = uri("https://issuer2.cert.example.com")
        cert_ocsp = uri("https://ocsp.cert.example.com")

        added_aia = authority_information_access(ca_issuers=[cert_issuers, cert_issuers2], ocsp=[cert_ocsp])

        with mock_signal(pre_sign_cert) as pre:
            cert = self.create_cert(
                prof,
                ca,
                csr,
                subject=self.subject,
                add_crl_url=False,
                add_ocsp_url=True,
                add_issuer_url=True,
                add_issuer_alternative_name=False,
                extensions=[added_aia],
            )
        self.assertEqual(pre.call_count, 1)

        ski = x509.SubjectKeyIdentifier.from_public_key(cert.pub.loaded.public_key())

        assert_extensions(
            cert,
            [
                ca.get_authority_key_identifier_extension(),
                basic_constraints(),
                x509.Extension(oid=ExtensionOID.SUBJECT_KEY_IDENTIFIER, critical=False, value=ski),
                authority_information_access(
                    ca_issuers=[cert_issuers, cert_issuers2],
                    ocsp=[cert_ocsp],
                ),
            ],
            expect_defaults=False,
        )

    @override_tmpcadir()
    def test_extension_as_cryptography(self) -> None:
        """Test with a profile that has cryptography extensions."""
        ca = self.load_ca(name="root", parsed=CERT_DATA["root"]["pub"]["parsed"])
        csr = CERT_DATA["child-cert"]["csr"]["parsed"]

        prof = Profile("example", extensions={EXTENSION_KEYS[ExtensionOID.OCSP_NO_CHECK]: {}})
        with mock_signal(pre_sign_cert) as pre:
            cert = self.create_cert(
                prof,
                ca,
                csr,
                subject=self.subject,
                add_issuer_alternative_name=False,
                extensions=[ocsp_no_check()],
            )
        self.assertEqual(pre.call_count, 1)
        assert_extensions(
            cert,
            [ca.get_authority_key_identifier_extension(), basic_constraints(), ocsp_no_check()],
        )

    @override_tmpcadir()
    def test_extension_overrides(self) -> None:
        """Test that all extensions can be overwritten when creating a new certificate."""
        # Profile with extensions (will be overwritten by the command line).
        prof = Profile(
            "example",
            extensions={
                EXTENSION_KEYS[ExtensionOID.AUTHORITY_INFORMATION_ACCESS]: authority_information_access(
                    ocsp=[uri("http://ocsp.example.com/profile")],
                    ca_issuers=[uri("http://issuer.example.com/issuer")],
                )
            },
        )
        ca = self.load_ca(name="root", parsed=CERT_DATA["root"]["pub"]["parsed"])

        ca.sign_authority_information_access = authority_information_access(
            ca_issuers=[uri("http://issuer.example.com/issuer")], ocsp=[uri("http://ocsp.example.com/ca")]
        )
        ca.save()

        csr = CERT_DATA["child-cert"]["csr"]["parsed"]

        expected_authority_information_access = authority_information_access(
            ocsp=[uri("http://ocsp.example.com/expected")],
            ca_issuers=[uri("http://issuer.example.com/expected")],
        )

        with mock_signal(pre_sign_cert) as pre:
            cert = self.create_cert(
                prof,
                ca,
                csr,
                subject=self.subject,
                add_issuer_alternative_name=False,
                add_issuer_url=True,
                add_ocsp_url=True,
                extensions=[expected_authority_information_access],
            )
        self.assertEqual(pre.call_count, 1)

        extensions = cert.extensions
        self.assertEqual(
            extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS], expected_authority_information_access
        )

    @override_tmpcadir()
    def test_partial_authority_information_access_override(self) -> None:
        """Test partial overwriting of the Authority Information Access extension."""
        prof = Profile(
            "example",
            extensions={
                EXTENSION_KEYS[ExtensionOID.AUTHORITY_INFORMATION_ACCESS]: authority_information_access(
                    ocsp=[uri("http://ocsp.example.com/profile")],
                    ca_issuers=[uri("http://issuer.example.com/issuer")],
                )
            },
        )
        ca = self.load_ca(name="root", parsed=CERT_DATA["root"]["pub"]["parsed"])
        self.assertIsNotNone(ca.sign_authority_information_access)
        ca_issuers_url = next(
            ad
            for ad in ca.sign_authority_information_access.value  # type: ignore[union-attr]
            if ad.access_method == AuthorityInformationAccessOID.CA_ISSUERS
        ).access_location
        ca_ocsp_url = next(
            ad
            for ad in ca.sign_authority_information_access.value  # type: ignore[union-attr]
            if ad.access_method == AuthorityInformationAccessOID.OCSP
        ).access_location
        ca.save()

        csr = CERT_DATA["child-cert"]["csr"]["parsed"]

        # Only pass an OCSP responder
        with mock_signal(pre_sign_cert) as pre:
            cert = self.create_cert(
                prof,
                ca,
                csr,
                subject=self.subject,
                add_issuer_alternative_name=False,
                add_issuer_url=True,
                add_ocsp_url=True,
                extensions=[
                    authority_information_access(
                        ocsp=[uri("http://ocsp.example.com/expected")],
                    )
                ],
            )
        self.assertEqual(pre.call_count, 1)

        extensions = cert.extensions
        self.assertEqual(
            extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS],
            authority_information_access(
                ocsp=[uri("http://ocsp.example.com/expected")], ca_issuers=[ca_issuers_url]
            ),
        )

        # Only pass an CA issuer
        with mock_signal(pre_sign_cert) as pre:
            cert = self.create_cert(
                prof,
                ca,
                csr,
                subject=self.subject,
                add_issuer_alternative_name=False,
                add_issuer_url=True,
                add_ocsp_url=True,
                extensions=[
                    authority_information_access(
                        ca_issuers=[uri("http://issuer.example.com/expected")],
                    )
                ],
            )
        self.assertEqual(pre.call_count, 1)

        extensions = cert.extensions
        self.assertEqual(
            extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS],
            authority_information_access(
                ocsp=[ca_ocsp_url], ca_issuers=[uri("http://issuer.example.com/expected")]
            ),
        )

    @override_tmpcadir()
    def test_no_cn_no_san(self) -> None:
        """Test creating a cert with no cn in san."""
        ca = self.load_ca(name="root", parsed=CERT_DATA["root"]["pub"]["parsed"])
        csr = CERT_DATA["child-cert"]["csr"]["parsed"]

        prof = Profile("example")
        msg = r"^Must name at least a CN or a subjectAlternativeName\.$"
        with mock_signal(pre_sign_cert) as pre, self.assertRaisesRegex(ValueError, msg):
            self.create_cert(prof, ca, csr, subject=None)
        self.assertEqual(pre.call_count, 0)

    @override_tmpcadir()
    def test_no_valid_cn_in_san(self) -> None:
        """Test what happens when the SAN has nothing usable as CN."""
        ca = self.load_ca(name="root", parsed=CERT_DATA["root"]["pub"]["parsed"])
        csr = CERT_DATA["child-cert"]["csr"]["parsed"]
        prof = Profile("example", extensions={EXTENSION_KEYS[ExtensionOID.OCSP_NO_CHECK]: {}})
        san = subject_alternative_name(x509.RegisteredID(ExtensionOID.OCSP_NO_CHECK))

        with mock_signal(pre_sign_cert) as pre:
            self.create_cert(prof, ca, csr, extensions=[san])
        self.assertEqual(pre.call_count, 1)

    def test_unknown_signature_hash_algorithm(self) -> None:
        """Test passing an unknown hash algorithm."""
        with self.assertRaisesRegex(ValueError, r"^foo: Unknown hash algorithm\.$"):
            Profile("wrong-algorithm", algorithm="foo")  # type: ignore[arg-type]

    @override_tmpcadir(CA_DEFAULT_SUBJECT=None)
    def test_no_valid_subject(self) -> None:
        """Test case where no subject at all could be determined."""
        ca = self.load_ca(name="root", parsed=CERT_DATA["root"]["pub"]["parsed"])
        csr = CERT_DATA["child-cert"]["csr"]["parsed"]
        prof = Profile("test")
        with self.assertRaisesRegex(ValueError, r"^Cannot determine subject for certificate\.$"):
            self.create_cert(prof, ca, csr)

    def test_str(self) -> None:
        """Test str()."""
        for name in ca_settings.CA_PROFILES:
            assert str(profiles[name]) == f"<Profile: {name}>"

    def test_repr(self) -> None:
        """Test repr()."""
        for name in ca_settings.CA_PROFILES:
            assert repr(profiles[name]) == f"<Profile: {name}>"


def test_deprecated_subject_value() -> None:
    """Test deprecated subject values."""
    value = "/C=AT/L=Vienna/ST=Vienna"
    msg = (
        rf"^{value}: Support for passing a value of type .* is deprecated and will be removed in "
        "django-ca 1.28.0.$"
    )
    with pytest.warns(RemovedInDjangoCA128Warning, match=msg):
        prof = Profile("test", value)  # type: ignore[arg-type]  # what we test

    assert prof.subject == x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "AT"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Vienna"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Vienna"),
        ]
    )


class GetProfileTestCase(TestCase):
    """Test the get_profile function."""

    def test_basic(self) -> None:
        """Basic tests."""
        for name in ca_settings.CA_PROFILES:
            prof = get_profile(name)
            self.assertEqual(name, prof.name)

        prof = get_profile()
        self.assertEqual(prof.name, ca_settings.CA_DEFAULT_PROFILE)


class ProfilesTestCase(TestCase):
    """Tests the ``profiles`` proxy."""

    def test_basic(self) -> None:
        """Some basic tests."""
        for name in ca_settings.CA_PROFILES:
            prof = profiles[name]
            self.assertEqual(prof.name, name)

        # Run a second time, b/c accessor also caches stuff sometimes
        for name in ca_settings.CA_PROFILES:
            prof = profiles[name]
            self.assertEqual(prof.name, name)

    def test_none(self) -> None:
        """Test the ``None`` key."""
        self.assertEqual(profiles[None], profile)

    def test_default_proxy(self) -> None:
        """Test using the default proxy."""
        self.assertEqual(profile.name, ca_settings.CA_DEFAULT_PROFILE)
        self.assertEqual(str(profile), f"<DefaultProfile: {ca_settings.CA_DEFAULT_PROFILE}>")
        self.assertEqual(repr(profile), f"<DefaultProfile: {ca_settings.CA_DEFAULT_PROFILE}>")

        self.assertEqual(profile, profile)
        self.assertEqual(profile, profiles[ca_settings.CA_DEFAULT_PROFILE])


def test_eq() -> None:
    """Test profile equality."""
    prof = None
    for name in ca_settings.CA_PROFILES:
        assert prof != profiles[name]
        prof = profiles[name]
        assert prof == prof  # noqa: PLR0124  # this is what we're testing
        assert prof is not None
        assert prof != -1


def test_eq_default_proxy() -> None:
    """Test equality for the default proxy."""
    assert profile == profile  # noqa: PLR0124  # what we're testing
    assert profile == profiles[ca_settings.CA_DEFAULT_PROFILE]  # proxy is equal to default profile
    assert profile != ["not-equal"]  # we are not equal to arbitrary stuff


def test_init_django_ca_values(subject: x509.Name) -> None:
    """Test passing serialized extensions leads to equal profiles."""
    prof1 = Profile("test", subject=subject, extensions={"ocsp_no_check": {}})
    prof2 = Profile("test", subject=subject, extensions={"ocsp_no_check": ocsp_no_check()})
    assert prof1 == prof2


def test_init_none_extension() -> None:
    """Test profiles that explicitly deactivate an extension."""
    prof = Profile("test", extensions={"ocsp_no_check": None})
    assert prof.extensions == {ExtensionOID.OCSP_NO_CHECK: None}
    assert prof.serialize()["clear_extensions"] == ["ocsp_no_check"]


def test_init_no_subject() -> None:
    """Test with no default subject."""
    # doesn't really occur in the wild, because ca_settings updates CA_PROFILES with the default
    # subject. But it still seems sensible to support this
    default_subject = (("CN", "testcase"),)

    with override_settings(CA_DEFAULT_SUBJECT=default_subject):
        prof = Profile("test")
    assert prof.subject == x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "testcase")])


def test_init_x509_subject(subject: x509.Name) -> None:
    """Test passing a cryptography subject."""
    prof = Profile("test", subject=subject)
    assert prof.subject == subject


def test_init_expires() -> None:
    """Test the `expire` parameter."""
    prof = Profile("example", expires=30)
    assert prof.expires == timedelta(days=30)

    exp = timedelta(hours=3)
    prof = Profile("example", expires=exp)
    assert prof.expires == exp


def test_serialize() -> None:
    """Test profile serialization."""
    desc = "foo bar"
    key_usage = ["digital_signature"]
    prof = Profile(
        "test",
        algorithm="SHA-512",
        description=desc,
        subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")]),
        extensions={
            EXTENSION_KEYS[ExtensionOID.KEY_USAGE]: {"value": key_usage},
            EXTENSION_KEYS[ExtensionOID.EXTENDED_KEY_USAGE]: None,
        },
    )
    assert prof.serialize() == {
        "name": "test",
        "algorithm": "SHA-512",
        "subject": [{"oid": NameOID.COMMON_NAME.dotted_string, "value": "example.com"}],
        "description": desc,
        "clear_extensions": ["extended_key_usage"],
        "extensions": [
            {
                "type": "key_usage",
                "value": key_usage,
                "critical": EXTENSION_DEFAULT_CRITICAL[ExtensionOID.KEY_USAGE],
            },
        ],
    }

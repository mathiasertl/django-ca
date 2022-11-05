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
# see <http://www.gnu.org/licenses/>.

"""Test :py:mod:`django_ca.profiles`."""

import doctest
import typing
import unittest
from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID

from django.conf import settings
from django.test import TestCase

from .. import ca_settings
from ..extensions import (
    AuthorityInformationAccess,
    BasicConstraints,
    CRLDistributionPoints,
    IssuerAlternativeName,
    KeyUsage,
    OCSPNoCheck,
    SubjectAlternativeName,
    SubjectKeyIdentifier,
)
from ..models import Certificate, CertificateAuthority
from ..profiles import Profile, get_profile, profile, profiles
from ..signals import pre_issue_cert
from ..subject import Subject
from ..utils import parse_hash_algorithm
from .base import certs, dns, override_settings, override_tmpcadir, uri
from .base.mixins import TestCaseMixin


@override_settings(CA_MIN_KEY_SIZE=1024, CA_DEFAULT_KEY_SIZE=1024)
@unittest.skipIf(  # https://github.com/pyca/cryptography/issues/6363
    settings.CRYPTOGRAPHY_VERSION >= (35, 0), "cg>=35.0 has broken subject name strings"
)
class DocumentationTestCase(TestCaseMixin, TestCase):
    """Test sphinx docs."""

    def setUp(self) -> None:
        super().setUp()
        self.ca = self.load_ca(name=certs["root"]["name"], parsed=certs["root"]["pub"]["parsed"])

    def get_globs(self) -> typing.Dict[str, typing.Any]:
        """Get globals for doctests."""
        return {
            "Profile": Profile,
            "get_profile": get_profile,
            "ca": self.ca,
            "ca_serial": self.ca.serial,
            "csr": certs["root-cert"]["csr"]["parsed"],
        }

    @override_tmpcadir()
    def test_module(self) -> None:
        """Test doctests from main module."""
        # pylint: disable=import-outside-toplevel; we need the top-level module
        from .. import profiles as profiles_mod

        doctest.testmod(profiles_mod, globs=self.get_globs())

    @override_tmpcadir()
    def test_python_intro(self) -> None:
        """Test python/profiles.rst."""
        doctest.testfile("../../../docs/source/python/profiles.rst", globs=self.get_globs())


class ProfileTestCase(TestCaseMixin, TestCase):
    """Main tests for the profile class."""

    def create_cert(  # type: ignore[override]
        self, prof: Profile, ca: CertificateAuthority, *args: typing.Any, **kwargs: typing.Any
    ) -> Certificate:
        """Shortcut to create a cert with the given profile."""
        cert = Certificate(ca=ca)
        cert.update_certificate(prof.create_cert(ca, *args, **kwargs))
        return cert

    def test_copy(self) -> None:
        """Test copying a profile."""
        prof1 = Profile("example")
        prof2 = prof1.copy()
        self.assertIsNot(prof1, prof2)
        self.assertEqual(prof1, prof2)
        prof2.extensions[SubjectAlternativeName.key] = SubjectAlternativeName({"value": ["example.com"]})
        self.assertNotEqual(prof1, prof2)
        self.assertNotIn(SubjectAlternativeName.key, prof1.extensions)
        self.assertIn(SubjectAlternativeName.key, prof2.extensions)

        # test algorithm b/c cryptography does not compare this properly
        prof2 = prof1.copy()
        prof2.algorithm = parse_hash_algorithm("MD5")
        self.assertNotEqual(prof1, prof2)

    def test_eq(self) -> None:
        """Test profile equality."""
        prof = None
        for name in ca_settings.CA_PROFILES:
            self.assertNotEqual(prof, profiles[name])
            prof = profiles[name]
            self.assertEqual(prof, prof)
            self.assertNotEqual(prof, None)
            self.assertNotEqual(prof, -1)

        self.assertNotEqual(profile, None)

    def test_init_django_ca_values(self) -> None:
        """Test django-ca extensions as extensions."""
        prof1 = Profile(
            "test",
            subject=[("C", "AT"), ("CN", self.hostname)],
            extensions={
                OCSPNoCheck.key: {},
            },
        )
        prof2 = Profile(
            "test",
            subject=[("C", "AT"), ("CN", self.hostname)],
            extensions={
                OCSPNoCheck.key: OCSPNoCheck(),
            },
        )
        self.assertEqual(prof1, prof2)

    def test_init_none_extension(self) -> None:
        """Test profiles that explicitly deactivate an extension."""
        prof = Profile("test", extensions={"ocsp_no_check": None})
        self.assertEqual(prof.extensions, {"ocsp_no_check": None, "basic_constraints": BasicConstraints()})
        self.assertIsNone(prof.serialize()["extensions"]["ocsp_no_check"])

    def test_init_no_subject(self) -> None:
        """Test with no default subject."""
        # doesn't really occur in the wild, because ca_settings updates CA_PROFILES with the default
        # subject. But it still seems sensible to support this
        default_subject = (("CN", "testcase"),)

        with override_settings(CA_DEFAULT_SUBJECT=default_subject):
            prof = Profile("test")
        self.assertEqual(prof.subject, x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "testcase")]))

    def test_init_expires(self) -> None:
        """Test the expire parameter."""
        prof = Profile("example", expires=30)
        self.assertEqual(prof.expires, timedelta(days=30))

        exp = timedelta(hours=3)
        prof = Profile("example", expires=exp)
        self.assertEqual(prof.expires, exp)

    def test_serialize(self) -> None:
        """Test profile serialization."""

        desc = "foo bar"
        kusage = ["digital_signature"]
        prof = Profile(
            "test",
            cn_in_san=True,
            description=desc,
            subject=[("CN", self.hostname)],
            extensions={
                KeyUsage.key: {"value": kusage},
            },
        )
        self.assertEqual(
            prof.serialize(),
            {
                "cn_in_san": True,
                "subject": {"CN": self.hostname},
                "description": desc,
                "extensions": {
                    BasicConstraints.key: {
                        "value": {"ca": False},
                        "critical": BasicConstraints.default_critical,
                    },
                    KeyUsage.key: {
                        "value": kusage,
                        "critical": KeyUsage.default_critical,
                    },
                },
            },
        )

    @override_tmpcadir()
    def test_create_cert_minimal(self) -> None:
        """Create a certificate with minimal parameters."""
        ca = self.load_ca(name="root", parsed=certs["root"]["pub"]["parsed"])
        csr = certs["child-cert"]["csr"]["parsed"]

        prof = Profile("example", subject=[])
        with self.mockSignal(pre_issue_cert) as pre:
            cert = self.create_cert(
                prof,
                ca,
                csr,
                subject=self.subject,
                add_issuer_alternative_name=False,
            )
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(cert.subject, self.subject)
        self.assertExtensions(
            cert,
            [ca.get_authority_key_identifier_extension(), self.subject_alternative_name(dns(self.hostname))],
        )

    @override_tmpcadir()
    def test_alternative_values(self) -> None:
        """Test overriding most values."""
        ca = self.load_ca(name="root", parsed=certs["root"]["pub"]["parsed"])
        ca.issuer_alt_name = "https://example.com"
        ca.save()
        csr = certs["child-cert"]["csr"]["parsed"]
        country_name = x509.NameAttribute(NameOID.COUNTRY_NAME, "AT")
        subject = x509.Name([country_name, x509.NameAttribute(NameOID.COMMON_NAME, self.hostname)])

        prof = Profile("example", subject=[])

        with self.mockSignal(pre_issue_cert) as pre:
            cert = self.create_cert(
                prof,
                ca,
                csr,
                subject=x509.Name([country_name]),
                algorithm=hashes.SHA256(),
                expires=timedelta(days=30),
                extensions=[SubjectAlternativeName({"value": [self.hostname]})],
            )
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(cert.cn, self.hostname)
        self.assertEqual(cert.subject, subject)
        self.assertExtensions(
            cert,
            [
                ca.get_authority_key_identifier_extension(),
                self.issuer_alternative_name(uri(ca.issuer_alt_name)),
                self.subject_alternative_name(dns(self.hostname)),
            ],
        )

    @override_tmpcadir()
    def test_overrides(self) -> None:
        """Test other overrides."""
        ca = self.load_ca(name="root", parsed=certs["root"]["pub"]["parsed"])
        csr = certs["child-cert"]["csr"]["parsed"]
        country_name = x509.NameAttribute(NameOID.COUNTRY_NAME, "AT")
        expected_subject = x509.Name([country_name, x509.NameAttribute(NameOID.COMMON_NAME, self.hostname)])

        prof = Profile(
            "example",
            subject=[("C", "AT")],
            add_crl_url=False,
            add_ocsp_url=False,
            add_issuer_url=False,
            add_issuer_alternative_name=False,
        )
        with self.mockSignal(pre_issue_cert) as pre:
            cert = self.create_cert(prof, ca, csr, subject=self.subject)
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(cert.subject, expected_subject)
        self.assertEqual(cert.ca, ca)

        self.assertExtensions(
            cert,
            [
                self.subject_key_identifier(cert),
                ca.get_authority_key_identifier_extension(),
                self.basic_constraints(),
                self.subject_alternative_name(dns(self.hostname)),
            ],
            expect_defaults=False,
        )

        with self.mockSignal(pre_issue_cert) as pre:
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
        self.assertExtensions(
            cert,
            [
                ca.get_authority_key_identifier_extension(),
                self.basic_constraints(),
                self.subject_alternative_name(dns(self.hostname)),
            ],
        )

    @override_tmpcadir()
    def test_none_override(self) -> None:
        """Test that we can remove a particular extension."""

        ca = self.load_ca(name="root", parsed=certs["root"]["pub"]["parsed"])
        csr = certs["child-cert"]["csr"]["parsed"]
        prof = Profile(
            "example",
            extensions={"ocsp_no_check": self.ocsp_no_check()},
            add_crl_url=False,
            add_ocsp_url=False,
            add_issuer_url=False,
            add_issuer_alternative_name=False,
        )
        with self.mockSignal(pre_issue_cert) as pre:
            cert = self.create_cert(prof, ca, csr, subject=self.subject, extensions={"ocsp_no_check": None})
        self.assertEqual(pre.call_count, 1)
        self.assertExtensions(
            cert,
            [
                self.subject_key_identifier(cert),
                ca.get_authority_key_identifier_extension(),
                self.basic_constraints(),
                self.subject_alternative_name(dns(self.hostname)),
            ],
            expect_defaults=False,
        )

    @override_tmpcadir()
    def test_cn_in_san(self) -> None:
        """Test writing the common name into the SAN."""
        ca = self.load_ca(name="root", parsed=certs["root"]["pub"]["parsed"])
        csr = certs["child-cert"]["csr"]["parsed"]
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "AT"),
                x509.NameAttribute(NameOID.COMMON_NAME, self.hostname),
            ]
        )

        prof = Profile("example", subject=[("C", "AT")], add_issuer_alternative_name=False, cn_in_san=False)
        with self.mockSignal(pre_issue_cert) as pre:
            cert = self.create_cert(prof, ca, csr, subject=self.subject)
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(cert.subject, subject)
        self.assertExtensions(cert, [ca.get_authority_key_identifier_extension()])

        # Create the same cert, but pass cn_in_san=True to create_cert
        with self.mockSignal(pre_issue_cert) as pre:
            cert = self.create_cert(prof, ca, csr, subject=self.subject, cn_in_san=True)
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(cert.subject, subject)
        self.assertExtensions(
            cert,
            [ca.get_authority_key_identifier_extension(), self.subject_alternative_name(dns(self.hostname))],
        )

        # test that cn_in_san=True with a SAN that already contains the CN does not lead to a duplicate
        with self.mockSignal(pre_issue_cert) as pre:
            cert = self.create_cert(
                prof,
                ca,
                csr,
                subject=self.subject,
                cn_in_san=True,
                extensions=[SubjectAlternativeName({"value": [f"DNS:{self.hostname}"]})],
            )
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(cert.subject, subject)
        self.assertExtensions(
            cert,
            [ca.get_authority_key_identifier_extension(), self.subject_alternative_name(dns(self.hostname))],
        )

        # test that the first SAN is added as CN if we don't have A CN
        with self.mockSignal(pre_issue_cert) as pre:
            cert = self.create_cert(
                prof,
                ca,
                csr,
                cn_in_san=True,
                extensions=[SubjectAlternativeName({"value": [f"DNS:{self.hostname}"]})],
            )
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(cert.subject, subject)
        self.assertExtensions(
            cert,
            [ca.get_authority_key_identifier_extension(), self.subject_alternative_name(dns(self.hostname))],
        )

    @override_tmpcadir()
    def test_override_ski(self) -> None:
        """Test overriding the subject key identifier."""
        ca = self.load_ca(name="root", parsed=certs["root"]["pub"]["parsed"])
        csr = certs["child-cert"]["csr"]["parsed"]
        ski = x509.Extension(
            oid=ExtensionOID.SUBJECT_KEY_IDENTIFIER,
            critical=False,
            value=x509.SubjectKeyIdentifier(b"custom value"),
        )

        prof = Profile("example", subject=[])
        with self.mockSignal(pre_issue_cert) as pre:
            cert = self.create_cert(
                prof,
                ca,
                csr,
                subject=self.subject,
                add_crl_url=False,
                add_ocsp_url=False,
                add_issuer_url=False,
                add_issuer_alternative_name=False,
                extensions={"subject_key_identifier": ski},
            )
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(cert.subject, self.subject)
        self.assertExtensions(
            cert,
            [
                ca.get_authority_key_identifier_extension(),
                self.basic_constraints(),
                self.subject_alternative_name(dns(self.hostname)),
                ski,
            ],
            expect_defaults=False,
        )

    @override_tmpcadir()
    def test_extensions_dict(self) -> None:
        """Test with a dict for an extension."""
        ca = self.load_ca(name="root", parsed=certs["root"]["pub"]["parsed"])
        csr = certs["child-cert"]["csr"]["parsed"]
        ski = x509.Extension(
            oid=ExtensionOID.SUBJECT_KEY_IDENTIFIER,
            critical=False,
            value=x509.SubjectKeyIdentifier(b"custom value"),
        )

        prof = Profile("example", subject=[])
        with self.mockSignal(pre_issue_cert) as pre:
            cert = self.create_cert(
                prof,
                ca,
                csr,
                subject=self.subject,
                add_crl_url=False,
                add_ocsp_url=False,
                add_issuer_url=False,
                add_issuer_alternative_name=False,
                extensions={"subject_key_identifier": ski},
            )
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(cert.subject, self.subject)
        self.assertExtensions(
            cert,
            [
                ca.get_authority_key_identifier_extension(),
                self.basic_constraints(),
                self.subject_alternative_name(dns(self.hostname)),
                ski,
            ],
            expect_defaults=False,
        )

    @override_tmpcadir()
    def test_hide_extension(self) -> None:
        """Test with hiding extensions from the profile."""
        ca = self.load_ca(name="root", parsed=certs["root"]["pub"]["parsed"])
        csr = certs["child-cert"]["csr"]["parsed"]

        prof = Profile("example", subject=[], extensions={OCSPNoCheck.key: {}})
        with self.mockSignal(pre_issue_cert) as pre:
            cert = self.create_cert(
                prof,
                ca,
                csr,
                subject=self.subject,
                add_crl_url=False,
                add_ocsp_url=False,
                add_issuer_url=False,
                add_issuer_alternative_name=False,
                extensions={OCSPNoCheck.key: None},
            )
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(cert.subject, self.subject)
        self.assertExtensions(
            cert,
            [
                self.subject_key_identifier(cert),
                ca.get_authority_key_identifier_extension(),
                self.basic_constraints(),
                self.subject_alternative_name(dns(self.hostname)),
            ],
            expect_defaults=False,
        )

    @override_tmpcadir()
    def test_extension_as_cryptography(self) -> None:
        """Test with a profile that has cryptography extensions."""
        ca = self.load_ca(name="root", parsed=certs["root"]["pub"]["parsed"])
        csr = certs["child-cert"]["csr"]["parsed"]

        prof = Profile("example", subject=[], extensions={OCSPNoCheck.key: {}})
        with self.mockSignal(pre_issue_cert) as pre:
            cert = self.create_cert(
                prof,
                ca,
                csr,
                subject=self.subject,
                add_issuer_alternative_name=False,
                extensions={"ocsp_no_check": self.ocsp_no_check()},
            )
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(cert.subject, self.subject)
        self.assertExtensions(
            cert,
            [
                ca.get_authority_key_identifier_extension(),
                self.basic_constraints(),
                self.ocsp_no_check(),
                self.subject_alternative_name(dns(self.hostname)),
            ],
        )

    @override_tmpcadir()
    def test_no_cn_no_san(self) -> None:
        """Test creating a cert with no cn in san."""
        ca = self.load_ca(name="root", parsed=certs["root"]["pub"]["parsed"])
        csr = certs["child-cert"]["csr"]["parsed"]

        prof = Profile("example", subject=[("C", "AT")])
        msg = r"^Must name at least a CN or a subjectAlternativeName\.$"
        with self.mockSignal(pre_issue_cert) as pre, self.assertRaisesRegex(ValueError, msg):
            self.create_cert(prof, ca, csr, subject=None)
        self.assertEqual(pre.call_count, 0)

    @override_tmpcadir()
    def test_no_valid_cn_in_san(self) -> None:
        """TEst what happens when the SAN has nothing usable as CN."""
        ca = self.load_ca(name="root", parsed=certs["root"]["pub"]["parsed"])
        csr = certs["child-cert"]["csr"]["parsed"]
        prof = Profile("example", subject=[], extensions={OCSPNoCheck.key: {}})
        san = self.subject_alternative_name(x509.RegisteredID(ExtensionOID.OCSP_NO_CHECK))

        with self.mockSignal(pre_issue_cert) as pre:
            self.create_cert(prof, ca, csr, cn_in_san=True, extensions={"subject_alternative_name": san})
        self.assertEqual(pre.call_count, 1)

    @override_tmpcadir()
    def test_unparsable_cn(self) -> None:
        """Try creating a profile with an unparseable Common Name."""
        ca = self.load_ca(name="root", parsed=certs["root"]["pub"]["parsed"])
        csr = certs["child-cert"]["csr"]["parsed"]
        cname = "foo bar"

        prof = Profile("example", subject=[("C", "AT"), ("CN", cname)])
        msg = rf"^{cname}: Could not parse CommonName as subjectAlternativeName\.$"
        with self.mockSignal(pre_issue_cert) as pre, self.assertRaisesRegex(ValueError, msg):
            self.create_cert(prof, ca, csr)
        self.assertEqual(pre.call_count, 0)

    @override_tmpcadir()
    def test_invalid_extensions(self) -> None:
        """Test with a dict with extensions of the wrong type."""
        ca = self.load_ca(name="root", parsed=certs["root"]["pub"]["parsed"])
        ca.issuer_url = "https://issuer.example.com"
        ca.issuer_alt_name = "https://ian.example.com"
        ca.save()
        csr = certs["child-cert"]["csr"]["parsed"]
        ski = SubjectKeyIdentifier({"value": b"333333"})
        prof = Profile("example", subject=[])

        msg = r"^extensions\[authority_information_access\] is not of type AuthorityInformationAccess"
        with self.mockSignal(pre_issue_cert) as pre, self.assertRaisesRegex(ValueError, msg):
            self.create_cert(
                prof,
                ca,
                csr,
                subject=self.subject,
                add_ocsp_url=False,
                add_issuer_url=True,
                extensions={AuthorityInformationAccess.key: ski},
            )
        self.assertEqual(pre.call_count, 0)

        msg = r"^extensions\[crl_distribution_points\] is not of type CRLDistributionPoints"
        with self.mockSignal(pre_issue_cert) as pre, self.assertRaisesRegex(ValueError, msg):
            self.create_cert(
                prof,
                ca,
                csr,
                subject=self.subject,
                add_crl_url=True,
                extensions={CRLDistributionPoints.key: ski},
            )
        self.assertEqual(pre.call_count, 0)

        msg = r"^extensions\[authority_information_access\] is not of type AuthorityInformationAccess"
        with self.mockSignal(pre_issue_cert) as pre, self.assertRaisesRegex(ValueError, msg):
            self.create_cert(
                prof,
                ca,
                csr,
                subject=self.subject,
                add_ocsp_url=True,
                extensions={AuthorityInformationAccess.key: ski},
            )
        self.assertEqual(pre.call_count, 0)

        msg = r"^extensions\[authority_information_access\] is not of type AuthorityInformationAccess"
        with self.mockSignal(pre_issue_cert) as pre, self.assertRaisesRegex(ValueError, msg):
            self.create_cert(
                prof,
                ca,
                csr,
                subject=self.subject,
                add_ocsp_url=False,
                add_issuer_url=True,
                extensions={AuthorityInformationAccess.key: ski},
            )
        self.assertEqual(pre.call_count, 0)

        msg = r"^extensions\[issuer_alternative_name\] is not of type IssuerAlternativeName"
        with self.mockSignal(pre_issue_cert) as pre, self.assertRaisesRegex(ValueError, msg):
            self.create_cert(
                prof,
                ca,
                csr,
                subject=self.subject,
                add_ocsp_url=False,
                add_issuer_url=False,
                add_issuer_alternative_name=True,
                extensions={IssuerAlternativeName.key: ski},
            )
        self.assertEqual(pre.call_count, 0)

    def test_str(self) -> None:
        """Test str()."""
        for name in ca_settings.CA_PROFILES:
            self.assertEqual(str(profiles[name]), f"<Profile: {name}>")

    def test_repr(self) -> None:
        """Test repr()."""
        for name in ca_settings.CA_PROFILES:
            self.assertEqual(repr(profiles[name]), f"<Profile: {name}>")

    @override_tmpcadir()
    def test_deprecated_create_cert_subject(self) -> None:
        """Pass an old subject to create_cert, to be removed in 1.24."""
        ca = self.load_ca(name="root", parsed=certs["root"]["pub"]["parsed"])
        csr = certs["child-cert"]["csr"]["parsed"]
        prof = Profile(self.id(), subject=[])
        warning = "Passing Subject for subject is deprecated and will be removed in django ca 1.24."
        with self.assertRemovedIn124Warning(warning):
            cert = self.create_cert(prof, ca, csr, subject=Subject({"CN": self.hostname}))
        self.assertEqual(cert.subject, self.subject)

        with self.assertRemovedIn124Warning(warning):
            prof = Profile(self.id(), subject=Subject({"C": "AT"}))  # type: ignore[arg-type]


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

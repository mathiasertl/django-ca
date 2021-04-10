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

"""TestCases for various model managers."""

import typing
import unittest

from freezegun import freeze_time

from .. import ca_settings
from ..extensions import AuthorityInformationAccess
from ..extensions import AuthorityKeyIdentifier
from ..extensions import BasicConstraints
from ..extensions import CRLDistributionPoints
from ..extensions import KeyUsage
from ..extensions import OCSPNoCheck
from ..extensions import SubjectAlternativeName
from ..extensions import SubjectKeyIdentifier
from ..extensions import TLSFeature
from ..models import Certificate
from ..models import CertificateAuthority
from ..profiles import profiles
from ..querysets import CertificateAuthorityQuerySet
from ..subject import Subject
from .base import DjangoCATestCase
from .base import DjangoCAWithGeneratedCAsTestCase
from .base import certs
from .base import override_settings
from .base import override_tmpcadir
from .base import timestamps


@override_settings(
    CA_PROFILES={},
    CA_DEFAULT_SUBJECT={},
)
class CertificateAuthorityManagerInitTestCase(DjangoCATestCase):
    """Tests for :py:func:`django_ca.managers.CertificateAuthorityManager.init` (create a new CA)."""

    def assertProperties(  # pylint: disable=invalid-name
        self,
        ca: CertificateAuthority,
        name: str,
        subject: str,
        parent: typing.Optional[CertificateAuthority] = None,
    ) -> None:
        """Assert some basic properties of a CA."""
        parent_ca = parent or ca
        parent_serial = parent_ca.serial
        parent_ski = parent_ca.subject_key_identifier.value  # type: ignore[union-attr] # always present
        issuer = parent_ca.subject

        base_url = "http://%s/django_ca/" % ca_settings.CA_DEFAULT_HOSTNAME
        self.assertEqual(ca.name, name)
        self.assertEqual(ca.issuer, issuer)
        self.assertEqual(ca.subject, Subject(subject))
        self.assertTrue(ca.enabled)
        self.assertEqual(ca.parent, parent)
        self.assertEqual(ca.crl_url, "%scrl/%s/" % (base_url, ca.serial))
        self.assertEqual(ca.crl_number, '{"scope": {}}')
        self.assertEqual(ca.issuer_url, "%sissuer/%s.der" % (base_url, parent_serial))
        self.assertEqual(ca.ocsp_url, "%socsp/%s/cert/" % (base_url, ca.serial))
        self.assertEqual(ca.issuer_alt_name, "")
        self.assertEqual(ca.authority_key_identifier.key_identifier, parent_ski)  # type: ignore[union-attr]

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_basic(self) -> None:
        """Test creating the most basic possible CA."""
        name = "basic"
        subject = "/CN=example.com"
        with self.assertCreateCASignals():
            ca = CertificateAuthority.objects.init(name, subject)
        self.assertProperties(ca, name, subject)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_intermediate(self) -> None:
        """Test creating intermediate CAs."""
        # test a few properties of intermediate CAs, with multiple levels
        host = ca_settings.CA_DEFAULT_HOSTNAME  # shortcut
        name = "root"
        subject = "/CN=root.example.com"
        with self.assertCreateCASignals():
            ca = CertificateAuthority.objects.init(name, subject, pathlen=2)
        self.assertProperties(ca, name, subject)
        self.assertIsNone(ca.authority_information_access)
        self.assertIsNone(ca.crl_distribution_points)

        name = "child"
        subject = "/CN=child.example.com"
        with self.assertCreateCASignals():
            child = CertificateAuthority.objects.init(name, subject, parent=ca)
        self.assertProperties(child, name, subject, parent=ca)
        self.assertEqual(
            child.authority_information_access,
            AuthorityInformationAccess(
                {
                    "value": {
                        "ocsp": ["URI:http://%s%s" % (host, self.reverse("ocsp-ca-post", serial=ca.serial))],
                        "issuers": ["URI:http://%s%s" % (host, self.reverse("issuer", serial=ca.serial))],
                    }
                }
            ),
        )
        self.assertEqual(
            child.crl_distribution_points,
            CRLDistributionPoints(
                {
                    "value": [
                        {"full_name": ["URI:http://%s%s" % (host, self.reverse("ca-crl", serial=ca.serial))]}
                    ]
                }
            ),
        )

        name = "grandchild"
        subject = "/CN=grandchild.example.com"
        with self.assertCreateCASignals():
            grandchild = CertificateAuthority.objects.init(name, subject, parent=child)
        self.assertProperties(grandchild, name, subject, parent=child)
        self.assertEqual(
            grandchild.authority_information_access,
            AuthorityInformationAccess(
                {
                    "value": {
                        "ocsp": [
                            "URI:http://%s%s" % (host, self.reverse("ocsp-ca-post", serial=child.serial))
                        ],
                        "issuers": ["URI:http://%s%s" % (host, self.reverse("issuer", serial=child.serial))],
                    }
                }
            ),
        )
        self.assertEqual(
            grandchild.crl_distribution_points,
            CRLDistributionPoints(
                {
                    "value": [
                        {
                            "full_name": [
                                "URI:http://%s%s" % (host, self.reverse("ca-crl", serial=child.serial))
                            ]
                        }
                    ]
                }
            ),
        )

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_no_default_hostname(self) -> None:
        """Test creating a CA with no default hostname."""
        name = "ndh"
        subject = "/CN=ndh.example.com"
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
        subject = "/CN=example.com"
        tlsf = TLSFeature({"value": ["OCSPMustStaple"]})
        ocsp_no_check = OCSPNoCheck()
        with self.assertCreateCASignals():
            ca = CertificateAuthority.objects.init(
                "with-extra", subject, extra_extensions=[tlsf, ocsp_no_check.as_extension()]
            )

        exts = [e for e in ca.extensions if not isinstance(e, (SubjectKeyIdentifier, AuthorityKeyIdentifier))]
        self.assertEqual(ca.subject, Subject(subject))
        self.assertCountEqual(
            exts,
            [
                tlsf,
                ocsp_no_check,
                BasicConstraints({"critical": True, "value": {"ca": True}}),
                KeyUsage({"critical": True, "value": ["cRLSign", "keyCertSign"]}),
            ],
        )

    def test_unknown_extension_type(self) -> None:
        """Test that creating a CA with an unknown extension throws an error."""
        name = "unknown-extension-type"
        subject = "/CN=%s.example.com" % name
        with self.assertRaisesRegex(ValueError, r"^Cannot add extension of type bool$"):
            CertificateAuthority.objects.init(
                name, subject, extra_extensions=[True]  # type: ignore[list-item]
            )
        self.assertEqual(CertificateAuthority.objects.filter(name=name).count(), 0)


@override_settings(CA_PROFILES={}, CA_DEFAULT_SUBJECT={}, CA_DEFAULT_CA=certs["root"]["serial"])
@freeze_time(timestamps["everything_valid"])
class CertificateAuthorityManagerDefaultTestCase(DjangoCAWithGeneratedCAsTestCase):
    """Tests for :py:func:`django_ca.managers.CertificateAuthorityManager.default`."""

    def setUp(self) -> None:
        super().setUp()
        self.ca = self.cas["root"]

    def test_default(self) -> None:
        """Test the correct CA is returned if CA_DEFAULT_CA is set."""
        self.assertEqual(CertificateAuthority.objects.default(), self.ca)

    def test_disabled(self) -> None:
        """Test that an exception is raised if the CA is disabled."""
        self.ca.enabled = False
        self.ca.save()

        with self.assertImproperlyConfigured(r"^CA_DEFAULT_CA: %s is disabled\.$" % self.ca.serial):
            CertificateAuthority.objects.default()

    @freeze_time(timestamps["everything_expired"])
    def test_expired(self) -> None:
        """Test that an exception is raised if CA is expired."""
        with self.assertImproperlyConfigured(r"^CA_DEFAULT_CA: %s is expired\.$" % self.ca.serial):
            CertificateAuthority.objects.default()

    @freeze_time(timestamps["before_everything"])
    def test_not_yet_valid(self) -> None:
        """Test that an exception is raised if CA is not yet valid."""
        with self.assertImproperlyConfigured(r"^CA_DEFAULT_CA: %s is not yet valid\.$" % self.ca.serial):
            CertificateAuthority.objects.default()

    @override_settings(CA_DEFAULT_CA="")
    def test_default_ca(self) -> None:
        """Test what is returned when **no** CA is configured as default."""
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


@override_settings(CA_DEFAULT_SUBJECT={})
class CreateCertTestCase(DjangoCAWithGeneratedCAsTestCase):
    """Test :py:class:`django_ca.managers.CertificateManager.create_cert` (create a new cert)."""

    @override_tmpcadir(CA_PROFILES={ca_settings.CA_DEFAULT_PROFILE: {"extensions": {}}})
    def test_basic(self) -> None:
        """Test creating the most basic cert possible."""
        ca = self.cas["root"]
        csr = certs["root-cert"]["csr"]["pem"]
        subject = "/CN=example.com"

        cert = Certificate.objects.create_cert(ca, csr, subject=subject)
        self.assertEqual(cert.subject, Subject(subject))
        self.assertExtensions(cert, [SubjectAlternativeName({"value": ["DNS:example.com"]})])

    @override_tmpcadir(CA_PROFILES={ca_settings.CA_DEFAULT_PROFILE: {"extensions": {}}})
    def test_explicit_profile(self) -> None:
        """Test creating a cert with a profile."""
        ca = self.cas["root"]
        csr = certs["root-cert"]["csr"]["pem"]
        subject = "/CN=example.com"

        cert = Certificate.objects.create_cert(
            ca, csr, subject=subject, profile=profiles[ca_settings.CA_DEFAULT_PROFILE]
        )
        self.assertEqual(cert.subject, Subject(subject))
        self.assertExtensions(cert, [SubjectAlternativeName({"value": ["DNS:example.com"]})])

    @override_tmpcadir()
    def test_no_cn_or_san(self) -> None:
        """Test that creating a cert with no CommonName or SubjectAlternativeName is an error."""
        ca = self.cas["root"]
        csr = certs["root-cert"]["csr"]["pem"]
        subject = None

        msg = r"^Must name at least a CN or a subjectAlternativeName\.$"
        with self.assertRaisesRegex(ValueError, msg):
            Certificate.objects.create_cert(ca, csr, subject=subject, extensions=[SubjectAlternativeName()])

    @override_tmpcadir(CA_PROFILES={k: None for k in ca_settings.CA_PROFILES})
    def test_no_profile(self) -> None:
        """Test that creating a cert with no profiles throws an error."""
        ca = self.cas["root"]
        csr = certs["root-cert"]["csr"]["pem"]
        subject = "/CN=example.com"

        with self.assertRaisesRegex(KeyError, r"^'webserver'$"):
            Certificate.objects.create_cert(
                ca, csr, subject=subject, add_crl_url=False, add_ocsp_url=False, add_issuer_url=False
            )


@unittest.skip("Only for type checkers.")
class TypingTestCase(unittest.TestCase):
    """Test case to create some code that would show an error in type checkers if type hinting is wrong.

    Note that none of these tests are designed to ever be executed.
    """
    # pylint: disable=missing-function-docstring

    def test_get(self) -> CertificateAuthority:
        return CertificateAuthority.objects.get(pk=1)

    def test_first(self) -> typing.Optional[CertificateAuthority]:
        return CertificateAuthority.objects.first()

    def test_get_queryset(self) -> CertificateAuthorityQuerySet:
        return CertificateAuthority.objects.get_queryset()

    def test_all(self) -> CertificateAuthorityQuerySet:
        return CertificateAuthority.objects.all()

    def test_filter(self) -> CertificateAuthorityQuerySet:
        return CertificateAuthority.objects.filter()

    def test_exclude(self) -> CertificateAuthorityQuerySet:
        return CertificateAuthority.objects.exclude()

    def test_get_by_serial_or_cn(self) -> CertificateAuthority:
        return CertificateAuthority.objects.get_by_serial_or_cn("foo")

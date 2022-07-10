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

"""Test the resign_cert management command."""

import os
import typing
from datetime import timedelta
from unittest.mock import patch

from cryptography import x509
from cryptography.x509.oid import NameOID

from django.test import TestCase
from django.utils import timezone

from freezegun import freeze_time

from .. import ca_settings
from ..extensions import AuthorityKeyIdentifier
from ..extensions import BasicConstraints
from ..extensions import CRLDistributionPoints
from ..extensions import ExtendedKeyUsage
from ..extensions import KeyUsage
from ..extensions import SubjectAlternativeName
from ..extensions import TLSFeature
from ..models import Certificate
from ..models import CertificateAuthority
from ..models import Watcher
from ..signals import post_issue_cert
from ..signals import pre_issue_cert
from .base import override_tmpcadir
from .base import timestamps
from .base.mixins import TestCaseMixin


@freeze_time(timestamps["everything_valid"])
class ResignCertTestCase(TestCaseMixin, TestCase):
    """Main test class for this command."""

    default_cert = "root-cert"
    load_cas = ("root", "child")
    load_certs = ("root-cert", "no-extensions")

    def assertResigned(  # pylint: disable=invalid-name
        self, old: Certificate, new: Certificate, new_ca: typing.Optional[CertificateAuthority] = None
    ) -> None:
        """Assert that the resigned certificate mathes the old cert."""
        new_ca = new_ca or old.ca
        issuer = new_ca.subject

        self.assertNotEqual(old.pk, new.pk)  # make sure we're not comparing the same cert

        # assert various properties
        self.assertEqual(new_ca, new.ca)
        self.assertEqual(issuer, new.issuer)
        self.assertEqual(old.hpkp_pin, new.hpkp_pin)

    def assertEqualExt(  # pylint: disable=invalid-name
        self, old: Certificate, new: Certificate, new_ca: typing.Optional[CertificateAuthority] = None
    ) -> None:
        """Assert that the extensions in both certs are equal."""
        new_ca = new_ca or old.ca
        self.assertEqual(old.subject, new.subject)

        # assert extensions that should be equal
        aki = AuthorityKeyIdentifier(new_ca.subject_key_identifier)
        self.assertEqual(aki, new.authority_key_identifier)
        self.assertEqual(old.extended_key_usage, new.extended_key_usage)
        self.assertEqual(old.key_usage, new.key_usage)
        self.assertEqual(old.subject_alternative_name, new.subject_alternative_name)
        self.assertEqual(old.tls_feature, new.tls_feature)

        # Test extensions that don't come from the old cert but from the signing CA
        self.assertEqual(new.basic_constraints, BasicConstraints({"critical": True, "value": {"ca": False}}))
        self.assertIsNone(new.issuer_alternative_name)  # signing ca does not have this set

        # Some properties come from the ca
        if new_ca.crl_url:
            self.assertEqual(
                CRLDistributionPoints({"value": [{"full_name": [new_ca.crl_url]}]}),
                new.crl_distribution_points,
            )
        else:
            self.assertIsNone(new.crl_distribution_points)

    @override_tmpcadir()
    def test_basic(self) -> None:
        """Simplest test while resigning a cert."""
        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd("resign_cert", self.cert.serial)
        self.assertEqual(stderr, "")
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(post.call_count, 1)

        new = Certificate.objects.get(pub=stdout)
        self.assertResigned(self.cert, new)
        self.assertEqualExt(self.cert, new)

    @override_tmpcadir()
    def test_different_ca(self) -> None:
        """Test writing with a different CA."""
        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd("resign_cert", self.cert.serial, ca=self.cas["child"])

        self.assertEqual(stderr, "")
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(post.call_count, 1)

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
        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd_e2e(
                [
                    "resign_cert",
                    self.cert.serial,
                    "--key-usage",
                    key_usage,
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
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(post.call_count, 1)

        new = Certificate.objects.get(pub=stdout)
        self.assertResigned(self.cert, new)

        # assert overwritten extensions
        self.assertEqual(new.subject, x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cname)]))
        self.assertEqual(new.subject_alternative_name, SubjectAlternativeName({"value": [f"DNS:{alt}"]}))
        self.assertEqual(new.key_usage, KeyUsage({"value": [key_usage], "critical": False}))
        self.assertEqual(
            new.extended_key_usage,
            ExtendedKeyUsage({"critical": True, "value": ext_key_usage.split(",")[1:]}),
        )
        self.assertEqual(new.tls_feature, TLSFeature({"critical": True, "value": tls_feature.split(",")[1:]}))
        self.assertEqual(list(new.watchers.all()), [Watcher.objects.get(mail=watcher)])

    @override_tmpcadir(
        CA_PROFILES={"server": {"expires": 200}, "webserver": {}},
        CA_DEFAULT_EXPIRES=31,
    )
    def test_set_profile(self) -> None:
        """Test getting the certificate from the profile."""

        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd_e2e(["resign_cert", self.cert.serial, "--server"])
        self.assertEqual(stderr, "")
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(post.call_count, 1)

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

        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd_e2e(["resign_cert", self.cert.serial])
        self.assertEqual(stderr, "")
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(post.call_count, 1)

        new = Certificate.objects.get(pub=stdout)
        self.assertEqual(new.expires.date(), timezone.now().date() + timedelta(days=200))
        self.assertResigned(self.cert, new)
        self.assertEqualExt(self.cert, new)

    @override_tmpcadir()
    def test_to_file(self) -> None:
        """Test writing output to file."""
        out_path = os.path.join(ca_settings.CA_DIR, "test.pem")

        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd("resign_cert", self.cert.serial, out=out_path)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(post.call_count, 1)

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
        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(
            post_issue_cert
        ) as post, self.assertCommandError(msg):
            self.cmd("resign_cert", cert, subject=subject)

        # signals not called
        self.assertEqual(pre.call_count, 0)
        self.assertEqual(post.call_count, 0)

    @override_tmpcadir()
    def test_error(self) -> None:
        """Test resign function throwing a random exception."""
        msg = "foobar"
        msg_re = rf"^{msg}$"
        with self.mockSignal(pre_issue_cert) as pre, self.mockSignal(post_issue_cert) as post, patch(
            "django_ca.managers.CertificateManager.create_cert", side_effect=Exception(msg)
        ), self.assertCommandError(msg_re):

            self.cmd("resign_cert", self.cert.serial)

        # signals not called
        self.assertEqual(pre.call_count, 0)
        self.assertEqual(post.call_count, 0)

    @override_tmpcadir(
        CA_PROFILES={"server": {"expires": 200}, "webserver": {}},
        CA_DEFAULT_EXPIRES=31,
    )
    def test_missing_cert_profile(self) -> None:
        """Test resigning a certificate with a profile that doesnt' exist.."""

        self.cert.profile = "profile-gone"
        self.cert.save()

        msg_re = rf'^Profile "{self.cert.profile}" for original certificate is no longer defined, please set one via the command line\.$'  # NOQA: E501
        with self.assertCommandError(msg_re):
            self.cmd("resign_cert", self.cert.serial)

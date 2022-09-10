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

"""Test querysets."""

import typing
from contextlib import contextmanager

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.x509.oid import NameOID

from django.db import models
from django.test import TestCase, TransactionTestCase

from freezegun import freeze_time

from .. import ca_settings
from ..extensions import BasicConstraints, KeyUsage
from ..models import (
    AcmeAccount,
    AcmeAuthorization,
    AcmeCertificate,
    AcmeChallenge,
    AcmeOrder,
    Certificate,
    CertificateAuthority,
)
from ..utils import x509_name
from .base import override_settings, override_tmpcadir, timestamps
from .base.mixins import AcmeValuesMixin, TestCaseMixin


class QuerySetTestCaseMixin(TestCaseMixin):
    """Mixin for QuerySet test cases."""

    def assertQuerySet(  # pylint: disable=invalid-name; unittest standard
        self, qs: "models.QuerySet[models.Model]", *items: models.Model
    ) -> None:
        """Minor shortcut to test querysets."""
        self.assertCountEqual(qs, items)

    @contextmanager
    def attr(self, obj: models.Model, attr: str, value: typing.Any) -> typing.Iterator[None]:
        """Context manager to temporarily set an attribute for an object."""

        original = getattr(obj, attr)
        try:
            setattr(obj, attr, value)
            obj.save()
            yield
        finally:
            setattr(obj, attr, original)
            obj.save()


@override_settings(CA_MIN_KEY_SIZE=1024)
class CertificateAuthorityQuerySetTestCase(TestCaseMixin, TestCase):
    """Test cases for :py:class:`~django_ca.querysets.CertificateAuthorityQuerySet`."""

    load_cas = ("root", "child")

    @override_tmpcadir()
    def test_basic(self) -> None:
        """Basic test for init()."""
        key_size = ca_settings.CA_MIN_KEY_SIZE
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ca.example.com")])
        ca = CertificateAuthority.objects.init(
            name="Root CA",
            key_size=key_size,
            key_type="RSA",
            algorithm=hashes.SHA256(),
            expires=self.expires(720),
            parent=None,
            pathlen=0,
            subject=subject,
        )

        self.assertEqual(ca.name, "Root CA")

        # verify private key properties
        key = typing.cast(rsa.RSAPrivateKey, ca.key(None))
        self.assertIsInstance(key, rsa.RSAPrivateKey)
        self.assertEqual(key.key_size, 1024)
        self.assertIsInstance(ca.key(None).public_key(), rsa.RSAPublicKey)

        # verity public key propertiesa
        self.assertBasic(ca.pub.loaded)
        self.assertEqual(ca.subject, subject)

        # verify X509 properties
        self.assertEqual(
            ca.basic_constraints, BasicConstraints({"critical": True, "value": {"ca": True, "pathlen": 0}})
        )
        self.assertEqual(ca.key_usage, KeyUsage({"critical": True, "value": ["cRLSign", "keyCertSign"]}))
        self.assertIsNone(ca.subject_alternative_name, None)

        self.assertIsNone(ca.extended_key_usage)
        self.assertIsNone(ca.tls_feature)
        self.assertIsNone(ca.issuer_alternative_name)
        self.assertFalse(ca.is_openssh_ca)

    @override_tmpcadir()
    def test_pathlen(self) -> None:
        """Test pathlen parameter in manager."""

        ca = CertificateAuthority.objects.init(
            name="1", key_size=ca_settings.CA_MIN_KEY_SIZE, subject=x509_name("CN=ca.example.com")
        )
        self.assertEqual(ca.basic_constraints, BasicConstraints({"critical": True, "value": {"ca": True}}))

        ca = CertificateAuthority.objects.init(
            pathlen=0, name="2", key_size=ca_settings.CA_MIN_KEY_SIZE, subject=x509_name("CN=ca.example.com")
        )
        self.assertEqual(
            ca.basic_constraints, BasicConstraints({"critical": True, "value": {"ca": True, "pathlen": 0}})
        )

        ca = CertificateAuthority.objects.init(
            pathlen=2, name="3", key_size=ca_settings.CA_MIN_KEY_SIZE, subject=x509_name("CN=ca.example.com")
        )
        self.assertEqual(
            ca.basic_constraints, BasicConstraints({"critical": True, "value": {"ca": True, "pathlen": 2}})
        )

    @override_tmpcadir()
    def test_parent(self) -> None:
        """Test parent parameter in manager."""
        key_size = ca_settings.CA_MIN_KEY_SIZE

        parent = CertificateAuthority.objects.init(
            name="Root",
            parent=None,
            pathlen=1,
            key_size=key_size,
            subject=x509_name("CN=ca.example.com"),
        )
        child = CertificateAuthority.objects.init(
            name="Child",
            parent=parent,
            pathlen=0,
            key_size=key_size,
            subject=x509_name("CN=child.ca.example.com"),
        )

        self.assertAuthorityKeyIdentifier(parent, child)

    @override_tmpcadir()
    def test_openssh_ca(self) -> None:
        """Test OpenSSH CA support"""

        ca_name = "OpenSSH CA"
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "openssh.example.com")])

        with self.assertRaisesRegex(ValueError, "EdDSA only supported for OpenSSH"):
            CertificateAuthority.objects.init(
                name=ca_name, key_size=None, key_type="EdDSA", subject=subject, openssh_ca=False
            )
        self.assertFalse(CertificateAuthority.objects.filter(name=ca_name).exists())

        # try creating a CA with a parent
        with self.assertRaisesRegex(ValueError, "OpenSSH does not support intermediate authorities"):
            CertificateAuthority.objects.init(
                name=ca_name,
                key_size=None,
                key_type="EdDSA",
                subject=subject,
                parent=self.ca,
                openssh_ca=True,
            )
        self.assertFalse(CertificateAuthority.objects.filter(name=ca_name).exists())

        ca = CertificateAuthority.objects.init(
            name=ca_name, key_size=None, key_type="EdDSA", subject=subject, openssh_ca=True
        )

        self.assertEqual(ca.name, ca_name)

        # verify private key properties
        self.assertIsInstance(ca.key(None).public_key(), Ed25519PublicKey)

        # verity public key properties
        self.assertEqual(ca.subject, subject)

        # verify X509 properties
        self.assertEqual(ca.key_usage, KeyUsage({"critical": True, "value": ["cRLSign", "keyCertSign"]}))
        self.assertIsNone(ca.subject_alternative_name, None)

        self.assertIsNone(ca.extended_key_usage)
        self.assertIsNone(ca.tls_feature)
        self.assertIsNone(ca.issuer_alternative_name)
        self.assertTrue(ca.is_openssh_ca)

    @override_tmpcadir()
    def test_key_size(self) -> None:
        """Test key size validation in manager."""
        kwargs = dict(
            name="Root CA",
            key_type="RSA",
            algorithm="sha256",
            expires=self.expires(720),
            parent=None,
            pathlen=0,
            subject={
                "CN": "ca.example.com",
            },
        )

        key_size = ca_settings.CA_MIN_KEY_SIZE

        # type ignores because kwargs is Dict[str, Any]
        with self.assertRaisesRegex(ValueError, r"^3072: Key size must be a power of two$"):
            CertificateAuthority.objects.init(key_size=key_size * 3, **kwargs)  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, r"^1025: Key size must be a power of two$"):
            CertificateAuthority.objects.init(key_size=key_size + 1, **kwargs)  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, r"^512: Key size must be least 1024 bits$"):
            CertificateAuthority.objects.init(key_size=int(key_size / 2), **kwargs)  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, r"^256: Key size must be least 1024 bits$"):
            CertificateAuthority.objects.init(key_size=int(key_size / 4), **kwargs)  # type: ignore[arg-type]

    def test_enabled_disabled(self) -> None:
        """Test enabled/disabled filter."""
        self.load_named_cas("__usable__")

        self.assertCountEqual(CertificateAuthority.objects.enabled(), self.cas.values())
        self.assertCountEqual(CertificateAuthority.objects.disabled(), [])

        self.ca.enabled = False
        self.ca.save()

        self.assertCountEqual(
            CertificateAuthority.objects.enabled(),
            [c for c in self.cas.values() if c.name != self.ca.name],
        )
        self.assertCountEqual(CertificateAuthority.objects.disabled(), [self.ca])

    def test_valid(self) -> None:
        """Test valid/usable/invalid filters."""
        self.load_named_cas("__usable__")

        with freeze_time(timestamps["before_cas"]):
            self.assertCountEqual(CertificateAuthority.objects.valid(), [])
            self.assertCountEqual(CertificateAuthority.objects.usable(), [])
            self.assertCountEqual(CertificateAuthority.objects.invalid(), self.cas.values())

        with freeze_time(timestamps["before_child"]):
            valid = [c for c in self.cas.values() if c.name != "child"]
            self.assertCountEqual(CertificateAuthority.objects.valid(), valid)
            self.assertCountEqual(CertificateAuthority.objects.usable(), valid)
            self.assertCountEqual(CertificateAuthority.objects.invalid(), [self.cas["child"]])

        with freeze_time(timestamps["after_child"]):
            self.assertCountEqual(CertificateAuthority.objects.valid(), self.cas.values())
            self.assertCountEqual(CertificateAuthority.objects.usable(), self.cas.values())
            self.assertCountEqual(CertificateAuthority.objects.invalid(), [])

        with freeze_time(timestamps["cas_expired"]):
            self.assertCountEqual(CertificateAuthority.objects.valid(), [])
            self.assertCountEqual(CertificateAuthority.objects.usable(), [])
            self.assertCountEqual(CertificateAuthority.objects.invalid(), self.cas.values())


class CertificateQuerysetTestCase(QuerySetTestCaseMixin, TestCase):
    """Test cases for :py:class:`~django_ca.querysets.CertificateQuerySet`."""

    load_cas = "__usable__"
    load_certs = "__usable__"

    def test_validity(self) -> None:
        """Test validity filter."""

        with freeze_time(timestamps["everything_valid"]):
            self.assertQuerySet(Certificate.objects.expired())
            self.assertQuerySet(Certificate.objects.not_yet_valid())
            self.assertQuerySet(Certificate.objects.valid(), *self.certs.values())

        with freeze_time(timestamps["everything_expired"]):
            self.assertQuerySet(Certificate.objects.expired(), *self.certs.values())
            self.assertQuerySet(Certificate.objects.not_yet_valid())
            self.assertQuerySet(Certificate.objects.valid())

        with freeze_time(timestamps["before_everything"]):
            self.assertQuerySet(Certificate.objects.expired())
            self.assertQuerySet(Certificate.objects.not_yet_valid(), *self.certs.values())
            self.assertQuerySet(Certificate.objects.valid())

        expired = [
            self.certs["root-cert"],
            self.certs["child-cert"],
            self.certs["ecc-cert"],
            self.certs["dsa-cert"],
            self.certs["pwd-cert"],
        ]
        valid = [c for c in self.certs.values() if c not in expired]
        with freeze_time(timestamps["ca_certs_expired"]):
            self.assertQuerySet(Certificate.objects.expired(), *expired)
            self.assertQuerySet(Certificate.objects.not_yet_valid())
            self.assertQuerySet(Certificate.objects.valid(), *valid)


class AcmeQuerySetTestCase(  # pylint: disable=too-many-instance-attributes
    QuerySetTestCaseMixin, AcmeValuesMixin, TransactionTestCase
):
    """Base class for ACME querysets (creates different instances)."""

    load_cas = "__usable__"

    def setUp(self) -> None:
        super().setUp()
        self.ca.acme_enabled = True
        self.ca.save()
        self.ca2 = self.cas["root"]
        self.ca2.acme_enabled = True
        self.ca2.save()
        self.kid = self.absolute_uri(":acme-account", serial=self.ca.serial, slug=self.ACME_SLUG_1)
        self.account = AcmeAccount.objects.create(
            ca=self.ca,
            contact="user@example.com",
            terms_of_service_agreed=True,
            status=AcmeAccount.STATUS_VALID,
            pem=self.ACME_PEM_1,
            thumbprint=self.ACME_THUMBPRINT_1,
            slug=self.ACME_SLUG_1,
            kid=self.kid,
        )
        self.kid2 = self.absolute_uri(":acme-account", serial=self.ca2.serial, slug=self.ACME_SLUG_2)
        self.account2 = AcmeAccount.objects.create(
            ca=self.ca2,
            contact="user@example.net",
            terms_of_service_agreed=True,
            status=AcmeAccount.STATUS_VALID,
            pem=self.ACME_PEM_2,
            thumbprint=self.ACME_THUMBPRINT_2,
            slug=self.ACME_SLUG_2,
            kid=self.kid2,
        )
        self.order = AcmeOrder.objects.create(account=self.account)
        self.auth = AcmeAuthorization.objects.create(order=self.order, value="example.com")
        self.chall = AcmeChallenge.objects.create(auth=self.auth, type=AcmeChallenge.TYPE_HTTP_01)
        self.cert = AcmeCertificate.objects.create(order=self.order)


class AcmeAccountQuerySetTestCase(AcmeQuerySetTestCase):
    """Test cases for :py:class:`~django_ca.querysets.AcmeAccountQuerySet`."""

    @freeze_time(timestamps["everything_valid"])
    def test_viewable(self) -> None:
        """Test the viewable() method."""

        self.assertQuerySet(AcmeAccount.objects.viewable(), self.account, self.account2)

        with self.attr(self.account, "status", AcmeAccount.STATUS_REVOKED):
            self.assertQuerySet(AcmeAccount.objects.viewable(), self.account, self.account2)

        with self.attr(self.ca, "enabled", False):
            self.assertQuerySet(AcmeAccount.objects.viewable(), self.account2)

        with self.attr(self.ca, "acme_enabled", False):
            self.assertQuerySet(AcmeAccount.objects.viewable(), self.account2)

        # Test that we're back to the original state
        self.assertQuerySet(AcmeAccount.objects.viewable(), self.account, self.account2)

        with freeze_time(timestamps["everything_expired"]):
            self.assertQuerySet(AcmeAccount.objects.viewable())


class AcmeOrderQuerysetTestCase(AcmeQuerySetTestCase):
    """Test cases for :py:class:`~django_ca.querysets.AcmeOrderQuerySet`."""

    def test_account(self) -> None:
        """Test the account filter."""
        self.assertQuerySet(AcmeOrder.objects.account(self.account), self.order)
        self.assertQuerySet(AcmeOrder.objects.account(self.account2))

    @freeze_time(timestamps["everything_valid"])
    def test_viewable(self) -> None:
        """Test the viewable() method."""

        self.assertQuerySet(AcmeOrder.objects.viewable(), self.order)

        with self.attr(self.order.account, "status", AcmeAccount.STATUS_REVOKED):
            self.assertQuerySet(AcmeOrder.objects.viewable())

        with freeze_time(timestamps["everything_expired"]):
            self.assertQuerySet(AcmeOrder.objects.viewable())


class AcmeAuthorizationQuerysetTestCase(AcmeQuerySetTestCase):
    """Test cases for :py:class:`~django_ca.querysets.AcmeAuthorizationQuerySet`."""

    def test_account(self) -> None:
        """Test the account filter."""
        self.assertQuerySet(AcmeAuthorization.objects.account(self.account), self.auth)
        self.assertQuerySet(AcmeAuthorization.objects.account(self.account2))

    @freeze_time(timestamps["everything_valid"])
    def test_url(self) -> None:
        """Test the url filter."""
        # pylint: disable=expression-not-assigned

        with self.assertNumQueries(1):
            AcmeAuthorization.objects.url().get(pk=self.auth.pk).acme_url

    @freeze_time(timestamps["everything_valid"])
    def test_viewable(self) -> None:
        """Test the viewable() method."""

        self.assertQuerySet(AcmeAuthorization.objects.viewable(), self.auth)

        with self.attr(self.order.account, "status", AcmeAccount.STATUS_REVOKED):
            self.assertQuerySet(AcmeAuthorization.objects.viewable())


class AcmeChallengeQuerysetTestCase(AcmeQuerySetTestCase):
    """Test cases for :py:class:`~django_ca.querysets.AcmeChallengeQuerySet`."""

    def test_account(self) -> None:
        """Test the account filter."""
        self.assertQuerySet(AcmeChallenge.objects.account(self.account), self.chall)
        self.assertQuerySet(AcmeChallenge.objects.account(self.account2))

    @freeze_time(timestamps["everything_valid"])
    def test_url(self) -> None:
        """Test the url filter."""
        # pylint: disable=expression-not-assigned

        with self.assertNumQueries(1):
            AcmeChallenge.objects.url().get(pk=self.chall.pk).acme_url

    @freeze_time(timestamps["everything_valid"])
    def test_viewable(self) -> None:
        """Test the viewable() method."""

        self.assertQuerySet(AcmeChallenge.objects.viewable(), self.chall)

        with self.attr(self.order.account, "status", AcmeAccount.STATUS_REVOKED):
            self.assertQuerySet(AcmeChallenge.objects.viewable())


class AcmeCertificateQuerysetTestCase(AcmeQuerySetTestCase):
    """Test cases for :py:class:`~django_ca.querysets.AcmeCertificateQuerySet`."""

    def test_account(self) -> None:
        """Test the account filter."""
        self.assertQuerySet(AcmeCertificate.objects.account(self.account), self.cert)
        self.assertQuerySet(AcmeCertificate.objects.account(self.account2))

    @freeze_time(timestamps["everything_valid"])
    def test_url(self) -> None:
        """Test the url filter."""
        # pylint: disable=expression-not-assigned

        with self.assertNumQueries(1):
            AcmeCertificate.objects.url().get(pk=self.cert.pk).acme_url

    @freeze_time(timestamps["everything_valid"])
    def test_viewable(self) -> None:
        """Test the viewable() method."""

        # none by default because we need a valid order and cert
        self.assertQuerySet(AcmeCertificate.objects.viewable())

        with self.attr(self.order.account, "status", AcmeAccount.STATUS_REVOKED):
            self.assertQuerySet(AcmeCertificate.objects.viewable())

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

"""Test the init_ca management command."""

import io
import typing
from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import NameOID

from django.test import TestCase
from django.utils import timezone

from freezegun import freeze_time

from .. import ca_settings
from ..extensions import AuthorityInformationAccess, CRLDistributionPoints, NameConstraints
from ..models import CertificateAuthority
from ..utils import int_to_hex, x509_name
from .base import override_settings, override_tmpcadir, timestamps, uri
from .base.mixins import TestCaseMixin


class InitCATest(TestCaseMixin, TestCase):
    """Test the init_ca management command."""

    def init_ca(self, **kwargs: typing.Any) -> typing.Tuple[str, str]:
        """Run a basic init_ca command."""

        stdout = io.StringIO()
        stderr = io.StringIO()
        name = kwargs.pop("name", "Test CA")
        kwargs.setdefault("key_size", ca_settings.CA_MIN_KEY_SIZE)
        return self.cmd(
            "init_ca",
            name,
            f"/C=AT/ST=Vienna/L=Vienna/O=Org/OU=OrgUnit/CN={name}",
            stdout=stdout,
            stderr=stderr,
            **kwargs,
        )

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_basic(self) -> None:
        """ "Basic tests for the command."""

        name = "test_basic"
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name=name)
        self.assertTrue(pre.called)
        self.assertEqual(out, "")
        self.assertEqual(err, "")

        ca = CertificateAuthority.objects.get(name=name)
        self.assertPostCreateCa(post, ca)
        self.assertPrivateKey(ca)
        self.assertSignature([ca], ca)
        ca.full_clean()  # assert e.g. max_length in serials
        self.assertBasic(ca.pub.loaded, algo=hashes.SHA512)

        # test the private key
        key = typing.cast(RSAPrivateKey, ca.key(None))
        self.assertIsInstance(key, RSAPrivateKey)
        self.assertEqual(key.key_size, 1024)

        self.assertEqual(
            ca.pub.loaded.subject,
            x509_name(
                [
                    ("C", "AT"),
                    ("ST", "Vienna"),
                    ("L", "Vienna"),
                    ("O", "Org"),
                    ("OU", "OrgUnit"),
                    ("CN", name),
                ]
            ),
        )
        self.assertIssuer(ca, ca)
        self.assertAuthorityKeyIdentifier(ca, ca)
        self.assertEqual(ca.serial, int_to_hex(ca.pub.loaded.serial_number))

    @override_settings(USE_TZ=True)
    def test_basic_with_use_tz(self) -> None:
        """Basic test with timezone support."""

        return self.test_basic()

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_subject_sort(self) -> None:
        """Assert that the subject is sorted by default."""
        cname = "subject-sort.example.com"
        name = "test_subject_sort"
        subject = f"/CN={cname}/C=AT"
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.cmd_e2e(["init_ca", name, subject])
        self.assertTrue(pre.called)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        ca = CertificateAuthority.objects.get(name=name)
        self.assertPostCreateCa(post, ca)
        self.assertPrivateKey(ca)
        ca.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([ca], ca)

        # Assert that common name and that subject is in correct order.
        self.assertEqual(ca.cn, cname)
        self.assertEqual(
            ca.pub.loaded.subject,
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "AT"),
                    x509.NameAttribute(NameOID.COMMON_NAME, cname),
                ]
            ),
        )

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_unsortable_subject(self) -> None:
        """Test subjects that do not have any standard storting."""
        cname = "subject-unsortable.example.com"
        name = "test_subject_unsortable"
        given_name = "given-name"
        subject = f"/CN={cname}/C=AT/givenName={given_name}"
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.cmd_e2e(["init_ca", name, subject])
        self.assertTrue(pre.called)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        ca = CertificateAuthority.objects.get(name=name)
        self.assertPostCreateCa(post, ca)
        self.assertPrivateKey(ca)
        ca.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([ca], ca)

        # Assert that common name and that subject is in correct order.
        self.assertEqual(ca.cn, cname)
        self.assertEqual(
            ca.pub.loaded.subject,
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, cname),
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "AT"),
                    x509.NameAttribute(NameOID.GIVEN_NAME, given_name),
                ]
            ),
        )

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_arguments(self) -> None:
        """Test most arguments."""

        hostname = "example.com"
        website = f"https://{hostname}"
        tos = f"{website}/tos/"
        caa = f"caa.{hostname}"
        name = "test_arguments"

        with self.assertCreateCASignals() as (pre, post):
            out, err = self.cmd_e2e(
                [
                    "init_ca",
                    name,
                    "/CN=args.example.com",
                    "--algorithm=SHA1",  # hashes.SHA1(),
                    "--key-type=DSA",
                    "--key-size=1024",
                    "--expires=720",
                    "--pathlen=3",
                    "--issuer-url=http://issuer.ca.example.com",
                    "--issuer-alt-name=http://ian.ca.example.com",
                    "--crl-url=http://crl.example.com",
                    "--ocsp-url=http://ocsp.example.com",
                    "--ca-issuer-url=http://ca.issuer.ca.example.com",
                    "--permit-name=DNS:.com",
                    "--exclude-name=DNS:.net",
                    f"--caa={caa}",
                    f"--website={website}",
                    f"--tos={tos}",
                ]
            )
        self.assertTrue(pre.called)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        ca = CertificateAuthority.objects.get(name=name)
        self.assertPostCreateCa(post, ca)
        self.assertPrivateKey(ca)
        ca.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([ca], ca)
        self.assertEqual(
            ca.name_constraints,
            NameConstraints({"value": {"permitted": ["DNS:.com"], "excluded": ["DNS:.net"]}}),
        )

        # test the private key
        key = typing.cast(RSAPrivateKey, ca.key(None))
        self.assertIsInstance(key, dsa.DSAPrivateKey)
        self.assertEqual(key.key_size, 1024)

        self.assertIsInstance(ca.pub.loaded.signature_hash_algorithm, hashes.SHA1)
        self.assertIsInstance(ca.pub.loaded.public_key(), dsa.DSAPublicKey)
        self.assertIsNone(ca.crl_distribution_points)
        self.assertEqual(
            ca.authority_information_access,
            AuthorityInformationAccess({"value": {"issuers": ["URI:http://ca.issuer.ca.example.com"]}}),
        )
        self.assertEqual(
            ca.name_constraints,
            NameConstraints({"value": {"permitted": ["DNS:.com"], "excluded": ["DNS:.net"]}}),
        )
        self.assertEqual(ca.pathlen, 3)
        self.assertEqual(ca.max_pathlen, 3)
        self.assertTrue(ca.allows_intermediate_ca)
        self.assertEqual(ca.issuer_url, "http://issuer.ca.example.com")
        self.assertEqual(ca.issuer_alt_name, "URI:http://ian.ca.example.com")
        self.assertEqual(ca.crl_url, "http://crl.example.com")
        self.assertEqual(ca.ocsp_url, "http://ocsp.example.com")
        self.assertIssuer(ca, ca)
        self.assertAuthorityKeyIdentifier(ca, ca)

        # test non-extension properties
        self.assertEqual(ca.caa_identity, caa)
        self.assertEqual(ca.website, website)
        self.assertEqual(ca.terms_of_service, tos)

        # test acme properties
        self.assertFalse(ca.acme_enabled)
        self.assertTrue(ca.acme_requires_contact)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_multiple_ians(self) -> None:
        """Test that we can set multiple IssuerAlternativeName values."""
        name = "test_multiple_ians"
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.cmd_e2e(
                [
                    "init_ca",
                    "--issuer-alt-name=example.com",
                    "--issuer-alt-name=https://example.com",
                    name,
                    f"/CN={name}",
                ]
            )
        self.assertTrue(pre.called)
        self.assertEqual(out, "")
        self.assertEqual(err, "")

        ca = CertificateAuthority.objects.get(name=name)
        self.assertPostCreateCa(post, ca)
        ca.full_clean()  # assert e.g. max_length in serials
        self.assertPrivateKey(ca)
        self.assertSignature([ca], ca)
        self.assertEqual(ca.issuer_alt_name, "DNS:example.com,URI:https://example.com")

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_acme_arguments(self) -> None:
        """Test ACME arguments."""

        with self.assertCreateCASignals() as (pre, post):
            out, err = self.cmd_e2e(
                ["init_ca", "Test CA", "/CN=acme.example.com", "--acme-enable", "--acme-contact-optional"]
            )
        self.assertTrue(pre.called)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        ca = CertificateAuthority.objects.get(cn="acme.example.com")
        self.assertPostCreateCa(post, ca)
        self.assertPrivateKey(ca)
        ca.full_clean()  # assert e.g. max_length in serials

        self.assertTrue(ca.acme_enabled)
        self.assertFalse(ca.acme_requires_contact)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024, CA_ENABLE_ACME=False)
    def test_disabled_acme_arguments(self) -> None:
        """Test that ACME options don't work when ACME is disabled."""
        with self.assertRaisesRegex(SystemExit, r"^2$") as excm:
            self.cmd_e2e(["init_ca", "Test CA", "/CN=acme.example.com", "--acme-enable"])
        self.assertEqual(excm.exception.args, (2,))

        with self.assertRaisesRegex(SystemExit, r"^2$") as excm:
            self.cmd_e2e(["init_ca", "Test CA", "/CN=acme.example.com", "--acme-contact-optional"])
        self.assertEqual(excm.exception.args, (2,))

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_ecc(self) -> None:
        """Test creating an ECC CA."""

        name = "test_ecc"
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(
                name=name,
                algorithm=hashes.SHA1(),
                key_type="ECC",
                key_size=1024,
                expires=self.expires(720),
                pathlen=3,
                issuer_url="http://issuer.ca.example.com",
                issuer_alt_name=x509.IssuerAlternativeName([uri("http://ian.ca.example.com")]),
                crl_url=["http://crl.example.com"],
                ocsp_url="http://ocsp.example.com",
                ca_issuer_url="http://ca.issuer.ca.example.com",
            )
        self.assertTrue(pre.called)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        ca = CertificateAuthority.objects.get(name=name)
        self.assertPostCreateCa(post, ca)
        self.assertIsInstance(ca.key(None), ec.EllipticCurvePrivateKey)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_permitted(self) -> None:
        """Test the NameConstraints extension with 'permitted'."""

        name = "test_permitted"
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.cmd_e2e(["init_ca", "--permit-name", "DNS:.com", name, f"/CN={name}"])
        self.assertTrue(pre.called)
        self.assertEqual(out, "")
        self.assertEqual(err, "")

        ca = CertificateAuthority.objects.get(name=name)
        self.assertPostCreateCa(post, ca)
        ca.full_clean()  # assert e.g. max_length in serials
        self.assertPrivateKey(ca)
        self.assertSignature([ca], ca)
        self.assertEqual(ca.name_constraints, NameConstraints({"value": {"permitted": ["DNS:.com"]}}))

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_excluded(self) -> None:
        """Test the NameConstraints extension with 'excluded'."""

        name = "test_excluded"
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.cmd_e2e(["init_ca", "--exclude-name", "DNS:.com", name, f"/CN={name}"])
        self.assertTrue(pre.called)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        ca = CertificateAuthority.objects.get(name=name)
        self.assertPostCreateCa(post, ca)
        self.assertPrivateKey(ca)
        ca.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([ca], ca)
        self.assertEqual(ca.name_constraints, NameConstraints({"value": {"excluded": ["DNS:.com"]}}))

    @override_settings(USE_TZ=True)
    def test_arguments_with_use_tz(self) -> None:
        """Test arguments without NameConstraints."""

        self.test_arguments()

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_no_pathlen(self) -> None:
        """Test creating a CA with no pathlen."""

        name = "test_no_pathlen"
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name=name, pathlen=None)
        self.assertTrue(pre.called)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        ca = CertificateAuthority.objects.get(name=name)
        self.assertPostCreateCa(post, ca)
        ca.full_clean()  # assert e.g. max_length in serials
        self.assertPrivateKey(ca)
        self.assertSignature([ca], ca)
        self.assertEqual(ca.max_pathlen, None)
        self.assertEqual(ca.pathlen, None)
        self.assertTrue(ca.allows_intermediate_ca)
        self.assertIssuer(ca, ca)
        self.assertAuthorityKeyIdentifier(ca, ca)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_empty_subject_fields(self) -> None:
        """Test creating a CA with empty subject fields."""

        name = "test_empty_subject_fields"
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.cmd("init_ca", name, f"/L=/CN={self.hostname}")
        self.assertTrue(pre.called)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        ca = CertificateAuthority.objects.get(name=name)
        self.assertPostCreateCa(post, ca)
        ca.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([ca], ca)
        self.assertEqual(
            ca.pub.loaded.subject,
            x509.Name(
                [
                    x509.NameAttribute(NameOID.LOCALITY_NAME, ""),
                    x509.NameAttribute(NameOID.COMMON_NAME, self.hostname),
                ]
            ),
        )
        self.assertIssuer(ca, ca)
        self.assertAuthorityKeyIdentifier(ca, ca)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_no_cn(self) -> None:
        """Test creating a CA with no CommonName."""

        name = "test_no_cn"
        subject = "/ST=/L=/O=/OU=smth"
        error = r"^Subject must contain a common name \(/CN=...\)\.$"
        with self.assertCreateCASignals(False, False), self.assertCommandError(error):
            self.cmd("init_ca", name, subject)

        error = r"CommonName must not be an empty value"
        subject = "/ST=/L=/O=/OU=smth/CN="
        with self.assertCreateCASignals(False, False), self.assertCommandError(error):
            self.cmd("init_ca", name, subject)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_parent(self) -> None:
        """Test creating a CA and an intermediate CA."""

        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name="Parent", pathlen=1)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        self.assertTrue(pre.called)
        parent = CertificateAuthority.objects.get(name="Parent")
        self.assertPostCreateCa(post, parent)
        parent.full_clean()  # assert e.g. max_length in serials
        self.assertPrivateKey(parent)
        self.assertSignature([parent], parent)

        # test that the default is not a child-relationship
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name="Second")
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        self.assertTrue(pre.called)

        second = CertificateAuthority.objects.get(name="Second")
        self.assertPostCreateCa(post, second)
        second.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([second], second)
        self.assertIsNone(second.parent)

        ca_crl_url = "http://ca.crl.example.com"
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(
                name="Child",
                parent=parent,
                ca_crl_url=[ca_crl_url],
                ca_ocsp_url="http://ca.ocsp.example.com",
            )
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        self.assertTrue(pre.called)
        child = CertificateAuthority.objects.get(name="Child")
        self.assertPostCreateCa(post, child)
        child.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([parent], child)
        self.assertPrivateKey(child)

        self.assertIsNone(parent.parent)
        self.assertEqual(child.parent, parent)
        self.assertEqual(list(child.children.all()), [])
        self.assertEqual(list(parent.children.all()), [child])
        self.assertIssuer(parent, child)
        self.assertAuthorityKeyIdentifier(parent, child)
        self.assertEqual(
            child.crl_distribution_points,
            CRLDistributionPoints(
                {
                    "value": [
                        {
                            "full_name": [ca_crl_url],
                        }
                    ]
                }
            ),
        )
        issuers = f"URI:http://{ca_settings.CA_DEFAULT_HOSTNAME}/django_ca/issuer/{parent.serial}.der"
        self.assertEqual(
            child.authority_information_access,
            AuthorityInformationAccess(
                {
                    "value": {
                        "issuers": [issuers],
                        "ocsp": ["URI:http://ca.ocsp.example.com"],
                    }
                }
            ),
        )

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_intermediate_check(self) -> None:  # pylint: disable=too-many-statements
        """Test intermediate pathlen checks."""

        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name="default")
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        self.assertTrue(pre.called)
        parent = CertificateAuthority.objects.get(name="default")
        self.assertPostCreateCa(post, parent)
        self.assertPrivateKey(parent)
        parent.full_clean()  # assert e.g. max_length in serials
        self.assertEqual(parent.pathlen, 0)
        self.assertEqual(parent.max_pathlen, 0)
        self.assertFalse(parent.allows_intermediate_ca)

        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name="pathlen-1", pathlen=1)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        self.assertTrue(pre.called)
        pathlen_1 = CertificateAuthority.objects.get(name="pathlen-1")
        self.assertPostCreateCa(post, pathlen_1)
        pathlen_1.full_clean()  # assert e.g. max_length in serials
        self.assertPrivateKey(pathlen_1)
        self.assertEqual(pathlen_1.pathlen, 1)
        self.assertEqual(pathlen_1.max_pathlen, 1)
        self.assertTrue(pathlen_1.allows_intermediate_ca)

        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name="pathlen-1-none", pathlen=None, parent=pathlen_1)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        self.assertTrue(pre.called)
        pathlen_1_none = CertificateAuthority.objects.get(name="pathlen-1-none")
        self.assertPostCreateCa(post, pathlen_1_none)
        pathlen_1_none.full_clean()  # assert e.g. max_length in serials
        self.assertPrivateKey(pathlen_1_none)

        # pathlen_1_none cannot have an intermediate CA because parent has pathlen=1
        self.assertIsNone(pathlen_1_none.pathlen)
        self.assertEqual(pathlen_1_none.max_pathlen, 0)
        self.assertFalse(pathlen_1_none.allows_intermediate_ca)
        with self.assertCommandError(
            r"^Parent CA cannot create intermediate CA due to pathlen restrictions\.$"
        ), self.assertCreateCASignals(False, False):
            out, err = self.init_ca(name="wrong", parent=pathlen_1_none)
        self.assertEqual(out, "")
        self.assertEqual(err, "")

        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name="pathlen-1-three", pathlen=3, parent=pathlen_1)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        self.assertTrue(pre.called)
        pathlen_1_three = CertificateAuthority.objects.get(name="pathlen-1-three")
        self.assertPostCreateCa(post, pathlen_1_three)
        pathlen_1_three.full_clean()  # assert e.g. max_length in serials
        self.assertPrivateKey(pathlen_1_three)

        # pathlen_1_none cannot have an intermediate CA because parent has pathlen=1
        self.assertEqual(pathlen_1_three.pathlen, 3)
        self.assertEqual(pathlen_1_three.max_pathlen, 0)
        self.assertFalse(pathlen_1_three.allows_intermediate_ca)
        with self.assertCommandError(
            r"^Parent CA cannot create intermediate CA due to pathlen restrictions\.$"
        ), self.assertCreateCASignals(False, False):
            out, _err = self.init_ca(name="wrong", parent=pathlen_1_none)
        self.assertEqual(out, "")

        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name="pathlen-none", pathlen=None)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        self.assertTrue(pre.called)
        pathlen_none = CertificateAuthority.objects.get(name="pathlen-none")
        self.assertPostCreateCa(post, pathlen_none)
        pathlen_none.full_clean()  # assert e.g. max_length in serials
        self.assertPrivateKey(pathlen_none)
        self.assertIsNone(pathlen_none.pathlen)
        self.assertIsNone(pathlen_none.max_pathlen, None)
        self.assertTrue(pathlen_none.allows_intermediate_ca)

        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name="pathlen-none-none", pathlen=None, parent=pathlen_none)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        self.assertTrue(pre.called)
        pathlen_none_none = CertificateAuthority.objects.get(name="pathlen-none-none")
        self.assertPostCreateCa(post, pathlen_none_none)
        pathlen_none_none.full_clean()  # assert e.g. max_length in serials
        self.assertIsNone(pathlen_none_none.pathlen)
        self.assertIsNone(pathlen_none_none.max_pathlen)

        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name="pathlen-none-1", pathlen=1, parent=pathlen_none)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        self.assertTrue(pre.called)
        pathlen_none_1 = CertificateAuthority.objects.get(name="pathlen-none-1")
        self.assertPostCreateCa(post, pathlen_none_1)
        pathlen_none_1.full_clean()  # assert e.g. max_length in serials
        self.assertEqual(pathlen_none_1.pathlen, 1)
        self.assertEqual(pathlen_none_1.max_pathlen, 1)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_expires_override(self) -> None:
        """Test that if we request an expiry after that of the parent, we override to that of the parent."""

        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name="Parent", pathlen=1)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        self.assertTrue(pre.called)
        parent = CertificateAuthority.objects.get(name="Parent")
        self.assertPostCreateCa(post, parent)
        parent.full_clean()  # assert e.g. max_length in serials
        self.assertPrivateKey(parent)
        self.assertSignature([parent], parent)

        # test that the default is not a child-relationship
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name="Second")
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        self.assertTrue(pre.called)
        second = CertificateAuthority.objects.get(name="Second")
        self.assertPostCreateCa(post, second)
        second.full_clean()  # assert e.g. max_length in serials
        self.assertIsNone(second.parent)
        self.assertSignature([second], second)

        expires = parent.expires - timezone.now() + timedelta(days=10)
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name="Child", parent=parent, expires=expires)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        self.assertTrue(pre.called)
        child = CertificateAuthority.objects.get(name="Child")
        self.assertPostCreateCa(post, child)
        child.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([parent], child)

        self.assertEqual(parent.expires, child.expires)
        self.assertIsNone(parent.parent)
        self.assertEqual(child.parent, parent)
        self.assertEqual(list(child.children.all()), [])
        self.assertEqual(list(parent.children.all()), [child])
        self.assertIssuer(parent, child)
        self.assertAuthorityKeyIdentifier(parent, child)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_password(self) -> None:
        """Test creating a CA with a password."""

        password = b"testpassword"
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name="Parent", password=password, pathlen=1)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        self.assertTrue(pre.called)
        parent = CertificateAuthority.objects.get(name="Parent")
        self.assertPostCreateCa(post, parent)
        parent.full_clean()  # assert e.g. max_length in serials
        self.assertPrivateKey(parent, password=password)
        self.assertSignature([parent], parent)

        # Assert that we cannot access this without a password
        msg = "^Password was not given but private key is encrypted$"
        parent = CertificateAuthority.objects.get(name="Parent")
        with self.assertRaisesRegex(TypeError, msg):
            parent.key(None)

        # Wrong password doesn't work either
        with self.assertRaises(ValueError):
            # NOTE: cryptography is notoriously unstable when it comes to the error message here, so we only
            # check the exception class.
            parent.key(b"wrong")

        # test the private key
        key = typing.cast(RSAPrivateKey, parent.key(password))
        self.assertIsInstance(key, RSAPrivateKey)
        self.assertEqual(key.key_size, 1024)

        # create a child ca, also password protected
        child_password = b"childpassword"
        parent = CertificateAuthority.objects.get(name="Parent")  # Get again, key is cached

        with self.assertCommandError(
            r"^Password was not given but private key is encrypted$"
        ), self.assertCreateCASignals(False, False):
            out, err = self.init_ca(name="Child", parent=parent, password=child_password)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        self.assertIsNone(CertificateAuthority.objects.filter(name="Child").first())

        # Create again with parent ca
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(
                name="Child", parent=parent, password=child_password, parent_password=password
            )
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        self.assertTrue(pre.called)

        child = CertificateAuthority.objects.get(name="Child")
        self.assertPostCreateCa(post, child)
        child.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([parent], child)

        # test the private key
        key = typing.cast(RSAPrivateKey, child.key(child_password))
        self.assertIsInstance(key, RSAPrivateKey)
        self.assertEqual(key.key_size, 1024)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    @freeze_time(timestamps["everything_valid"])
    def test_default_hostname(self) -> None:
        """Test manually passing a default hostname.

        Note: freeze time b/c this test uses root CA as a parent.
        """
        root = self.load_ca("root")

        name = "ca"
        hostname = "test-default-hostname.com"
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name=name, parent=root, default_hostname=hostname)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        self.assertTrue(pre.called)
        ca = CertificateAuthority.objects.get(name=name)
        self.assertPostCreateCa(post, ca)

        self.assertEqual(ca.issuer_url, f"http://{hostname}/django_ca/issuer/{root.serial}.der")
        self.assertEqual(ca.ocsp_url, f"http://{hostname}/django_ca/ocsp/{ca.serial}/cert/")
        self.assertEqual(
            ca.authority_information_access,
            AuthorityInformationAccess(
                {
                    "value": {
                        "issuers": [f"URI:http://{hostname}/django_ca/issuer/{root.serial}.der"],
                        "ocsp": [f"URI:http://{hostname}/django_ca/ocsp/{root.serial}/ca/"],
                    }
                }
            ),
        )

        ca_crl_urlpath = self.reverse("ca-crl", serial=root.serial)
        self.assertEqual(
            ca.crl_distribution_points,
            CRLDistributionPoints({"value": [{"full_name": [f"http://{hostname}{ca_crl_urlpath}"]}]}),
        )

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_no_default_hostname(self) -> None:
        """Disable default hostname via the command line."""

        name = "ca"
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name=name, default_hostname=False)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        self.assertTrue(pre.called)
        ca = CertificateAuthority.objects.get(name=name)
        self.assertPostCreateCa(post, ca)

        self.assertIsNone(ca.issuer_url)
        self.assertIsNone(ca.ocsp_url)
        self.assertIsNone(ca.authority_information_access)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_root_ca_crl_url(self) -> None:
        """Test that you cannot create a CA with a CRL URL."""

        with self.assertCommandError(
            r"^CRLs cannot be used to revoke root CAs\.$"
        ), self.assertCreateCASignals(False, False):
            self.init_ca(name="foobar", ca_crl_url="https://example.com")

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_root_ca_ocsp_url(self) -> None:
        """Test that you cannot create a CA with a OCSP URL."""

        with self.assertCommandError(
            r"^OCSP cannot be used to revoke root CAs\.$"
        ), self.assertCreateCASignals(False, False):
            self.init_ca(name="foobar", ca_ocsp_url="https://example.com")

    @override_tmpcadir()
    def test_small_key_size(self) -> None:
        """Test creating a key with a key size that is too small."""

        with self.assertCommandError(r"^256: Key size must be least 1024 bits$"), self.assertCreateCASignals(
            False, False
        ):
            self.init_ca(key_size=256)

    @override_tmpcadir()
    def test_key_not_power_of_two(self) -> None:
        """Test creating a key with invalid key size."""

        with self.assertCommandError(r"^2049: Key size must be a power of two$"), self.assertCreateCASignals(
            False, False
        ):
            self.init_ca(key_size=2049)

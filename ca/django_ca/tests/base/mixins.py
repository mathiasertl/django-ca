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

"""Collection of mixin classes for unittest.TestCase subclasses."""

import copy
import io
import json
import re
import textwrap
import typing
from contextlib import contextmanager
from datetime import datetime, timedelta
from http import HTTPStatus
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple, Type, Union
from unittest import mock
from urllib.parse import quote

from OpenSSL.crypto import FILETYPE_PEM, X509Store, X509StoreContext, load_certificate

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed448, ed25519, rsa, x448, x25519
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID

import django
from django.conf import settings
from django.contrib.auth.models import User  # pylint: disable=imported-auth-user; for mypy
from django.contrib.messages import get_messages
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.core.management import ManagementUtility, call_command
from django.core.management.base import CommandError
from django.db import models
from django.dispatch.dispatcher import Signal
from django.templatetags.static import static
from django.test.testcases import SimpleTestCase
from django.urls import reverse

from freezegun import freeze_time
from freezegun.api import FrozenDateTimeFactory, StepTickTimeFactory

from django_ca import ca_settings, constants
from django_ca.constants import ReasonFlags
from django_ca.deprecation import RemovedInDjangoCA125Warning, RemovedInDjangoCA126Warning
from django_ca.extensions import extension_as_text
from django_ca.models import Certificate, CertificateAuthority, DjangoCAModel, X509CertMixin
from django_ca.signals import (
    post_create_ca,
    post_issue_cert,
    post_revoke_cert,
    post_sign_cert,
    pre_create_ca,
    pre_sign_cert,
)
from django_ca.tests.base import certs, timestamps, uri
from django_ca.tests.base.typehints import DjangoCAModelTypeVar
from django_ca.utils import add_colons, ca_storage, parse_general_name

if typing.TYPE_CHECKING:
    # Use SimpleTestCase as base class when type checking. This way mypy will know about attributes/methods
    # that the mixin accesses. See also:
    #   https://github.com/python/mypy/issues/5837
    TestCaseProtocol = SimpleTestCase

    from django.test.client import _MonkeyPatchedWSGIResponse as HttpResponse
else:
    TestCaseProtocol = object


class TestCaseMixin(TestCaseProtocol):  # pylint: disable=too-many-public-methods
    """Mixin providing augmented functionality to all test cases."""

    load_cas: Union[str, Tuple[str, ...]] = tuple()
    load_certs: Union[str, Tuple[str, ...]] = tuple()
    default_ca = "child"
    default_cert = "child-cert"
    cas: Dict[str, CertificateAuthority] = {}
    certs: Dict[str, Certificate] = {}

    # Note: cryptography sometimes adds another sentence at the end
    re_false_password = r"^Could not decrypt private key - bad password\?$"

    def setUp(self) -> None:
        # Add custom equality functions
        self.addTypeEqualityFunc(x509.ExtendedKeyUsage, self.assertExtendedKeyUsageEqual)
        self.addTypeEqualityFunc(x509.Extension, self.assertCryptographyExtensionEqual)
        self.addTypeEqualityFunc(x509.KeyUsage, self.assertKeyUsageEqual)
        self.addTypeEqualityFunc(x509.TLSFeature, self.assertTLSFeatureEqual)

        super().setUp()
        cache.clear()

        self.cas = {}
        self.certs = {}
        self.load_cas = self.load_named_cas(self.load_cas)
        self.load_certs = self.load_named_certs(self.load_certs)

        # Set `self.ca` as a default certificate authority (if at least one is loaded)
        if len(self.load_cas) == 1:  # only one CA specified, set self.ca for convenience
            self.ca: CertificateAuthority = self.cas[self.load_cas[0]]
        elif self.load_cas:
            if self.default_ca not in self.load_cas:  # pragma: no cover
                self.fail(f"{self.default_ca}: Not in {self.load_cas}.")
            self.ca = self.cas[self.default_ca]

        # Set `self.cert` as a default certificate (if at least one is loaded)
        if len(self.load_certs) == 1:  # only one CA specified, set self.cert for convenience
            self.cert = self.certs[self.load_certs[0]]
        elif self.load_certs:
            if self.default_cert not in self.load_certs:  # pragma: no cover
                self.fail(f"{self.default_cert}: Not in {self.load_certs}.")
            self.cert = self.certs[self.default_cert]

    def load_named_cas(self, cas: Union[str, Tuple[str, ...]]) -> Tuple[str, ...]:
        """Load CAs by the given name."""
        if cas == "__all__":
            cas = tuple(k for k, v in certs.items() if v.get("type") == "ca")
        elif cas == "__usable__":
            cas = tuple(k for k, v in certs.items() if v.get("type") == "ca" and v["key_filename"])
        elif isinstance(cas, str):  # pragma: no cover
            self.fail(f"{cas}: Unknown alias for load_cas.")

        # Filter CAs that we already loaded
        cas = tuple(ca for ca in cas if ca not in self.cas)

        # Load all CAs (sort by len() of parent so that root CAs are loaded first)
        for name in sorted(cas, key=lambda n: len(certs[n].get("parent", ""))):
            self.cas[name] = self.load_ca(name)
        return cas

    def load_named_certs(self, names: Union[str, Tuple[str, ...]]) -> Tuple[str, ...]:
        """Load certs by the given name."""
        if names == "__all__":
            names = tuple(k for k, v in certs.items() if v.get("type") == "cert")
        elif names == "__usable__":
            names = tuple(k for k, v in certs.items() if v.get("type") == "cert" and v["cat"] == "generated")
        elif isinstance(names, str):  # pragma: no cover
            self.fail(f"{names}: Unknown alias for load_certs.")

        # Filter certificates that are already loaded
        names = tuple(name for name in names if name not in self.certs)

        for name in names:
            try:
                self.certs[name] = self.load_named_cert(name)
            except CertificateAuthority.DoesNotExist:  # pragma: no cover
                self.fail(f'{certs[name]["ca"]}: Could not load CertificateAuthority.')
        return names

    def absolute_uri(self, name: str, hostname: Optional[str] = None, **kwargs: Any) -> str:
        """Build an absolute uri for the given request.

        The `name` is assumed to be a URL name or a full path. If `name` starts with a colon, ``django_ca``
        is used as namespace.
        """
        if hostname is None:
            hostname = settings.ALLOWED_HOSTS[0]

        if name.startswith("/"):
            return f"http://{hostname}{name}"
        if name.startswith(":"):  # pragma: no branch
            name = f"django_ca{name}"
        return f"http://{hostname}{reverse(name, kwargs=kwargs)}"

    def assertAuthorityKeyIdentifier(  # pylint: disable=invalid-name
        self, issuer: CertificateAuthority, cert: X509CertMixin
    ) -> None:
        """Test the key identifier of the AuthorityKeyIdentifier extenion of `cert`."""
        actual = typing.cast(
            x509.AuthorityKeyIdentifier, cert.x509_extensions[ExtensionOID.AUTHORITY_KEY_IDENTIFIER].value
        )
        expected = typing.cast(
            x509.SubjectKeyIdentifier, issuer.x509_extensions[ExtensionOID.SUBJECT_KEY_IDENTIFIER].value
        )
        self.assertEqual(actual.key_identifier, expected.key_identifier)

    def assertBasic(  # pylint: disable=invalid-name
        self, cert: x509.Certificate, algo: Type[hashes.HashAlgorithm] = hashes.SHA256
    ) -> None:
        """Assert some basic key properties."""
        self.assertEqual(cert.version, x509.Version.v3)
        self.assertIsInstance(cert.public_key(), rsa.RSAPublicKey)
        self.assertIsInstance(cert.signature_hash_algorithm, algo)

    def assertCRL(
        # pylint: disable=invalid-name
        self,
        crl: bytes,
        expected: Optional[typing.Sequence[X509CertMixin]] = None,
        signer: Optional[CertificateAuthority] = None,
        expires: int = 86400,
        algorithm: Optional[hashes.HashAlgorithm] = None,
        encoding: Encoding = Encoding.PEM,
        idp: Optional["x509.Extension[x509.IssuingDistributionPoint]"] = None,
        extensions: Optional[List["x509.Extension[x509.ExtensionType]"]] = None,
        crl_number: int = 0,
    ) -> None:
        """Test the given CRL.

        Parameters
        ----------
        crl : bytes
            The raw CRL
        expected : list
            List of CAs/certs to be expected in this CRL
        signer
        expires
        algorithm
        encoding
        idp
        extensions
        crl_number
        """
        expected = expected or []
        signer = signer or self.cas["child"]
        extensions = extensions or []
        expires_timestamp = datetime.utcnow() + timedelta(seconds=expires)

        if idp is not None:  # pragma: no branch
            extensions.append(idp)
        extensions.append(
            x509.Extension(
                value=x509.CRLNumber(crl_number=crl_number), critical=False, oid=ExtensionOID.CRL_NUMBER
            )
        )
        extensions.append(signer.get_authority_key_identifier_extension())

        if encoding == Encoding.PEM:
            parsed_crl = x509.load_pem_x509_crl(crl)
        else:
            parsed_crl = x509.load_der_x509_crl(crl)

        public_key = signer.pub.loaded.public_key()
        if isinstance(public_key, (x448.X448PublicKey, x25519.X25519PublicKey)):  # pragma: no cover
            raise TypeError()  # just to make mypy happy

        self.assertIsInstance(parsed_crl.signature_hash_algorithm, type(algorithm))

        # cryptography can not validate signatures of CRLs for non DSA/RSA/EC keys
        # https://github.com/pyca/cryptography/issues/8156
        if settings.CRYPTOGRAPHY_VERSION >= (40, 0) or not isinstance(  # pragma: cryptography<40.0 branch
            public_key, (ed448.Ed448PublicKey, ed25519.Ed25519PublicKey)
        ):
            self.assertTrue(parsed_crl.is_signature_valid(public_key))
        self.assertEqual(parsed_crl.issuer, signer.pub.loaded.subject)
        self.assertEqual(parsed_crl.last_update, datetime.utcnow())
        self.assertEqual(parsed_crl.next_update, expires_timestamp)
        self.assertCountEqual(list(parsed_crl.extensions), extensions)

        entries = {e.serial_number: e for e in parsed_crl}
        self.assertCountEqual(entries, {c.pub.loaded.serial_number: c for c in expected})
        for entry in entries.values():
            self.assertEqual(entry.revocation_date, datetime.utcnow())
            self.assertEqual(list(entry.extensions), [])

    @contextmanager
    def assertCommandError(self, msg: str) -> Iterator[None]:  # pylint: disable=invalid-name
        """Context manager asserting that CommandError is raised.

        Parameters
        ----------
        msg : str
            The regex matching the exception message.
        """
        with self.assertRaisesRegex(CommandError, msg):
            yield

    @contextmanager
    def assertCreateCASignals(  # pylint: disable=invalid-name
        self, pre: bool = True, post: bool = True
    ) -> Iterator[Tuple[mock.Mock, mock.Mock]]:
        """Context manager mocking both pre and post_create_ca signals."""
        with self.mockSignal(pre_create_ca) as pre_sig, self.mockSignal(post_create_ca) as post_sig:
            try:
                yield pre_sig, post_sig
            finally:
                self.assertTrue(pre_sig.called is pre)
                self.assertTrue(post_sig.called is post)

    @contextmanager
    def assertSignCertSignals(  # pylint: disable=invalid-name
        self, pre: bool = True, post: bool = True
    ) -> Iterator[Tuple[mock.Mock, mock.Mock]]:
        """Context manager mocking both pre and post_create_ca signals."""
        with self.mockSignal(pre_sign_cert) as pre_sig, self.mockSignal(post_sign_cert) as post_sig:
            try:
                yield pre_sig, post_sig
            finally:
                self.assertTrue(pre_sig.called is pre)
                self.assertTrue(post_sig.called is post)

    def assertCryptographyExtensionEqual(  # pylint: disable=invalid-name
        self,
        first: x509.Extension[x509.ExtensionType],
        second: x509.Extension[x509.ExtensionType],
        msg: Optional[str] = None,
    ) -> None:
        """Type equality function for x509.Extension."""
        # NOTE: Cryptography in name comes from overriding class in AbstractExtensionTestMixin
        #       remove once old wrapper classes are removed
        self.assertEqual(first.oid, second.oid, msg=msg)
        self.assertEqual(first.critical, second.critical, msg="critical is unequal.")
        self.assertEqual(first.value, second.value, msg=msg)

    def assertExtendedKeyUsageEqual(  # pylint: disable=invalid-name
        self, first: x509.ExtendedKeyUsage, second: x509.ExtendedKeyUsage, msg: Optional[str] = None
    ) -> None:
        """Type equality function for x509.ExtendedKeyUsage."""
        self.assertEqual(set(first), set(second), msg=msg)

    def assertKeyUsageEqual(  # pylint: disable=invalid-name
        self, first: x509.KeyUsage, second: x509.KeyUsage, msg: Optional[str] = None
    ) -> None:
        """Type equality function for x509.KeyUsage."""
        diffs = []
        for usage in [
            "content_commitment",
            "crl_sign",
            "data_encipherment",
            "decipher_only",
            "digital_signature",
            "encipher_only",
            "key_agreement",
            "key_cert_sign",
            "key_encipherment",
        ]:
            try:
                first_val = getattr(first, usage)
            except ValueError:
                first_val = False
            try:
                second_val = getattr(second, usage)
            except ValueError:
                second_val = False

            if first_val != second_val:  # pragma: no cover  # would only be run in case of error
                diffs.append(f"  * {usage}: {first_val} -> {second_val}")

        if msg is None:
            msg = "KeyUsage extensions differ:"
        if diffs:  # pragma: no cover  # would only be run in case of error
            raise self.failureException(msg + "\n" + "\n".join(diffs))

    def assertTLSFeatureEqual(  # pylint: disable=invalid-name
        self, first: x509.TLSFeature, second: x509.TLSFeature, msg: Optional[str] = None
    ) -> None:
        """Type equality function for x509.TLSFeature."""
        self.assertEqual(set(first), set(second), msg=msg)

    @contextmanager
    def assertCreateCertSignals(  # pylint: disable=invalid-name
        self, pre: bool = True, post: bool = True
    ) -> Iterator[Tuple[mock.Mock, mock.Mock]]:
        """Context manager mocking both pre and post_create_ca signals."""
        with self.mockSignal(pre_sign_cert) as pre_sig, self.mockSignal(post_issue_cert) as post_sig:
            try:
                yield pre_sig, post_sig
            finally:
                self.assertTrue(pre_sig.called is pre)
                self.assertTrue(post_sig.called is post)

    def assertE2ECommandError(  # pylint: disable=invalid-name
        self, cmd: typing.Sequence[str], stdout: bytes = b"", stderr: bytes = b""
    ) -> None:
        """Assert that the passed command raises a CommandError with the given message."""
        actual_stdout = io.BytesIO()
        actual_stderr = io.BytesIO()

        stdout = b"CommandError: " + stdout + b"\n"

        with self.assertRaisesRegex(SystemExit, r"^1$"):
            self.cmd_e2e(cmd, stdout=actual_stdout, stderr=actual_stderr)
        self.assertEqual(stdout, actual_stdout.getvalue())
        self.assertEqual(stderr, actual_stderr.getvalue())

    def assertExtensions(  # pylint: disable=invalid-name
        self,
        cert: Union[X509CertMixin, x509.Certificate],
        extensions: Iterable[x509.Extension[x509.ExtensionType]],
        signer: Optional[CertificateAuthority] = None,
        expect_defaults: bool = True,
    ) -> None:
        """Assert that `cert` has the given extensions."""
        # temporary fast check
        for ext in extensions:
            self.assertIsInstance(ext, x509.Extension, ext)

        expected = {e.oid: e for e in extensions}

        if isinstance(cert, Certificate):
            pubkey = cert.pub.loaded.public_key()
            actual = cert.x509_extensions
            signer = cert.ca
        elif isinstance(cert, CertificateAuthority):
            pubkey = cert.pub.loaded.public_key()
            actual = cert.x509_extensions

            if cert.parent is None:  # root CA
                signer = cert
            else:  # intermediate CA
                signer = cert.parent
        elif isinstance(cert, x509.Certificate):  # cg cert
            pubkey = cert.public_key()
            actual = {e.oid: e for e in cert.extensions}
        else:  # pragma: no cover
            raise ValueError("cert must be Certificate(Authority) or x509.Certificate)")

        if expect_defaults is True:
            if isinstance(cert, Certificate):
                expected.setdefault(ExtensionOID.BASIC_CONSTRAINTS, self.basic_constraints(ca=False))
            if signer is not None:  # pragma: no branch
                expected.setdefault(
                    ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
                    signer.get_authority_key_identifier_extension(),
                )

                if isinstance(cert, Certificate) and signer.crl_url:
                    full_name = [parse_general_name(name) for name in signer.crl_url.split()]
                    expected.setdefault(
                        ExtensionOID.CRL_DISTRIBUTION_POINTS,
                        self.crl_distribution_points(full_name=full_name),
                    )

                if isinstance(cert, Certificate):
                    aia = signer.get_authority_information_access_extension()
                    if aia:  # pragma: no branch
                        expected.setdefault(aia.oid, aia)

            ski = x509.SubjectKeyIdentifier.from_public_key(pubkey)
            expected.setdefault(
                ExtensionOID.SUBJECT_KEY_IDENTIFIER,
                x509.Extension(oid=ExtensionOID.SUBJECT_KEY_IDENTIFIER, critical=False, value=ski),
            )

        # Diff output is bad for dicts, so we sort this based on dotted string to get better output
        actual_tuple = sorted(actual.items(), key=lambda t: t[0].dotted_string)
        expected_tuple = sorted(expected.items(), key=lambda t: t[0].dotted_string)
        self.assertEqual(actual_tuple, expected_tuple)

    @contextmanager
    def assertImproperlyConfigured(self, msg: str) -> Iterator[None]:  # pylint: disable=invalid-name
        """Shortcut for testing that the code raises ImproperlyConfigured with the given message."""
        with self.assertRaisesRegex(ImproperlyConfigured, msg):
            yield

    def assertIssuer(  # pylint: disable=invalid-name
        self, issuer: CertificateAuthority, cert: X509CertMixin
    ) -> None:
        """Assert that the issuer for `cert` matches the subject of `issuer`."""
        self.assertEqual(cert.issuer, issuer.subject)

    def assertMessages(  # pylint: disable=invalid-name
        self, response: "HttpResponse", expected: List[str]
    ) -> None:
        """Assert given Django messages for `response`."""
        messages = [str(m) for m in list(get_messages(response.wsgi_request))]
        self.assertEqual(messages, expected)

    def assertNotRevoked(self, cert: X509CertMixin) -> None:  # pylint: disable=invalid-name
        """Assert that the certificate is not revoked."""
        cert.refresh_from_db()
        self.assertFalse(cert.revoked)
        self.assertEqual(cert.revoked_reason, "")

    def assertPostCreateCa(  # pylint: disable=invalid-name
        self, post: mock.Mock, ca: CertificateAuthority
    ) -> None:
        """Assert that the post_create_ca signal was called."""
        post.assert_called_once_with(ca=ca, signal=post_create_ca, sender=CertificateAuthority)

    def assertPostIssueCert(self, post: mock.Mock, cert: Certificate) -> None:  # pylint: disable=invalid-name
        """Assert that the post_issue_cert signal was called."""
        post.assert_called_once_with(cert=cert, signal=post_issue_cert, sender=Certificate)

    def assertPostRevoke(self, post: mock.Mock, cert: Certificate) -> None:  # pylint: disable=invalid-name
        """Assert that the post_revoke_cert signal was called."""
        post.assert_called_once_with(cert=cert, signal=post_revoke_cert, sender=Certificate)

    def assertPrivateKey(  # pylint: disable=invalid-name
        self, ca: CertificateAuthority, password: Optional[Union[str, bytes]] = None
    ) -> None:
        """Assert some basic properties for a private key."""
        key = ca.key(password)
        self.assertIsNotNone(key)
        if not isinstance(  # pragma: no branch  # only used for RSA keys
            key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)
        ):
            self.assertTrue(key.key_size > 0)

    @contextmanager
    def assertRemovedIn125Warning(self, msg: str) -> Iterator[None]:  # pylint: disable=invalid-name
        """Assert that a RemovedInDjangoCA125Warning is thrown."""
        with self.assertWarnsRegex(RemovedInDjangoCA125Warning, msg):
            yield

    @contextmanager
    def assertRemovedIn126Warning(self, msg: str) -> Iterator[None]:  # pylint: disable=invalid-name
        """Assert that a RemovedInDjangoCA126Warning is thrown."""
        with self.assertWarnsRegex(RemovedInDjangoCA126Warning, msg):
            yield

    def assertRevoked(  # pylint: disable=invalid-name
        self, cert: X509CertMixin, reason: Optional[str] = None
    ) -> None:
        """Assert that the certificate is now revoked."""
        if isinstance(cert, CertificateAuthority):
            cert = CertificateAuthority.objects.get(serial=cert.serial)
        else:
            cert = Certificate.objects.get(serial=cert.serial)

        self.assertTrue(cert.revoked)

        if reason is None:
            self.assertEqual(cert.revoked_reason, ReasonFlags.unspecified.name)
        else:
            self.assertEqual(cert.revoked_reason, reason)

    def assertSignature(  # pylint: disable=invalid-name
        self, chain: Iterable[CertificateAuthority], cert: Union[Certificate, CertificateAuthority]
    ) -> None:
        """Assert that `cert` is properly signed by `chain`.

        .. seealso:: http://stackoverflow.com/questions/30700348
        """
        store = X509Store()

        # set the time of the OpenSSL context - freezegun doesn't work, because timestamp comes from OpenSSL
        now = datetime.utcnow()
        store.set_time(now)

        for elem in chain:
            ca = load_certificate(FILETYPE_PEM, elem.pub.pem.encode())
            store.add_cert(ca)

            # Verify that the CA itself is valid
            store_ctx = X509StoreContext(store, ca)
            self.assertIsNone(store_ctx.verify_certificate())  # type: ignore[func-returns-value]

        loaded_cert = load_certificate(FILETYPE_PEM, cert.pub.pem.encode())
        store_ctx = X509StoreContext(store, loaded_cert)
        self.assertIsNone(store_ctx.verify_certificate())  # type: ignore[func-returns-value]

    @contextmanager
    def assertSystemExit(self, code: int) -> Iterator[None]:  # pylint: disable=invalid-name
        """Assert that SystemExit is raised."""
        with self.assertRaisesRegex(SystemExit, rf"^{code}$") as excm:
            yield
        self.assertEqual(excm.exception.args, (code,))

    @contextmanager
    def assertValidationError(  # pylint: disable=invalid-name; unittest standard
        self, errors: Dict[str, List[str]]
    ) -> Iterator[None]:
        """Context manager to assert that a ValidationError is thrown."""
        with self.assertRaises(ValidationError) as cmex:
            yield
        self.assertEqual(cmex.exception.message_dict, errors)

    def authority_information_access(
        self,
        ca_issuers: Optional[Iterable[x509.GeneralName]] = None,
        ocsp: Optional[Iterable[x509.GeneralName]] = None,
        critical: bool = False,
    ) -> x509.Extension[x509.AuthorityInformationAccess]:
        """Shortcut for getting a AuthorityInformationAccess extension."""
        access_descriptions = []
        if ocsp is not None:  # pragma: no branch
            access_descriptions += [self.ocsp(name) for name in ocsp]
        if ca_issuers is not None:  # pragma: no branch
            access_descriptions += [self.ca_issuers(issuer) for issuer in ca_issuers]
        value = x509.AuthorityInformationAccess(access_descriptions)

        return x509.Extension(oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS, critical=critical, value=value)

    def basic_constraints(
        self, ca: bool = False, path_length: Optional[int] = None, critical: bool = True
    ) -> x509.Extension[x509.BasicConstraints]:
        """Shortcut for getting a BasicConstraints extension."""
        return x509.Extension(
            oid=ExtensionOID.BASIC_CONSTRAINTS,
            critical=critical,
            value=x509.BasicConstraints(ca=ca, path_length=path_length),
        )

    @property
    def ca_certs(self) -> Iterator[Tuple[str, Certificate]]:
        """Yield loaded certificates for each certificate authority."""
        for name, cert in self.certs.items():
            if name in [
                "root-cert",
                "child-cert",
                "ec-cert",
                "dsa-cert",
                "pwd-cert",
                "ed448-cert",
                "ed25519-cert",
            ]:
                yield name, cert

    def ca_issuers(self, issuer: x509.GeneralName) -> x509.AccessDescription:
        """Get a x509.AccessDescription for the given issuer."""
        return x509.AccessDescription(
            access_method=AuthorityInformationAccessOID.CA_ISSUERS, access_location=issuer
        )

    @typing.overload
    def cmd(self, *args: Any, stdout: io.BytesIO, stderr: io.BytesIO, **kwargs: Any) -> Tuple[bytes, bytes]:
        ...

    @typing.overload
    def cmd(
        self,
        *args: Any,
        stdout: io.BytesIO,
        stderr: Optional[io.StringIO] = None,
        **kwargs: Any,
    ) -> Tuple[bytes, str]:
        ...

    @typing.overload
    def cmd(
        self,
        *args: Any,
        stdout: Optional[io.StringIO] = None,
        stderr: io.BytesIO,
        **kwargs: Any,
    ) -> Tuple[str, bytes]:
        ...

    @typing.overload
    def cmd(
        self,
        *args: Any,
        stdout: Optional[io.StringIO] = None,
        stderr: Optional[io.StringIO] = None,
        **kwargs: Any,
    ) -> Tuple[str, str]:
        ...

    def cmd(
        self,
        *args: Any,
        stdout: Optional[Union[io.StringIO, io.BytesIO]] = None,
        stderr: Optional[Union[io.StringIO, io.BytesIO]] = None,
        **kwargs: Any,
    ) -> Tuple[Union[str, bytes], Union[str, bytes]]:
        """Call to a manage.py command using call_command."""
        if stdout is None:
            stdout = io.StringIO()
        if stderr is None:
            stderr = io.StringIO()
        stdin = kwargs.pop("stdin", io.StringIO())

        if isinstance(stdin, io.StringIO):
            with mock.patch("sys.stdin", stdin):
                call_command(*args, stdout=stdout, stderr=stderr, **kwargs)
        else:
            # mock https://docs.python.org/3/library/io.html#io.BufferedReader.read
            def _read_mock(size=None):  # type: ignore # pylint: disable=unused-argument
                return stdin

            with mock.patch("sys.stdin.buffer.read", side_effect=_read_mock):
                call_command(*args, stdout=stdout, stderr=stderr, **kwargs)

        return stdout.getvalue(), stderr.getvalue()

    @typing.overload
    def cmd_e2e(
        self,
        cmd: typing.Sequence[str],
        *,
        stdin: Optional[Union[io.StringIO, bytes]] = None,
        stdout: Optional[io.StringIO] = None,
        stderr: Optional[io.StringIO] = None,
    ) -> Tuple[str, str]:
        ...

    @typing.overload
    def cmd_e2e(
        self,
        cmd: typing.Sequence[str],
        *,
        stdin: Optional[Union[io.StringIO, bytes]] = None,
        stdout: io.BytesIO,
        stderr: Optional[io.StringIO] = None,
    ) -> Tuple[bytes, str]:
        ...

    @typing.overload
    def cmd_e2e(
        self,
        cmd: typing.Sequence[str],
        *,
        stdin: Optional[Union[io.StringIO, bytes]] = None,
        stdout: Optional[io.StringIO] = None,
        stderr: io.BytesIO,
    ) -> Tuple[str, bytes]:
        ...

    @typing.overload
    def cmd_e2e(
        self,
        cmd: typing.Sequence[str],
        *,
        stdin: Optional[Union[io.StringIO, bytes]] = None,
        stdout: io.BytesIO,
        stderr: io.BytesIO,
    ) -> Tuple[bytes, bytes]:
        ...

    def cmd_e2e(
        self,
        cmd: typing.Sequence[str],
        stdin: Optional[Union[io.StringIO, bytes]] = None,
        stdout: Optional[Union[io.BytesIO, io.StringIO]] = None,
        stderr: Optional[Union[io.BytesIO, io.StringIO]] = None,
    ) -> Tuple[Union[str, bytes], Union[str, bytes]]:
        """Call a management command the way manage.py does.

        Unlike call_command, this method also tests the argparse configuration of the called command.
        """
        stdout = stdout or io.StringIO()
        stderr = stderr or io.StringIO()
        if stdin is None:
            stdin = io.StringIO()

        if isinstance(stdin, io.StringIO):
            stdin_mock = mock.patch("sys.stdin", stdin)
        else:

            def _read_mock(size=None):  # type: ignore # pylint: disable=unused-argument
                return stdin

            # TYPE NOTE: mypy detects a different type, but important thing is it's a context manager
            stdin_mock = mock.patch(  # type: ignore[assignment]
                "sys.stdin.buffer.read", side_effect=_read_mock
            )

        # BinaryCommand commands (such as dump_crl) write to sys.stdout.buffer, but BytesIO does not have a
        # buffer attribute, so we manually add the attribute.
        if isinstance(stdout, io.BytesIO):
            stdout.buffer = stdout  # type: ignore[attr-defined]
        if isinstance(stderr, io.BytesIO):
            stderr.buffer = stderr  # type: ignore[attr-defined]

        with stdin_mock, mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
            util = ManagementUtility(["manage.py"] + list(cmd))
            util.execute()

        return stdout.getvalue(), stderr.getvalue()

    def cmd_help_text(self, cmd: str) -> str:
        """Get the help message for a given management command.

        Also asserts that stderr is empty and the command exists with status code 0.
        """
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
            util = ManagementUtility(["manage.py", cmd, "--help"])
            with self.assertSystemExit(0):
                util.execute()

        self.assertEqual(stderr.getvalue(), "")
        return stdout.getvalue()

    @classmethod
    def create_cert(
        cls,
        ca: CertificateAuthority,
        csr: x509.CertificateSigningRequest,
        subject: Optional[x509.Name],
        **kwargs: Any,
    ) -> Certificate:
        """Create a certificate with the given data."""
        cert = Certificate.objects.create_cert(ca, csr, subject=subject, **kwargs)
        cert.full_clean()
        return cert

    def crl_distribution_points(
        self,
        full_name: Optional[Iterable[x509.GeneralName]] = None,
        relative_name: Optional[x509.RelativeDistinguishedName] = None,
        reasons: Optional[typing.FrozenSet[x509.ReasonFlags]] = None,
        crl_issuer: Optional[Iterable[x509.GeneralName]] = None,
        critical: bool = False,
    ) -> x509.Extension[x509.CRLDistributionPoints]:
        """Shortcut for getting a CRLDistributionPoints extension."""
        dpoint = x509.DistributionPoint(
            full_name=full_name, relative_name=relative_name, reasons=reasons, crl_issuer=crl_issuer
        )
        return x509.Extension(
            oid=ExtensionOID.CRL_DISTRIBUTION_POINTS,
            critical=critical,
            value=x509.CRLDistributionPoints([dpoint]),
        )

    @property
    def crl_profiles(self) -> Dict[str, Dict[str, Any]]:
        """Return a list of CRL profiles."""
        profiles = copy.deepcopy(ca_settings.CA_CRL_PROFILES)
        for config in profiles.values():
            config.setdefault("OVERRIDES", {})

            for data in [d for d in certs.values() if d.get("type") == "ca"]:
                config["OVERRIDES"][data["serial"]] = {}
                if data.get("password"):
                    config["OVERRIDES"][data["serial"]]["password"] = data["password"]

        return profiles

    def extended_key_usage(
        self, *usages: x509.ObjectIdentifier, critical: bool = False
    ) -> x509.Extension[x509.ExtendedKeyUsage]:
        """Shortcut for getting an ExtendedKeyUsage extension."""
        return x509.Extension(
            oid=ExtensionOID.EXTENDED_KEY_USAGE, critical=critical, value=x509.ExtendedKeyUsage(usages)
        )

    def ext(
        self, value: x509.ExtensionType, critical: Optional[bool] = None
    ) -> x509.Extension[x509.ExtensionType]:
        """Shortcut to get a x509.Extension object from the given ExtensionType"""
        if critical is None:  # pragma: no branch
            critical = constants.EXTENSION_DEFAULT_CRITICAL[value.oid]
        return x509.Extension(oid=value.oid, critical=critical, value=value)

    def freshest_crl(
        self,
        full_name: Optional[Iterable[x509.GeneralName]] = None,
        relative_name: Optional[x509.RelativeDistinguishedName] = None,
        reasons: Optional[typing.FrozenSet[x509.ReasonFlags]] = None,
        crl_issuer: Optional[Iterable[x509.GeneralName]] = None,
        critical: bool = False,
    ) -> x509.Extension[x509.FreshestCRL]:
        """Shortcut for getting a CRLDistributionPoints extension."""
        dpoint = x509.DistributionPoint(
            full_name=full_name, relative_name=relative_name, reasons=reasons, crl_issuer=crl_issuer
        )
        return x509.Extension(
            oid=ExtensionOID.FRESHEST_CRL, critical=critical, value=x509.FreshestCRL([dpoint])
        )

    def get_idp(
        self,
        full_name: Optional[Iterable[x509.GeneralName]] = None,
        indirect_crl: bool = False,
        only_contains_attribute_certs: bool = False,
        only_contains_ca_certs: bool = False,
        only_contains_user_certs: bool = False,
        only_some_reasons: Optional[typing.FrozenSet[x509.ReasonFlags]] = None,
        relative_name: Optional[x509.RelativeDistinguishedName] = None,
    ) -> "x509.Extension[x509.IssuingDistributionPoint]":
        """Get an IssuingDistributionPoint extension."""
        return x509.Extension(
            oid=x509.oid.ExtensionOID.ISSUING_DISTRIBUTION_POINT,
            value=x509.IssuingDistributionPoint(
                full_name=full_name,
                indirect_crl=indirect_crl,
                only_contains_attribute_certs=only_contains_attribute_certs,
                only_contains_ca_certs=only_contains_ca_certs,
                only_contains_user_certs=only_contains_user_certs,
                only_some_reasons=only_some_reasons,
                relative_name=relative_name,
            ),
            critical=True,
        )

    def get_idp_full_name(self, ca: CertificateAuthority) -> Optional[List[x509.UniformResourceIdentifier]]:
        """Get the IDP full name for `ca`."""
        crl_url = [url.strip() for url in ca.crl_url.split()]
        return [uri(c) for c in crl_url] or None

    @property
    def hostname(self) -> str:
        """Get a hostname unique for the test case."""
        name = self.id().split(".", 2)[-1].lower()
        name = re.sub("[^a-z0-9.-]", "-", name)
        return f"{name}.example.com"

    def issuer_alternative_name(
        self, *names: x509.GeneralName, critical: bool = False
    ) -> x509.Extension[x509.IssuerAlternativeName]:
        """Shortcut for getting a IssuerAlternativeName extension."""
        return x509.Extension(
            oid=ExtensionOID.ISSUER_ALTERNATIVE_NAME,
            critical=critical,
            value=x509.IssuerAlternativeName(names),
        )

    def key_usage(self, **usages: bool) -> x509.Extension[x509.KeyUsage]:
        """Shortcut for getting a KeyUsage extension."""
        critical = usages.pop("critical", True)
        usages.setdefault("content_commitment", False)
        usages.setdefault("crl_sign", False)
        usages.setdefault("data_encipherment", False)
        usages.setdefault("decipher_only", False)
        usages.setdefault("digital_signature", False)
        usages.setdefault("encipher_only", False)
        usages.setdefault("key_agreement", False)
        usages.setdefault("key_cert_sign", False)
        usages.setdefault("key_encipherment", False)
        return x509.Extension(oid=ExtensionOID.KEY_USAGE, critical=critical, value=x509.KeyUsage(**usages))

    def name_constraints(
        self,
        permitted: Optional[Iterable[x509.GeneralName]] = None,
        excluded: Optional[Iterable[x509.GeneralName]] = None,
        critical: bool = False,
    ) -> x509.Extension[x509.NameConstraints]:
        """Shortcut for getting a NameConstraints extension."""
        return x509.Extension(
            oid=ExtensionOID.NAME_CONSTRAINTS,
            value=x509.NameConstraints(permitted_subtrees=permitted, excluded_subtrees=excluded),
            critical=critical,
        )

    def ocsp(self, ocsp: x509.GeneralName) -> x509.AccessDescription:
        """Get a x509.AccessDescription for the given issuer."""
        return x509.AccessDescription(access_method=AuthorityInformationAccessOID.OCSP, access_location=ocsp)

    def ocsp_no_check(self, critical: bool = False) -> x509.Extension[x509.OCSPNoCheck]:
        """Shortcut for getting a OCSPNoCheck extension."""
        return x509.Extension(oid=ExtensionOID.OCSP_NO_CHECK, critical=critical, value=x509.OCSPNoCheck())

    def precert_poison(self) -> x509.Extension[x509.PrecertPoison]:
        """Shortcut for getting a PrecertPoison extension."""
        return x509.Extension(oid=ExtensionOID.PRECERT_POISON, critical=True, value=x509.PrecertPoison())

    @property
    def subject(self) -> x509.Name:
        """Subject containing a common name that is unique for the test case."""
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.hostname)])

    def subject_alternative_name(
        self, *names: x509.GeneralName
    ) -> x509.Extension[x509.SubjectAlternativeName]:
        """Shortcut for getting a SubjectAlternativeName extension."""
        return x509.Extension(
            oid=ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
            critical=False,
            value=x509.SubjectAlternativeName(names),
        )

    def subject_key_identifier(self, cert: X509CertMixin) -> x509.Extension[x509.SubjectKeyIdentifier]:
        """Shortcut for getting a SubjectKeyIdentifier extension."""
        ski = x509.SubjectKeyIdentifier.from_public_key(cert.pub.loaded.public_key())
        return x509.Extension(oid=ExtensionOID.SUBJECT_KEY_IDENTIFIER, critical=False, value=ski)

    def tls_feature(
        self, *features: x509.TLSFeatureType, critical: bool = False
    ) -> x509.Extension[x509.TLSFeature]:
        """Shortcut for getting a TLSFeature extension."""
        return x509.Extension(
            oid=ExtensionOID.TLS_FEATURE, critical=critical, value=x509.TLSFeature(features)
        )

    @classmethod
    def expires(cls, days: int) -> datetime:
        """Get a timestamp `days` from now."""
        now = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        return now + timedelta(days + 1)

    @contextmanager
    def freeze_time(
        self, timestamp: Union[str, datetime]
    ) -> Iterator[Union[FrozenDateTimeFactory, StepTickTimeFactory]]:
        """Context manager to freeze time to a given timestamp.

        If `timestamp` is a str that is in the `timestamps` dict (e.g. "everything-valid"), use that
        timestamp.
        """
        if isinstance(timestamp, str):  # pragma: no branch
            timestamp = timestamps[timestamp]

        with freeze_time(timestamp) as frozen:
            yield frozen

    def get_cert_context(self, name: str) -> Dict[str, Any]:
        """Get a dictionary suitable for testing output based on the dictionary in basic.certs."""
        ctx: Dict[str, Any] = {}
        for key, value in sorted(certs[name].items()):
            # Handle cryptography extensions
            if key == "precert_poison":
                ctx["precert_poison"] = "* Precert Poison (critical):\n  Yes"
            elif isinstance(value, x509.Extension):
                if value.critical:
                    ctx[f"{key}_critical"] = " (critical)"
                else:
                    ctx[f"{key}_critical"] = ""

                ctx[f"{key}_text"] = textwrap.indent(extension_as_text(value.value), "  ")
            elif key == "precertificate_signed_certificate_timestamps_serialized":
                ctx["sct_critical"] = " (critical)" if value["critical"] else ""
                ctx["sct_values"] = []
                for val in value["value"]:
                    ctx["sct_values"].append(val)
            elif key == "precertificate_signed_certificate_timestamps":
                continue  # special extension b/c it cannot be created
            elif key == "path_length":
                ctx[key] = value
                ctx[f"{key}_text"] = "unlimited" if value is None else value
            else:
                ctx[key] = value

        if certs[name].get("parent"):
            parent = certs[certs[name]["parent"]]
            ctx["parent_name"] = parent["name"]
            ctx["parent_serial"] = parent["serial"]
            ctx["parent_serial_colons"] = add_colons(parent["serial"])

        if certs[name]["key_filename"] is not False:
            ctx["key_path"] = ca_storage.path(certs[name]["key_filename"])
        return ctx

    @classmethod
    def load_ca(
        cls,
        name: str,
        parsed: Optional[x509.Certificate] = None,
        enabled: bool = True,
        parent: Optional[CertificateAuthority] = None,
        **kwargs: Any,
    ) -> CertificateAuthority:
        """Load a CA from one of the preloaded files."""
        path = f"{name}.key"
        if parsed is None:
            parsed = certs[name]["pub"]["parsed"]
        if parent is None and certs[name].get("parent"):
            parent = CertificateAuthority.objects.get(name=certs[name]["parent"])

        # set some default values
        kwargs.setdefault("issuer_alt_name", certs[name].get("issuer_alternative_name", ""))
        kwargs.setdefault("crl_url", certs[name].get("crl_url", ""))
        kwargs.setdefault("ocsp_url", certs[name].get("ocsp_url", ""))
        kwargs.setdefault("issuer_url", certs[name].get("issuer_url", ""))

        ca = CertificateAuthority(name=name, private_key_path=path, enabled=enabled, parent=parent, **kwargs)
        ca.update_certificate(parsed)  # calculates serial etc
        ca.save()
        return ca

    @classmethod
    def load_named_cert(cls, name: str) -> Certificate:
        """Load a certificate with the given mame."""
        data = certs[name]
        ca = CertificateAuthority.objects.get(name=data["ca"])
        csr = data.get("csr", {}).get("parsed", "")
        profile = data.get("profile", "")

        cert = Certificate(ca=ca, csr=csr, profile=profile)
        cert.update_certificate(data["pub"]["parsed"])
        cert.save()
        cert.refresh_from_db()  # make sure we have lazy fields set
        return cert

    @contextmanager
    def mockSignal(self, signal: Signal) -> Iterator[mock.Mock]:  # pylint: disable=invalid-name
        """Context manager to attach a mock to the given signal."""

        # This function is only here to create an autospec. From the documentation:
        #
        #   Notice that the function takes a sender argument, along with wildcard keyword arguments
        #   (**kwargs); all signal handlers must take these arguments.
        #
        # https://docs.djangoproject.com/en/dev/topics/signals/#connecting-to-specific-signals
        def callback(sender: models.Model, **kwargs: Any) -> None:  # pragma: no cover
            # pylint: disable=unused-argument
            pass

        signal_mock = mock.create_autospec(callback, spec_set=True)
        signal.connect(signal_mock)
        try:
            yield signal_mock
        finally:
            signal.disconnect(signal_mock)

    @contextmanager
    def mute_celery(self, *calls: Any) -> Iterator[mock.MagicMock]:
        """Context manager to mock celery invocations.

        This context manager mocks ``celery.app.task.Task.apply_async``, the final function in celery before
        the message is passed to the handlers for the configured message transport (Redis, MQTT, ...). The
        context manager will validate the mock was called as specified in the passed *calls* arguments.

        The context manager will also assert that the args and kwargs passed to the tasks are JSON
        serializable.

        .. WARNING::

           The args and kwargs passed to the task are the first and second *argument* passed to the mocked
           ``apply_async``. You must consider this when passing calls. For example::

               with self.mute_celery((((), {}), {})):
                   cache_crls.delay()

               with self.mute_celery(((("foo"), {"key": "bar"}), {})):
                   cache_crls.delay("foo", key="bar")
        """
        with mock.patch("celery.app.task.Task.apply_async", spec_set=True) as mocked:
            yield mocked

        # Make sure that all invocations are JSON serializable
        for invocation in mocked.call_args_list:
            # invocation apply_async() has task args as arg[0] and arg[1]
            self.assertIsInstance(json.dumps(invocation.args[0]), str)
            self.assertIsInstance(json.dumps(invocation.args[1]), str)

        # Make sure that task was called the right number of times
        self.assertEqual(len(calls), len(mocked.call_args_list))
        for expected, actual in zip(calls, mocked.call_args_list):
            self.assertEqual(expected, actual, actual)

    @contextmanager
    def patch(self, *args: Any, **kwargs: Any) -> Iterator[mock.MagicMock]:
        """Shortcut to :py:func:`py:unittest.mock.patch`."""
        with mock.patch(*args, **kwargs) as mocked:
            yield mocked

    @contextmanager
    def patch_object(self, *args: Any, **kwargs: Any) -> Iterator[Any]:
        """Shortcut to :py:func:`py:unittest.mock.patch.object`."""
        with mock.patch.object(*args, **kwargs) as mocked:
            yield mocked

    def reverse(self, name: str, *args: Any, **kwargs: Any) -> str:
        """Shortcut to reverse a URI name."""
        return reverse(f"django_ca:{name}", args=args, kwargs=kwargs)

    @property
    def usable_cas(self) -> Iterator[Tuple[str, CertificateAuthority]]:
        """Yield loaded generated certificates."""
        for name, ca in self.cas.items():
            if certs[name]["key_filename"]:
                yield name, ca

    @property
    def usable_certs(self) -> Iterator[Tuple[str, Certificate]]:
        """Yield loaded generated certificates."""
        for name, cert in self.certs.items():
            if certs[name]["cat"] == "generated":
                yield name, cert


class AdminTestCaseMixin(TestCaseMixin, typing.Generic[DjangoCAModelTypeVar]):
    """Common mixin for testing admin classes for models."""

    model: Type[DjangoCAModelTypeVar]
    """Model must be configured for TestCase instances using this mixin."""

    media_css: Tuple[str, ...] = tuple()
    """List of custom CSS files loaded by the ModelAdmin.Media class."""

    view_name: str
    """The name of the view being tested."""

    # TODO: we should get rid of this, it's ugly
    obj: DjangoCAModelTypeVar

    def setUp(self) -> None:
        super().setUp()
        self.user = self.create_superuser()
        self.client.force_login(self.user)
        self.obj = self.model.objects.first()  # type: ignore[assignment] # TODO: get rid of this

    @property
    def add_url(self) -> str:
        """Shortcut for the "add" URL of the model under test."""
        return self.model.admin_add_url

    def assertBundle(  # pylint: disable=invalid-name
        self, cert: DjangoCAModelTypeVar, expected: Iterable[X509CertMixin], filename: str
    ) -> None:
        """Assert that the bundle for the given certificate matches the expected chain and filename."""
        url = self.get_url(cert)

        # Do not use bundle_as_pem to make sure that chain really has expected number of newlines everywhere
        expected_content = "\n".join([e.pub.pem.strip() for e in expected]) + "\n"

        response = self.client.get(url, {"format": "PEM"})
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(response["Content-Type"], "application/pkix-cert")
        self.assertEqual(response["Content-Disposition"], f"attachment; filename={filename}")
        self.assertEqual(response.content.decode("utf-8"), expected_content)

    def assertCSS(self, response: "HttpResponse", path: str) -> None:  # pylint: disable=invalid-name
        """Assert that the HTML from the given response includes the mentioned CSS."""
        if django.VERSION[:2] <= (4, 0):  # pragma: only django<4.1
            css = f'<link href="{static(path)}" type="text/css" media="all" rel="stylesheet" />'
        else:  # pragma: only django>=4.1
            css = f'<link href="{static(path)}" media="all" rel="stylesheet" />'
        self.assertInHTML(css, response.content.decode("utf-8"), 1)

    def assertChangeResponse(  # pylint: disable=invalid-name,unused-argument # obj is unused
        self, response: "HttpResponse", obj: DjangoCAModelTypeVar, status: int = HTTPStatus.OK
    ) -> None:
        """Assert that the passed response is a model change view."""
        self.assertEqual(response.status_code, status)
        templates = [t.name for t in response.templates]
        self.assertIn("admin/change_form.html", templates)
        self.assertIn("admin/base.html", templates)

        for css in self.media_css:
            self.assertCSS(response, css)

    def assertChangelistResponse(  # pylint: disable=invalid-name
        self, response: "HttpResponse", *objects: models.Model, status: int = HTTPStatus.OK
    ) -> None:
        """Assert that the passed response is a model changelist view."""
        self.assertEqual(response.status_code, status)
        self.assertCountEqual(response.context["cl"].result_list, objects)

        templates = [t.name for t in response.templates]
        self.assertIn("admin/base.html", templates)
        self.assertIn("admin/change_list.html", templates)

        for css in self.media_css:
            self.assertCSS(response, css)

    def assertRequiresLogin(  # pylint: disable=invalid-name
        self, response: "HttpResponse", **kwargs: Any
    ) -> None:
        """Assert that the given response is a redirect to the login page."""
        path = reverse("admin:login")
        qs = quote(response.wsgi_request.get_full_path())
        self.assertRedirects(response, f"{path}?next={qs}", **kwargs)

    def change_url(self, obj: Optional[DjangoCAModel] = None) -> str:
        """Shortcut for the change URL of the given instance."""
        obj = obj or self.obj
        return obj.admin_change_url

    @property
    def changelist_url(self) -> str:
        """Shortcut for the changelist URL of the model under test."""
        return self.model.admin_changelist_url

    def create_superuser(
        self, username: str = "admin", password: str = "admin", email: str = "user@example.com"
    ) -> User:
        """Shortcut to create a superuser."""
        return User.objects.create_superuser(username=username, password=password, email=email)

    @contextmanager
    def freeze_time(
        self, timestamp: Union[str, datetime]
    ) -> Iterator[Union[FrozenDateTimeFactory, StepTickTimeFactory]]:
        """Overridden to force a client login, otherwise the user session is expired."""
        with super().freeze_time(timestamp) as frozen:
            self.client.force_login(self.user)
            yield frozen

    def get_changelist_view(self, data: Optional[Dict[str, str]] = None) -> "HttpResponse":
        """Get the response to a changelist view for the given model."""
        return self.client.get(self.changelist_url, data)

    def get_change_view(
        self, obj: DjangoCAModelTypeVar, data: Optional[Dict[str, str]] = None
    ) -> "HttpResponse":
        """Get the response to a change view for the given model instance."""
        return self.client.get(self.change_url(obj), data)

    def get_objects(self) -> Iterable[DjangoCAModelTypeVar]:
        """Get list of objects for defined for this test."""
        return self.model.objects.all()

    def get_url(self, obj: DjangoCAModelTypeVar) -> str:
        """Get URL for the given object for this test case."""
        return reverse(f"admin:{self.view_name}", kwargs={"pk": obj.pk})


class StandardAdminViewTestCaseMixin(AdminTestCaseMixin[DjangoCAModelTypeVar]):
    """A mixin that adds tests for the standard Django admin views.

    TestCases using this mixin are expected to implement ``setUp`` to add some useful test model instances.
    """

    def get_changelists(
        self,
    ) -> Iterator[Tuple[Iterable[DjangoCAModel], Dict[str, str]]]:
        """Generate list of objects for possible changelist views.

        Should yield tuples of objects that should be displayed and a dict of query parameters.
        """
        yield self.model.objects.all(), {}

    def test_model_count(self) -> None:
        """Test that the implementing TestCase actually creates some instances."""
        self.assertGreater(self.model.objects.all().count(), 0)

    def test_changelist_view(self) -> None:
        """Test that the changelist view works."""
        for qs, data in self.get_changelists():
            self.assertChangelistResponse(self.get_changelist_view(data), *qs)

    def test_change_view(self) -> None:
        """Test that the change view works for all instances."""
        for obj in self.model.objects.all():
            self.assertChangeResponse(self.get_change_view(obj), obj)


class AcmeValuesMixin:
    """Mixin that sets a few static valid ACME values."""

    # ACME data present in all mixins
    ACME_THUMBPRINT_1 = "U-yUM27CQn9pClKlEITobHB38GJOJ9YbOxnw5KKqU-8"
    ACME_THUMBPRINT_2 = "s_glgc6Fem0CW7ZioXHBeuUQVHSO-viZ3xNR8TBebCo"
    ACME_PEM_1 = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvP5N/1KjBQniyyukn30E
tyHz6cIYPv5u5zZbHGfNvrmMl8qHMmddQSv581AAFa21zueS+W8jnRI5ISxER95J
tNad2XEDsFINNvYaSG8E54IHMNQijVLR4MJchkfMAa6g1gIsJB+ffEt4Ea3TMyGr
MifJG0EjmtjkjKFbr2zuPhRX3fIGjZTlkxgvb1AY2P4AxALwS/hG4bsxHHNxHt2Z
s9Bekv+55T5+ZqvhNz1/3yADRapEn6dxHRoUhnYebqNLSVoEefM+h5k7AS48waJS
lKC17RMZfUgGE/5iMNeg9qtmgWgZOIgWDyPEpiXZEDDKeoifzwn1LO59W8c4W6L7
XwIDAQAB
-----END PUBLIC KEY-----"""
    ACME_PEM_2 = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp8SCUVQqpTBRyryuu560
Q8cAi18Ac+iLjaSLL4gOaDEU9CpPi4l9yCGphnQFQ92YP+GWv+C6/JRp24852QbR
RzuUJqJPdDxD78yFXoxYCLPmwQMnToA7SE3SnZ/PW2GPFMbAICuRdd3PhMAWCODS
NewZPLBlG35brRlfFtUEc2oQARb2lhBkMXrpIWeuSNQtInAHtfTJNA51BzdrIT2t
MIfadw4ljk7cVbrSYemT6e59ATYxiMXalu5/4v22958voEBZ38TE8AXWiEtTQYwv
/Kj0P67yuzE94zNdT28pu+jJYr5nHusa2NCbvnYFkDwzigmwCxVt9kW3xj3gfpgc
VQIDAQAB
-----END PUBLIC KEY-----"""
    ACME_SLUG_1 = "Mr6FfdD68lzp"
    ACME_SLUG_2 = "DzW4PQ6L76PE"

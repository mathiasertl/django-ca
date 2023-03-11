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

"""This test module validates certificates using the openssl command line tool."""

import os
import shlex
import subprocess
import tempfile
from contextlib import contextmanager
from typing import Any, Iterable, Iterator, List, Optional, Tuple

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from django.test import TestCase
from django.urls import reverse

from django_ca.models import CertificateAuthority, X509CertMixin
from django_ca.tests.base import certs, override_tmpcadir, uri
from django_ca.tests.base.mixins import TestCaseMixin


class CRLValidationTestCase(TestCaseMixin, TestCase):
    """CRL validation tests."""

    def setUp(self) -> None:
        super().setUp()
        self.csr_pem = certs["root-cert"]["csr"]["pem"]  # just some CSR

    def assertFullName(  # pylint: disable=invalid-name
        self,
        crl: x509.CertificateRevocationList,
        expected: Optional[List[x509.GeneralName]] = None,
    ) -> None:
        """Assert that the full name of the CRL matches `expected`."""

        idp = crl.extensions.get_extension_for_class(x509.IssuingDistributionPoint).value
        self.assertEqual(idp.full_name, expected)

    def assertNoIssuingDistributionPoint(  # pylint: disable=invalid-name
        self, crl: x509.CertificateRevocationList
    ) -> None:
        """Assert that the given CRL has *no* IssuingDistributionPoint extension."""
        try:
            idp = crl.extensions.get_extension_for_class(x509.IssuingDistributionPoint)
            self.fail(f"CRL contains an IssuingDistributionPoint extension: {idp}")
        except x509.ExtensionNotFound:
            pass

    def assertScope(  # pylint: disable=invalid-name
        self,
        crl: x509.CertificateRevocationList,
        ca: bool = False,
        user: bool = False,
        attribute: bool = False,
    ) -> None:
        """Assert that the scope at `path` is `expected`."""
        idp = crl.extensions.get_extension_for_class(x509.IssuingDistributionPoint).value
        self.assertIs(idp.only_contains_ca_certs, ca, idp)
        self.assertIs(idp.only_contains_user_certs, user)
        self.assertIs(idp.only_contains_attribute_certs, attribute)

    def init_ca(self, name: str, **kwargs: Any) -> CertificateAuthority:
        """Create a CA."""
        self.cmd("init_ca", name, f"/CN={name}", **kwargs)
        return CertificateAuthority.objects.get(name=name)

    @contextmanager
    def crl(
        self, ca: CertificateAuthority, **kwargs: Any
    ) -> Iterator[Tuple[str, x509.CertificateRevocationList]]:
        """Dump CRL to a tmpdir, yield path to it."""
        kwargs["ca"] = ca
        with tempfile.TemporaryDirectory() as tempdir:
            path = os.path.join(tempdir, f"{ca.name}.{kwargs.get('scope')}.crl")
            self.cmd("dump_crl", path, **kwargs)

            with open(path, "rb") as stream:
                crl = x509.load_pem_x509_crl(stream.read())

            yield path, crl

    @contextmanager
    def dumped(self, *certificates: X509CertMixin) -> Iterator[List[str]]:
        """Dump certificates to a tempdir, yield list of paths."""
        with tempfile.TemporaryDirectory() as tempdir:
            paths = []
            for cert in certificates:
                path = os.path.join(tempdir, f"{cert.serial}.pem")
                paths.append(path)
                with open(path, "w", encoding="ascii") as stream:
                    stream.write(cert.pub.pem)

            yield paths

    @contextmanager
    def sign_cert(
        self, ca: CertificateAuthority, hostname: str = "example.com", **kwargs: Any
    ) -> Iterator[str]:
        """Create a signed certificate in a temporary directory."""
        stdin = self.csr_pem.encode()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])

        with tempfile.TemporaryDirectory() as tempdir:
            out_path = os.path.join(tempdir, f"{hostname}.pem")
            self.cmd("sign_cert", ca=ca, subject=subject, out=out_path, stdin=stdin, **kwargs)
            yield out_path

    def openssl(self, cmd: str, *args: str, code: int = 0, **kwargs: str) -> None:
        """Run openssl."""
        # pylint: disable=subprocess-run-check; we use an assertion
        exp_stdout = kwargs.pop("stdout", False)
        exp_stderr = kwargs.pop("stderr", False)
        cmd = cmd.format(*args, **kwargs)
        if kwargs.pop("verbose", False):
            print(f"openssl {cmd}")
        proc = subprocess.run(["openssl"] + shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout = proc.stdout.decode("utf-8")
        stderr = proc.stderr.decode("utf-8")
        self.assertEqual(proc.returncode, code, stderr)
        if isinstance(exp_stdout, str):
            self.assertRegex(stdout, exp_stdout)
        if isinstance(exp_stderr, str):
            self.assertRegex(stderr, exp_stderr)

    def verify(
        self,
        cmd: str,
        *args: str,
        untrusted: Optional[Iterable[str]] = None,
        crl: Optional[Iterable[str]] = None,
        code: int = 0,
        **kwargs: str,
    ) -> None:
        """Run openssl verify."""
        if untrusted:
            untrusted_args = " ".join(f"-untrusted {path}" for path in untrusted)
            cmd = f"{untrusted_args} {cmd}"
        if crl:
            crlfile_args = " ".join(f"-CRLfile {path}" for path in crl)
            cmd = f"{crlfile_args} {cmd}"

        self.openssl(f"verify {cmd}", *args, code=code, **kwargs)

    @override_tmpcadir()
    def test_root_ca(self) -> None:
        """Try validating a root CA."""
        name = "Root"
        ca = self.init_ca(name)

        # Very simple validation of the Root CRL
        with self.dumped(ca) as paths:
            self.verify("-CAfile {0} {0}", *paths)

        # Create a CRL too and include it
        with self.dumped(ca) as paths, self.crl(ca, scope="ca") as (crl_path, crl):
            self.verify("-CAfile {0} -crl_check_all {0}", *paths, crl=[crl_path])

        # Try again with no scope
        with self.dumped(ca) as paths, self.crl(ca) as (crl_path, crl):
            self.verify("-CAfile {0} -crl_check_all {0}", *paths, crl=[crl_path])

        # Try with cert scope (fails because of wrong scope
        with self.dumped(ca) as paths, self.crl(ca, scope="user") as (crl_path, crl), self.assertRaises(
            AssertionError
        ):
            self.verify("-CAfile {0} -crl_check_all {0}", *paths, crl=[crl_path])

    @override_tmpcadir(CA_DEFAULT_HOSTNAME="")
    def test_root_ca_cert(self) -> None:
        """Try validating a cert issued by the root CA."""
        name = "Root"
        ca = self.init_ca(name)

        with self.dumped(ca) as paths, self.sign_cert(ca) as cert:
            self.verify("-CAfile {0} {cert}", *paths, cert=cert)

            # Create a CRL too and include it
            with self.crl(ca, scope="user") as (crl_path, crl):
                self.assertScope(crl, user=True)
                self.verify("-CAfile {0} -crl_check {cert}", *paths, crl=[crl_path], cert=cert)

                # for crl_check_all, we also need the root CRL
                with self.crl(ca, scope="ca") as (crl2_path, crl2):
                    self.assertScope(crl2, ca=True)
                    self.verify(
                        "-CAfile {0} -crl_check_all {cert}", *paths, crl=[crl_path, crl2_path], cert=cert
                    )

            # Try a single CRL with a global scope
            with self.crl(ca, scope=None) as (crl_global_path, crl_global):
                self.assertNoIssuingDistributionPoint(crl_global)
                self.verify("-CAfile {0} -crl_check_all {cert}", *paths, crl=[crl_global_path], cert=cert)

    @override_tmpcadir(CA_DEFAULT_HOSTNAME="example.com")
    def test_ca_default_hostname(self) -> None:
        """Test that CA_DEFAULT_HOSTNAME does not lead to problems."""

        ca = self.init_ca("root")
        # Root CAs have no CRLDistributionPoints
        self.assertNotIn(ExtensionOID.CRL_DISTRIBUTION_POINTS, ca.x509_extensions)

        with self.dumped(ca) as paths, self.sign_cert(ca) as cert:
            with self.crl(ca) as (crl_path, crl):  # test global CRL
                self.assertNoIssuingDistributionPoint(crl)
                self.verify("-trusted {0} -crl_check {cert}", *paths, crl=[crl_path], cert=cert)
                self.verify("-trusted {0} -crl_check_all {cert}", *paths, crl=[crl_path], cert=cert)

            with self.crl(ca, scope="user") as (crl_path, crl):  # test user-only CRL
                self.assertScope(crl, user=True)
                self.verify("-trusted {0} -crl_check {cert}", *paths, crl=[crl_path], cert=cert)
                # crl_check_all does not work,  b/c the scope  is only "user"
                self.verify(
                    "-trusted {0} -crl_check_all {cert}",
                    *paths,
                    crl=[crl_path],
                    cert=cert,
                    code=2,
                    stderr="[dD]ifferent CRL scope",
                )

    @override_tmpcadir(CA_DEFAULT_HOSTNAME="")
    def test_intermediate_ca(self) -> None:
        """Validate intermediate CA and its certs."""
        root = self.init_ca("Root", path_length=2)
        child = self.init_ca("Child", parent=root, path_length=1)
        grandchild = self.init_ca("Grandchild", parent=child)

        #  Verify the state of the CAs themselves.
        self.assertNotIn(ExtensionOID.CRL_DISTRIBUTION_POINTS, root.x509_extensions)
        self.assertNotIn(ExtensionOID.CRL_DISTRIBUTION_POINTS, child.x509_extensions)
        self.assertNotIn(ExtensionOID.CRL_DISTRIBUTION_POINTS, grandchild.x509_extensions)

        with self.dumped(root, child, grandchild) as paths:
            untrusted = paths[1:]
            # Simple validation of the CAs
            self.verify("-CAfile {0} {1}", *paths)
            self.verify("-CAfile {0} -untrusted {1} {2}", *paths)

            # Try validation with CRLs
            with self.crl(root, scope="ca") as (crl1_path, crl1), self.crl(child, scope="ca") as (
                crl2_path,
                crl2,
            ):
                self.verify(
                    "-CAfile {0} -untrusted {1} -crl_check_all {2}", *paths, crl=[crl1_path, crl2_path]
                )

                with self.sign_cert(child) as cert, self.crl(child, scope="user") as (crl3_path, crl3):
                    self.verify("-CAfile {0} -untrusted {1} {cert}", *paths, cert=cert)
                    self.verify(
                        "-CAfile {0} -untrusted {1} {cert}", *paths, cert=cert, crl=[crl1_path, crl3_path]
                    )

                with self.sign_cert(grandchild) as cert, self.crl(child, scope="ca") as (
                    crl4_path,
                    crl4,
                ), self.crl(grandchild, scope="user") as (crl6_path, crl6):
                    self.verify("-CAfile {0} {cert}", *paths, untrusted=untrusted, cert=cert)
                    self.verify(
                        "-CAfile {0} -crl_check_all {cert}",
                        *paths,
                        untrusted=untrusted,
                        crl=[crl1_path, crl4_path, crl6_path],
                        cert=cert,
                    )

    @override_tmpcadir(CA_DEFAULT_HOSTNAME="example.com")
    def test_intermediate_ca_default_hostname(self) -> None:
        """Test that a changing CA_DEFAULT_HOSTNAME does not lead to problems."""

        root = self.init_ca("Root", path_length=2)
        child = self.init_ca("Child", parent=root, path_length=1)
        grandchild = self.init_ca("Grandchild", parent=child)

        child_ca_crl = reverse("django_ca:ca-crl", kwargs={"serial": root.serial})
        grandchild_ca_crl = reverse("django_ca:ca-crl", kwargs={"serial": child.serial})

        #  Verify the state of the CAs themselves.
        self.assertNotIn(ExtensionOID.CRL_DISTRIBUTION_POINTS, root.x509_extensions)
        self.assertEqual(
            child.x509_extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS],
            self.crl_distribution_points([uri(f"http://example.com{child_ca_crl}")]),
        )
        self.assertEqual(
            grandchild.x509_extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS],
            self.crl_distribution_points([uri(f"http://example.com{grandchild_ca_crl}")]),
        )

        with self.dumped(root, child, grandchild) as paths, self.crl(root, scope="ca") as (crl_path, crl):
            # Simple validation of the CAs
            self.verify("-trusted {0} {1}", *paths)
            self.verify("-trusted {0} -untrusted {1} {2}", *paths)

            with self.crl(child, scope="ca") as (crl2_path, crl2):
                self.assertFullName(crl, None)
                self.assertFullName(crl2, [uri(f"http://example.com{grandchild_ca_crl}")])
                self.verify(
                    "-trusted {0} -untrusted {1} -crl_check_all {2}", *paths, crl=[crl_path, crl2_path]
                )

            # Globally scoped CRLs do not validate, as the CRL will contain a different full name from the
            # CRLdp extension
            with self.crl(child) as (crl2_path, crl2):
                self.assertFullName(crl, None)
                # self.assertFullName(crl2, [uri(f"http://example.com{grandchild_ca_crl}")])
                self.verify(
                    "-trusted {0} -untrusted {1} -crl_check_all {2}",
                    *paths,
                    crl=[crl_path, crl2_path],
                    code=2,
                    stderr="[dD]ifferent CRL scope",
                )

            # Changing the default hostname setting should not change the validation result
            with self.settings(CA_DEFAULT_HOSTNAME="example.net"), self.crl(root, scope="ca") as (
                crl_path,
                crl,
            ), self.crl(child, scope="ca") as (
                crl2_path,
                crl2,
            ):
                # Known but not easily fixable issue: If CA_DEFAULT_HOSTNAME is changed, CRLs will get wrong
                # full name and validation fails.
                self.assertFullName(crl, None)
                # self.assertFullName(crl2, [uri(f"http://example.com{grandchild_ca_crl}")])
                self.verify(
                    "-trusted {0} -untrusted {1} -crl_check_all {2}",
                    *paths,
                    crl=[crl_path, crl2_path],
                    code=2,
                    stderr="[dD]ifferent CRL scope",
                )

            # Again, global CRLs do not validate
            with self.settings(CA_DEFAULT_HOSTNAME="example.net"), self.crl(root, scope="ca") as (
                crl_path,
                crl,
            ), self.crl(child) as (
                crl2_path,
                crl2,
            ):
                self.assertFullName(crl, None)
                self.verify(
                    "-trusted {0} -untrusted {1} -crl_check_all {2}",
                    *paths,
                    crl=[crl_path, crl2_path],
                    code=2,
                    stderr="[dD]ifferent CRL scope",
                )

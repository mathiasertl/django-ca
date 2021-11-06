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

"""This test module validates certificates using the openssl command line tool."""

import os
import shlex
import subprocess
import tempfile
import typing
from contextlib import contextmanager

from cryptography import x509

from django.test import TestCase

from ..models import CertificateAuthority
from ..models import X509CertMixin
from ..subject import Subject
from .base import certs
from .base import override_tmpcadir
from .base.mixins import TestCaseMixin


class CRLValidationTestCase(TestCaseMixin, TestCase):
    """CRL validation tests."""

    def setUp(self) -> None:
        super().setUp()
        self.csr_pem = certs["root-cert"]["csr"]["pem"]  # just some CSR

    def assertNoIssuingDistributionPoint(self, path: str):
        """Assert that the given CRL has *no* IssuingDistributionPoint extension."""
        with open(path, "rb") as stream:
            crl = x509.load_pem_x509_crl(stream.read())

        try:
            idp = crl.extensions.get_extension_for_class(x509.IssuingDistributionPoint)
            self.fail(f"CRL contains an IssuingDistributionPoint extension: {idp}")
        except x509.ExtensionNotFound:
            pass

    def assertScope(self, path: str, ca=False, user=False, attribute=False) -> None:
        """Assert that the scope at `path` is `expected`."""
        with open(path, "rb") as stream:
            crl = x509.load_pem_x509_crl(stream.read())
        print(crl)
        idp = crl.extensions.get_extension_for_class(x509.IssuingDistributionPoint)
        print(idp)

    def init_ca(self, name: str, **kwargs: typing.Any) -> CertificateAuthority:
        """Create a CA."""
        self.cmd("init_ca", name, f"/CN={name}", **kwargs)
        return CertificateAuthority.objects.get(name=name)

    @contextmanager
    def crl(self, ca: CertificateAuthority, **kwargs: typing.Any) -> typing.Iterator[str]:
        """Dump CRL to a tmpdir, yield path to it."""
        kwargs["ca"] = ca
        with tempfile.TemporaryDirectory() as tempdir:
            path = os.path.join(tempdir, f"{ca.name}.{kwargs.get('scope')}.crl")
            self.cmd("dump_crl", path, **kwargs)
            yield path

    @contextmanager
    def dumped(self, *certificates: X509CertMixin) -> typing.Iterator[typing.List[str]]:
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
        self, ca: CertificateAuthority, hostname: str = "example.com", **kwargs: typing.Any
    ) -> typing.Iterator[str]:
        """Create a signed certificate in a temporary directory."""
        stdin = self.csr_pem.encode()

        with tempfile.TemporaryDirectory() as tempdir:
            out_path = os.path.join(tempdir, f"{hostname}.pem")
            self.cmd(
                "sign_cert", ca=ca, subject=Subject([("CN", hostname)]), out=out_path, stdin=stdin, **kwargs
            )
            yield out_path

    def openssl(self, cmd: str, *args: str, **kwargs: str) -> None:
        """Run openssl."""
        # pylint: disable=subprocess-run-check; we use an assertion
        cmd = cmd.format(*args, **kwargs)
        # print("openssl %s" % cmd)
        proc = subprocess.run(
            ["openssl"] + shlex.split(cmd), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
        )
        self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8"))

    def verify(
        self,
        cmd: str,
        *args: str,
        untrusted: typing.Optional[typing.Iterable[str]] = None,
        crl: typing.Optional[typing.Iterable[str]] = None,
        **kwargs: str,
    ) -> None:
        """Run openssl verify."""
        if untrusted:
            untrusted_args = " ".join(f"-untrusted {path}" for path in untrusted)
            cmd = f"{untrusted_args} {cmd}"
        if crl:
            crlfile_args = " ".join(f"-CRLfile {path}" for path in crl)
            cmd = f"{crlfile_args} {cmd}"

        self.openssl(f"verify {cmd}", *args, **kwargs)

    @override_tmpcadir()
    def test_root_ca(self) -> None:
        """Try validating a root CA."""
        name = "Root"
        ca = self.init_ca(name)

        # Very simple validation of the Root CRL
        with self.dumped(ca) as paths:
            self.verify("-CAfile {0} {0}", *paths)

        # Create a CRL too and include it
        with self.dumped(ca) as paths, self.crl(ca, scope="ca") as crl:
            self.verify("-CAfile {0} -crl_check_all {0}", *paths, crl=[crl])

        # Try again with no scope
        with self.dumped(ca) as paths, self.crl(ca) as crl:
            self.verify("-CAfile {0} -crl_check_all {0}", *paths, crl=[crl])

        # Try with cert scope (fails because of wrong scope
        with self.dumped(ca) as paths, self.crl(ca, scope="user") as crl, self.assertRaises(AssertionError):
            self.verify("-CAfile {0} -crl_check_all {0}", *paths, crl=[crl])

    @override_tmpcadir()
    def test_root_ca_cert(self) -> None:
        """Try validating a cert issued by the root CA."""
        name = "Root"
        ca = self.init_ca(name)

        with self.dumped(ca) as paths, self.sign_cert(ca) as cert:
            self.verify("-CAfile {0} {cert}", *paths, cert=cert)

            # Create a CRL too and include it
            with self.crl(ca, scope="user") as crl:
                self.verify("-CAfile {0} -crl_check {cert}", *paths, crl=[crl], cert=cert)

                # for crl_check_all, we also need the root CRL
                with self.crl(ca, scope="ca") as crl2:
                    self.verify("-CAfile {0} -crl_check_all {cert}", *paths, crl=[crl, crl2], cert=cert)

            # Try a single CRL with a global scope
            with self.crl(ca, scope=None) as crl_global:
                self.assertNoIssuingDistributionPoint(crl_global)
                self.verify("-CAfile {0} -crl_check_all {cert}", *paths, crl=[crl_global], cert=cert)

    @override_tmpcadir()
    def test_intermediate_ca(self) -> None:
        """Validate intermediate CA and its certs."""
        root = self.init_ca("Root", pathlen=2)
        child = self.init_ca("Child", parent=root, pathlen=1)
        grandchild = self.init_ca("Grandchild", parent=child)

        with self.dumped(root, child, grandchild) as paths:
            untrusted = paths[1:]
            # Simple validation of the CAs
            self.verify("-CAfile {0} {1}", *paths)
            self.verify("-CAfile {0} -untrusted {1} {2}", *paths)

            # Try validation with CRLs
            with self.crl(root, scope="ca") as crl1, self.crl(child, scope="ca") as crl2:
                self.verify("-CAfile {0} -untrusted {1} -crl_check_all {2}", *paths, crl=[crl1, crl2])

                with self.sign_cert(child) as cert, self.crl(child, scope="user") as crl3:
                    self.verify("-CAfile {0} -untrusted {1} {cert}", *paths, cert=cert)
                    self.verify("-CAfile {0} -untrusted {1} {cert}", *paths, cert=cert, crl=[crl1, crl3])

                with self.sign_cert(grandchild) as cert, self.crl(child, scope="ca") as crl4, self.crl(
                    grandchild, scope="user"
                ) as crl6:

                    self.verify("-CAfile {0} {cert}", *paths, untrusted=untrusted, cert=cert)
                    self.verify(
                        "-CAfile {0} -crl_check_all {cert}",
                        *paths,
                        untrusted=untrusted,
                        crl=[crl1, crl4, crl6],
                        cert=cert,
                    )

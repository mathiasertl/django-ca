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

import os
import shlex
import subprocess
import tempfile
from contextlib import contextmanager
from io import StringIO

from ..models import CertificateAuthority
from ..subject import Subject
from .base import DjangoCATestCase
from .base import certs
from .base import override_tmpcadir


class CertificateAuthorityTests(DjangoCATestCase):
    def setUp(self):
        super().setUp()
        self.csr_pem = certs['root-cert']['csr']['pem']  # just some CSR

    def init_ca(self, name, **kwargs):
        self.cmd('init_ca', name, '/CN=%s' % name, **kwargs)
        return CertificateAuthority.objects.get(name=name)

    @contextmanager
    def crl(self, ca, **kwargs):
        kwargs['ca'] = ca
        with tempfile.TemporaryDirectory() as tempdir:
            path = os.path.join(tempdir, '%s.%s.crl' % (ca.name, kwargs.get('scope')))
            self.cmd('dump_crl', path, **kwargs)
            yield path

    @contextmanager
    def dumped(self, *certificates):
        with tempfile.TemporaryDirectory() as tempdir:
            paths = []
            for cert in certificates:
                path = os.path.join(tempdir, '%s.pem' % cert.serial)
                paths.append(path)
                with open(path, 'w') as stream:
                    stream.write(cert.pub)

            yield paths

    @contextmanager
    def sign_cert(self, ca, hostname='example.com', **kwargs):
        stdin = StringIO(self.csr_pem)

        with tempfile.TemporaryDirectory() as tempdir:
            out_path = os.path.join(tempdir, '%s.pem' % hostname)
            self.cmd('sign_cert', ca=ca, subject=Subject([('CN', hostname)]),
                     out=out_path, stdin=stdin, **kwargs)
            yield out_path

    def openssl(self, cmd, *args, **kwargs):
        cmd = cmd.format(*args, **kwargs)
        #print('openssl %s' % cmd)
        p = subprocess.run(['openssl'] + shlex.split(cmd), text=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.assertEqual(p.returncode, 0, p.stderr)

    def verify(self, cmd, *args, **kwargs):
        if 'untrusted' in kwargs:
            cmd = '%s %s' % (' '.join('-untrusted %s' % path for path in kwargs.pop('untrusted')), cmd)
        if 'crl' in kwargs:
            cmd = '%s %s' % (' '.join('-CRLfile %s' % path for path in kwargs.pop('crl')), cmd)

        return self.openssl('verify %s' % cmd, *args, **kwargs)

    @override_tmpcadir()
    def test_root_ca(self):
        # Try validating a root CA
        name = 'Root'
        ca = self.init_ca(name)

        # Very simple validation of the Root CRL
        with self.dumped(ca) as paths:
            self.verify('-CAfile {0} {0}', *paths)

        # Create a CRL too and include it
        with self.dumped(ca) as paths, self.crl(ca, scope='ca') as crl:
            self.verify('-CAfile {0} -crl_check_all {0}', *paths, crl=[crl])

        # Try again with no scope
        with self.dumped(ca) as paths, self.crl(ca) as crl:
            self.verify('-CAfile {0} -crl_check_all {0}', *paths, crl=[crl])

        # Try with cert scope (fails because of wrong scope
        with self.dumped(ca) as paths, self.crl(ca, scope='user') as crl, \
                self.assertRaises(AssertionError):
            self.verify('-CAfile {0} -crl_check_all {0}', *paths, crl=[crl])

    @override_tmpcadir()
    def test_root_ca_cert(self):
        # Try validating a cert issued by the root CA
        name = 'Root'
        ca = self.init_ca(name)

        with self.dumped(ca) as paths, self.sign_cert(ca) as cert:
            self.verify('-CAfile {0} {cert}', *paths, cert=cert)

            # Create a CRL too and include it
            with self.crl(ca, scope='user') as crl:
                self.verify('-CAfile {0} -crl_check {cert}', *paths, crl=[crl], cert=cert)

                # for crl_check_all, we also need the root CRL
                with self.crl(ca, scope='ca') as crl2:
                    self.verify('-CAfile {0} -crl_check_all {cert}', *paths, crl=[crl, crl2], cert=cert)

    @override_tmpcadir()
    def test_intermediate_ca(self):
        # validate intermediate CA and its certs
        root = self.init_ca('Root', pathlen=2)
        child = self.init_ca('Child', parent=root, pathlen=1)
        grandchild = self.init_ca('Grandchild', parent=child)

        with self.dumped(root, child, grandchild) as paths:
            untrusted = paths[1:]
            # Simple validation of the CAs
            self.verify('-CAfile {0} {1}', *paths)
            self.verify('-CAfile {0} -untrusted {1} {2}', *paths)

            # Try validation with CRLs
            with self.crl(root, scope='ca') as crl1, self.crl(child, scope='ca') as crl2:
                self.verify('-CAfile {0} -untrusted {1} -crl_check_all {2}',
                            *paths, crl=[crl1, crl2])

                with self.sign_cert(child) as cert, self.crl(child, scope='user') as crl3:
                    self.verify('-CAfile {0} -untrusted {1} {cert}', *paths, cert=cert)
                    self.verify('-CAfile {0} -untrusted {1} {cert}', *paths, cert=cert, crl=[crl1, crl3])

                with self.sign_cert(grandchild) as cert, self.crl(child, scope='ca') as crl4, \
                        self.crl(grandchild, scope='user') as crl6:

                    self.verify('-CAfile {0} {cert}', *paths, untrusted=untrusted, cert=cert)
                    self.verify('-CAfile {0} -crl_check_all {cert}',
                                *paths, untrusted=untrusted, crl=[crl1, crl4, crl6], cert=cert)

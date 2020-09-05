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
        self.cmd('init_ca', name, '/CN=%s' % name)
        return CertificateAuthority.objects.get(name=name)

    @contextmanager
    def dump_crl(self, ca, **kwargs):
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
        subprocess.run(['openssl'] + shlex.split(cmd), check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)

    @override_tmpcadir()
    def test_root_ca(self):
        # Try validating a root CA
        name = 'Root'
        ca = self.init_ca(name)

        # Very simple validation of the Root CRL
        with self.dumped(ca) as paths:
            self.openssl('verify -CAfile {0} {0}', *paths)

        # Create a CRL too and include it
        with self.dumped(ca) as paths, self.dump_crl(ca, scope='ca') as crl:
            self.openssl('verify -CAfile {0} -CRLfile {crl} -crl_check_all {0}', *paths, crl=crl)

        # Try again with no scope
        with self.dumped(ca) as paths, self.dump_crl(ca) as crl:
            self.openssl('verify -CAfile {0} -CRLfile {crl} -crl_check_all {0}', *paths, crl=crl)

        # Try with cert scope (fails because of wrong scope
        with self.dumped(ca) as paths, self.dump_crl(ca, scope='user') as crl, \
                self.assertRaises(subprocess.CalledProcessError):
            self.openssl('verify -CAfile {0} -CRLfile {crl} -crl_check_all {0}', *paths, crl=crl)

    @override_tmpcadir()
    def test_root_ca_cert(self):
        # Try validating a cert issued by the root CA
        name = 'Root'
        ca = self.init_ca(name)

        with self.dumped(ca) as paths, self.sign_cert(ca) as cert:
            self.openssl('verify -CAfile {0} {cert}', *paths, cert=cert)

            # Create a CRL too and include it
            with self.dump_crl(ca, scope='user') as crl:
                self.openssl('verify -CAfile {0} -CRLfile {crl} -crl_check {cert}', *paths,
                             crl=crl, cert=cert)

                # for crl_check_all, we also need the root CRL
                with self.dump_crl(ca, scope='ca') as crl2:
                    self.openssl('verify -CAfile {0} -CRLfile {crl} -CRLfile {crl2} -crl_check_all {cert}',
                                 *paths, crl=crl, crl2=crl2, cert=cert)

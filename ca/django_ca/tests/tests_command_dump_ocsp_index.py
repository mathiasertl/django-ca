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

# pylint: disable=missing-function-docstring,missing-module-docstring; module is deprecated anyway

import os
import shutil
import tempfile
from contextlib import contextmanager
from datetime import datetime
from datetime import timedelta

from freezegun import freeze_time

from ..constants import ReasonFlags
from ..deprecation import RemovedInDjangoCA120Warning
from .base import DjangoCAWithCertTestCase
from .base import certs
from .base import timestamps

BASIC = """V\t{child-cert[ocsp-expires]}\t\t{child-cert[ocsp-serial]}\tunknown\t{child-cert[subject]}
V\t{profile-client[ocsp-expires]}\t\t{profile-client[ocsp-serial]}\tunknown\t{profile-client[subject]}
V\t{profile-enduser[ocsp-expires]}\t\t{profile-enduser[ocsp-serial]}\tunknown\t{profile-enduser[subject]}
V\t{profile-ocsp[ocsp-expires]}\t\t{profile-ocsp[ocsp-serial]}\tunknown\t{profile-ocsp[subject]}
V\t{profile-server[ocsp-expires]}\t\t{profile-server[ocsp-serial]}\tunknown\t{profile-server[subject]}
V\t{profile-webserver[ocsp-expires]}\t\t{profile-webserver[ocsp-serial]}\tunknown\t{profile-webserver[subject]}
V\t{no-extensions[ocsp-expires]}\t\t{no-extensions[ocsp-serial]}\tunknown\t{no-extensions[subject]}
V\t{all-extensions[ocsp-expires]}\t\t{all-extensions[ocsp-serial]}\tunknown\t{all-extensions[subject]}
V\t{alt-extensions[ocsp-expires]}\t\t{alt-extensions[ocsp-serial]}\tunknown\t{alt-extensions[subject]}
"""

CA_CERTS = "V\t{child-cert[ocsp-expires]}\t\t{child-cert[ocsp-serial]}\tunknown\t{child-cert[subject]}\n"
PROFILE_CERTS = """V\t{child-cert[ocsp-expires]}\t\t{child-cert[ocsp-serial]}\tunknown\t{child-cert[subject]}
V\t{profile-client[ocsp-expires]}\t\t{profile-client[ocsp-serial]}\tunknown\t{profile-client[subject]}
V\t{profile-enduser[ocsp-expires]}\t\t{profile-enduser[ocsp-serial]}\tunknown\t{profile-enduser[subject]}
V\t{profile-ocsp[ocsp-expires]}\t\t{profile-ocsp[ocsp-serial]}\tunknown\t{profile-ocsp[subject]}
V\t{profile-server[ocsp-expires]}\t\t{profile-server[ocsp-serial]}\tunknown\t{profile-server[subject]}
V\t{profile-webserver[ocsp-expires]}\t\t{profile-webserver[ocsp-serial]}\tunknown\t{profile-webserver[subject]}
"""

CA_CERTS_EXPIRED = """E\t{child-cert[ocsp-expires]}\t\t{child-cert[ocsp-serial]}\tunknown\t{child-cert[subject]}
V\t{profile-client[ocsp-expires]}\t\t{profile-client[ocsp-serial]}\tunknown\t{profile-client[subject]}
V\t{profile-enduser[ocsp-expires]}\t\t{profile-enduser[ocsp-serial]}\tunknown\t{profile-enduser[subject]}
V\t{profile-ocsp[ocsp-expires]}\t\t{profile-ocsp[ocsp-serial]}\tunknown\t{profile-ocsp[subject]}
V\t{profile-server[ocsp-expires]}\t\t{profile-server[ocsp-serial]}\tunknown\t{profile-server[subject]}
V\t{profile-webserver[ocsp-expires]}\t\t{profile-webserver[ocsp-serial]}\tunknown\t{profile-webserver[subject]}
V\t{no-extensions[ocsp-expires]}\t\t{no-extensions[ocsp-serial]}\tunknown\t{no-extensions[subject]}
V\t{all-extensions[ocsp-expires]}\t\t{all-extensions[ocsp-serial]}\tunknown\t{all-extensions[subject]}
V\t{alt-extensions[ocsp-expires]}\t\t{alt-extensions[ocsp-serial]}\tunknown\t{alt-extensions[subject]}
"""
CA_CERTS_GONE = """V\t{profile-client[ocsp-expires]}\t\t{profile-client[ocsp-serial]}\tunknown\t{profile-client[subject]}
V\t{profile-enduser[ocsp-expires]}\t\t{profile-enduser[ocsp-serial]}\tunknown\t{profile-enduser[subject]}
V\t{profile-ocsp[ocsp-expires]}\t\t{profile-ocsp[ocsp-serial]}\tunknown\t{profile-ocsp[subject]}
V\t{profile-server[ocsp-expires]}\t\t{profile-server[ocsp-serial]}\tunknown\t{profile-server[subject]}
V\t{profile-webserver[ocsp-expires]}\t\t{profile-webserver[ocsp-serial]}\tunknown\t{profile-webserver[subject]}
V\t{no-extensions[ocsp-expires]}\t\t{no-extensions[ocsp-serial]}\tunknown\t{no-extensions[subject]}
V\t{all-extensions[ocsp-expires]}\t\t{all-extensions[ocsp-serial]}\tunknown\t{all-extensions[subject]}
V\t{alt-extensions[ocsp-expires]}\t\t{alt-extensions[ocsp-serial]}\tunknown\t{alt-extensions[subject]}
"""
PROFILE_CERTS_EXPIRED = """E\t{profile-client[ocsp-expires]}\t\t{profile-client[ocsp-serial]}\tunknown\t{profile-client[subject]}
E\t{profile-enduser[ocsp-expires]}\t\t{profile-enduser[ocsp-serial]}\tunknown\t{profile-enduser[subject]}
E\t{profile-ocsp[ocsp-expires]}\t\t{profile-ocsp[ocsp-serial]}\tunknown\t{profile-ocsp[subject]}
E\t{profile-server[ocsp-expires]}\t\t{profile-server[ocsp-serial]}\tunknown\t{profile-server[subject]}
E\t{profile-webserver[ocsp-expires]}\t\t{profile-webserver[ocsp-serial]}\tunknown\t{profile-webserver[subject]}
V\t{no-extensions[ocsp-expires]}\t\t{no-extensions[ocsp-serial]}\tunknown\t{no-extensions[subject]}
V\t{all-extensions[ocsp-expires]}\t\t{all-extensions[ocsp-serial]}\tunknown\t{all-extensions[subject]}
V\t{alt-extensions[ocsp-expires]}\t\t{alt-extensions[ocsp-serial]}\tunknown\t{alt-extensions[subject]}
"""
PROFILE_CERTS_GONE = """V\t{no-extensions[ocsp-expires]}\t\t{no-extensions[ocsp-serial]}\tunknown\t{no-extensions[subject]}
V\t{all-extensions[ocsp-expires]}\t\t{all-extensions[ocsp-serial]}\tunknown\t{all-extensions[subject]}
V\t{alt-extensions[ocsp-expires]}\t\t{alt-extensions[ocsp-serial]}\tunknown\t{alt-extensions[subject]}
"""

ALL_EXPIRED = """E\t{child-cert[ocsp-expires]}\t\t{child-cert[ocsp-serial]}\tunknown\t{child-cert[subject]}
E\t{profile-client[ocsp-expires]}\t\t{profile-client[ocsp-serial]}\tunknown\t{profile-client[subject]}
E\t{profile-server[ocsp-expires]}\t\t{profile-server[ocsp-serial]}\tunknown\t{profile-server[subject]}
E\t{profile-webserver[ocsp-expires]}\t\t{profile-webserver[ocsp-serial]}\tunknown\t{profile-webserver[subject]}
E\t{profile-enduser[ocsp-expires]}\t\t{profile-enduser[ocsp-serial]}\tunknown\t{profile-enduser[subject]}
E\t{profile-ocsp[ocsp-expires]}\t\t{profile-ocsp[ocsp-serial]}\tunknown\t{profile-ocsp[subject]}
E\t{no-extensions[ocsp-expires]}\t\t{no-extensions[ocsp-serial]}\tunknown\t{no-extensions[subject]}
E\t{all-extensions[ocsp-expires]}\t\t{all-extensions[ocsp-serial]}\tunknown\t{all-extensions[subject]}
"""

ECC_CA = "V\t{ecc-cert[ocsp-expires]}\t\t{ecc-cert[ocsp-serial]}\tunknown\t{ecc-cert[subject]}\n"

REVOKED_FIRST = (
    "R\t{ecc-cert[ocsp-expires]}\t{revoked}\t{ecc-cert[ocsp-serial]}\tunknown\t{ecc-cert[subject]}\n"  # NOQA
)
REVOKED_SECOND = "R\t{ecc-cert[ocsp-expires]}\t{revoked},key_compromise\t{ecc-cert[ocsp-serial]}\tunknown\t{ecc-cert[subject]}\n"  # NOQA


class OCSPIndexTestCase(DjangoCAWithCertTestCase):
    """Test the ``dump_ocsp_index`` management command."""

    timeformat = "%y%m%d%H%M%SZ"

    @contextmanager
    def assertDeprecation(self):  # pylint: disable=invalid-name; unittest standard
        """Context manager to assert the deprecation message."""
        with self.assertWarnsRegex(
            RemovedInDjangoCA120Warning,
            r"^Creating an OCSP index is deprecated and will be removed in 1\.20\.0\.$",
        ) as warn_cm:
            yield warn_cm

    def assertIndex(self, ca=None, expected="", **context):  # pylint: disable=invalid-name; unittest standard
        if ca is None:
            ca = self.cas["child"]

        context.update(certs)
        with self.assertDeprecation():
            stdout, stderr = self.cmd("dump_ocsp_index", ca=ca)
        self.assertEqual(stdout, expected.format(**context))
        self.assertEqual(stderr, "")

    @freeze_time(timestamps["ca_certs_valid"])
    def test_ca_certs_valid(self):
        self.assertIndex(expected=CA_CERTS)

    @freeze_time(timestamps["profile_certs_valid"])
    def test_profile_certs_valid(self):
        self.assertIndex(expected=PROFILE_CERTS)

    @freeze_time(timestamps["everything_valid"])
    def test_all_certs_valid(self):
        self.assertIndex(expected=BASIC)

    @freeze_time(timestamps["everything_expired"])
    def test_all_expired(self):
        # All certificates are expired by now, so no certs here
        self.assertIndex()

    @freeze_time(timestamps["before_everything"])
    def test_before_everything(self):
        # Certs are not yet valid, so we get no certs
        self.assertIndex()

    def test_ca_certs_expired(self):
        # CA certs are the first to expire, since they just expired an hour ago, they still show up in index
        with freeze_time(timestamps["ca_certs_expired"]) as frozen_time:
            self.assertIndex(expected=CA_CERTS_EXPIRED)

            # a day later, they're gone
            frozen_time.tick(timedelta(days=1))
            self.assertIndex(expected=CA_CERTS_GONE)

    def test_profile_certs_expired(self):
        # CA certs are the first to expire, since they just expired an hour ago, they still show up in index
        with freeze_time(timestamps["profile_certs_expired"]) as frozen_time:
            self.assertIndex(expected=PROFILE_CERTS_EXPIRED)

            # a day later, they're gone
            frozen_time.tick(timedelta(days=1))
            self.assertIndex(expected=PROFILE_CERTS_GONE)

    @freeze_time(timestamps["everything_valid"])
    def test_ecc_ca(self):
        # test another CA
        self.assertIndex(ca=self.cas["ecc"], expected=ECC_CA)

    @freeze_time(timestamps["everything_valid"])
    def test_file(self):
        tmpdir = tempfile.mkdtemp()

        try:
            path = os.path.join(tmpdir, "ocsp-index.txt")

            with self.assertDeprecation():
                stdout, stderr = self.cmd("dump_ocsp_index", path, ca=self.cas["child"])
            self.assertEqual(stdout, "")
            self.assertEqual(stderr, "")

            with open(path) as stream:
                data = stream.read()
            self.assertEqual(data, BASIC.format(**certs))
        finally:
            shutil.rmtree(tmpdir)

    def test_revoked(self):
        with freeze_time(timestamps["everything_valid"]) as frozen_timestamp:
            revoked_timestamp = datetime.utcnow().strftime(self.timeformat)
            cert = self.certs["ecc-cert"]
            cert.revoke()

            self.assertIndex(expected=REVOKED_FIRST, ca=self.cas["ecc"], revoked=revoked_timestamp)

            frozen_timestamp.tick(timedelta(seconds=3600))

            revoked_timestamp = datetime.utcnow().strftime(self.timeformat)
            cert.revoke(ReasonFlags.key_compromise)
            self.assertIndex(expected=REVOKED_SECOND, ca=self.cas["ecc"], revoked=revoked_timestamp)

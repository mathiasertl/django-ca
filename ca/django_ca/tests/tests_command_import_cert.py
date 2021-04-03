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

"""Test the import_cert  management command."""

import os

from django.conf import settings

from freezegun import freeze_time

from ..models import Certificate
from .base import DjangoCAWithCATestCase
from .base import certs
from .base import override_tmpcadir
from .base import timestamps


@freeze_time(timestamps["everything_valid"])
class ImportCertTest(DjangoCAWithCATestCase):
    """Main test class for this command."""

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_basic(self) -> None:
        """Import a standard certificate."""
        pem_path = os.path.join(settings.FIXTURES_DIR, certs["root-cert"]["pub_filename"])
        out, err = self.cmd("import_cert", pem_path, ca=self.cas["root"])

        self.assertEqual(out, "")
        self.assertEqual(err, "")

        cert = Certificate.objects.get(serial=certs["root-cert"]["serial"])
        self.assertSignature([self.cas["root"]], cert)
        self.assertEqual(cert.ca, self.cas["root"])
        cert.full_clean()  # assert e.g. max_length in serials
        self.assertBasic(cert.x509_cert, algo=certs["root-cert"]["algorithm"])

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_der(self) -> None:
        """Import a DER certificate."""
        pem_path = os.path.join(settings.FIXTURES_DIR, certs["root-cert"]["pub_der_filename"])
        out, err = self.cmd("import_cert", pem_path, ca=self.cas["root"])

        self.assertEqual(out, "")
        self.assertEqual(err, "")

        cert = Certificate.objects.get(serial=certs["root-cert"]["serial"])
        self.assertSignature([self.cas["root"]], cert)
        self.assertEqual(cert.ca, self.cas["root"])
        cert.full_clean()  # assert e.g. max_length in serials
        self.assertBasic(cert.x509_cert, algo=certs["root-cert"]["algorithm"])

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_bogus(self) -> None:
        """Try to import bogus data."""
        with self.assertCommandError(r"^Unable to load public key\.$"):
            self.cmd("import_cert", __file__, ca=self.cas["root"])
        self.assertEqual(Certificate.objects.count(), 0)

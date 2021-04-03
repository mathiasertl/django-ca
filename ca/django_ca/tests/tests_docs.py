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

"""Test some sphinx documents."""

import doctest

from .base import DjangoCATestCase
from .base import certs
from .base import override_settings
from .base import override_tmpcadir

BASE = "../../../docs/source"


@override_settings(CA_MIN_KEY_SIZE=1024, CA_DEFAULT_KEY_SIZE=1024)
class DocumentationTestCase(DjangoCATestCase):
    """Main testcase class."""

    def setUp(self) -> None:
        super().setUp()
        self.ca = self.load_ca(name=certs["root"]["name"], parsed=certs["root"]["pub"]["parsed"])
        self.cert = self.load_cert(
            self.ca, parsed=certs["root-cert"]["pub"]["parsed"], csr=certs["root-cert"]["csr"]["pem"]
        )

    def get_globs(self):
        """Get globs for test cases."""
        return {
            "ca": self.ca,
            "ca_serial": self.ca.serial,
            "cert": self.cert,
            "cert_serial": self.cert.serial,
            "csr": certs["root-cert"]["csr"]["pem"],
        }

    @override_tmpcadir()
    def test_python_intro(self) -> None:
        """Test python/intro.rst."""
        doctest.testfile("%s/python/intro.rst" % BASE, globs=self.get_globs())

    @override_tmpcadir()
    def test_python_models(self) -> None:
        """Test python/models.rst."""
        doctest.testfile("%s/python/models.rst" % BASE, globs=self.get_globs())

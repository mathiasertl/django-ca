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
import os
import typing
import unittest

from cryptography import x509

from django.conf import settings
from django.test import TestCase

from .base import certs
from .base import override_settings
from .base import override_tmpcadir
from .base.mixins import TestCaseMixin

BASE = os.path.relpath(settings.DOC_DIR, os.path.dirname(__file__))


@override_settings(CA_MIN_KEY_SIZE=1024, CA_DEFAULT_KEY_SIZE=1024)
class DocumentationTestCase(TestCaseMixin, TestCase):
    """Main testcase class."""

    load_cas = ("root",)
    load_certs = ("root-cert",)

    def get_globs(self) -> typing.Dict[str, typing.Any]:
        """Get globs for test cases."""
        return {
            "ca": self.ca,
            "ca_serial": self.ca.serial,
            "cert": self.cert,
            "cert_serial": self.cert.serial,
            "csr": certs["root-cert"]["csr"]["parsed"],
            "x509": x509,
        }

    @override_tmpcadir()
    def test_python_intro(self) -> None:
        """Test python/intro.rst."""
        doctest.testfile(f"{BASE}/python/intro.rst", globs=self.get_globs())

    @unittest.skipIf(  # https://github.com/pyca/cryptography/issues/6363
        settings.CRYPTOGRAPHY_VERSION < (35, 0), "cg==35.0 changed CertificateSigningRequest.__str__"
    )
    @override_tmpcadir()
    def test_python_models(self) -> None:
        """Test python/models.rst."""
        doctest.testfile(f"{BASE}/python/models.rst", globs=self.get_globs())

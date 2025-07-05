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

"""Test the list_cas management command."""

from datetime import timedelta
from typing import Any

from django.test import TestCase
from django.utils import timezone

from freezegun import freeze_time

from django_ca.models import CertificateAuthority
from django_ca.tests.base.constants import CERT_DATA, TIMESTAMPS
from django_ca.tests.base.mixins import TestCaseMixin
from django_ca.tests.base.utils import cmd

EXPECTED = """{dsa[serial_colons]} - {dsa[name]}{dsa_state}
{ec[serial_colons]} - {ec[name]}{ec_state}
{ed25519[serial_colons]} - {ed25519[name]}{ed25519_state}
{ed448[serial_colons]} - {ed448[name]}{ed448_state}
{pwd[serial_colons]} - {pwd[name]}{pwd_state}
{root[serial_colons]} - {root[name]}{root_state}
{child[serial_colons]} - {child[name]}{child_state}
"""


class ListCertsTestCase(TestCaseMixin, TestCase):
    """Test the list_cas management command."""

    load_cas = "__usable__"

    def assertOutput(  # pylint: disable=invalid-name
        self, output: str, expected: str, **context: Any
    ) -> None:
        """Assert the output of this command."""
        context.update(CERT_DATA)
        for ca_name in self.cas:
            context.setdefault(f"{ca_name}_state", "")
        assert output == expected.format(**context)

    def test_all_cas(self) -> None:
        """Test list with all CAs."""
        for name in [k for k, v in CERT_DATA.items() if v.get("type") == "ca" and k not in self.cas]:
            self.load_ca(name)

        stdout, stderr = cmd("list_cas")
        assert (
            stdout
            == f"{CERT_DATA['letsencrypt_x1']['serial_colons']} - {CERT_DATA['letsencrypt_x1']['name']}\n"
            f"{CERT_DATA['letsencrypt_x3']['serial_colons']} - {CERT_DATA['letsencrypt_x3']['name']}\n"
            f"{CERT_DATA['dst_root_x3']['serial_colons']} - {CERT_DATA['dst_root_x3']['name']}\n"
            f"{CERT_DATA['google_g3']['serial_colons']} - {CERT_DATA['google_g3']['name']}\n"
            f"{CERT_DATA['globalsign_r2_root']['serial_colons']}"
            f" - {CERT_DATA['globalsign_r2_root']['name']}\n"
            f"{CERT_DATA['trustid_server_a52']['serial_colons']}"
            f" - {CERT_DATA['trustid_server_a52']['name']}\n"
            f"{CERT_DATA['rapidssl_g3']['serial_colons']} - {CERT_DATA['rapidssl_g3']['name']}\n"
            f"{CERT_DATA['geotrust']['serial_colons']} - {CERT_DATA['geotrust']['name']}\n"
            f"{CERT_DATA['startssl_class2']['serial_colons']} - {CERT_DATA['startssl_class2']['name']}\n"
            f"{CERT_DATA['digicert_sha2']['serial_colons']} - {CERT_DATA['digicert_sha2']['name']}\n"
            f"{CERT_DATA['globalsign_dv']['serial_colons']} - {CERT_DATA['globalsign_dv']['name']}\n"
            f"{CERT_DATA['dsa']['serial_colons']} - {CERT_DATA['dsa']['name']}\n"
            f"{CERT_DATA['ec']['serial_colons']} - {CERT_DATA['ec']['name']}\n"
            f"{CERT_DATA['ed25519']['serial_colons']} - {CERT_DATA['ed25519']['name']}\n"
            f"{CERT_DATA['ed448']['serial_colons']} - {CERT_DATA['ed448']['name']}\n"
            f"{CERT_DATA['pwd']['serial_colons']} - {CERT_DATA['pwd']['name']}\n"
            f"{CERT_DATA['root']['serial_colons']} - {CERT_DATA['root']['name']}\n"
            f"{CERT_DATA['child']['serial_colons']} - {CERT_DATA['child']['name']}\n"
            f"{CERT_DATA['comodo_ev']['serial_colons']} - {CERT_DATA['comodo_ev']['name']}\n"
            f"{CERT_DATA['globalsign']['serial_colons']} - {CERT_DATA['globalsign']['name']}\n"
            f"{CERT_DATA['digicert_ha_intermediate']['serial_colons']}"
            f" - {CERT_DATA['digicert_ha_intermediate']['name']}\n"
            f"{CERT_DATA['comodo_dv']['serial_colons']} - {CERT_DATA['comodo_dv']['name']}\n"
            f"{CERT_DATA['startssl_class3']['serial_colons']} - {CERT_DATA['startssl_class3']['name']}\n"
            f"{CERT_DATA['godaddy_g2_intermediate']['serial_colons']}"
            f" - {CERT_DATA['godaddy_g2_intermediate']['name']}\n"
            f"{CERT_DATA['digicert_ev_root']['serial_colons']} - {CERT_DATA['digicert_ev_root']['name']}\n"
            f"{CERT_DATA['digicert_global_root']['serial_colons']}"
            f" - {CERT_DATA['digicert_global_root']['name']}\n"
            f"{CERT_DATA['identrust_root_1']['serial_colons']} - {CERT_DATA['identrust_root_1']['name']}\n"
            f"{CERT_DATA['startssl_root']['serial_colons']} - {CERT_DATA['startssl_root']['name']}\n"
            f"{CERT_DATA['comodo']['serial_colons']} - {CERT_DATA['comodo']['name']}\n"
        )
        assert stderr == ""

    def test_no_cas(self) -> None:
        """Test the command if no CAs are defined."""
        CertificateAuthority.objects.all().delete()
        stdout, stderr = cmd("list_cas")
        assert stdout == ""
        assert stderr == ""

    def test_basic(self) -> None:
        """Basic test of the command."""
        stdout, stderr = cmd("list_cas")
        self.assertOutput(stdout, EXPECTED)
        assert stderr == ""

    def test_disabled(self) -> None:
        """Test the command if some CA is disabled."""
        self.ca.enabled = False
        self.ca.save()

        stdout, stderr = cmd("list_cas")
        self.assertOutput(stdout, EXPECTED, child_state=" (disabled)")
        assert stderr == ""

    @freeze_time(TIMESTAMPS["everything_valid"])
    def test_tree(self) -> None:
        """Test the tree output.

        NOTE: freeze_time b/c we create some fake CA objects and order in the tree depends on validity.
        """
        stdout, stderr = cmd("list_cas", tree=True)
        assert (
            stdout == f"{CERT_DATA['dsa']['serial_colons']} - {CERT_DATA['dsa']['name']}\n"
            f"{CERT_DATA['ec']['serial_colons']} - {CERT_DATA['ec']['name']}\n"
            f"{CERT_DATA['ed25519']['serial_colons']} - {CERT_DATA['ed25519']['name']}\n"
            f"{CERT_DATA['ed448']['serial_colons']} - {CERT_DATA['ed448']['name']}\n"
            f"{CERT_DATA['pwd']['serial_colons']} - {CERT_DATA['pwd']['name']}\n"
            f"{CERT_DATA['root']['serial_colons']} - {CERT_DATA['root']['name']}\n"
            f"└───{CERT_DATA['child']['serial_colons']} - {CERT_DATA['child']['name']}\n"
        )
        assert stderr == ""

        # manually create Certificate objects
        not_after = timezone.now() + timedelta(days=3)
        not_before = timezone.now() - timedelta(days=3)
        root = self.cas["root"]
        pub = CERT_DATA["child-cert"]["pub"]["parsed"]
        child3 = CertificateAuthority.objects.create(
            name="child3", serial="child3", parent=root, not_after=not_after, not_before=not_before, pub=pub
        )
        CertificateAuthority.objects.create(
            name="child4", serial="child4", parent=root, not_after=not_after, not_before=not_before, pub=pub
        )
        CertificateAuthority.objects.create(
            name="child3.1",
            serial="child3.1",
            parent=child3,
            not_after=not_after,
            not_before=not_before,
            pub=pub,
        )

        stdout, stderr = cmd("list_cas", tree=True)
        assert (
            stdout == f"{CERT_DATA['dsa']['serial_colons']} - {CERT_DATA['dsa']['name']}\n"
            f"{CERT_DATA['ec']['serial_colons']} - {CERT_DATA['ec']['name']}\n"
            f"{CERT_DATA['ed25519']['serial_colons']} - {CERT_DATA['ed25519']['name']}\n"
            f"{CERT_DATA['ed448']['serial_colons']} - {CERT_DATA['ed448']['name']}\n"
            f"{CERT_DATA['pwd']['serial_colons']} - {CERT_DATA['pwd']['name']}\n"
            f"{CERT_DATA['root']['serial_colons']} - {CERT_DATA['root']['name']}\n"
            f"│───ch:il:d3 - child3\n"
            f"│   └───ch:il:d3:.1 - child3.1\n"
            f"│───ch:il:d4 - child4\n"
            f"└───{CERT_DATA['child']['serial_colons']} - {CERT_DATA['child']['name']}\n"
        )

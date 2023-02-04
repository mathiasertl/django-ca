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

"""Test the list_cas management command."""

import typing
from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from freezegun import freeze_time

from django_ca.models import CertificateAuthority
from django_ca.tests.base import certs, override_settings, timestamps
from django_ca.tests.base.mixins import TestCaseMixin

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
        self, output: str, expected: str, **context: typing.Any
    ) -> None:
        """Assert the output of this command."""
        context.update(certs)
        for ca_name in self.cas:
            context.setdefault(f"{ca_name}_state", "")
        self.assertEqual(output, expected.format(**context))

    def test_all_cas(self) -> None:
        """Test list with all CAs."""
        for name in [k for k, v in certs.items() if v.get("type") == "ca" and k not in self.cas]:
            self.load_ca(name)

        stdout, stderr = self.cmd("list_cas")
        self.assertEqual(
            stdout,
            f"""{certs['letsencrypt_x1']['serial_colons']} - {certs['letsencrypt_x1']['name']}
{certs['letsencrypt_x3']['serial_colons']} - {certs['letsencrypt_x3']['name']}
{certs['dst_root_x3']['serial_colons']} - {certs['dst_root_x3']['name']}
{certs['google_g3']['serial_colons']} - {certs['google_g3']['name']}
{certs['globalsign_r2_root']['serial_colons']} - {certs['globalsign_r2_root']['name']}
{certs['trustid_server_a52']['serial_colons']} - {certs['trustid_server_a52']['name']}
{certs['rapidssl_g3']['serial_colons']} - {certs['rapidssl_g3']['name']}
{certs['geotrust']['serial_colons']} - {certs['geotrust']['name']}
{certs['startssl_class2']['serial_colons']} - {certs['startssl_class2']['name']}
{certs['digicert_sha2']['serial_colons']} - {certs['digicert_sha2']['name']}
{certs['dsa']['serial_colons']} - {certs['dsa']['name']}
{certs['ec']['serial_colons']} - {certs['ec']['name']}
{certs['ed25519']['serial_colons']} - {certs['ed25519']['name']}
{certs['ed448']['serial_colons']} - {certs['ed448']['name']}
{certs['pwd']['serial_colons']} - {certs['pwd']['name']}
{certs['root']['serial_colons']} - {certs['root']['name']}
{certs['child']['serial_colons']} - {certs['child']['name']}
{certs['globalsign_dv']['serial_colons']} - {certs['globalsign_dv']['name']}
{certs['comodo_ev']['serial_colons']} - {certs['comodo_ev']['name']}
{certs['globalsign']['serial_colons']} - {certs['globalsign']['name']}
{certs['digicert_ha_intermediate']['serial_colons']} - {certs['digicert_ha_intermediate']['name']}
{certs['comodo_dv']['serial_colons']} - {certs['comodo_dv']['name']}
{certs['startssl_class3']['serial_colons']} - {certs['startssl_class3']['name']}
{certs['godaddy_g2_intermediate']['serial_colons']} - {certs['godaddy_g2_intermediate']['name']}
{certs['digicert_ev_root']['serial_colons']} - {certs['digicert_ev_root']['name']}
{certs['digicert_global_root']['serial_colons']} - {certs['digicert_global_root']['name']}
{certs['identrust_root_1']['serial_colons']} - {certs['identrust_root_1']['name']}
{certs['startssl_root']['serial_colons']} - {certs['startssl_root']['name']}
{certs['godaddy_g2_root']['serial_colons']} - {certs['godaddy_g2_root']['name']}
{certs['comodo']['serial_colons']} - {certs['comodo']['name']}
""",
        )
        self.assertEqual(stderr, "")

    def test_no_cas(self) -> None:
        """Test the command if no CAs are defined."""

        CertificateAuthority.objects.all().delete()
        stdout, stderr = self.cmd("list_cas")
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")

    def test_basic(self) -> None:
        """Basic test of the command."""

        stdout, stderr = self.cmd("list_cas")
        self.assertOutput(stdout, EXPECTED)
        self.assertEqual(stderr, "")

    def test_disabled(self) -> None:
        """Test the command if some CA is disabled."""

        self.ca.enabled = False
        self.ca.save()

        stdout, stderr = self.cmd("list_cas")
        self.assertOutput(stdout, EXPECTED, child_state=" (disabled)")
        self.assertEqual(stderr, "")

    @freeze_time(timestamps["everything_valid"])
    def test_tree(self) -> None:
        """Test the tree output.

        NOTE: freeze_time b/c we create some fake CA objects and order in the tree depends on validity.
        """

        stdout, stderr = self.cmd("list_cas", tree=True)
        self.assertEqual(
            stdout,
            f"""{certs['dsa']['serial_colons']} - {certs['dsa']['name']}
{certs['ec']['serial_colons']} - {certs['ec']['name']}
{certs['ed25519']['serial_colons']} - {certs['ed25519']['name']}
{certs['ed448']['serial_colons']} - {certs['ed448']['name']}
{certs['pwd']['serial_colons']} - {certs['pwd']['name']}
{certs['root']['serial_colons']} - {certs['root']['name']}
└───{certs['child']['serial_colons']} - {certs['child']['name']}
""",
        )
        self.assertEqual(stderr, "")

        # manually create Certificate objects
        expires = timezone.now() + timedelta(days=3)
        valid_from = timezone.now() - timedelta(days=3)
        root = self.cas["root"]
        pub = certs["child-cert"]["pub"]["parsed"]
        child3 = CertificateAuthority.objects.create(
            name="child3", serial="child3", parent=root, expires=expires, valid_from=valid_from, pub=pub
        )
        CertificateAuthority.objects.create(
            name="child4", serial="child4", parent=root, expires=expires, valid_from=valid_from, pub=pub
        )
        CertificateAuthority.objects.create(
            name="child3.1", serial="child3.1", parent=child3, expires=expires, valid_from=valid_from, pub=pub
        )

        stdout, stderr = self.cmd("list_cas", tree=True)
        self.assertEqual(
            stdout,
            f"""{certs['dsa']['serial_colons']} - {certs['dsa']['name']}
{certs['ec']['serial_colons']} - {certs['ec']['name']}
{certs['ed25519']['serial_colons']} - {certs['ed25519']['name']}
{certs['ed448']['serial_colons']} - {certs['ed448']['name']}
{certs['pwd']['serial_colons']} - {certs['pwd']['name']}
{certs['root']['serial_colons']} - {certs['root']['name']}
│───ch:il:d3 - child3
│   └───ch:il:d3:.1 - child3.1
│───ch:il:d4 - child4
└───{certs['child']['serial_colons']} - {certs['child']['name']}
""",
        )


@override_settings(USE_TZ=True)
class ListCertsWithTZTestCase(ListCertsTestCase):
    """Same tests as above but with Timezone support."""

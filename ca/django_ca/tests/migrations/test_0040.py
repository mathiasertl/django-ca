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
#
# pylint: disable=redefined-outer-name  # because of fixtures
# pylint: disable=invalid-name  # for model loading

"""Test 0043 database migration."""

from typing import Callable, Optional

from django_test_migrations.migrator import Migrator

from django.db.migrations.state import ProjectState
from django.utils import timezone

from django_ca.tests.base.constants import CERT_DATA
from django_ca.tests.base.utils import (
    authority_information_access,
    crl_distribution_points,
    distribution_point,
    issuer_alternative_name,
    uri,
)


def setup(migrator: Migrator, setup: Optional[Callable[[ProjectState], None]] = None) -> ProjectState:
    """Set up a CA with a CRL Number for the given scope."""
    old_state = migrator.apply_initial_migration(
        ("django_ca", "0039_certificateauthority_sign_authority_information_access_and_more")
    )
    now = timezone.now()

    CertificateAuthority = old_state.apps.get_model("django_ca", "CertificateAuthority")
    CertificateAuthority.objects.create(
        name="foo",
        pub=CERT_DATA["root"]["pub"]["parsed"],
        cn="",
        serial="123",
        valid_from=now,  # doesn't matter here, just need something with right tz.
        expires=now,  # doesn't matter here, just need something with right tz.
        private_key_path="/foo/bar/ca.key",
        crl_url="https://crl.example.com",
        issuer_alt_name="https://ian.example.com",
        ocsp_url="http://ocsp.example.com",
        issuer_url="http://ocsp.example.com",
    )

    if setup is not None:
        setup(old_state)

    return migrator.apply_tested_migration(("django_ca", "0040_auto_20240120_0931"))


def test_forward(migrator: Migrator) -> None:
    """Test standard migration and backwards migration."""
    state = setup(migrator)

    CertificateAuthority = state.apps.get_model("django_ca", "CertificateAuthority")
    ca = CertificateAuthority.objects.get(serial="123")
    assert ca.sign_crl_distribution_points == crl_distribution_points(
        distribution_point([uri("https://crl.example.com")])
    )
    assert ca.sign_issuer_alternative_name == issuer_alternative_name(uri("https://ian.example.com"))
    assert ca.sign_authority_information_access == authority_information_access(
        ca_issuers=[uri("http://ocsp.example.com")], ocsp=[uri("http://ocsp.example.com")]
    )


def test_backward(migrator: Migrator) -> None:
    """Run migration backwards."""
    state = migrator.apply_tested_migration(("django_ca", "0040_auto_20240120_0931"))

    now = timezone.now()
    CertificateAuthority = state.apps.get_model("django_ca", "CertificateAuthority")
    CertificateAuthority.objects.create(
        serial="123",
        pub=CERT_DATA["root"]["pub"]["parsed"],
        valid_from=now,  # doesn't matter here, just need something with right tz.
        expires=now,  # doesn't matter here, just need something with right tz.
        sign_crl_distribution_points=crl_distribution_points(
            distribution_point([uri("https://crl.example.com")])
        ),
        sign_issuer_alternative_name=issuer_alternative_name(uri("https://ian.example.com")),
        sign_authority_information_access=authority_information_access(
            ca_issuers=[uri("http://ocsp.example.com")], ocsp=[uri("http://ocsp.example.com")]
        ),
    )

    new_state = migrator.apply_tested_migration(
        ("django_ca", "0039_certificateauthority_sign_authority_information_access_and_more")
    )

    CertificateAuthority = new_state.apps.get_model("django_ca", "CertificateAuthority")
    ca = CertificateAuthority.objects.get(serial="123")
    assert ca.crl_url == "https://crl.example.com"
    assert ca.issuer_alt_name == "URI:https://ian.example.com"
    assert ca.issuer_url == "http://ocsp.example.com"
    assert ca.ocsp_url == "http://ocsp.example.com"

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

"""Test :class:`~django_ca.models.CertificateRevocationList`."""

from datetime import datetime, timedelta, timezone as tz

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

import pytest
from pytest_django.fixtures import SettingsWrapper

from django_ca.constants import ReasonFlags
from django_ca.key_backends.storages.models import StoragesUsePrivateKeyOptions
from django_ca.models import Certificate, CertificateAuthority, CertificateRevocationList
from django_ca.tests.base.assertions import assert_issuing_distribution_point
from django_ca.tests.base.constants import TIMESTAMPS

pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])]

KEY_BACKEND_OPTIONS = StoragesUsePrivateKeyOptions.model_validate({})


def assert_crl_number(crl: CertificateRevocationList, number: int) -> None:
    """Test the given CRL number."""
    assert crl.number == number
    assert crl.loaded.extensions.get_extension_for_oid(ExtensionOID.CRL_NUMBER) == x509.Extension(
        oid=ExtensionOID.CRL_NUMBER, critical=False, value=x509.CRLNumber(number)
    )


def assert_no_idp(crl: CertificateRevocationList) -> None:
    """Asert that the given CRL does *not* have an Issuing Distribution Point extension."""
    with pytest.raises(x509.ExtensionNotFound):
        crl.loaded.extensions.get_extension_for_oid(ExtensionOID.ISSUING_DISTRIBUTION_POINT)


def test_create_empty_certificate_revocation_list(usable_ca: CertificateAuthority) -> None:
    """Test creating an empty CRL."""
    key_backend_options = StoragesUsePrivateKeyOptions.model_validate({}, context={"ca": usable_ca})
    obj = CertificateRevocationList.objects.create_certificate_revocation_list(usable_ca, key_backend_options)
    assert obj.ca == usable_ca
    assert_crl_number(obj, 0)
    assert_no_idp(obj)

    assert obj.last_update == TIMESTAMPS["everything_valid"]
    assert obj.next_update == TIMESTAMPS["everything_valid"] + timedelta(days=1)
    assert obj.only_contains_ca_certs is False
    assert obj.only_contains_user_certs is False
    assert obj.only_some_reasons is None
    assert obj.pem.startswith(b"-----BEGIN X509 CRL-----\n")
    assert obj.pem.endswith(b"\n-----END X509 CRL-----\n")

    # Assert properties of embedded CRL
    crl = obj.loaded
    assert isinstance(crl, x509.CertificateRevocationList)
    assert crl.issuer == usable_ca.subject
    assert crl.last_update_utc == TIMESTAMPS["everything_valid"]
    assert crl.next_update_utc == TIMESTAMPS["everything_valid"] + timedelta(days=1)
    assert crl.signature_hash_algorithm == usable_ca.algorithm
    assert not list(crl)  # CRL is empty


@pytest.mark.usefixtures("child_cert", "ec")  # to make sure they *don't* show up in the CRL
def test_full_crl(
    usable_root: CertificateAuthority, child: CertificateAuthority, root_cert: Certificate
) -> None:
    """Test generating a full CRL parameters (and some of its properties)."""
    obj = CertificateRevocationList.objects.create_certificate_revocation_list(
        usable_root, KEY_BACKEND_OPTIONS
    )
    assert obj.ca == usable_root
    assert_crl_number(obj, 0)
    assert str(obj) == f"0 (next update: {obj.next_update})"  # just so we have str() tested too

    root_cert.revoke()
    child.revoke()

    obj = CertificateRevocationList.objects.create_certificate_revocation_list(
        usable_root, KEY_BACKEND_OPTIONS
    )
    assert obj.ca == usable_root
    assert_crl_number(obj, 1)
    assert [rev.serial_number for rev in obj.loaded] == [
        child.get_revocation().serial_number,
        root_cert.get_revocation().serial_number,
    ]


@pytest.mark.usefixtures("child_cert", "ec")  # to make sure they *don't* show up in the CRL
def test_user_certs_crl(
    usable_root: CertificateAuthority, child: CertificateAuthority, root_cert: Certificate
) -> None:
    """Test generating a CRL that contains only CA certs."""
    root_cert.revoke()
    child.revoke()

    obj = CertificateRevocationList.objects.create_certificate_revocation_list(
        usable_root, KEY_BACKEND_OPTIONS, only_contains_ca_certs=True
    )
    crl = obj.loaded
    assert [rev.serial_number for rev in crl] == [child.get_revocation().serial_number]
    idp = crl.extensions.get_extension_for_oid(ExtensionOID.ISSUING_DISTRIBUTION_POINT)
    assert_issuing_distribution_point(idp, only_contains_ca_certs=True)  # type: ignore[arg-type]


@pytest.mark.usefixtures("child_cert", "ec")  # to make sure they *don't* show up in the CRL
def test_ca_certs_crl(
    usable_root: CertificateAuthority, child: CertificateAuthority, root_cert: Certificate
) -> None:
    """Test generating a CRL that contains only user certs."""
    root_cert.revoke()
    child.revoke()

    obj = CertificateRevocationList.objects.create_certificate_revocation_list(
        usable_root, KEY_BACKEND_OPTIONS, only_contains_user_certs=True
    )
    crl = obj.loaded
    assert [rev.serial_number for rev in crl] == [root_cert.get_revocation().serial_number]
    idp = crl.extensions.get_extension_for_oid(ExtensionOID.ISSUING_DISTRIBUTION_POINT)
    assert_issuing_distribution_point(idp, only_contains_user_certs=True)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "reasons",
    (
        frozenset([x509.ReasonFlags.key_compromise]),
        frozenset([x509.ReasonFlags.key_compromise, x509.ReasonFlags.affiliation_changed]),
    ),
)
def test_with_reasons(
    usable_root: CertificateAuthority, root_cert: Certificate, reasons: frozenset[x509.ReasonFlags]
) -> None:
    """Generate a CRL with only one reason."""
    root_cert.revoke(ReasonFlags.key_compromise)

    obj = CertificateRevocationList.objects.create_certificate_revocation_list(
        usable_root, KEY_BACKEND_OPTIONS, only_some_reasons=reasons
    )
    assert obj.only_some_reasons == reasons
    crl = obj.loaded
    assert [rev.serial_number for rev in crl] == [root_cert.get_revocation().serial_number]
    idp = crl.extensions.get_extension_for_oid(ExtensionOID.ISSUING_DISTRIBUTION_POINT)
    assert_issuing_distribution_point(idp, only_some_reasons=reasons)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "reasons",
    (
        frozenset([x509.ReasonFlags.key_compromise]),
        frozenset([x509.ReasonFlags.key_compromise, x509.ReasonFlags.aa_compromise]),
    ),
)
def test_with_reasons_not_included(
    usable_root: CertificateAuthority, root_cert: Certificate, reasons: frozenset[x509.ReasonFlags]
) -> None:
    """Generate a CRL with only some reasons, where the certificate is revoked for a different reason."""
    root_cert.revoke(ReasonFlags.affiliation_changed)

    obj = CertificateRevocationList.objects.create_certificate_revocation_list(
        usable_root, KEY_BACKEND_OPTIONS, only_some_reasons=reasons
    )
    assert obj.only_some_reasons == reasons
    crl = obj.loaded
    assert not list(crl)
    idp = crl.extensions.get_extension_for_oid(ExtensionOID.ISSUING_DISTRIBUTION_POINT)
    assert_issuing_distribution_point(idp, only_some_reasons=reasons)  # type: ignore[arg-type]


def test_use_tz_is_false(usable_root: CertificateAuthority, settings: SettingsWrapper) -> None:
    """Generate a CRL with settings.USE_TZ = False."""
    settings.USE_TZ = False

    obj = CertificateRevocationList.objects.create_certificate_revocation_list(
        usable_root, KEY_BACKEND_OPTIONS
    )
    assert obj.loaded.last_update_utc == TIMESTAMPS["everything_valid"]
    assert obj.loaded.next_update_utc == TIMESTAMPS["everything_valid"] + timedelta(days=1)


def test_use_tz_is_false_with_next_update(
    usable_root: CertificateAuthority, settings: SettingsWrapper
) -> None:
    """Generate a CRL with settings.USE_TZ = False and passing a timezone-naive next_update."""
    next_update = datetime.now().replace(microsecond=10) + timedelta(days=2)
    settings.USE_TZ = False

    obj = CertificateRevocationList.objects.create_certificate_revocation_list(
        usable_root, KEY_BACKEND_OPTIONS, next_update=next_update
    )
    assert obj.loaded.last_update_utc == TIMESTAMPS["everything_valid"]
    assert obj.loaded.next_update_utc == TIMESTAMPS["everything_valid"] + timedelta(days=2)


def test_use_tz_is_false_with_tz_aware_next_update(
    usable_root: CertificateAuthority, settings: SettingsWrapper
) -> None:
    """Generate a CRL with settings.USE_TZ = False and passing a timezone-aware next_update."""
    next_update = datetime.now(tz=tz.utc).replace(microsecond=10) + timedelta(days=2)
    settings.USE_TZ = False

    obj = CertificateRevocationList.objects.create_certificate_revocation_list(
        usable_root, KEY_BACKEND_OPTIONS, next_update=next_update
    )
    assert obj.loaded.last_update_utc == TIMESTAMPS["everything_valid"]
    assert obj.loaded.next_update_utc == TIMESTAMPS["everything_valid"] + timedelta(days=2)


def test_invalid_scope(root: CertificateAuthority) -> None:
    """Try generating a CRL where both `only_contains_ca_certs` and `only_contains_user_certs` are True."""
    match = r"^`only_contains_ca_certs` and `only_contains_user_certs` cannot both be set\.$"
    match = (
        r"^Only one of `only_contains_ca_certs`, `only_contains_user_certs` and "
        r"`only_contains_attribute_certs` can be set\.$"
    )
    with pytest.raises(ValueError, match=match):
        CertificateRevocationList.objects.create_certificate_revocation_list(
            root, KEY_BACKEND_OPTIONS, only_contains_user_certs=True, only_contains_ca_certs=True
        )


def test_invalid_reasons(root: CertificateAuthority) -> None:
    """Try creating a CRL with an invalid type set in reasons."""
    match = r"^Object of type ReasonFlags is not serializable with this encoder\.$"
    with pytest.raises(TypeError, match=match):
        CertificateRevocationList.objects.create(
            ca=root,
            number=1,
            last_update=TIMESTAMPS["everything_valid"],
            next_update=TIMESTAMPS["everything_valid"],
            only_some_reasons=x509.ReasonFlags.key_compromise,
        )


def test_loaded_with_data_is_none(root: CertificateAuthority) -> None:
    """Try accessing the `loaded` property when data has not yet been set."""
    crl = CertificateRevocationList.objects.create(
        ca=root,
        number=1,
        last_update=TIMESTAMPS["everything_valid"],
        next_update=TIMESTAMPS["everything_valid"],
    )
    with pytest.raises(ValueError, match=r"^CRL is not yet generated for this object\.$"):
        crl.loaded  # noqa: B018  # this is what we test


def test_cache_with_data_is_none(root: CertificateAuthority) -> None:
    """Try accessing the `loaded` property when data has not yet been set."""
    crl = CertificateRevocationList.objects.create(
        ca=root,
        number=1,
        last_update=TIMESTAMPS["everything_valid"],
        next_update=TIMESTAMPS["everything_valid"],
    )
    with pytest.raises(ValueError, match=r"^CRL is not yet generated for this object\.$"):
        crl.cache()

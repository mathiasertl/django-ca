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

"""Test the edit_ca management command."""

from typing import Any

from cryptography import x509

from django.test import TestCase

import pytest
from pytest_django.fixtures import SettingsWrapper

from django_ca.conf import model_settings
from django_ca.models import CertificateAuthority
from django_ca.tests.base.assertions import assert_command_error
from django_ca.tests.base.mixins import TestCaseMixin
from django_ca.tests.base.utils import (
    authority_information_access,
    certificate_policies,
    cmd,
    cmd_e2e,
    crl_distribution_points,
    distribution_point,
    issuer_alternative_name,
    uri,
)


class EditCATestCase(TestCaseMixin, TestCase):
    """Test the edit_ca management command."""


ISSUER = "https://issuer-test.example.org"
ISSUER_ALTERNATIVE_NAME = "http://ian-test.example.org"
OCSP_URL = "http://ocsp-test.example.org"
CRL = ("http://example.org/crl-test",)
CAA = "caa.example.com"
WEBSITE = "https://website.example.com"
TOS = "https://tos.example.com"


def edit_ca(ca: CertificateAuthority, **kwargs: Any) -> None:
    """Execute the edit_ca command."""
    stdout, stderr = cmd("edit_ca", ca.serial, **kwargs)
    assert stdout == ""
    assert stderr == ""
    ca.refresh_from_db()


def test_basic(root: CertificateAuthority) -> None:
    """Test basic command."""
    edit_ca(root, caa=CAA, website=WEBSITE, tos=TOS)

    assert root.caa_identity == CAA
    assert root.website == WEBSITE
    assert root.terms_of_service, TOS


def test_signing_extensions(root: CertificateAuthority) -> None:
    """Test editing extensions used for signing certificates."""
    stdout, stderr = cmd_e2e(
        [
            "edit_ca",
            root.serial,
            f"--sign-ca-issuer={ISSUER}",
            f"--sign-issuer-alternative-name={ISSUER_ALTERNATIVE_NAME}",
            f"--sign-ocsp-responder={OCSP_URL}",
            f"--sign-crl-full-name={CRL[0]}",
            # Certificate Policies extension
            "--sign-policy-identifier=1.2.3",
            "--sign-certification-practice-statement=https://cps.example.com",
            "--sign-user-notice=explicit-text",
        ]
    )
    assert stdout == ""
    assert stderr == ""
    root.refresh_from_db()

    assert root.sign_authority_information_access == authority_information_access(
        ocsp=[uri(OCSP_URL)], ca_issuers=[uri(ISSUER)]
    )

    assert root.sign_issuer_alternative_name == issuer_alternative_name(uri(ISSUER_ALTERNATIVE_NAME))
    assert root.sign_crl_distribution_points == crl_distribution_points(distribution_point([uri(CRL[0])]))

    # Certificate Policies extension
    assert root.sign_certificate_policies == certificate_policies(
        x509.PolicyInformation(
            policy_identifier=x509.ObjectIdentifier("1.2.3"),
            policy_qualifiers=[
                "https://cps.example.com",
                x509.UserNotice(notice_reference=None, explicit_text="explicit-text"),
            ],
        )
    )


def test_enable_disable(root: CertificateAuthority) -> None:
    """Test the enable/disable options."""
    assert root.enabled  # initial state

    edit_ca(root, enabled=False)
    assert root.enabled is False
    edit_ca(root, enabled=True)
    assert root.enabled

    with pytest.raises(SystemExit, match=r"^2$") as exception_info:
        cmd_e2e(["edit_ca", "--enable", "--disable"])
    assert exception_info.value.args == (2,)
    assert root.enabled  # state unchanged


def test_acme_arguments(root: CertificateAuthority) -> None:
    """Test ACME arguments."""
    # Test initial state
    assert root.acme_enabled is True
    assert root.acme_registration
    assert root.acme_profile == model_settings.CA_DEFAULT_PROFILE
    assert root.acme_requires_contact

    # change all settings
    edit_ca(
        root, acme_enabled=False, acme_registration=False, acme_requires_contact=False, acme_profile="client"
    )
    assert root.acme_enabled is False
    assert root.acme_registration is False
    assert root.acme_profile == "client"
    assert root.acme_requires_contact is False


def test_acme_arguments_mutually_exclusive(root: CertificateAuthority) -> None:
    """Try mutually exclusive ACME arguments."""
    # Check initial state:
    assert root.acme_enabled is True
    assert root.acme_requires_contact is True

    with pytest.raises(SystemExit, match=r"^2$") as exception_info:
        cmd_e2e(["edit_ca", "--acme-enable", "--acme-disable"])
    assert exception_info.value.args == (2,)
    assert root.acme_enabled is True  # state unchanged

    with pytest.raises(SystemExit, match=r"^2$") as exception_info:
        cmd_e2e(["edit_ca", "--acme-contact-optional", "--acme-contact-required"])
    assert exception_info.value.args == (2,)
    assert root.acme_requires_contact is True  # state unchanged


def test_rest_api_arguments(root: CertificateAuthority) -> None:
    """Test REST API arguments."""
    # Test initial state
    assert root.api_enabled is False

    # change all settings
    edit_ca(root, api_enable=True)
    assert root.api_enabled is True


def test_rest_api_arguments_mutually_exclusive(root: CertificateAuthority) -> None:
    """Try mutually exclusive rest api arguments."""
    assert root.api_enabled is False  # test initial state
    with pytest.raises(SystemExit, match=r"^2$") as exception_info:
        cmd_e2e(["edit_ca", "--api-enable", "--api-disable"])
    assert exception_info.value.args == (2,)
    assert root.api_enabled is False  # state unchanged


def test_ocsp_responder_arguments(root: CertificateAuthority, settings: SettingsWrapper) -> None:
    """Test ACME arguments."""
    settings.CA_OCSP_KEY_BACKENDS = {
        "default": {
            "BACKEND": "django_ca.key_backends.storages.StoragesOCSPBackend",
            "OPTIONS": {"storage_alias": "django-ca"},
        },
        "other": {
            "BACKEND": "django_ca.key_backends.storages.StoragesOCSPBackend",
            "OPTIONS": {"storage_alias": "django-ca"},
        },
    }

    edit_ca(root, ocsp_key_backend="other", ocsp_responder_key_validity=10, ocsp_response_validity=3600)

    assert root.ocsp_key_backend_alias == "other"
    assert root.ocsp_responder_key_validity == 10
    assert root.ocsp_response_validity == 3600


def test_invalid_acme_profile(root: CertificateAuthority) -> None:
    """Test setting an invalid ACME profile."""
    with assert_command_error(r"^unknown-profile: Profile is not defined\.$"):
        edit_ca(root, acme_profile="unknown-profile")
    assert root.acme_profile == model_settings.CA_DEFAULT_PROFILE


def test_acme_disabled(settings: SettingsWrapper, root: CertificateAuthority) -> None:
    """Test ACME arguments do not work when ACME support is disabled."""
    settings.CA_ENABLE_ACME = False
    with pytest.raises(SystemExit, match=r"^2$") as exception_info:
        cmd_e2e(["edit_ca", root.serial, "--acme-enable"])
    assert exception_info.value.args == (2,)

    with pytest.raises(SystemExit, match=r"^2$") as exception_info:
        cmd_e2e(["edit_ca", root.serial, "--acme-contact-optional"])
    assert exception_info.value.args == (2,)

    with pytest.raises(SystemExit, match=r"^2$") as exception_info:
        cmd_e2e(["edit_ca", root.serial, "--acme-profile=foo"])
    assert exception_info.value.args == (2,)


def test_enable(root: CertificateAuthority) -> None:
    """Test enabling the CA."""
    root.enabled = False
    root.save()

    edit_ca(root, enabled=True)
    assert root.enabled

    # disable it again
    edit_ca(root, enabled=False)
    assert root.enabled is False

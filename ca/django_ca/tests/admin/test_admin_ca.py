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

"""Test cases for the admin interface for Certificate Authorities."""

from http import HTTPStatus

from cryptography import x509
from cryptography.x509.oid import CertificatePoliciesOID, ExtensionOID

from django.contrib.admin.helpers import AdminForm
from django.test import Client, TestCase

import pytest
from pytest_django.asserts import assertInHTML
from pytest_django.fixtures import SettingsWrapper

from django_ca.models import CertificateAuthority
from django_ca.tests.admin.assertions import assert_change_response
from django_ca.tests.base.mixins import AdminTestCaseMixin, StandardAdminViewTestCaseMixin
from django_ca.tests.base.utils import certificate_policies


class TestCertificateAuthorityAdminView(StandardAdminViewTestCaseMixin[CertificateAuthority]):
    """Test CA admin views."""

    model = CertificateAuthority

    @pytest.fixture
    def change_object(self, root: CertificateAuthority) -> CertificateAuthority:
        """Fixture for the object in detail view."""
        return root

    @pytest.fixture
    def changelist_objects(self, usable_cas: list[CertificateAuthority]) -> list[CertificateAuthority]:
        """Fixture for the objects in the changelist."""
        return usable_cas

    def test_change_view_without_acme(
        self, settings: SettingsWrapper, admin_client: Client, root: CertificateAuthority
    ) -> None:
        """Basic tests but with ACME support disabled."""
        settings.CA_ENABLE_ACME = False
        response = self.get_change_response(admin_client, root)
        assert_change_response(response)
        assert b"ACME support is currently disabled in the configuration." in response.content
        adminform = response.context["adminform"]
        assert isinstance(adminform, AdminForm)
        assert "acme_enabled" in adminform.readonly_fields

    def test_change_view_without_api(
        self, settings: SettingsWrapper, admin_client: Client, root: CertificateAuthority
    ) -> None:
        """Basic tests but with API support disabled."""
        settings.CA_ENABLE_REST_API = False
        response = self.get_change_response(admin_client, root)
        assert_change_response(response)
        assert b"REST API support is currently disabled in the configuration." in response.content
        adminform = response.context["adminform"]
        assert isinstance(adminform, AdminForm)
        assert "api_enabled" in adminform.readonly_fields

    def test_change_view_with_ed_ca(self, admin_client: Client, ed448: CertificateAuthority) -> None:
        """Test viewing an Ed-based CA, which does not have a signature hash algorithm."""
        response = self.get_change_response(admin_client, ed448)
        assert_change_response(response)
        assertInHTML(
            """
            <div class="form-row field-signature_hash_algorithm">
                <div>        
                    <div class="flex-container">    
                        <label>Signature hash algorithm:</label>
                        <div class="readonly">None</div>
                    </div>
                </div>
            </div>""",
            response.content.decode("utf-8"),
        )

    def test_complex_sign_certificate_policies(
        self, admin_client: Client, root: CertificateAuthority
    ) -> None:
        """Test that complex Certificate Policy extensions are read-only."""
        # This test is only meaningful if the CA does **not** have the Certificate Policies extension in its
        # own extensions. We (can) only test for the used template after viewing, and the template would be
        # used for that extension.
        assert ExtensionOID.CERTIFICATE_POLICIES not in root.extensions

        root.sign_certificate_policies = certificate_policies(
            x509.PolicyInformation(
                policy_identifier=CertificatePoliciesOID.ANY_POLICY,
                policy_qualifiers=[
                    x509.UserNotice(
                        explicit_text=None,
                        notice_reference=x509.NoticeReference(organization="org", notice_numbers=[1]),
                    )
                ],
            ),
            x509.PolicyInformation(
                policy_identifier=CertificatePoliciesOID.CPS_QUALIFIER,
                policy_qualifiers=[
                    x509.UserNotice(
                        explicit_text=None,
                        notice_reference=x509.NoticeReference(organization="org2", notice_numbers=[1]),
                    )
                ],
            ),
        )
        root.save()
        response = self.get_change_response(admin_client, root)
        assert_change_response(response)
        templates = [t.name for t in response.templates]
        assert "django_ca/admin/extensions/2.5.29.32.html" in templates


class CADownloadBundleTestCase(AdminTestCaseMixin[CertificateAuthority], TestCase):
    """Tests for downloading the certificate bundle."""

    default_ca = "root"
    load_cas = (
        "root",
        "child",
    )
    model = CertificateAuthority
    view_name = "django_ca_certificateauthority_download_bundle"

    @property
    def url(self) -> str:
        """Shortcut property to get the bundle URL for the root CA."""
        return self.get_url(self.ca)

    def test_root(self) -> None:
        """Test downloading the bundle for the root CA."""
        self.assertBundle(self.ca, [self.ca], f"{self.ca.serial}_bundle.pem")

    def test_child(self) -> None:
        """Test downloading the bundle for a child CA."""
        child = self.cas["child"]
        self.assertBundle(child, [child, self.ca], f"{child.serial}_bundle.pem")

    def test_invalid_format(self) -> None:
        """Test downloading the bundle in an invalid format."""
        response = self.client.get(f"{self.url}?format=INVALID")
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.content == b""

        # DER is not supported for bundles
        response = self.client.get(f"{self.url}?format=DER")
        assert response.status_code == 400
        assert response.content == b"DER/ASN.1 certificates cannot be downloaded as a bundle."

    def test_permission_denied(self) -> None:
        """Test downloading without permissions fails."""
        self.user.is_superuser = False
        self.user.save()

        response = self.client.get(f"{self.url}?format=PEM")
        assert response.status_code == HTTPStatus.FORBIDDEN

    def test_unauthorized(self) -> None:
        """Test viewing as unauthorized viewer."""
        client = Client()
        response = client.get(self.url)
        self.assertRequiresLogin(response)

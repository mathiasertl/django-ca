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

"""Base test cases for admin views and CertificateAdmin tests."""

from django.contrib.auth.models import User  # pylint: disable=[imported-auth-user]  # needed for typehints
from django.test.client import Client
from django.urls import reverse

import pytest
from freezegun import freeze_time
from pytest_django.asserts import assertContains, assertInHTML, assertRedirects

from django_ca.constants import ReasonFlags
from django_ca.models import Certificate, Watcher
from django_ca.tests.base.assertions import assert_change_response, assert_changelist_response
from django_ca.tests.base.constants import TIMESTAMPS
from django_ca.tests.base.typehints import HttpResponse


def assert_cert_change_response(response: HttpResponse, cert: Certificate) -> None:
    """Specialized version of assert_change_response with features unique to certificates."""
    assert_change_response(response, media_css=(("django_ca/admin/css/base.css", "all"),))
    assert response.request["PATH_INFO"] == cert.admin_change_url

    prefix = f"admin:{cert._meta.app_label}_{cert._meta.model_name}"
    url = reverse(f"{prefix}_download", kwargs={"pk": cert.pk})
    bundle_url = reverse(f"{prefix}_download_bundle", kwargs={"pk": cert.pk})
    text = response.content.decode()
    pem = cert.pub.pem.replace("\n", "<br>")  # newlines are replaced with <br> by Django
    assertInHTML(f"<div class='readonly'>{pem}</div>", text, 1)
    assertInHTML(f"<a href='{url}?format=PEM'>as PEM</a>", text, 1)
    assertInHTML(f"<a href='{url}?format=DER'>as DER</a>", text, 1)
    assertInHTML(f"<a href='{bundle_url}?format=PEM'>as PEM</a>", text, 1)


@pytest.mark.django_db
def test_change_view(admin_client: Client, interesting_cert: Certificate) -> None:
    """Test the basic change view for interesting certificates."""
    response = admin_client.get(interesting_cert.admin_change_url)
    assert_cert_change_response(response, interesting_cert)

    html = """
        <div class="flex-container fieldBox field-revoked">
            <label>Revoked:</label>
            <div class="readonly">
                <img src="/static/admin/img/icon-no.svg" alt="False">
            </div>
        </div>"""

    assertContains(response, text=html, html=True)


def test_change_watchers(admin_client: Client, root_cert: Certificate) -> None:
    """Test changing watchers.

    NOTE: This only tests standard Django functionality, BUT save_model() has special handling when
    creating a new object (=sign a new cert). So we have to test saving a cert that already exists for
    code coverage.
    """
    watcher = Watcher.objects.create(name="User", mail="user@example.com")
    response = admin_client.post(root_cert.admin_change_url, data={"watchers": [watcher.pk]})

    assert response.status_code == 302
    assertRedirects(response, root_cert.admin_changelist_url)
    assert list(root_cert.watchers.all()) == [watcher]


def test_change_view_with_revoked_certificate(admin_client: Client, child_cert: Certificate) -> None:
    """View a revoked certificate (fieldset should be collapsed)."""
    child_cert.revoke()
    response = admin_client.get(child_cert.admin_change_url)
    assert_cert_change_response(response, child_cert)

    html = """
        <div class="flex-container fieldBox field-revoked">
            <label>Revoked:</label>
            <div class="readonly">
                <img src="/static/admin/img/icon-yes.svg" alt="True">
            </div>
        </div>
    """

    assertContains(response, text=html, html=True)


def test_change_view_with_no_subject_alternative_name(
    admin_client: Client, no_extensions: Certificate
) -> None:
    """Test viewing a certificate with no extensions."""
    response = admin_client.get(no_extensions.admin_change_url)
    assert_cert_change_response(response, no_extensions)

    html = """
        <div class="form-row field-oid_2_5_29_17">
            <div>
                <div class="flex-container">
                    <label>Subject Alternative Name:</label>
                    <div class="readonly">
                        <span class="django-ca-extension">
                            <div class="django-ca-extension-value">
                                &lt;Not present&gt;
                            </div>
                        </span>
                    </div>
                </div>
            </div>
        </div>"""

    assertContains(response, text=html, html=True)


@freeze_time(TIMESTAMPS["everything_valid"])
def test_changelist_autogenerated_filter(admin_client: Client, root_cert: Certificate) -> None:
    """Test :py:class:`~django_ca.admin.AutoGeneratedFilter`."""
    response = admin_client.get(Certificate.admin_changelist_url)
    assert_changelist_response(response, root_cert)
    response = admin_client.get(Certificate.admin_changelist_url, {"auto": "auto"})
    assert_changelist_response(response)
    response = admin_client.get(Certificate.admin_changelist_url, {"auto": "all"})
    assert_changelist_response(response, root_cert)

    # Mark the certificate as auto-generated:
    root_cert.autogenerated = True
    root_cert.save()

    response = admin_client.get(Certificate.admin_changelist_url)
    assert_changelist_response(response)
    response = admin_client.get(Certificate.admin_changelist_url, {"auto": "auto"})
    assert_changelist_response(response, root_cert)
    response = admin_client.get(Certificate.admin_changelist_url, {"auto": "all"})
    assert_changelist_response(response, root_cert)


def test_changelist_status_filter(
    admin_user: User, admin_client: Client, root_cert: Certificate, child_cert: Certificate
) -> None:
    """Test :py:class:`~django_ca.admin.StatusListFilter`."""
    child_cert.revoke(ReasonFlags.unspecified)
    child_cert.save()

    with freeze_time(TIMESTAMPS["everything_valid"]):
        response = admin_client.get(Certificate.admin_changelist_url)
        assert_changelist_response(response, root_cert)
        response = admin_client.get(Certificate.admin_changelist_url, {"status": "expired"})
        assert_changelist_response(response)
        response = admin_client.get(Certificate.admin_changelist_url, {"status": "revoked"})
        assert_changelist_response(response, child_cert)
        response = admin_client.get(Certificate.admin_changelist_url, {"status": "all"})
        assert_changelist_response(response, root_cert, child_cert)

    with freeze_time(TIMESTAMPS["everything_expired"]):
        admin_client.force_login(admin_user)
        response = admin_client.get(Certificate.admin_changelist_url)
        assert_changelist_response(response)
        response = admin_client.get(Certificate.admin_changelist_url, {"status": "expired"})
        assert_changelist_response(response, root_cert)
        response = admin_client.get(Certificate.admin_changelist_url, {"status": "revoked"})
        assert_changelist_response(response, child_cert)
        response = admin_client.get(Certificate.admin_changelist_url, {"status": "all"})
        assert_changelist_response(response, root_cert, child_cert)

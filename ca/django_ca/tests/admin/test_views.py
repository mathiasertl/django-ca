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

import typing
from http import HTTPStatus
from typing import Dict, Iterable, Iterator, Tuple

from django.test import TestCase
from django.urls import reverse

from freezegun import freeze_time

from django_ca.models import Certificate, Watcher
from django_ca.tests.admin.base import CertificateAdminTestCaseMixin
from django_ca.tests.base import timestamps
from django_ca.tests.base.mixins import StandardAdminViewTestCaseMixin

if typing.TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse as HttpResponse


@freeze_time(timestamps["everything_valid"])
class CertificateAdminViewTestCase(
    CertificateAdminTestCaseMixin, StandardAdminViewTestCaseMixin[Certificate], TestCase
):
    """Tests for the Certificate ModelAdmin class."""

    load_cas = "__usable__"
    load_certs = "__usable__"
    model = Certificate

    def assertChangeResponse(
        self, response: "HttpResponse", obj: Certificate, status: int = HTTPStatus.OK
    ) -> None:
        super().assertChangeResponse(response, obj=obj, status=status)

        prefix = f"admin:{obj._meta.app_label}_{obj._meta.model_name}"
        url = reverse(f"{prefix}_download", kwargs={"pk": obj.pk})
        bundle_url = reverse(f"{prefix}_download_bundle", kwargs={"pk": obj.pk})
        text = response.content.decode()
        pem = obj.pub.pem.replace("\n", "<br>")  # newlines are replaced with HTML linebreaks by Django
        self.assertInHTML(f"<div class='readonly'>{pem}</div>", text, 1)
        self.assertInHTML(f"<a href='{url}?format=PEM'>as PEM</a>", text, 1)
        self.assertInHTML(f"<a href='{url}?format=DER'>as DER</a>", text, 1)
        self.assertInHTML(f"<a href='{bundle_url}?format=PEM'>as PEM</a>", text, 1)

    def get_changelists(
        self,
    ) -> Iterator[Tuple[Iterable[Certificate], Dict[str, str]]]:
        # yield various different result sets for different filters and times
        with self.freeze_time("everything_valid"):
            yield self.model.objects.all(), {}
            yield self.model.objects.all(), {"status": "valid"}
            yield self.model.objects.all(), {"status": "all"}
            yield [], {"status": "expired"}
            yield [], {"status": "revoked"}

            yield [], {"auto": "auto"}
            yield self.model.objects.all(), {"auto": "all"}

        with self.freeze_time("ca_certs_expired"):
            yield self.model.objects.all(), {"status": "all"}
            yield [
                self.certs["profile-client"],
                self.certs["profile-server"],
                self.certs["profile-webserver"],
                self.certs["profile-enduser"],
                self.certs["profile-ocsp"],
                self.certs["no-extensions"],
                self.certs["all-extensions"],
                self.certs["alt-extensions"],
            ], {}
            yield [
                self.certs["root-cert"],
                self.certs["pwd-cert"],
                self.certs["ec-cert"],
                self.certs["ed25519-cert"],
                self.certs["ed448-cert"],
                self.certs["dsa-cert"],
                self.certs["child-cert"],
            ], {"status": "expired"}
            yield [], {"status": "revoked"}

        with self.freeze_time("everything_expired"):
            yield [], {}  # default view shows nothing - everything is expired
            yield self.model.objects.all(), {"status": "all"}
            yield self.model.objects.all(), {"status": "expired"}

        # load all certs (including 3rd party certs) and view with status_all
        with self.freeze_time("everything_valid"):
            self.load_named_cas("__all__")
            self.load_named_certs("__all__")
            yield self.model.objects.all(), {"status": "all"}

            # now revoke all certs, to test that filter
            self.model.objects.update(revoked=True)
            yield self.model.objects.all(), {"status": "all"}
            yield self.model.objects.all(), {"status": "revoked"}
            yield [], {}  # default shows nothing - everything expired

            # unrevoke all certs, but set one of them as auto-generated
            self.model.objects.update(revoked=False)
            self.certs["profile-ocsp"].autogenerated = True
            self.certs["profile-ocsp"].save()

            yield [self.certs["profile-ocsp"]], {"auto": "auto"}
            yield self.model.objects.all(), {"auto": "all", "status": "all"}

    def test_change_view(self) -> None:
        self.load_named_cas("__all__")
        self.load_named_certs("__all__")
        super().test_change_view()

    def test_revoked(self) -> None:
        """View a revoked certificate (fieldset should be collapsed)."""
        self.obj.revoke()
        response = self.client.get(self.change_url())
        self.assertChangeResponse(response, obj=self.obj)

        self.assertContains(
            response,
            text="""<div class="fieldBox field-revoked"><label>Revoked:</label>
                     <div class="readonly"><img src="/static/admin/img/icon-yes.svg" alt="True"></div>
                </div>""",
            html=True,
        )

    def test_no_san(self) -> None:
        """Test viewing a certificate with no extensions."""
        cert = self.certs["no-extensions"]
        response = self.client.get(cert.admin_change_url)
        self.assertChangeResponse(response, obj=cert)
        self.assertContains(
            response,
            text="""
<div class="form-row field-oid_2_5_29_17">
    <div>
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
""",
            html=True,
        )

    def test_change_watchers(self) -> None:
        """Test changing watchers.

        NOTE: This only tests standard Django functionality, BUT save_model() has special handling when
        creating a new object (=sign a new cert). So we have to test saving a cert that already exists for
        code coverage.
        """

        watcher = Watcher.objects.create(name="User", mail="user@example.com")
        response = self.client.post(self.change_url(), data={"watchers": [watcher.pk]})

        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, self.changelist_url)
        self.assertEqual(list(self.obj.watchers.all()), [watcher])

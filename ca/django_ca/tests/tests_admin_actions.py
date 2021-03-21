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

"""Test cases to test various admin actions."""

from contextlib import contextmanager
from http import HTTPStatus

from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.test import Client
from django.urls import reverse

from django_webtest import WebTestMixin
from freezegun import freeze_time

from .. import ca_settings
from ..constants import ReasonFlags
from ..models import Certificate
from ..signals import post_issue_cert
from ..signals import post_revoke_cert
from ..signals import pre_issue_cert
from ..signals import pre_revoke_cert
from .base import DjangoCAWithGeneratedCertsTestCase
from .base import override_tmpcadir
from .base import timestamps
from .base_mixins import AdminTestCaseMixin


class AdminActionTestCaseMixin(AdminTestCaseMixin):
    """TestCase mixin for normal Django admin actions."""

    action = ""
    insufficient_permissions = []
    required_permissions = []

    def setUp(self):
        super().setUp()
        self.data = {"action": self.action, "_selected_action": [self.obj.pk]}

    def assertFailedRequest(self, response, *objects):  # pylint: disable=invalid-name
        """Assert that a request did not have any effect."""
        raise NotImplementedError

    def assertSuccessfulRequest(self, response, *objects):  # pylint: disable=invalid-name
        """Assert that the request was successful."""
        raise NotImplementedError

    def test_user_is_staff_only(self):
        """Test that an action does **not** work when the user is only staff with no permissions."""
        self.user.is_superuser = False
        self.user.user_permissions.clear()
        self.user.save()

        response = self.client.post(self.changelist_url, self.data)
        self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)
        self.assertFailedRequest(response, self.obj)

    def test_insufficient_permissions(self):
        """Test with insufficient permissions.

        Note that Django is very peculiar about the required permissions for admin actions:

        * By *default*, the view permission is sufficient.
        * If a different required permission is required, Django behaves differently depending on if the view
          permission is present or not:

          * If it is **not** present, it will return a HTTP 403.
          * If it is present, it will return HTTP 200.
        """
        self.user.is_superuser = False
        self.user.user_permissions.clear()
        self.user.save()

        # Test if the view permission is not the only action required anyway. If yes, that would mean the code
        # below would actually succeed.
        view_codename = "view_%s" % self.model._meta.model_name
        if self.required_permissions == ["%s.%s" % (self.model._meta.app_label, view_codename)]:
            return

        # Add view permission for the model. If we do not have it, Django will just return FORBIDDEN like in
        # test_user_is_staff_only().
        ctype = ContentType.objects.get_for_model(self.model)
        view_perm = Permission.objects.get(content_type=ctype, codename=view_codename)
        self.user.user_permissions.add(view_perm)

        for perm in self.insufficient_permissions:
            app, name = perm.split(".", 1)
            self.user.user_permissions.add(Permission.objects.get(codename=name, content_type__app_label=app))

        response = self.client.post(self.changelist_url, self.data)
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertFailedRequest(response, self.obj)

    def test_required_permissions(self):
        """Test that the required permissions make the request work."""
        self.user.is_superuser = False
        self.user.user_permissions.clear()
        self.user.save()

        for perm in self.required_permissions:
            app, name = perm.split(".", 1)
            self.user.user_permissions.add(Permission.objects.get(codename=name, content_type__app_label=app))

        response = self.client.post(self.changelist_url, self.data)
        self.assertRedirects(response, self.changelist_url)
        self.assertSuccessfulRequest(response, self.obj)


class AdminChangeActionTestCaseMixin(AdminTestCaseMixin):
    """Mixin to test Django object actions."""

    data = {}
    tool = ""
    pre_signal = None
    post_signal = None

    def get_url(self, obj):
        """Get action URL of the given object."""
        view_name = "admin:%s_%s_actions" % (self.model._meta.app_label, self.model._meta.model_name)
        return reverse(view_name, kwargs={"pk": obj.pk, "tool": self.tool})

    @property
    def url(self):
        """Get default url for this test case."""
        return self.get_url(obj=self.obj)

    def assertFailedRequest(self, response, obj=None):  # pylint: disable=invalid-name
        """Assert that a request did not have any effect."""
        raise NotImplementedError

    def assertForbidden(self, response, obj=None):  # pylint: disable=invalid-name
        """Assert that the action returned HTTP 403 (Forbidden)."""
        self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)
        self.assertFailedRequest(response, obj=obj)

    @contextmanager
    def assertNoSignals(self):  # pylint: disable=invalid-name
        """Shortcut to assert that **no** signals where called."""
        with self.assertSignals(False, False) as (pre, post):
            yield pre, post

    def assertRequiresLogin(self, response, **kwargs):  # pylint: disable=invalid-name
        """Overwritten as a shortcut to also test that the certificate was not revoked."""
        super().assertRequiresLogin(response, **kwargs)
        self.assertFailedRequest(response)

    @contextmanager
    def assertSignals(self, pre_called=True, post_called=True):  # pylint: disable=invalid-name
        """Assert that the singals were (not) called."""
        with self.assertSignal(self.pre_signal) as pre, self.assertSignal(self.post_signal) as post:
            try:
                yield pre, post
            finally:
                self.assertEqual(pre.called, pre_called)
                self.assertEqual(post.called, post_called)

    def assertSuccessfulRequest(self, response, obj=None):  # pylint: disable=invalid-name
        """Assert that the request was successful."""
        raise NotImplementedError

    @override_tmpcadir()
    def test_get(self):
        """Just test getting the page."""
        with self.assertNoSignals():
            response = self.client.get(self.url)
        self.assertEqual(response.status_code, HTTPStatus.OK)

    def test_anonymous(self):
        """Test performing action as anonymous user."""
        client = Client()
        with self.assertNoSignals():
            self.assertRequiresLogin(client.get(self.url))
            self.assertRequiresLogin(client.post(self.url, data=self.data))

    def test_plain_user(self):
        """Test that a plain user (no staff, no permissions) cannot perform this action."""
        self.user.is_superuser = self.user.is_staff = False
        self.user.save()

        with self.assertNoSignals():
            self.assertRequiresLogin(self.client.get(self.url))
            self.assertRequiresLogin(self.client.post(self.url, data=self.data))

    def test_permissions_required(self):
        """Test that action requires the change_certificate permission."""
        self.user.is_superuser = False
        self.user.save()

        with self.assertNoSignals():
            self.assertForbidden(self.client.get(self.url))
            self.assertForbidden(self.client.post(self.url, self.data))

    def test_is_staff_is_required(self):
        """Test that action requires is_staff, even if the user has the right permissions."""

        self.user.is_superuser = self.user.is_staff = False
        self.user.save()
        self.user.user_permissions.add(Permission.objects.get(codename="change_certificate"))

        with self.assertNoSignals():
            self.assertRequiresLogin(self.client.get(self.url))
            self.assertRequiresLogin(self.client.post(self.url, data=self.data))

    def test_unknown_object(self):
        """Test an unknown object (get_change_actions() fetches object, so it should work)."""
        with self.assertSignals(False, False):
            # pylint: disable=not-callable; self.model is None in Mixin
            response = self.client.get(self.change_url(self.model(pk=1234)))
        self.assertRedirects(response, "/admin/")


@freeze_time(timestamps["everything_valid"])
class RevokeActionTestCase(AdminActionTestCaseMixin, DjangoCAWithGeneratedCertsTestCase):
    """Test the revoke action."""

    action = "revoke"
    model = Certificate
    required_permissions = ["django_ca.change_certificate"]

    def assertFailedRequest(self, response, *objects):
        for obj in objects:
            self.assertNotRevoked(obj)

    def assertSuccessfulRequest(self, response, *objects):
        for obj in objects:
            self.assertRevoked(obj)


@freeze_time(timestamps["everything_valid"])
class RevokeChangeActionTestCase(AdminChangeActionTestCaseMixin, DjangoCAWithGeneratedCertsTestCase):
    """Test the revoke change action."""

    model = Certificate
    data = {"revoked_reason": ""}  # default post data
    tool = "revoke_change"
    pre_signal = pre_revoke_cert
    post_signal = post_revoke_cert

    def assertFailedRequest(self, response, obj=None):
        obj = obj or self.obj
        self.assertNotRevoked(obj)

    def assertSuccessfulRequest(self, response, obj=None, reason=""):  # pylint: disable=arguments-differ
        self.assertRedirects(response, self.change_url())
        self.assertTemplateUsed("admin/django_ca/certificate/revoke_form.html")
        self.assertRevoked(self.obj, reason=reason)

    def test_no_reason(self):
        """Test revoking without any reason."""
        with self.assertSignals():
            response = self.client.post(self.url, data={"revoked_reason": ""})
        self.assertSuccessfulRequest(response, reason="unspecified")

    def test_with_reason(self):
        """Test revoking a certificate with an explicit reason."""
        reason = ReasonFlags.certificate_hold
        with self.assertSignals():
            response = self.client.post(self.url, data={"revoked_reason": reason.name})
        self.assertSuccessfulRequest(response, reason=reason.name)

    def test_with_bogus_reason(self):
        """Try setting an invalid reason."""
        reason = "bogus"
        with self.assertNoSignals():
            response = self.client.post(self.url, data={"revoked_reason": reason})
        self.assertNotRevoked(self.obj)
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertTemplateUsed("admin/django_ca/certificate/revoke_form.html")
        self.assertEqual(
            response.context["form"].errors,
            {"revoked_reason": ["Select a valid choice. bogus is not one of the available choices."]},
        )

    def test_revoked(self):
        """Try revoking a certificate that already is revoked."""
        cert = Certificate.objects.get(serial=self.obj.serial)
        cert.revoke()
        cert.save()

        # Viewing page already redirects to change URL
        with self.assertNoSignals():
            self.assertRedirects(self.client.get(self.url), self.change_url())

        # Revoke a second time, which does not update the reason
        with self.assertNoSignals():
            response = self.client.post(self.url, data={"revoked_reason": "certificateHold"})
        self.assertRedirects(response, self.change_url())
        self.assertRevoked(self.obj)


@freeze_time(timestamps["everything_valid"])
class ResignChangeActionTestCase(
    AdminChangeActionTestCaseMixin, WebTestMixin, DjangoCAWithGeneratedCertsTestCase
):
    """Test the resign change action."""

    model = Certificate
    tool = "resign"
    pre_signal = pre_issue_cert
    post_signal = post_issue_cert

    def setUp(self):
        super().setUp()
        self.obj.profile = "webserver"
        self.obj.save()

    def assertFailedRequest(self, response, obj=None):
        obj = obj or self.obj
        self.assertEqual(self.model.objects.filter(cn=obj.cn).count(), 1)

    def assertSuccessfulRequest(self, response, obj=None):
        obj = obj or self.obj
        resigned = Certificate.objects.filter(cn=obj.cn).exclude(pk=obj.pk).get()

        self.assertFalse(resigned.revoked)
        self.assertFalse(obj.revoked)
        self.assertEqual(obj.cn, resigned.cn)
        self.assertEqual(obj.csr, resigned.csr)
        self.assertEqual(obj.profile, resigned.profile)
        self.assertEqual(obj.distinguished_name, resigned.distinguished_name)
        self.assertEqual(obj.extended_key_usage, resigned.extended_key_usage)
        self.assertEqual(obj.key_usage, resigned.key_usage)
        self.assertEqual(obj.subject_alternative_name, resigned.subject_alternative_name)
        self.assertEqual(obj.tls_feature, resigned.tls_feature)

        # Some properties are obviously *not* equal
        self.assertNotEqual(obj.pub, resigned.pub)
        self.assertNotEqual(obj.serial, resigned.serial)

    @property
    def data(self):
        """Return default data."""
        return {
            "ca": self.obj.ca.pk,
            "profile": "webserver",
            "subject_5": self.obj.cn,
            "subject_alternative_name_1": True,
            "algorithm": "SHA256",
            "expires": self.obj.ca.expires.strftime("%Y-%m-%d"),
            "key_usage_0": ["digitalSignature", "keyAgreement", "keyEncipherment"],
            "key_usage_1": True,
            "extended_key_usage_0": [
                "clientAuth",
                "serverAuth",
            ],
            "extended_key_usage_1": False,
            "tls_feature_0": [],
            "tls_feature_1": False,
        }

    @override_tmpcadir()
    def test_resign(self):
        """Try a basic resign request."""
        with self.assertSignals():
            response = self.client.post(self.url, data=self.data)
        self.assertSuccessfulRequest(response)
        self.assertRedirects(response, self.changelist_url)

    @override_tmpcadir()  # otherwise there are no usable CAs, hiding the message we want to test
    def test_no_csr(self):
        """Try resigning a cert that has no CSR."""
        self.obj.csr = ""
        self.obj.save()

        with self.assertNoSignals():
            response = self.client.get(self.url)
        self.assertRedirects(response, self.change_url())
        self.assertMessages(response, ["Certificate has no CSR (most likely because it was imported)."])

    @override_tmpcadir()
    def test_no_profile(self):
        """Test that resigning a cert with no stored profile stores the default profile."""

        self.obj.profile = ""
        self.obj.save()
        form = self.app.get(self.url, user=self.user.username).form
        form.submit().follow()

        resigned = Certificate.objects.filter(cn=self.obj.cn).exclude(pk=self.obj.pk).get()
        self.assertEqual(resigned.profile, ca_settings.CA_DEFAULT_PROFILE)

    @override_tmpcadir()
    def test_webtest_basic(self):
        """Resign basic certificate."""
        form = self.app.get(self.url, user=self.user.username).form
        response = form.submit().follow()
        self.assertSuccessfulRequest(response)

    @override_tmpcadir()
    def test_webtest_all(self):
        """Resign certificate with **all** extensions."""
        cert = self.certs["all-extensions"]
        cert.profile = "webserver"
        cert.save()
        form = self.app.get(self.get_url(cert), user=self.user.username).form
        response = form.submit().follow()
        self.assertSuccessfulRequest(response, obj=cert)

    @override_tmpcadir(CA_DEFAULT_SUBJECT={})
    def test_webtest_no_ext(self):
        """Resign certificate with **no** extensions."""
        cert = self.certs["no-extensions"]
        cert.profile = "webserver"
        cert.save()
        form = self.app.get(self.get_url(cert), user=self.user.username).form
        response = form.submit().follow()
        self.assertSuccessfulRequest(response, obj=cert)

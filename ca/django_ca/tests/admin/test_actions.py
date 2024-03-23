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

"""Test cases to test various admin actions."""

import json
import typing
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone as tz
from http import HTTPStatus
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union
from unittest import mock

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.dispatch.dispatcher import Signal
from django.test import Client, TestCase
from django.urls import reverse

from django_webtest import DjangoWebtestResponse, WebTestMixin
from freezegun import freeze_time

from django_ca import ca_settings
from django_ca.constants import ReasonFlags
from django_ca.models import Certificate, X509CertMixin
from django_ca.pydantic.general_name import GeneralNameModelList
from django_ca.signals import post_issue_cert, post_revoke_cert, pre_revoke_cert, pre_sign_cert
from django_ca.tests.base.assertions import assert_revoked
from django_ca.tests.base.constants import TIMESTAMPS
from django_ca.tests.base.mixins import AdminTestCaseMixin
from django_ca.tests.base.mocks import mock_signal
from django_ca.tests.base.typehints import DjangoCAModelTypeVar
from django_ca.tests.base.utils import override_tmpcadir

if typing.TYPE_CHECKING:
    from django.test.client import _MonkeyPatchedWSGIResponse as HttpResponse


class AdminActionTestCaseMixin(
    AdminTestCaseMixin[DjangoCAModelTypeVar], typing.Generic[DjangoCAModelTypeVar]
):
    """TestCase mixin for normal Django admin actions."""

    action = ""
    data: Dict[str, Any]
    insufficient_permissions: Tuple[str, ...] = ()
    required_permissions: Tuple[str, ...] = ()

    def assertFailedRequest(  # pylint: disable=invalid-name
        self, response: "HttpResponse", *objects: DjangoCAModelTypeVar
    ) -> None:
        """Assert that a request did not have any effect."""
        raise NotImplementedError

    def assertSuccessfulRequest(  # pylint: disable=invalid-name
        self, response: "HttpResponse", *objects: DjangoCAModelTypeVar
    ) -> None:
        """Assert that the request was successful."""
        raise NotImplementedError

    def test_user_is_staff_only(self) -> None:
        """Test that an action does **not** work when the user is only staff with no permissions."""
        self.user.is_superuser = False
        self.user.user_permissions.clear()
        self.user.save()

        for obj in self.get_objects():
            response = self.client.post(self.changelist_url, self.data)
            self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)
            self.assertFailedRequest(response, obj)

    def test_insufficient_permissions(self) -> None:
        """Test with insufficient permissions.

        Note that Django is very peculiar about the required permissions for admin actions:

        * By *default*, the view permission is sufficient.
        * If a different required permission is required, Django behaves differently depending on if the view
          permission is present or not:

          * If it is **not** present, it will return an HTTP 403.
          * If it is present, it will return HTTP 200.
        """
        self.user.is_superuser = False
        self.user.user_permissions.clear()
        self.user.save()

        # Test if the view permission is not the only action required anyway. If yes, that would mean the code
        # below would actually succeed.
        view_codename = f"view_{self.model._meta.model_name}"
        if self.required_permissions == (f"{self.model._meta.app_label}{view_codename}",):
            return

        # Add view permission for the model. If we do not have it, Django will just return FORBIDDEN like in
        # test_user_is_staff_only().
        ctype = ContentType.objects.get_for_model(self.model)
        view_perm = Permission.objects.get(content_type=ctype, codename=view_codename)
        self.user.user_permissions.add(view_perm)

        for perm in self.insufficient_permissions:
            app, name = perm.split(".", 1)
            self.user.user_permissions.add(Permission.objects.get(codename=name, content_type__app_label=app))

        for obj in self.get_objects():
            response = self.client.post(self.changelist_url, self.data)
            self.assertEqual(response.status_code, HTTPStatus.OK)
            self.assertFailedRequest(response, obj)

    def test_required_permissions(self) -> None:
        """Test that the required permissions make the request work."""
        self.user.is_superuser = False
        self.user.user_permissions.clear()
        self.user.save()

        for perm in self.required_permissions:
            app, name = perm.split(".", 1)
            self.user.user_permissions.add(Permission.objects.get(codename=name, content_type__app_label=app))

        for obj in self.get_objects():
            response = self.client.post(self.changelist_url, self.data)
            self.assertRedirects(response, self.changelist_url)
            self.assertSuccessfulRequest(response, obj)


class AdminChangeActionTestCaseMixin(
    AdminTestCaseMixin[DjangoCAModelTypeVar], typing.Generic[DjangoCAModelTypeVar]
):
    """Mixin to test Django object actions."""

    load_cas = (
        "root",
        "child",
    )
    load_certs = ("profile-webserver",)
    data: Dict[str, Any]
    tool = ""
    pre_signal: Signal
    post_signal: Signal

    def get_url(self, obj: DjangoCAModelTypeVar) -> str:
        """Get action URL of the given object."""
        view_name = f"admin:{self.model._meta.app_label}_{self.model._meta.model_name}_actions"
        return reverse(view_name, kwargs={"pk": obj.pk, "tool": self.tool})

    def assertFailedRequest(  # pylint: disable=invalid-name
        self, response: "HttpResponse", obj: Optional[DjangoCAModelTypeVar] = None
    ) -> None:
        """Assert that a request did not have any effect."""
        raise NotImplementedError

    def assertForbidden(  # pylint: disable=invalid-name
        self, response: "HttpResponse", obj: Optional[DjangoCAModelTypeVar] = None
    ) -> None:
        """Assert that the action returned HTTP 403 (Forbidden)."""
        self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)
        self.assertFailedRequest(response, obj=obj)

    @contextmanager
    def assertNoSignals(  # pylint: disable=invalid-name
        self,
    ) -> Iterator[Tuple[mock.MagicMock, mock.MagicMock]]:
        """Shortcut to assert that **no** signals where called."""
        with self.mockSignals(False, False) as (pre, post):
            yield pre, post

    def assertRequiresLogin(self, response: "HttpResponse", **kwargs: Any) -> None:
        """Overwritten as a shortcut to also test that the certificate was not revoked."""
        super().assertRequiresLogin(response, **kwargs)
        self.assertFailedRequest(response)

    def assertSuccessfulRequest(  # pylint: disable=invalid-name
        self, response: "HttpResponse", obj: Optional[DjangoCAModelTypeVar] = None
    ) -> None:
        """Assert that the request was successful."""
        raise NotImplementedError

    @contextmanager
    def mockSignals(  # pylint: disable=invalid-name
        self, pre_called: bool = True, post_called: bool = True
    ) -> Iterator[Tuple[mock.Mock, mock.Mock]]:
        """Assert that the signals were (not) called."""
        with mock_signal(self.pre_signal) as pre, mock_signal(self.post_signal) as post:
            try:
                yield pre, post
            finally:
                assert pre.called is pre_called
                assert post.called is post_called

    @override_tmpcadir()
    def test_get(self) -> None:
        """Just test getting the page."""
        for obj in self.get_objects():
            with self.assertNoSignals():
                response = self.client.get(self.get_url(obj=obj))
            self.assertEqual(response.status_code, HTTPStatus.OK)

    def test_anonymous(self) -> None:
        """Test performing action as anonymous user."""
        client = Client()
        for obj in self.get_objects():
            url = self.get_url(obj)
            with self.assertNoSignals():
                self.assertRequiresLogin(client.get(url))
                self.assertRequiresLogin(client.post(url, data=self.data))

    def test_plain_user(self) -> None:
        """Test that a plain user (no staff, no permissions) cannot perform this action."""
        self.user.is_superuser = self.user.is_staff = False
        self.user.save()

        for obj in self.get_objects():
            url = self.get_url(obj)
            with self.assertNoSignals():
                self.assertRequiresLogin(self.client.get(url))
                self.assertRequiresLogin(self.client.post(url, data=self.data))

    def test_permissions_required(self) -> None:
        """Test that action requires the change_certificate permission."""
        self.user.is_superuser = False
        self.user.save()

        for obj in self.get_objects():
            url = self.get_url(obj)
            with self.assertNoSignals():
                self.assertForbidden(self.client.get(url))
                self.assertForbidden(self.client.post(url, self.data))

    def test_is_staff_is_required(self) -> None:
        """Test that action requires is_staff, even if the user has the right permissions."""
        self.user.is_superuser = self.user.is_staff = False
        self.user.save()
        self.user.user_permissions.add(Permission.objects.get(codename="change_certificate"))

        for obj in self.get_objects():
            url = self.get_url(obj)
            with self.assertNoSignals():
                self.assertRequiresLogin(self.client.get(url))
                self.assertRequiresLogin(self.client.post(url, data=self.data))

    def test_unknown_object(self) -> None:
        """Test an unknown object (get_change_actions() fetches object, so it should work)."""
        with self.mockSignals(False, False):
            response = self.client.get(self.change_url(self.model(pk=1234)))
        self.assertRedirects(response, "/admin/")


@freeze_time(TIMESTAMPS["everything_valid"])
class RevokeActionTestCase(AdminActionTestCaseMixin[Certificate], TestCase):
    """Test the revoke action."""

    load_cas = ("root",)
    load_certs = ("root-cert",)
    action = "revoke"
    model = Certificate
    required_permissions = ("django_ca.change_certificate",)

    def setUp(self) -> None:
        super().setUp()
        self.data = {"action": self.action, "_selected_action": [self.cert.pk]}

    def assertFailedRequest(self, response: "HttpResponse", *objects: Certificate) -> None:
        for obj in objects:
            self.assertNotRevoked(obj)

    def assertSuccessfulRequest(self, response: "HttpResponse", *objects: Certificate) -> None:
        for obj in objects:
            assert_revoked(obj)


@freeze_time(TIMESTAMPS["everything_valid"])
class RevokeChangeActionTestCase(AdminChangeActionTestCaseMixin[Certificate], TestCase):
    """Test the revoke change action."""

    model = Certificate
    tool = "revoke_change"
    pre_signal = pre_revoke_cert
    post_signal = post_revoke_cert

    def setUp(self) -> None:
        super().setUp()
        self.data = {"revoked_reason": ""}  # default post data

    def assertFailedRequest(self, response: "HttpResponse", obj: Optional[Certificate] = None) -> None:
        obj = obj or self.cert
        self.assertNotRevoked(obj)

    def assertFormValidationError(  # pylint: disable=invalid-name
        self, cert: X509CertMixin, response: "HttpResponse", **errors: List[str]
    ) -> None:
        """Assert that the form validation failed with the given errors."""
        self.assertNotRevoked(cert)
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertTemplateUsed("admin/django_ca/certificate/revoke_form.html")
        self.assertEqual(response.context["form"].errors, errors)

    def assertSuccessfulRequest(
        self,
        response: "HttpResponse",
        obj: Optional[Certificate] = None,
        reason: str = "unspecified",
        compromised: Optional[datetime] = None,
    ) -> None:
        self.assertRedirects(response, self.change_url())
        self.assertTemplateUsed("admin/django_ca/certificate/revoke_form.html")
        assert_revoked(self.cert, reason=reason, compromised=compromised)

    def test_no_reason(self) -> None:
        """Test revoking without any reason."""
        for obj in self.get_objects():
            with self.mockSignals():
                response = self.client.post(self.get_url(obj), data={"revoked_reason": ""})
        self.assertSuccessfulRequest(response)

    def test_with_reason(self) -> None:
        """Test revoking a certificate with an explicit reason."""
        reason = ReasonFlags.certificate_hold
        for obj in self.get_objects():
            with self.mockSignals():
                response = self.client.post(self.get_url(obj), data={"revoked_reason": reason.name})
            self.assertSuccessfulRequest(response, reason=reason.name)

    def test_with_compromised(self) -> None:
        """Test revoking a certificate with a revocation date."""
        value = datetime.now(tz=tz.utc) - timedelta(days=1)
        data = {"compromised_0": value.strftime("%Y-%m-%d"), "compromised_1": value.strftime("%H:%M:%S")}

        with self.mockSignals():
            response = self.client.post(self.get_url(self.cert), data=data)
        self.assertSuccessfulRequest(response, compromised=value)

    def test_with_compromised_without_use_tz(self) -> None:
        """Test revoking a certificate with a revocation date with USE_TZ=False."""
        value = datetime.now() - timedelta(days=1)
        data = {"compromised_0": value.strftime("%Y-%m-%d"), "compromised_1": value.strftime("%H:%M:%S")}

        with self.mockSignals(), self.settings(USE_TZ=False):
            response = self.client.post(self.get_url(self.cert), data=data)
            self.assertSuccessfulRequest(response, compromised=value)

    def test_compromised_in_the_future(self) -> None:
        """Test that the compromised must be in the past."""
        value = datetime.now() + timedelta(days=1)
        data = {"compromised_0": value.strftime("%Y-%m-%d"), "compromised_1": value.strftime("%H:%M:%S")}

        with self.assertNoSignals():
            response = self.client.post(self.get_url(self.cert), data=data)
        self.assertFormValidationError(self.cert, response, compromised=["Date must be in the past!"])

    def test_with_bogus_reason(self) -> None:
        """Try setting an invalid reason."""
        reason = "bogus"
        with self.assertNoSignals():
            response = self.client.post(self.get_url(self.cert), data={"revoked_reason": reason})
        self.assertFormValidationError(
            self.cert,
            response,
            revoked_reason=["Select a valid choice. bogus is not one of the available choices."],
        )

    def test_revoked(self) -> None:
        """Try revoking a certificate that already is revoked."""
        cert = Certificate.objects.get(serial=self.cert.serial)
        cert.revoke()
        cert.save()

        # Viewing page already redirects to change URL
        with self.assertNoSignals():
            self.assertRedirects(self.client.get(self.get_url(self.cert)), self.change_url())

        # Revoke a second time, which does not update the reason
        with self.assertNoSignals():
            response = self.client.post(self.get_url(self.cert), data={"revoked_reason": "certificateHold"})
        self.assertRedirects(response, self.change_url())
        assert_revoked(self.cert)


@freeze_time(TIMESTAMPS["everything_valid"])
class ResignChangeActionTestCase(AdminChangeActionTestCaseMixin[Certificate], WebTestMixin, TestCase):
    """Test the "resign" change action."""

    model = Certificate
    tool = "resign"
    pre_signal = pre_sign_cert
    post_signal = post_issue_cert

    def assertFailedRequest(self, response: "HttpResponse", obj: Optional[Certificate] = None) -> None:
        obj = obj or self.cert
        self.assertEqual(self.model.objects.filter(cn=obj.cn).count(), 1)

    def assertSuccessfulRequest(
        self,
        response: Union[DjangoWebtestResponse, "HttpResponse"],
        obj: Optional[Certificate] = None,
    ) -> None:
        obj = obj or self.cert
        obj.refresh_from_db()
        resigned = Certificate.objects.filter(cn=obj.cn).exclude(pk=obj.pk).get()

        self.assertFalse(resigned.revoked)
        self.assertFalse(obj.revoked)
        self.assertEqual(obj.cn, resigned.cn)
        self.assertEqual(obj.csr, resigned.csr)
        self.assertEqual(obj.profile, resigned.profile)
        self.assertEqual(obj.cn, resigned.cn)
        self.assertEqual(obj.algorithm, resigned.algorithm)

        for oid in [
            ExtensionOID.EXTENDED_KEY_USAGE,
            ExtensionOID.TLS_FEATURE,
            ExtensionOID.KEY_USAGE,
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
        ]:
            self.assertEqual(obj.extensions.get(oid), resigned.extensions.get(oid))

        # Some properties are obviously *not* equal
        self.assertNotEqual(obj.pub, resigned.pub)
        self.assertNotEqual(obj.serial, resigned.serial)

    @property
    def data(self) -> Dict[str, Any]:  # type: ignore[override]
        """Return default data."""
        # mypy override: https://github.com/python/mypy/issues/4125
        san = typing.cast(
            x509.SubjectAlternativeName,
            self.cert.extensions[ExtensionOID.SUBJECT_ALTERNATIVE_NAME].value,
        )
        models = GeneralNameModelList.validate_python(list(san))
        serialized = [m.model_dump(mode="json") for m in models]

        return {
            "ca": self.cert.ca.pk,
            "profile": "webserver",
            "subject": json.dumps([{"oid": NameOID.COMMON_NAME.dotted_string, "value": self.cert.cn}]),
            "subject_alternative_name_0": json.dumps(serialized),
            "subject_alternative_name_1": False,
            "algorithm": "SHA-256",
            "expires": self.cert.ca.expires.strftime("%Y-%m-%d"),
            "key_usage_0": ["digital_signature", "key_agreement", "key_encipherment"],
            "key_usage_1": True,
            "extended_key_usage_0": [ExtendedKeyUsageOID.SERVER_AUTH.dotted_string],
            "extended_key_usage_1": False,
            "tls_feature_0": [],
            "tls_feature_1": False,
        }

    @override_tmpcadir()
    def test_resign(self) -> None:
        """Try a basic resign request."""
        with self.mockSignals():
            url = self.get_url(self.cert)
            response = self.client.post(url, data=self.data)
        self.assertRedirects(response, self.changelist_url)
        self.assertSuccessfulRequest(response)

    @override_tmpcadir()  # otherwise there are no usable CAs, hiding the message we want to test
    def test_no_csr(self) -> None:
        """Try resigning a cert that has no CSR."""
        self.cert.csr = ""
        self.cert.save()

        for obj in self.get_objects():
            with self.assertNoSignals():
                response = self.client.get(self.get_url(obj))
        self.assertRedirects(response, self.change_url())
        self.assertMessages(response, ["Certificate has no CSR (most likely because it was imported)."])

    @override_tmpcadir()
    def test_no_profile(self) -> None:
        """Test that resigning a cert with no stored profile stores the default profile."""
        self.cert.profile = ""
        self.cert.save()
        response = self.app.get(self.get_url(self.cert), user=self.user.username)
        form = response.forms["certificate_form"]
        form.submit().follow()

        resigned = Certificate.objects.filter(cn=self.cert.cn).exclude(pk=self.cert.pk).get()
        self.assertEqual(resigned.profile, ca_settings.CA_DEFAULT_PROFILE)

    @override_tmpcadir()
    def test_webtest_basic(self) -> None:
        """Resign basic certificate."""
        response = self.app.get(self.get_url(self.cert), user=self.user.username)
        form = response.forms["certificate_form"]
        response = form.submit().follow()
        self.assertSuccessfulRequest(response)

    @override_tmpcadir()
    def test_webtest_all(self) -> None:
        """Resign certificate with **all** extensions."""
        cert = self.load_named_cert("all-extensions")
        cert.profile = "webserver"
        cert.save()
        response = self.app.get(self.get_url(cert), user=self.user.username)
        form = response.forms["certificate_form"]
        response = form.submit().follow()
        self.assertSuccessfulRequest(response, obj=cert)

    @override_tmpcadir(CA_DEFAULT_SUBJECT=tuple())
    def test_webtest_no_ext(self) -> None:
        """Resign certificate with **no** extensions."""
        cert = self.load_named_cert("no-extensions")
        cert.profile = "webserver"
        cert.save()
        response = self.app.get(self.get_url(cert), user=self.user.username)
        form = response.forms["certificate_form"]
        response = form.submit().follow()
        self.assertSuccessfulRequest(response, obj=cert)

    @override_tmpcadir()
    def test_webtest_dsa(self) -> None:
        """Resign certificate signed with a DSA CA."""
        self.load_ca("dsa")
        cert = self.load_named_cert("dsa-cert")
        cert.profile = "webserver"
        cert.save()
        response = self.app.get(self.get_url(cert), user=self.user.username)
        form = response.forms["certificate_form"]
        response = form.submit().follow()
        self.assertSuccessfulRequest(response, obj=cert)

    @override_tmpcadir()
    def test_webtest_ed448(self) -> None:
        """Resign certificate signed with an Ed448 CA."""
        self.load_ca("ed448")
        cert = self.load_named_cert("ed448-cert")
        cert.profile = "webserver"
        cert.save()
        response = self.app.get(self.get_url(cert), user=self.user.username)
        form = response.forms["certificate_form"]
        response = form.submit().follow()
        self.assertSuccessfulRequest(response, obj=cert)

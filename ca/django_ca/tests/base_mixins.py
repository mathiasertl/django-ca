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

"""Collection of mixin classes for unittest.TestCase subclasses."""

import typing
from contextlib import contextmanager
from datetime import datetime
from http import HTTPStatus
from io import StringIO
from unittest import mock
from urllib.parse import quote

from cryptography import x509

from django.conf import settings
from django.contrib.auth.models import User  # pylint: disable=imported-auth-user; for mypy
from django.core.management import ManagementUtility
from django.core.management import call_command
from django.db import models
from django.http import HttpResponse
from django.templatetags.static import static
from django.test.testcases import SimpleTestCase
from django.urls import reverse

from freezegun import freeze_time
from freezegun.api import FrozenDateTimeFactory

from ..models import Certificate
from ..models import CertificateAuthority
from ..models import DjangoCAModel
from ..models import X509CertMixin
from .base import certs
from .base import timestamps

if typing.TYPE_CHECKING:
    # Use SimpleTestCase as base class when type checking. This way mypy will know about attributes/methods
    # that the mixin accesses. See also:
    #   https://github.com/python/mypy/issues/5837
    TestCaseProtocol = SimpleTestCase
else:
    TestCaseProtocol = object

DjangoCAModelTypeVar = typing.TypeVar("DjangoCAModelTypeVar", bound=DjangoCAModel)
X509CertMixinTypeVar = typing.TypeVar("X509CertMixinTypeVar", bound=X509CertMixin)


class TestCaseMixin(TestCaseProtocol):
    """Mixin providing augmented functionality to all test cases."""

    load_cas: typing.Iterable[str]
    load_certs: typing.Iterable[str]
    new_cas: typing.Dict[str, CertificateAuthority]
    new_certs: typing.Dict[str, Certificate]

    def setUp(self) -> None:  # pylint: disable=invalid-name,missing-function-docstring
        super().setUp()

    def absolute_uri(self, name: str, hostname: typing.Optional[str] = None, **kwargs: typing.Any) -> str:
        """Build an absolute uri for the given request.

        The `name` is assumed to be a URL name or a full path. If `name` starts with a colon, ``django_ca``
        is used as namespace.
        """

        if hostname is None:
            hostname = settings.ALLOWED_HOSTS[0]

        if name.startswith("/"):
            return "http://%s%s" % (hostname, name)
        if name.startswith(":"):  # pragma: no branch
            name = "django_ca%s" % name
        return "http://%s%s" % (hostname, reverse(name, kwargs=kwargs))

    def cmd(self, *args: typing.Any, **kwargs: typing.Any) -> typing.Tuple[str, str]:
        """Call to a manage.py command using call_command."""
        kwargs.setdefault("stdout", StringIO())
        kwargs.setdefault("stderr", StringIO())
        stdin = kwargs.pop("stdin", StringIO())

        with mock.patch("sys.stdin", stdin):
            call_command(*args, **kwargs)
        return kwargs["stdout"].getvalue(), kwargs["stderr"].getvalue()

    def cmd_e2e(
        self,
        cmd: typing.Sequence[str],
        stdin: typing.Optional[StringIO] = None,
        stdout: typing.Optional[StringIO] = None,
        stderr: typing.Optional[StringIO] = None,
    ) -> typing.Tuple[str, str]:
        """Call a management command the way manage.py does.

        Unlike call_command, this method also tests the argparse configuration of the called command.
        """
        stdout = stdout or StringIO()
        stderr = stderr or StringIO()
        if stdin is None:
            stdin = StringIO()

        with mock.patch("sys.stdin", stdin), mock.patch("sys.stdout", stdout), mock.patch(
            "sys.stderr", stderr
        ):
            util = ManagementUtility(["manage.py"] + list(cmd))
            util.execute()

        return stdout.getvalue(), stderr.getvalue()

    @contextmanager
    def freeze_time(self, timestamp: typing.Union[str, datetime]) -> typing.Iterator[FrozenDateTimeFactory]:
        """Context manager to freeze time to one of the given timestamps.

        If `timestamp` is a str that is in the `timestamps` dict (e.g. "everything-valid"), use that
        timestamp.
        """
        if isinstance(timestamp, str):  # pragma: no branch
            timestamp = timestamps[timestamp]

        with freeze_time(timestamp) as frozen:
            yield frozen

    @classmethod
    def load_ca(
        cls,
        name: str,
        parsed: x509.Certificate,
        enabled: bool = True,
        parent: typing.Optional[CertificateAuthority] = None,
        **kwargs: typing.Any
    ) -> CertificateAuthority:
        """Load a CA from one of the preloaded files."""
        path = "%s.key" % name

        # set some default values
        kwargs.setdefault("issuer_alt_name", certs[name].get("issuer_alternative_name", ""))
        kwargs.setdefault("crl_url", certs[name].get("crl_url", ""))
        kwargs.setdefault("ocsp_url", certs[name].get("ocsp_url", ""))
        kwargs.setdefault("issuer_url", certs[name].get("issuer_url", ""))

        ca = CertificateAuthority(name=name, private_key_path=path, enabled=enabled, parent=parent, **kwargs)
        ca.x509_cert = parsed  # calculates serial etc
        ca.save()
        return ca

    @classmethod
    def load_cert(
        cls, ca: CertificateAuthority, parsed: x509.Certificate, csr: str = "", profile: str = ""
    ) -> Certificate:
        """Load a certificate from the given data."""
        cert = Certificate(ca=ca, csr=csr, profile=profile)
        cert.x509_cert = parsed
        cert.save()
        return cert


class AdminTestCaseMixin(TestCaseMixin, typing.Generic[DjangoCAModelTypeVar]):
    """Common mixin for testing admin classes for models."""

    model: typing.Type[DjangoCAModelTypeVar]
    """Model must be configured for TestCase instances using this mixin."""

    media_css: typing.Tuple[str, ...] = tuple()
    """List of custom CSS files loaded by the ModelAdmin.Media class."""

    view_name: str
    """The name of the view being tested."""

    # TODO: we should get rid of this, it's ugly
    obj: typing.Optional[DjangoCAModel]

    def setUp(self) -> None:  # pylint: disable=invalid-name,missing-function-docstring
        super().setUp()
        self.user = self.create_superuser()
        self.client.force_login(self.user)
        self.obj = self.model.objects.first()  # TODO: get rid of this

    @property
    def add_url(self) -> str:
        """Shortcut for the "add" URL of the model under test."""
        return typing.cast(str, self.model.admin_add_url)  # type hinting for @classproperty doesn't work

    def assertBundle(  # pylint: disable=invalid-name
        self, cert: DjangoCAModelTypeVar, expected: typing.Iterable[X509CertMixin], filename: str
    ) -> None:
        """Assert that the bundle for the given certificate matches the expected chain and filename."""
        url = self.get_url(cert)
        expected_content = "\n".join([e.pub.strip() for e in expected]) + "\n"
        response = self.client.get(url, {"format": "PEM"})
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(response["Content-Type"], "application/pkix-cert")
        self.assertEqual(response["Content-Disposition"], "attachment; filename=%s" % filename)
        self.assertEqual(response.content.decode("utf-8"), expected_content)

    def assertCSS(self, response: HttpResponse, path: str) -> None:  # pylint: disable=invalid-name
        """Assert that the HTML from the given response includes the mentioned CSS."""
        css = '<link href="%s" type="text/css" media="all" rel="stylesheet" />' % static(path)
        self.assertInHTML(css, response.content.decode("utf-8"), 1)

    def assertChangeResponse(  # pylint: disable=invalid-name
        self, response: HttpResponse, status: int = HTTPStatus.OK
    ) -> None:
        """Assert that the passed response is a model change view."""
        self.assertEqual(response.status_code, status)
        templates = [t.name for t in response.templates]
        self.assertIn("admin/change_form.html", templates)
        self.assertIn("admin/base.html", templates)

        for css in self.media_css:
            self.assertCSS(response, css)

    def assertChangelistResponse(  # pylint: disable=invalid-name
        self, response: HttpResponse, *objects: models.Model, status: int = HTTPStatus.OK
    ) -> None:
        """Assert that the passed response is a model changelist view."""
        self.assertEqual(response.status_code, status)
        self.assertCountEqual(response.context["cl"].result_list, objects)

        templates = [t.name for t in response.templates]
        self.assertIn("admin/base.html", templates)
        self.assertIn("admin/change_list.html", templates)

        for css in self.media_css:
            self.assertCSS(response, css)

    def assertRequiresLogin(  # pylint: disable=invalid-name
        self, response: HttpResponse, **kwargs: typing.Any
    ) -> None:
        """Assert that the given response is a redirect to the login page."""
        expected = "%s?next=%s" % (reverse("admin:login"), quote(response.wsgi_request.get_full_path()))
        self.assertRedirects(response, expected, **kwargs)

    def change_url(self, obj: typing.Optional[DjangoCAModel] = None) -> str:
        """Shortcut for the change URL of the given instance."""
        obj = obj or self.obj
        return obj.admin_change_url  # type: ignore[union-attr]

    @property
    def changelist_url(self) -> str:
        """Shortcut for the changelist URL of the model under test."""
        return typing.cast(str, self.model.admin_changelist_url)

    def create_superuser(
        self, username: str = "admin", password: str = "admin", email: str = "user@example.com"
    ) -> User:
        """Shortcut to create a superuser."""
        return User.objects.create_superuser(username=username, password=password, email=email)

    @contextmanager
    def freeze_time(self, timestamp: typing.Union[str, datetime]) -> typing.Iterator[FrozenDateTimeFactory]:
        """Overridden to force a client login, otherwise the user session is expired."""

        with super().freeze_time(timestamp) as frozen:
            self.client.force_login(self.user)
            yield frozen

    def get_changelist_view(self, data: typing.Optional[typing.Dict[str, str]] = None) -> HttpResponse:
        """Get the response to a changelist view for the given model."""
        return self.client.get(self.changelist_url, data)

    def get_change_view(
        self, obj: DjangoCAModel, data: typing.Optional[typing.Dict[str, str]] = None
    ) -> HttpResponse:
        """Get the response to a change view for the given model instance."""
        return self.client.get(self.change_url(obj), data)

    def get_url(self, obj: DjangoCAModelTypeVar) -> str:
        """Get URL for the given object for this test case."""
        return reverse("admin:%s" % self.view_name, kwargs={"pk": obj.pk})


class StandardAdminViewTestCaseMixin(AdminTestCaseMixin[DjangoCAModelTypeVar]):
    """A mixin that adds tests for the standard Django admin views.

    TestCases using this mixin are expected to implement ``setUp`` to add some useful test model instances.
    """

    def get_changelists(
        self,
    ) -> typing.Iterator[typing.Tuple[typing.Iterable[DjangoCAModel], typing.Dict[str, str]]]:
        """Generator for possible changelist views.

        Should yield tuples of objects that should be displayed and a dict of query parameters.
        """
        yield (self.model.objects.all(), {})

    def test_model_count(self) -> None:
        """Test that the implementing TestCase actually creates some instances."""
        self.assertGreater(self.model.objects.all().count(), 0)

    def test_changelist_view(self) -> None:
        """Test that the changelist view works."""
        for qs, data in self.get_changelists():
            self.assertChangelistResponse(self.get_changelist_view(data), *qs)

    def test_change_view(self) -> None:
        """Test that the change view works for all instances."""
        for obj in self.model.objects.all():
            self.assertChangeResponse(self.get_change_view(obj))

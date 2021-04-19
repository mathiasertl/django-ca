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
from django.contrib.messages import get_messages
from django.core.cache import cache
from django.core.management import ManagementUtility
from django.core.management import call_command
from django.db import models
from django.dispatch.dispatcher import Signal
from django.http import HttpResponse
from django.templatetags.static import static
from django.test.testcases import SimpleTestCase
from django.urls import reverse

from freezegun import freeze_time
from freezegun.api import FrozenDateTimeFactory

from ..constants import ReasonFlags
from ..extensions import OID_TO_EXTENSION
from ..extensions import AuthorityInformationAccess
from ..extensions import AuthorityKeyIdentifier
from ..extensions import BasicConstraints
from ..extensions import CRLDistributionPoints
from ..extensions import Extension
from ..extensions import SubjectKeyIdentifier
from ..models import Certificate
from ..models import CertificateAuthority
from ..models import DjangoCAModel
from ..models import X509CertMixin
from ..signals import post_issue_cert
from ..subject import Subject
from ..typehints import ParsableSubject
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

    load_cas: typing.Tuple[str, ...] = tuple()
    load_certs: typing.Tuple[str, ...] = tuple()
    new_cas: typing.Dict[str, CertificateAuthority] = {}
    new_certs: typing.Dict[str, Certificate] = {}

    def setUp(self) -> None:  # pylint: disable=invalid-name,missing-function-docstring
        super().setUp()
        cache.clear()

        for name in self.load_cas:
            self.new_cas[name] = self.load_ca(name)
        if len(self.load_cas) == 1:  # only one CA specified, set self.ca for convenience
            self.ca = self.new_cas[self.load_cas[0]]

        for name in self.load_certs:
            try:
                self.new_certs[name] = self.load_named_cert(name)
            except CertificateAuthority.DoesNotExist:  # pragma: no cover
                self.fail(f'{certs[name]["ca"]}: Could not load CertificateAuthority.')
        if len(self.load_certs) == 1:  # only one CA specified, set self.cert for convenience
            self.cert = self.new_certs[self.load_certs[0]]

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

    def assertAuthorityKeyIdentifier(  # pylint: disable=invalid-name
        self, issuer: CertificateAuthority, cert: X509CertMixin
    ) -> None:
        """Test the key identifier of the AuthorityKeyIdentifier extenion of `cert`."""
        self.assertEqual(
            cert.authority_key_identifier.key_identifier,  # type: ignore[union-attr] # aki theoretically None
            issuer.subject_key_identifier.value,  # type: ignore[union-attr] # ski theoretically None
        )

    def assertExtensions(  # pylint: disable=invalid-name
        self,
        cert: typing.Union[X509CertMixin, x509.Certificate],
        extensions: typing.Iterable[Extension[typing.Any, typing.Any, typing.Any]],
        signer: typing.Optional[CertificateAuthority] = None,
        expect_defaults: bool = True,
    ) -> None:
        """Assert that `cert` has the given extensions."""
        mapped_extensions = {e.key: e for e in extensions}

        if isinstance(cert, Certificate):
            pubkey = cert.x509_cert.public_key()
            actual = {e.key: e for e in cert.extensions}
            signer = cert.ca
        elif isinstance(cert, CertificateAuthority):
            pubkey = cert.x509_cert.public_key()
            actual = {e.key: e for e in cert.extensions}

            if cert.parent is None:  # root CA
                signer = cert
            else:  # intermediate CA
                signer = cert.parent
        elif isinstance(cert, x509.Certificate):  # cg cert
            pubkey = cert.public_key()
            actual = {
                e.key: e
                for e in [
                    OID_TO_EXTENSION[e.oid](e) if e.oid in OID_TO_EXTENSION else e for e in cert.extensions
                ]
            }
        else:  # pragma: no cover
            raise ValueError("cert must be Certificate(Authority) or x509.Certificate)")

        if expect_defaults is True:
            if isinstance(cert, Certificate):
                mapped_extensions.setdefault(BasicConstraints.key, BasicConstraints())
            if signer is not None:
                mapped_extensions.setdefault(
                    AuthorityKeyIdentifier.key, signer.get_authority_key_identifier_extension()
                )

                if isinstance(cert, Certificate) and signer.crl_url:
                    urls = signer.crl_url.split()
                    ext = CRLDistributionPoints({"value": [{"full_name": urls}]})
                    mapped_extensions.setdefault(CRLDistributionPoints.key, ext)

                aia = AuthorityInformationAccess()
                if isinstance(cert, Certificate) and signer.ocsp_url:
                    aia.ocsp = [signer.ocsp_url]
                if isinstance(cert, Certificate) and signer.issuer_url:
                    aia.issuers = [signer.issuer_url]
                if aia.ocsp or aia.issuers:
                    mapped_extensions.setdefault(AuthorityInformationAccess.key, aia)

            ski = x509.SubjectKeyIdentifier.from_public_key(pubkey)
            mapped_extensions.setdefault(SubjectKeyIdentifier.key, SubjectKeyIdentifier(ski))

        self.assertEqual(actual, mapped_extensions)

    def assertIssuer(  # pylint: disable=invalid-name
        self, issuer: CertificateAuthority, cert: X509CertMixin
    ) -> None:
        """Assert that the issuer for `cert` matches the subject of `issuer`."""
        self.assertEqual(cert.issuer, issuer.subject)

    def assertMessages(  # pylint: disable=invalid-name
        self, response: HttpResponse, expected: typing.List[str]
    ) -> None:
        """Assert given Django messages for `response`."""
        messages = [str(m) for m in list(get_messages(response.wsgi_request))]
        self.assertEqual(messages, expected)

    def assertNotRevoked(self, cert: X509CertMixin) -> None:  # pylint: disable=invalid-name
        """Assert that the certificate is not revoked."""
        cert.refresh_from_db()
        self.assertFalse(cert.revoked)
        self.assertEqual(cert.revoked_reason, "")

    def assertPostIssueCert(self, post: mock.Mock, cert: Certificate) -> None:  # pylint: disable=invalid-name
        """Assert that the post_issue_cert signal was called."""
        post.assert_called_once_with(cert=cert, signal=post_issue_cert, sender=Certificate)

    def assertRevoked(  # pylint: disable=invalid-name
        self, cert: X509CertMixin, reason: typing.Optional[str] = None
    ) -> None:
        """Assert that the certificate is now revoked."""
        if isinstance(cert, CertificateAuthority):
            cert = CertificateAuthority.objects.get(serial=cert.serial)
        else:
            cert = Certificate.objects.get(serial=cert.serial)

        self.assertTrue(cert.revoked)

        if reason is None:
            self.assertEqual(cert.revoked_reason, ReasonFlags.unspecified.name)
        else:
            self.assertEqual(cert.revoked_reason, reason)

    def assertSubject(  # pylint: disable=invalid-name
        self, cert: x509.Certificate, expected: typing.Union[Subject, ParsableSubject]
    ) -> None:
        """Assert the subject of `cert` matches `expected`."""
        if not isinstance(expected, Subject):
            expected = Subject(expected)
        self.assertEqual(Subject([(s.oid, s.value) for s in cert.subject]), expected)

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
        """Context manager to freeze time to a given timestamp.

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
        parsed: typing.Optional[x509.Certificate] = None,
        enabled: bool = True,
        parent: typing.Optional[CertificateAuthority] = None,
        **kwargs: typing.Any,
    ) -> CertificateAuthority:
        """Load a CA from one of the preloaded files."""
        path = "%s.key" % name
        if parsed is None:
            parsed = certs[name]["pub"]["parsed"]
        if parent is None and certs[name].get("parent"):
            parent = CertificateAuthority.objects.get(name=certs[name]["parent"])

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

    @classmethod
    def load_named_cert(cls, name: str) -> Certificate:
        """Load a certificate with the given mame."""
        data = certs[name]
        ca = CertificateAuthority.objects.get(name=data["ca"])
        csr = data.get("csr", {}).get("pem", "")
        profile = data.get("profile", "")

        cert = Certificate(ca=ca, csr=csr, profile=profile)
        cert.x509_cert = data["pub"]["parsed"]
        cert.save()
        return cert

    @contextmanager
    def mockSignal(self, signal: Signal) -> typing.Iterator[mock.Mock]:  # pylint: disable=invalid-name
        """Context manager to attach a mock to the given signal."""

        # This function is only here to create an autospec. From the documentation:
        #
        #   Notice that the function takes a sender argument, along with wildcard keyword arguments
        #   (**kwargs); all signal handlers must take these arguments.
        #
        # https://docs.djangoproject.com/en/dev/topics/signals/#connecting-to-specific-signals
        def callback(sender: models.Model, **kwargs: typing.Any) -> None:  # pragma: no cover
            # pylint: disable=unused-argument
            pass

        signal_mock = mock.create_autospec(callback, spec_set=True)
        signal.connect(signal_mock)
        try:
            yield signal_mock
        finally:
            signal.disconnect(signal_mock)

    @contextmanager
    def mute_celery(self) -> typing.Iterator[mock.MagicMock]:
        """Mock celery invocations."""
        with mock.patch("celery.app.task.Task.apply_async", spec_set=True) as mocked:
            yield mocked

    @contextmanager
    def patch(self, *args: typing.Any, **kwargs: typing.Any) -> typing.Iterator[mock.MagicMock]:
        """Shortcut to :py:func:`py:unittest.mock.patch`."""
        with mock.patch(*args, **kwargs) as mocked:
            yield mocked


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

    def get_objects(self) -> typing.Iterable[DjangoCAModelTypeVar]:
        return self.model.objects.all()

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

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

"""Collection of mixin classes for unittest.TestCase subclasses."""

import json
import re
import typing
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta
from http import HTTPStatus
from typing import Any, Optional, Union
from unittest import mock
from urllib.parse import quote

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from django.conf import settings
from django.contrib.auth.models import User  # pylint: disable=imported-auth-user; for mypy
from django.contrib.messages import get_messages
from django.core.cache import cache
from django.test.testcases import SimpleTestCase
from django.urls import reverse

from freezegun import freeze_time
from freezegun.api import FrozenDateTimeFactory, StepTickTimeFactory

from django_ca.models import Certificate, CertificateAuthority, DjangoCAModel, X509CertMixin
from django_ca.signals import post_revoke_cert
from django_ca.tests.admin.assertions import assert_change_response, assert_changelist_response
from django_ca.tests.base.constants import CERT_DATA
from django_ca.tests.base.typehints import DjangoCAModelTypeVar

if typing.TYPE_CHECKING:
    # Use SimpleTestCase as base class when type checking. This way mypy will know about attributes/methods
    # that the mixin accesses. See also:
    #   https://github.com/python/mypy/issues/5837
    TestCaseProtocol = SimpleTestCase

    from django.test.client import _MonkeyPatchedWSGIResponse as HttpResponse
else:
    TestCaseProtocol = object


class TestCaseMixin(TestCaseProtocol):
    """Mixin providing augmented functionality to all test cases."""

    load_cas: Union[str, tuple[str, ...]] = tuple()
    load_certs: Union[str, tuple[str, ...]] = tuple()
    default_ca = "child"
    default_cert = "child-cert"
    cas: dict[str, CertificateAuthority]
    certs: dict[str, Certificate]

    # Note: cryptography sometimes adds another sentence at the end
    re_false_password = r"^Could not decrypt private key - bad password\?$"

    def setUp(self) -> None:
        super().setUp()
        cache.clear()

        self.cas = {}
        self.certs = {}
        self.load_cas = self.load_named_cas(self.load_cas)
        self.load_certs = self.load_named_certs(self.load_certs)

        # Set `self.ca` as a default certificate authority (if at least one is loaded)
        if len(self.load_cas) == 1:  # only one CA specified, set self.ca for convenience
            self.ca: CertificateAuthority = self.cas[self.load_cas[0]]
        elif self.load_cas:
            if self.default_ca not in self.load_cas:  # pragma: no cover
                self.fail(f"{self.default_ca}: Not in {self.load_cas}.")
            self.ca = self.cas[self.default_ca]

        # Set `self.cert` as a default certificate (if at least one is loaded)
        if len(self.load_certs) == 1:  # only one CA specified, set self.cert for convenience
            self.cert = self.certs[self.load_certs[0]]
        elif self.load_certs:
            if self.default_cert not in self.load_certs:  # pragma: no cover
                self.fail(f"{self.default_cert}: Not in {self.load_certs}.")
            self.cert = self.certs[self.default_cert]

    def load_named_cas(self, cas: Union[str, tuple[str, ...]]) -> tuple[str, ...]:
        """Load CAs by the given name."""
        if cas == "__all__":
            cas = tuple(k for k, v in CERT_DATA.items() if v.get("type") == "ca")
        elif cas == "__usable__":
            cas = tuple(k for k, v in CERT_DATA.items() if v.get("type") == "ca" and v["key_filename"])
        elif isinstance(cas, str):  # pragma: no cover
            self.fail(f"{cas}: Unknown alias for load_cas.")

        # Filter CAs that we already loaded
        cas = tuple(ca for ca in cas if ca not in self.cas)

        # Load all CAs (sort by len() of parent so that root CAs are loaded first)
        for name in sorted(cas, key=lambda n: len(CERT_DATA[n].get("parent", ""))):
            self.cas[name] = self.load_ca(name)
        return cas

    def load_named_certs(self, names: Union[str, tuple[str, ...]]) -> tuple[str, ...]:
        """Load certs by the given name."""
        if names == "__all__":
            names = tuple(k for k, v in CERT_DATA.items() if v.get("type") == "cert")
        elif names == "__usable__":
            names = tuple(
                k for k, v in CERT_DATA.items() if v.get("type") == "cert" and v["cat"] == "generated"
            )
        elif isinstance(names, str):  # pragma: no cover
            self.fail(f"{names}: Unknown alias for load_certs.")

        # Filter certificates that are already loaded
        names = tuple(name for name in names if name not in self.certs)

        for name in names:
            try:
                self.certs[name] = self.load_named_cert(name)
            except CertificateAuthority.DoesNotExist:  # pragma: no cover
                self.fail(f"{CERT_DATA[name]['ca']}: Could not load CertificateAuthority.")
        return names

    def absolute_uri(self, name: str, hostname: Optional[str] = None, **kwargs: Any) -> str:
        """Build an absolute uri for the given request.

        The `name` is assumed to be a URL name or a full path. If `name` starts with a colon, ``django_ca``
        is used as namespace.
        """
        if hostname is None:
            hostname = settings.ALLOWED_HOSTS[0]

        if name.startswith("/"):  # pragma: no cover
            return f"http://{hostname}{name}"
        if name.startswith(":"):  # pragma: no branch
            name = f"django_ca{name}"
        return f"http://{hostname}{reverse(name, kwargs=kwargs)}"

    def assertMessages(  # pylint: disable=invalid-name
        self, response: "HttpResponse", expected: list[str]
    ) -> None:
        """Assert given Django messages for `response`."""
        messages = [str(m) for m in list(get_messages(response.wsgi_request))]
        assert messages == expected

    def assertNotRevoked(self, cert: X509CertMixin) -> None:  # pylint: disable=invalid-name
        """Assert that the certificate is not revoked."""
        cert.refresh_from_db()
        assert not cert.revoked
        assert cert.revoked_reason == ""

    def assertPostRevoke(self, post: mock.Mock, cert: Certificate) -> None:  # pylint: disable=invalid-name
        """Assert that the post_revoke_cert signal was called."""
        post.assert_called_once_with(cert=cert, signal=post_revoke_cert, sender=Certificate)

    def crl_distribution_points(
        self,
        full_name: Optional[Iterable[x509.GeneralName]] = None,
        relative_name: Optional[x509.RelativeDistinguishedName] = None,
        reasons: Optional[frozenset[x509.ReasonFlags]] = None,
        crl_issuer: Optional[Iterable[x509.GeneralName]] = None,
        critical: bool = False,
    ) -> x509.Extension[x509.CRLDistributionPoints]:
        """Shortcut for getting a CRLDistributionPoints extension."""
        dpoint = x509.DistributionPoint(
            full_name=full_name, relative_name=relative_name, reasons=reasons, crl_issuer=crl_issuer
        )
        return x509.Extension(
            oid=ExtensionOID.CRL_DISTRIBUTION_POINTS,
            critical=critical,
            value=x509.CRLDistributionPoints([dpoint]),
        )

    def freshest_crl(
        self,
        full_name: Optional[Iterable[x509.GeneralName]] = None,
        relative_name: Optional[x509.RelativeDistinguishedName] = None,
        reasons: Optional[frozenset[x509.ReasonFlags]] = None,
        crl_issuer: Optional[Iterable[x509.GeneralName]] = None,
        critical: bool = False,
    ) -> x509.Extension[x509.FreshestCRL]:
        """Shortcut for getting a CRLDistributionPoints extension."""
        dpoint = x509.DistributionPoint(
            full_name=full_name, relative_name=relative_name, reasons=reasons, crl_issuer=crl_issuer
        )
        return x509.Extension(
            oid=ExtensionOID.FRESHEST_CRL, critical=critical, value=x509.FreshestCRL([dpoint])
        )

    @property
    def hostname(self) -> str:
        """Get a hostname unique for the test case."""
        name = self.id().split(".", 2)[-1].lower()
        name = re.sub("[^a-z0-9.-]", "-", name)
        return f"{name}.example.com"[-64:].lstrip("-.")

    @classmethod
    def expires(cls, days: int) -> timedelta:
        """Get a timestamp `days` from now."""
        return timedelta(days=days + 1)

    @contextmanager
    def freeze_time(
        self, timestamp: Union[datetime]
    ) -> Iterator[Union[FrozenDateTimeFactory, StepTickTimeFactory]]:
        """Context manager to freeze time to a given timestamp.

        If `timestamp` is a str that is in the `TIMESTAMPS` dict (e.g. "everything-valid"), use that
        timestamp.
        """
        with freeze_time(timestamp) as frozen:
            yield frozen

    @classmethod
    def load_ca(
        cls,
        name: str,
        enabled: bool = True,
        parent: Optional[CertificateAuthority] = None,
        **kwargs: Any,
    ) -> CertificateAuthority:
        """Load a CA from one of the preloaded files."""
        if parent is None and CERT_DATA[name].get("parent"):
            parent = CertificateAuthority.objects.get(name=CERT_DATA[name]["parent"])

        # set some default values (3rd-party CAs don't set sign_* properties)
        kwargs.setdefault("sign_crl_distribution_points", CERT_DATA[name].get("sign_crl_distribution_points"))
        kwargs.setdefault(
            "sign_authority_information_access", CERT_DATA[name].get("sign_authority_information_access")
        )

        key_backend_options = {}
        if CERT_DATA[name]["key_filename"]:
            key_backend_options["path"] = CERT_DATA[name]["key_filename"]

        ca = CertificateAuthority(
            name=name,
            enabled=enabled,
            parent=parent,
            key_backend_alias="default",
            key_backend_options=key_backend_options,
            ocsp_key_backend_alias="default",
            **kwargs,
        )
        ca.update_certificate(CERT_DATA[name]["pub"]["parsed"])  # calculates serial etc
        ca.full_clean()
        ca.save()
        return ca

    @classmethod
    def load_named_cert(cls, name: str) -> Certificate:
        """Load a certificate with the given mame."""
        data = CERT_DATA[name]
        ca = CertificateAuthority.objects.get(name=data["ca"])
        csr = data.get("csr", {}).get("parsed", "")
        profile = data.get("profile", "")

        cert = Certificate(ca=ca, csr=csr, profile=profile)
        cert.update_certificate(data["pub"]["parsed"])
        cert.save()
        cert.refresh_from_db()  # make sure we have lazy fields set
        return cert

    @contextmanager
    def mute_celery(self, *calls: Any) -> Iterator[mock.MagicMock]:
        """Context manager to mock celery invocations.

        This context manager mocks ``celery.app.task.Task.apply_async``, the final function in celery before
        the message is passed to the handlers for the configured message transport (Redis, MQTT, ...). The
        context manager will validate the mock was called as specified in the passed *calls* arguments.

        The context manager will also assert that the args and kwargs passed to the tasks are JSON
        serializable.

        .. WARNING::

           The args and kwargs passed to the task are the first and second *argument* passed to the mocked
           ``apply_async``. You must consider this when passing calls. For example::

               with self.mute_celery((((), {}), {})):
                   cache_crls.delay()

               with self.mute_celery(((("foo"), {"key": "bar"}), {})):
                   cache_crls.delay("foo", key="bar")
        """
        with mock.patch("celery.app.task.Task.apply_async", spec_set=True) as mocked:
            yield mocked

        # Make sure that all invocations are JSON serializable
        for invocation in mocked.call_args_list:
            # invocation apply_async() has task args as arg[0] and arg[1]
            assert isinstance(json.dumps(invocation.args[0]), str)
            assert isinstance(json.dumps(invocation.args[1]), str)

        # Make sure that task was called the right number of times
        assert len(calls) == len(mocked.call_args_list)
        for expected, actual in zip(calls, mocked.call_args_list):
            assert expected == actual, actual

    @contextmanager
    def patch(self, *args: Any, **kwargs: Any) -> Iterator[mock.MagicMock]:
        """Shortcut to :py:func:`py:unittest.mock.patch`."""
        with mock.patch(*args, **kwargs) as mocked:
            yield mocked

    @contextmanager
    def patch_object(self, *args: Any, **kwargs: Any) -> Iterator[Any]:
        """Shortcut to :py:func:`py:unittest.mock.patch.object`."""
        with mock.patch.object(*args, **kwargs) as mocked:
            yield mocked

    @property
    def usable_cas(self) -> Iterator[tuple[str, CertificateAuthority]]:
        """Yield loaded generated certificates."""
        for name, ca in self.cas.items():
            if CERT_DATA[name]["key_filename"]:  # pragma: no branch
                yield name, ca


class AdminTestCaseMixin(TestCaseMixin, typing.Generic[DjangoCAModelTypeVar]):
    """Common mixin for testing admin classes for models."""

    model: type[DjangoCAModelTypeVar]
    """Model must be configured for TestCase instances using this mixin."""

    media_css: tuple[str, ...] = tuple()
    """List of custom CSS files loaded by the ModelAdmin.Media class."""

    view_name: str
    """The name of the view being tested."""

    # TODO: we should get rid of this, it's ugly
    obj: DjangoCAModelTypeVar

    def setUp(self) -> None:
        super().setUp()
        self.user = self.create_superuser()
        self.client.force_login(self.user)
        self.obj = self.model._default_manager.first()  # type: ignore[assignment]

    @property
    def add_url(self) -> str:
        """Shortcut for the "add" URL of the model under test."""
        return self.model.admin_add_url

    def assertBundle(  # pylint: disable=invalid-name
        self, cert: DjangoCAModelTypeVar, expected: Iterable[X509CertMixin], filename: str
    ) -> None:
        """Assert that the bundle for the given certificate matches the expected chain and filename."""
        url = self.get_url(cert)

        # Do not use bundle_as_pem to make sure that chain really has expected number of newlines everywhere
        expected_content = "\n".join([e.pub.pem.strip() for e in expected]) + "\n"

        response = self.client.get(url, {"format": "PEM"})
        assert response.status_code == HTTPStatus.OK
        assert response["Content-Type"] == "application/pkix-cert"
        assert response["Content-Disposition"] == f"attachment; filename={filename}"
        assert response.content.decode("utf-8") == expected_content

    def assertRequiresLogin(  # pylint: disable=invalid-name
        self, response: "HttpResponse", **kwargs: Any
    ) -> None:
        """Assert that the given response is a redirect to the login page."""
        path = reverse("admin:login")
        qs = quote(response.wsgi_request.get_full_path())
        self.assertRedirects(response, f"{path}?next={qs}", **kwargs)

    def change_url(self, obj: Optional[DjangoCAModel] = None) -> str:
        """Shortcut for the change URL of the given instance."""
        obj = obj or self.obj
        return obj.admin_change_url

    @property
    def changelist_url(self) -> str:
        """Shortcut for the changelist URL of the model under test."""
        return self.model.admin_changelist_url

    @classmethod
    def create_superuser(
        cls, username: str = "admin", password: str = "admin", email: str = "user@example.com"
    ) -> User:
        """Shortcut to create a superuser."""
        return User.objects.create_superuser(username=username, password=password, email=email)

    def get_changelist_view(self, data: Optional[dict[str, str]] = None) -> "HttpResponse":
        """Get the response to a changelist view for the given model."""
        return self.client.get(self.changelist_url, data)

    def get_change_view(
        self, obj: DjangoCAModelTypeVar, data: Optional[dict[str, str]] = None
    ) -> "HttpResponse":
        """Get the response to a change view for the given model instance."""
        return self.client.get(self.change_url(obj), data)

    def get_objects(self) -> Iterable[DjangoCAModelTypeVar]:
        """Get list of objects for defined for this test."""
        return self.model._default_manager.all()

    def get_url(self, obj: DjangoCAModelTypeVar) -> str:
        """Get URL for the given object for this test case."""
        return reverse(f"admin:{self.view_name}", kwargs={"pk": obj.pk})


class StandardAdminViewTestCaseMixin(AdminTestCaseMixin[DjangoCAModelTypeVar]):
    """A mixin that adds tests for the standard Django admin views.

    TestCases using this mixin are expected to implement ``setUp`` to add some useful test model instances.
    """

    def get_changelists(
        self,
    ) -> Iterator[tuple[Iterable[DjangoCAModel], dict[str, str]]]:
        """Generate list of objects for possible changelist views.

        Should yield tuples of objects that should be displayed and a dict of query parameters.
        """
        yield self.model._default_manager.all(), {}

    def test_model_count(self) -> None:
        """Test that the implementing TestCase actually creates some instances."""
        assert self.model._default_manager.all().count() > 0

    def test_changelist_view(self) -> None:
        """Test that the changelist view works."""
        for qs, data in self.get_changelists():
            assert_changelist_response(self.get_changelist_view(data), *qs)

    def test_change_view(self) -> None:
        """Test that the change view works for all instances."""
        for obj in self.model._default_manager.all():
            assert_change_response(self.get_change_view(obj))


class AcmeValuesMixin:
    """Mixin that sets a few static valid ACME values."""

    # ACME data present in all mixins
    ACME_THUMBPRINT_1 = "U-yUM27CQn9pClKlEITobHB38GJOJ9YbOxnw5KKqU-8"
    ACME_THUMBPRINT_2 = "s_glgc6Fem0CW7ZioXHBeuUQVHSO-viZ3xNR8TBebCo"
    ACME_PEM_1 = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvP5N/1KjBQniyyukn30E
tyHz6cIYPv5u5zZbHGfNvrmMl8qHMmddQSv581AAFa21zueS+W8jnRI5ISxER95J
tNad2XEDsFINNvYaSG8E54IHMNQijVLR4MJchkfMAa6g1gIsJB+ffEt4Ea3TMyGr
MifJG0EjmtjkjKFbr2zuPhRX3fIGjZTlkxgvb1AY2P4AxALwS/hG4bsxHHNxHt2Z
s9Bekv+55T5+ZqvhNz1/3yADRapEn6dxHRoUhnYebqNLSVoEefM+h5k7AS48waJS
lKC17RMZfUgGE/5iMNeg9qtmgWgZOIgWDyPEpiXZEDDKeoifzwn1LO59W8c4W6L7
XwIDAQAB
-----END PUBLIC KEY-----"""
    ACME_PEM_2 = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp8SCUVQqpTBRyryuu560
Q8cAi18Ac+iLjaSLL4gOaDEU9CpPi4l9yCGphnQFQ92YP+GWv+C6/JRp24852QbR
RzuUJqJPdDxD78yFXoxYCLPmwQMnToA7SE3SnZ/PW2GPFMbAICuRdd3PhMAWCODS
NewZPLBlG35brRlfFtUEc2oQARb2lhBkMXrpIWeuSNQtInAHtfTJNA51BzdrIT2t
MIfadw4ljk7cVbrSYemT6e59ATYxiMXalu5/4v22958voEBZ38TE8AXWiEtTQYwv
/Kj0P67yuzE94zNdT28pu+jJYr5nHusa2NCbvnYFkDwzigmwCxVt9kW3xj3gfpgc
VQIDAQAB
-----END PUBLIC KEY-----"""
    ACME_SLUG_1 = "Mr6FfdD68lzp"
    ACME_SLUG_2 = "DzW4PQ6L76PE"

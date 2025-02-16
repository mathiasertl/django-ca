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

"""Basic tests for various celery tasks."""

import importlib
import io
import types
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from http import HTTPStatus
from unittest import mock

import dns.resolver
import josepy as jose
from dns.rdtypes.txtbase import TXTBase
from requests.packages.urllib3.response import HTTPResponse

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtensionOID

from django.test import TestCase, override_settings
from django.utils import timezone

import requests_mock
from freezegun import freeze_time

from django_ca import tasks
from django_ca.conf import model_settings
from django_ca.key_backends.storages.models import StoragesUsePrivateKeyOptions
from django_ca.models import AcmeAccount, AcmeAuthorization, AcmeCertificate, AcmeChallenge, AcmeOrder
from django_ca.tests.base.constants import CERT_DATA, TIMESTAMPS
from django_ca.tests.base.mixins import AcmeValuesMixin, TestCaseMixin
from django_ca.tests.base.utils import override_tmpcadir, subject_alternative_name

key_backend_options = StoragesUsePrivateKeyOptions(password=None)


class TestBasic(TestCaseMixin, TestCase):
    """Test the basic handling of celery tasks."""

    def test_missing_celery(self) -> None:
        """Test that we work even if celery is not installed."""
        # negative assertion to make sure that the IsInstance assertion below is actually meaningful
        assert not isinstance(tasks.cache_crl, types.FunctionType)

        try:
            with mock.patch.dict("sys.modules", celery=None):
                importlib.reload(tasks)
                assert isinstance(tasks.cache_crl, types.FunctionType)
        finally:
            # Make sure that module is reloaded, or any failed test in the try block will cause *all other
            # tests* to fail, because the celery import would be cached to *not* work
            importlib.reload(tasks)

    def test_run_task(self) -> None:
        """Test our run_task wrapper."""
        # run_task() without celery
        with self.settings(CA_USE_CELERY=False), self.patch("django_ca.tasks.cache_crls") as task_mock:
            tasks.run_task(tasks.cache_crls)
            assert task_mock.call_count == 1

        # finally, run_task() with celery
        with self.settings(CA_USE_CELERY=True), self.mute_celery((((), {}), {})):
            tasks.run_task(tasks.cache_crls)


class AcmeValidateChallengeTestCaseMixin(TestCaseMixin, AcmeValuesMixin):
    """Test :py:func:`~django_ca.tasks.acme_validate_challenge`."""

    type: str
    load_cas = ("root",)

    def setUp(self) -> None:
        super().setUp()
        self.account = AcmeAccount.objects.create(
            ca=self.cas["root"],
            contact="mailto:user@example.com",
            terms_of_service_agreed=True,
            status=AcmeAccount.STATUS_VALID,
            pem=self.ACME_PEM_1,
            thumbprint=self.ACME_THUMBPRINT_1,
        )
        self.order = AcmeOrder.objects.create(account=self.account)
        self.auth = AcmeAuthorization.objects.create(
            order=self.order, type=AcmeAuthorization.TYPE_DNS, value=self.hostname
        )
        self.chall = AcmeChallenge.objects.create(
            auth=self.auth, type=self.type, status=AcmeChallenge.STATUS_PROCESSING
        )

        encoded = jose.json_util.encode_b64jose(self.chall.token.encode("utf-8"))
        thumbprint = self.account.thumbprint
        self.expected = f"{encoded}.{thumbprint}"
        self.url = f"http://{self.auth.value}/.well-known/acme-challenge/{encoded}"

    def refresh_from_db(self) -> None:
        """Refresh objects from database."""
        self.account.refresh_from_db()
        self.order.refresh_from_db()
        self.auth.refresh_from_db()
        self.chall.refresh_from_db()

    def assertInvalid(self) -> None:  # pylint: disable=invalid-name; unittest standard
        """Assert that the challenge validation failed."""
        self.refresh_from_db()
        assert self.chall.status == AcmeChallenge.STATUS_INVALID
        assert self.auth.status == AcmeAuthorization.STATUS_INVALID
        assert self.order.status == AcmeOrder.STATUS_INVALID

    def assertValid(self, order_state: str = AcmeOrder.STATUS_READY) -> None:  # pylint: disable=invalid-name
        """Assert that the challenge is valid."""
        self.refresh_from_db()
        assert self.chall.status == AcmeChallenge.STATUS_VALID
        assert self.auth.status == AcmeAuthorization.STATUS_VALID
        assert self.order.status == order_state

    @contextmanager
    def mock_challenge(
        self,
        challenge: AcmeChallenge | None = None,
        status: int = HTTPStatus.OK,
        content: bytes | None = None,
        call_count: int = 1,
        token: str | None = None,
    ) -> Iterator[requests_mock.mocker.Mocker]:
        """Mock the client fullfilling the challenge."""
        raise NotImplementedError

    def test_acme_disabled(self) -> None:
        """Test invoking task when ACME support is not enabled."""
        with self.settings(CA_ENABLE_ACME=False), self.assertLogs() as logcm:
            tasks.acme_validate_challenge(self.chall.pk)
        assert logcm.output == ["ERROR:django_ca.tasks:ACME is not enabled."]

    def test_unknown_challenge(self) -> None:
        """Test invoking task with an unknown challenge."""
        AcmeChallenge.objects.all().delete()
        with self.assertLogs() as logcm:
            tasks.acme_validate_challenge(self.chall.pk)

        assert logcm.output == [f"ERROR:django_ca.tasks:Challenge with id={self.chall.pk} not found"]

    def test_status_not_processing(self) -> None:
        """Test invoking task where the status is not "processing"."""
        self.chall.status = AcmeChallenge.STATUS_PENDING
        self.chall.save()

        with self.assertLogs() as logcm:
            tasks.acme_validate_challenge(self.chall.pk)

        assert logcm.output == [
            f"ERROR:django_ca.tasks:{self.chall}: pending: Invalid state (must be processing)"
        ]

    def test_unusable_auth(self) -> None:
        """Test invoking task with an unusable authentication."""
        self.auth.status = AcmeAuthorization.STATUS_VALID
        self.auth.save()

        with self.assertLogs() as logcm:
            tasks.acme_validate_challenge(self.chall.pk)

        assert logcm.output == [f"ERROR:django_ca.tasks:{self.chall}: Authentication is not usable"]

    def test_response_wrong_content(self) -> None:
        """Test the server returning the wrong content in the response."""
        with (
            self.mock_challenge(content=b"wrong answer"),
            self.assertLogs("django_ca.tasks", "DEBUG") as logcm,
        ):
            tasks.acme_validate_challenge(self.chall.pk)
        self.assertInvalid()
        assert logcm.output == [
            f"INFO:django_ca.tasks:{self.chall!s} is invalid",
        ]

    def test_unsupported_challenge(self) -> None:
        """Test what happens when challenge type is not supported."""
        self.chall.type = AcmeChallenge.TYPE_TLS_ALPN_01
        self.chall.save()

        with (
            self.mock_challenge(call_count=0, content=b"foo", token="foo"),
            self.assertLogs("django_ca.tasks", "DEBUG") as logcm,
        ):
            tasks.acme_validate_challenge(self.chall.pk)
        self.assertInvalid()
        assert logcm.output == [
            f"ERROR:django_ca.tasks:{self.chall!s}: Challenge type is not supported.",
            f"INFO:django_ca.tasks:{self.chall!s} is invalid",
        ]

    def test_basic(self) -> None:
        """Test validation actually working."""
        with self.mock_challenge():
            tasks.acme_validate_challenge(self.chall.pk)
        self.assertValid()

    @override_settings(USE_TZ=False)
    def test_basic_without_timezone_support(self) -> None:
        """Same as test_basic but without timezone support."""
        self.test_basic()

    def test_multiple_auths(self) -> None:
        """If other authentications exist that are not in the valid state, order does not become valid."""
        AcmeAuthorization.objects.create(
            order=self.order, type=AcmeAuthorization.TYPE_DNS, value="other.example.com"
        )
        with self.mock_challenge():
            tasks.acme_validate_challenge(self.chall.pk)

        self.assertValid(AcmeOrder.STATUS_PENDING)


@freeze_time(TIMESTAMPS["everything_valid"])
class AcmeValidateHttp01ChallengeTestCase(AcmeValidateChallengeTestCaseMixin, TestCase):
    """Test :py:func:`~django_ca.tasks.acme_validate_challenge`."""

    load_cas = ("root",)
    type = AcmeChallenge.TYPE_HTTP_01

    def setUp(self) -> None:
        super().setUp()
        encoded = jose.json_util.encode_b64jose(self.chall.token.encode("utf-8"))
        thumbprint = self.account.thumbprint
        self.expected = f"{encoded}.{thumbprint}"
        self.url = f"http://{self.auth.value}/.well-known/acme-challenge/{encoded}"

    @contextmanager
    def mock_challenge(
        self,
        challenge: AcmeChallenge | None = None,
        status: int = HTTPStatus.OK,
        content: io.BytesIO | bytes | None = None,
        call_count: int = 1,
        token: str | None = None,
    ) -> Iterator[requests_mock.mocker.Mocker]:
        """Mock a request to satisfy an ACME challenge."""
        challenge = challenge or self.chall
        auth = challenge.auth

        if content is None:
            content = io.BytesIO(challenge.expected)

        if token is None:
            token = challenge.encoded_token.decode("utf-8")
        url = f"http://{auth.value}/.well-known/acme-challenge/{token}"

        with requests_mock.Mocker() as req_mock:
            matcher = req_mock.get(url, raw=HTTPResponse(body=content, status=status, preload_content=False))
            yield req_mock

        assert matcher.call_count == call_count

    def test_response_not_ok(self) -> None:
        """Test the server not returning a HTTP status code 200."""
        with self.mock_challenge(status=HTTPStatus.NOT_FOUND):
            tasks.acme_validate_challenge(self.chall.pk)
        self.assertInvalid()

    def test_request_exception(self) -> None:
        """Test requests throwing an exception."""
        val = f"{__name__}.{self.__class__.__name__}.test_request_exception"
        with self.patch("requests.get", side_effect=Exception(val)) as req_mock, self.assertLogs() as logcm:
            tasks.acme_validate_challenge(self.chall.pk)
        self.assertInvalid()
        assert req_mock.mock_calls == [((self.url,), {"timeout": 1, "stream": True})]
        assert len(logcm.output) == 2
        assert val in logcm.output[0]
        assert logcm.output[1] == f"INFO:django_ca.tasks:{self.chall!s} is invalid"


@freeze_time(TIMESTAMPS["everything_valid"])
class AcmeValidateDns01ChallengeTestCase(AcmeValidateChallengeTestCaseMixin, TestCase):
    """Test :py:func:`~django_ca.tasks.acme_validate_challenge`."""

    load_cas = ("root",)
    type = AcmeChallenge.TYPE_DNS_01

    def setUp(self) -> None:
        super().setUp()
        encoded = jose.json_util.encode_b64jose(self.chall.token.encode("utf-8"))
        thumbprint = self.account.thumbprint
        self.expected = f"{encoded}.{thumbprint}"
        self.url = f"http://{self.auth.value}/.well-known/acme-challenge/{encoded}"

    @contextmanager
    def mock_challenge(
        self,
        challenge: AcmeChallenge | None = None,
        status: int = HTTPStatus.OK,
        content: bytes | None = None,
        call_count: int = 1,
        token: str | None = None,
    ) -> Iterator[requests_mock.mocker.Mocker]:
        """Mock a request to satisfy an ACME challenge."""
        dns.resolver.reset_default_resolver()
        challenge = challenge or self.chall
        domain = self.auth.value
        if content is None:
            content = challenge.expected

        with mock.patch.object(dns.resolver.default_resolver, "resolve", autospec=True) as resolve_cm:
            resolve_cm.return_value = [
                TXTBase(dns.rdataclass.RdataClass.IN, dns.rdatatype.RdataType.TXT, [content])
            ]
            yield resolve_cm

        if call_count == 0:
            resolve_cm.assert_not_called()
        else:
            # Note: Only assert the first two parameters, as otherwise we'd test dnspython internals
            resolve_cm.assert_called_once()
            expected = (f"_acme_challenge.{domain}", "TXT")
            assert resolve_cm.call_args_list[0].args[:2] == expected

    def test_nxdomain(self) -> None:
        """Test a ACME validation where the domain does not exist."""
        with (
            mock.patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN) as rmcm,
            self.assertLogs(level="DEBUG") as logcm,
        ):
            tasks.acme_validate_challenge(self.chall.pk)
        rmcm.assert_called_once_with(f"_acme_challenge.{self.hostname}", "TXT", lifetime=1, search=False)
        self.assertInvalid()

        domain = self.hostname
        exp = self.chall.expected.decode("ascii")
        acme_domain = f"_acme_challenge.{domain}"
        logger = "django_ca.acme.validation"
        assert logcm.output == [
            f"INFO:{logger}:DNS-01 validation of {domain}: Expect {exp} on {acme_domain}",
            f"DEBUG:{logger}:TXT {acme_domain}: record does not exist.",
            f"INFO:django_ca.tasks:{self.chall!s} is invalid",
        ]


@freeze_time(TIMESTAMPS["everything_valid"])
class AcmeIssueCertificateTestCase(TestCaseMixin, AcmeValuesMixin, TestCase):
    """Test :py:func:`~django_ca.tasks.acme_issue_certificate`."""

    load_cas = ("root",)

    def setUp(self) -> None:
        super().setUp()
        self.account = AcmeAccount.objects.create(
            ca=self.cas["root"],
            contact="mailto:user@example.com",
            terms_of_service_agreed=True,
            pem=self.ACME_PEM_1,
            thumbprint=self.ACME_THUMBPRINT_1,
        )
        self.order = AcmeOrder.objects.create(account=self.account, status=AcmeOrder.STATUS_PROCESSING)
        self.auth = AcmeAuthorization.objects.create(order=self.order, value=self.hostname)

        # NOTE: This is of course not the right CSR for the order. It would be validated on submission, and
        # all data from the CSR is discarded anyway.
        csr = CERT_DATA["root-cert"]["csr"]["parsed"].public_bytes(Encoding.PEM).decode("utf-8")
        self.acme_cert = AcmeCertificate.objects.create(order=self.order, csr=csr)

    def test_acme_disabled(self) -> None:
        """Test invoking task when ACME support is not enabled."""
        with self.settings(CA_ENABLE_ACME=False), self.assertLogs() as logcm:
            tasks.acme_issue_certificate(self.acme_cert.pk)
        assert logcm.output == ["ERROR:django_ca.tasks:ACME is not enabled."]

    def test_unknown_certificate(self) -> None:
        """Test invoking task with an unknown cert."""
        AcmeCertificate.objects.all().delete()
        with self.assertLogs() as logcm:
            tasks.acme_issue_certificate(self.acme_cert.pk)

        assert logcm.output == [f"ERROR:django_ca.tasks:Certificate with id={self.acme_cert.pk} not found"]

    def test_unusable_cert(self) -> None:
        """Test invoking task where the order is not usable."""
        self.order.status = AcmeChallenge.STATUS_VALID  # usually would mean: already issued
        self.order.save()

        with self.assertLogs() as logcm:
            tasks.acme_issue_certificate(self.acme_cert.pk)

        assert logcm.output == [
            f"ERROR:django_ca.tasks:{self.order}: Cannot issue certificate for this order"
        ]

    @override_tmpcadir()
    def test_basic(self) -> None:
        """Test basic certificate issuance."""
        with self.assertLogs() as logcm:
            tasks.acme_issue_certificate(self.acme_cert.pk)

        assert logcm.output == [
            f"INFO:django_ca.tasks:{self.order}: Issuing certificate for dns:{self.hostname}"
        ]

        self.acme_cert.refresh_from_db()
        assert self.acme_cert.cert is not None, "Check to make mypy happy"
        self.order.refresh_from_db()
        assert self.order.status == AcmeOrder.STATUS_VALID
        assert self.acme_cert.cert.extensions[
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ] == subject_alternative_name(x509.DNSName(self.hostname))
        assert self.acme_cert.cert.not_after == timezone.now() + model_settings.CA_ACME_DEFAULT_CERT_VALIDITY
        assert self.acme_cert.cert.cn == self.hostname
        assert self.acme_cert.cert.profile == model_settings.CA_DEFAULT_PROFILE

    @override_settings(USE_TZ=False)
    def test_basic_without_timezone_support(self) -> None:
        """Same as test_basic but with USE_TZ=False."""
        self.test_basic()

    @override_tmpcadir()
    def test_two_hostnames(self) -> None:
        """Test setting two hostnames."""
        hostname2 = "example.net"
        AcmeAuthorization.objects.create(order=self.order, value=hostname2)

        # NOTE; not testing log output here, because order of hostnames might not be stable
        tasks.acme_issue_certificate(self.acme_cert.pk)

        self.acme_cert.refresh_from_db()
        assert self.acme_cert.cert is not None, "Check to make mypy happy"
        self.order.refresh_from_db()
        assert self.order.status == AcmeOrder.STATUS_VALID
        assert self.acme_cert.cert.extensions[
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ] == subject_alternative_name(x509.DNSName(self.hostname), x509.DNSName(hostname2))

        assert self.acme_cert.cert.not_after == timezone.now() + model_settings.CA_ACME_DEFAULT_CERT_VALIDITY
        assert self.acme_cert.cert.cn in [self.hostname, hostname2]

    @override_tmpcadir()
    def test_not_after(self) -> None:
        """Test certificate issuance with not_after attr."""
        not_after = timezone.now() + timedelta(days=20)
        self.order.not_after = not_after
        self.order.save()

        with self.assertLogs() as logcm:
            tasks.acme_issue_certificate(self.acme_cert.pk)

        assert logcm.output == [
            f"INFO:django_ca.tasks:{self.order}: Issuing certificate for dns:{self.hostname}"
        ]

        self.acme_cert.refresh_from_db()
        assert self.acme_cert.cert is not None, "Check to make mypy happy"
        self.order.refresh_from_db()
        assert self.order.status == AcmeOrder.STATUS_VALID
        assert self.acme_cert.cert.extensions[
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ] == subject_alternative_name(x509.DNSName(self.hostname))

        assert self.acme_cert.cert.not_after == not_after
        assert self.acme_cert.cert.cn == self.hostname

    def test_not_after_with_use_tz_is_false(self) -> None:
        """Test not_after with USE_TZ=False."""
        with self.settings(USE_TZ=False):
            self.order.refresh_from_db()  # otherwise save() fails in SQLite
            self.test_not_after()

    @override_tmpcadir()
    def test_profile(self) -> None:
        """Test that setting a different profile also returns the appropriate certificate."""
        self.ca.acme_profile = "client"
        self.ca.save()

        with self.assertLogs() as logcm:
            tasks.acme_issue_certificate(self.acme_cert.pk)

        assert logcm.output == [
            f"INFO:django_ca.tasks:{self.order}: Issuing certificate for dns:{self.hostname}"
        ]

        self.acme_cert.refresh_from_db()
        assert self.acme_cert.cert is not None, "Check to make mypy happy"
        self.order.refresh_from_db()
        assert self.order.status == AcmeOrder.STATUS_VALID
        assert self.acme_cert.cert.extensions[
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ] == subject_alternative_name(x509.DNSName(self.hostname))

        assert self.acme_cert.cert.not_after == timezone.now() + model_settings.CA_ACME_DEFAULT_CERT_VALIDITY

        assert self.acme_cert.cert.cn == self.hostname
        assert self.acme_cert.cert.profile == "client"


@freeze_time(TIMESTAMPS["everything_valid"])
class AcmeCleanupTestCase(TestCaseMixin, AcmeValuesMixin, TestCase):
    """Test :py:func:`~django_ca.tasks.acme_cleanup`."""

    load_cas = ("root",)

    def setUp(self) -> None:
        super().setUp()
        self.account = AcmeAccount.objects.create(
            ca=self.cas["root"],
            contact="mailto:user@example.com",
            terms_of_service_agreed=True,
            pem=self.ACME_PEM_1,
            thumbprint=self.ACME_THUMBPRINT_1,
        )
        self.order = AcmeOrder.objects.create(account=self.account, status=AcmeOrder.STATUS_PROCESSING)
        self.auth = AcmeAuthorization.objects.create(order=self.order, value=self.hostname)
        self.chall = AcmeChallenge.objects.create(
            auth=self.auth, type=AcmeChallenge.TYPE_HTTP_01, status=AcmeChallenge.STATUS_PROCESSING
        )

        # NOTE: This is of course not the right CSR for the order. It would be validated on submission, and
        # all data from the CSR is discarded anyway.
        csr = CERT_DATA["root-cert"]["csr"]["parsed"].public_bytes(Encoding.PEM).decode("utf-8")
        self.acme_cert = AcmeCertificate.objects.create(order=self.order, csr=csr)

    def test_basic(self) -> None:
        """Basic test."""
        tasks.acme_cleanup()  # does nothing if nothing is expired

        assert self.acme_cert == AcmeCertificate.objects.get(pk=self.acme_cert.pk)
        assert self.order == AcmeOrder.objects.get(pk=self.order.pk)
        assert self.auth == AcmeAuthorization.objects.get(pk=self.auth.pk)
        assert self.account == AcmeAccount.objects.get(pk=self.account.pk)

        with self.freeze_time(timezone.now() + timedelta(days=3)):
            tasks.acme_cleanup()

        assert AcmeOrder.objects.all().count() == 0
        assert AcmeAuthorization.objects.all().count() == 0
        assert AcmeChallenge.objects.all().count() == 0
        assert AcmeCertificate.objects.all().count() == 0

    def test_acme_disabled(self) -> None:
        """Test task when ACME is disabled."""
        with self.settings(CA_ENABLE_ACME=False), self.assertLogs() as logcm:
            with self.freeze_time(timezone.now() + timedelta(days=3)):
                tasks.acme_cleanup()
        assert logcm.output == ["INFO:django_ca.tasks:ACME is not enabled, not doing anything."]

        assert AcmeOrder.objects.all().count() == 1
        assert AcmeAuthorization.objects.all().count() == 1
        assert AcmeChallenge.objects.all().count() == 1
        assert AcmeCertificate.objects.all().count() == 1

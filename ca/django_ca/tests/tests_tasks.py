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
# see <http://www.gnu.org/licenses/>.

"""Basic tests for various celery tasks."""

import importlib
import io
import types
import typing
from contextlib import contextmanager
from datetime import timedelta
from http import HTTPStatus
from unittest import mock

import josepy as jose
from requests.packages.urllib3.response import HTTPResponse

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

import requests_mock
from freezegun import freeze_time

from .. import ca_settings
from .. import tasks
from ..extensions import SubjectAlternativeName
from ..models import AcmeAccount
from ..models import AcmeAuthorization
from ..models import AcmeCertificate
from ..models import AcmeChallenge
from ..models import AcmeOrder
from ..utils import ca_storage
from ..utils import get_crl_cache_key
from .base import certs
from .base import override_tmpcadir
from .base import timestamps
from .base.mixins import AcmeValuesMixin
from .base.mixins import TestCaseMixin


class TestBasic(TestCaseMixin, TestCase):
    """Test the basic handling of celery tasks."""

    def test_missing_celery(self) -> None:
        """Test that we work even if celery is not installed."""

        # negative assertion to make sure that the IsInstance assertion below is actually meaningful
        self.assertNotIsInstance(tasks.cache_crl, types.FunctionType)

        try:
            with mock.patch.dict("sys.modules", celery=None):
                importlib.reload(tasks)
                self.assertIsInstance(tasks.cache_crl, types.FunctionType)
        finally:
            # Make sure that module is reloaded, or any failed test in the try block will cause *all other
            # tests* to fail, because the celery import would be cached to *not* work
            importlib.reload(tasks)

    def test_run_task(self) -> None:
        """Test our run_task wrapper."""

        # run_task() without celery
        with self.settings(CA_USE_CELERY=False), self.patch("django_ca.tasks.cache_crls") as task_mock:
            tasks.run_task(tasks.cache_crls)
            self.assertEqual(task_mock.call_count, 1)

        # finally, run_task() with celery
        with self.settings(CA_USE_CELERY=True), self.mute_celery((((), {}), {})):
            tasks.run_task(tasks.cache_crls)


class TestCacheCRLs(TestCaseMixin, TestCase):
    """Test the cache_crl Celery task."""

    load_cas = "__usable__"

    @override_tmpcadir()
    def test_basic(self) -> None:
        """Test caching with a specific serial."""

        hash_cls = hashes.SHA512
        enc_cls = Encoding.DER

        for data in self.cas.values():
            tasks.cache_crl(data.serial)

            key = get_crl_cache_key(data.serial, hash_cls(), enc_cls, "ca")
            crl = x509.load_der_x509_crl(cache.get(key), default_backend())
            self.assertIsInstance(crl.signature_hash_algorithm, hash_cls)

            key = get_crl_cache_key(data.serial, hash_cls(), enc_cls, "user")
            crl = x509.load_der_x509_crl(cache.get(key), default_backend())

    @override_tmpcadir()
    @freeze_time(timestamps["everything_valid"])
    def test_cache_all_crls(self) -> None:
        """Test caching when all CAs are valid."""
        hash_cls = hashes.SHA512
        enc_cls = Encoding.DER
        tasks.cache_crls()

        for data in self.cas.values():
            key = get_crl_cache_key(data.serial, hash_cls(), enc_cls, "ca")
            crl = x509.load_der_x509_crl(cache.get(key), default_backend())
            self.assertIsInstance(crl.signature_hash_algorithm, hash_cls)

            key = get_crl_cache_key(data.serial, hash_cls(), enc_cls, "user")
            crl = x509.load_der_x509_crl(cache.get(key), default_backend())

    @override_tmpcadir()
    @freeze_time(timestamps["everything_expired"])
    def test_cache_all_crls_expired(self) -> None:
        """Test that nothing is cashed if all CAs are expired."""

        hash_cls = hashes.SHA512
        enc_cls = Encoding.DER
        tasks.cache_crls()

        for data in self.cas.values():
            key = get_crl_cache_key(data.serial, hash_cls(), enc_cls, "ca")
            self.assertIsNone(cache.get(key))

    @override_tmpcadir()
    def test_no_password(self) -> None:
        """Test creating a CRL for a CA where we have no password."""

        msg = r"^Password was not given but private key is encrypted$"
        with self.settings(CA_PASSWORDS={}), self.assertRaisesRegex(TypeError, msg):
            tasks.cache_crl(self.cas["pwd"].serial)

    def test_no_private_key(self) -> None:
        """Test creating a CRL for a CA where no private key is available."""

        with self.assertRaises(FileNotFoundError):
            tasks.cache_crl(self.cas["pwd"].serial)


@freeze_time(timestamps["everything_valid"])
class GenerateOCSPKeysTestCase(TestCaseMixin, TestCase):
    """Test the generate_ocsp_key task."""

    load_cas = "__usable__"

    @override_tmpcadir()
    def test_single(self) -> None:
        """Test creating a single key."""

        for ca in self.cas.values():
            tasks.generate_ocsp_key(ca.serial)
            self.assertTrue(ca_storage.exists("ocsp/%s.key" % ca.serial))
            self.assertTrue(ca_storage.exists("ocsp/%s.pem" % ca.serial))

    @override_tmpcadir()
    def test_all(self) -> None:
        """Test creating all keys."""

        tasks.generate_ocsp_keys()

        for ca in self.cas.values():
            tasks.generate_ocsp_key(ca.serial)
            self.assertTrue(ca_storage.exists("ocsp/%s.key" % ca.serial))
            self.assertTrue(ca_storage.exists("ocsp/%s.pem" % ca.serial))


@freeze_time(timestamps["everything_valid"])
class AcmeValidateChallengeTestCase(TestCaseMixin, AcmeValuesMixin, TestCase):
    """Test :py:func:`~django_ca.tasks.acme_validate_challenge`."""

    load_cas = ("root",)

    def setUp(self) -> None:
        super().setUp()
        self.hostname = "challenge.example.com"
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
            auth=self.auth, type=AcmeChallenge.TYPE_HTTP_01, status=AcmeChallenge.STATUS_PROCESSING
        )

        encoded = jose.encode_b64jose(self.chall.token.encode("utf-8"))
        thumbprint = self.account.thumbprint
        self.expected = f"{encoded}.{thumbprint}"
        self.url = f"http://{self.auth.value}/.well-known/acme-challenge/{encoded}"

    @contextmanager
    def mock_challenge(
        self,
        challenge: typing.Optional[AcmeChallenge] = None,
        status: int = HTTPStatus.OK,
        content: typing.Optional[typing.Union[io.BytesIO, bytes]] = None,
        call_count: int = 1,
        token: typing.Optional[str] = None,
    ) -> typing.Iterator[requests_mock.mocker.Mocker]:
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

        self.assertEqual(matcher.call_count, call_count)

    def refresh_from_db(self) -> None:
        """Refresh objects from database."""
        self.account.refresh_from_db()
        self.order.refresh_from_db()
        self.auth.refresh_from_db()
        self.chall.refresh_from_db()

    def assertInvalid(self) -> None:  # pylint: disable=invalid-name; unittest standard
        """Assert that the challenge validation failed."""
        self.refresh_from_db()
        self.assertEqual(self.chall.status, AcmeChallenge.STATUS_INVALID)
        self.assertEqual(self.auth.status, AcmeAuthorization.STATUS_INVALID)
        self.assertEqual(self.order.status, AcmeOrder.STATUS_INVALID)

    def assertValid(self, order_state: str = AcmeOrder.STATUS_READY) -> None:  # pylint: disable=invalid-name
        """Assert that the challenge is valid."""
        self.refresh_from_db()
        self.assertEqual(self.chall.status, AcmeChallenge.STATUS_VALID)
        self.assertEqual(self.auth.status, AcmeAuthorization.STATUS_VALID)
        self.assertEqual(self.order.status, order_state)

    def test_acme_disabled(self) -> None:
        """Test invoking task when ACME support is not enabled."""

        with self.settings(CA_ENABLE_ACME=False), self.assertLogs() as logcm:
            tasks.acme_validate_challenge(self.chall.pk)
        self.assertEqual(logcm.output, ["ERROR:django_ca.tasks:ACME is not enabled."])

    def test_unknown_challenge(self) -> None:
        """Test invoking task with an unknown challenge."""

        AcmeChallenge.objects.all().delete()
        with self.assertLogs() as logcm:
            tasks.acme_validate_challenge(self.chall.pk)

        self.assertEqual(logcm.output, [f"ERROR:django_ca.tasks:Challenge with id={self.chall.pk} not found"])

    def test_status_not_processing(self) -> None:
        """Test invoking task where the status is not "processing"."""

        self.chall.status = AcmeChallenge.STATUS_PENDING
        self.chall.save()

        with self.assertLogs() as logcm:
            tasks.acme_validate_challenge(self.chall.pk)

        self.assertEqual(
            logcm.output, [f"ERROR:django_ca.tasks:{self.chall}: pending: Invalid state (must be processing)"]
        )

    def test_unusable_auth(self) -> None:
        """Test invoking task with an unusable authentication."""
        self.auth.status = AcmeAuthorization.STATUS_VALID
        self.auth.save()

        with self.assertLogs() as logcm:
            tasks.acme_validate_challenge(self.chall.pk)

        self.assertEqual(logcm.output, [f"ERROR:django_ca.tasks:{self.chall}: Authentication is not usable"])

    def test_request_exception(self) -> None:
        """Test requests throwing an exception."""
        with self.patch("requests.get", side_effect=Exception("foo")) as req_mock:
            tasks.acme_validate_challenge(self.chall.pk)
        self.assertInvalid()
        self.assertEqual(req_mock.mock_calls, [((self.url,), {"timeout": 1, "stream": True})])

    def test_response_not_ok(self) -> None:
        """Test the server not returning a HTTP status code 200."""

        with self.mock_challenge(status=HTTPStatus.NOT_FOUND):
            tasks.acme_validate_challenge(self.chall.pk)
        self.assertInvalid()

    def test_response_wrong_content(self) -> None:
        """Test the server returning the wrong content in the response."""

        with self.mock_challenge(content=b"wrong answer"), self.assertLogs(
            "django_ca.tasks", "DEBUG"
        ) as logcm:
            tasks.acme_validate_challenge(self.chall.pk)
        self.assertInvalid()
        self.assertEqual(
            logcm.output,
            [
                f"INFO:django_ca.tasks:{str(self.chall)} is invalid",
            ],
        )

    def test_unsupported_challenge(self) -> None:
        """Test what happens when challenge type is not supported."""

        self.chall.type = AcmeChallenge.TYPE_TLS_ALPN_01
        self.chall.save()

        with self.mock_challenge(call_count=0, content="foo", token="foo"), self.assertLogs(
            "django_ca.tasks", "DEBUG"
        ) as logcm:
            tasks.acme_validate_challenge(self.chall.pk)
        self.assertInvalid()
        self.assertEqual(
            logcm.output,
            [
                f"ERROR:django_ca.tasks:{str(self.chall)}: Challenge type is not supported.",
                f"INFO:django_ca.tasks:{str(self.chall)} is invalid",
            ],
        )

    def test_basic(self) -> None:
        """Test validation actually working."""

        with self.mock_challenge():
            tasks.acme_validate_challenge(self.chall.pk)
        self.assertValid()

    def test_multiple_auths(self) -> None:
        """If other authentications exist that are not in the valid state, order does not become valid."""

        AcmeAuthorization.objects.create(
            order=self.order, type=AcmeAuthorization.TYPE_DNS, value="other.example.com"
        )
        with self.mock_challenge():
            tasks.acme_validate_challenge(self.chall.pk)

        self.assertValid(AcmeOrder.STATUS_PENDING)


@freeze_time(timestamps["everything_valid"])
class AcmeIssueCertificateTestCase(TestCaseMixin, AcmeValuesMixin, TestCase):
    """Test :py:func:`~django_ca.tasks.acme_issue_certificate`."""

    load_cas = ("root",)

    def setUp(self) -> None:
        super().setUp()
        self.hostname = "challenge.example.com"
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
        self.acme_cert = AcmeCertificate.objects.create(
            order=self.order, csr=certs["root-cert"]["csr"]["pem"]
        )

    def test_acme_disabled(self) -> None:
        """Test invoking task when ACME support is not enabled."""

        with self.settings(CA_ENABLE_ACME=False), self.assertLogs() as logcm:
            tasks.acme_issue_certificate(self.acme_cert.pk)
        self.assertEqual(logcm.output, ["ERROR:django_ca.tasks:ACME is not enabled."])

    def test_unknown_ert(self) -> None:
        """Test invoking task with an unknown cert."""

        AcmeCertificate.objects.all().delete()
        with self.assertLogs() as logcm:
            tasks.acme_issue_certificate(self.acme_cert.pk)

        self.assertEqual(
            logcm.output, [f"ERROR:django_ca.tasks:Certificate with id={self.acme_cert.pk} not found"]
        )

    def test_unusable_cert(self) -> None:
        """Test invoking task where the order is not usable."""

        self.order.status = AcmeChallenge.STATUS_VALID  # usually would mean: already issued
        self.order.save()

        with self.assertLogs() as logcm:
            tasks.acme_issue_certificate(self.acme_cert.pk)

        self.assertEqual(
            logcm.output, [f"ERROR:django_ca.tasks:{self.order}: Cannot issue certificate for this order"]
        )

    @override_tmpcadir()
    def test_basic(self) -> None:
        """Test basic certificate issuance."""

        with self.assertLogs() as logcm:
            tasks.acme_issue_certificate(self.acme_cert.pk)

        self.assertEqual(
            logcm.output, [f"INFO:django_ca.tasks:{self.order}: Issuing certificate for dns:{self.hostname}"]
        )
        self.acme_cert.refresh_from_db()
        self.order.refresh_from_db()
        self.assertEqual(self.order.status, AcmeOrder.STATUS_VALID)
        self.assertEqual(
            self.acme_cert.cert.subject_alternative_name,
            SubjectAlternativeName({"value": ["dns:%s" % self.hostname]}),
        )
        self.assertEqual(self.acme_cert.cert.expires, timezone.now() + ca_settings.ACME_DEFAULT_CERT_VALIDITY)
        self.assertEqual(self.acme_cert.cert.cn, self.hostname)

    @override_tmpcadir()
    def test_two_hostnames(self) -> None:
        """Test setting two hostnames."""

        hostname2 = "example.net"
        AcmeAuthorization.objects.create(order=self.order, value=hostname2)

        # NOTE; not testing log output here, because order of hostnames might not be stable
        tasks.acme_issue_certificate(self.acme_cert.pk)

        self.acme_cert.refresh_from_db()
        self.order.refresh_from_db()
        self.assertEqual(self.order.status, AcmeOrder.STATUS_VALID)
        self.assertEqual(
            self.acme_cert.cert.subject_alternative_name,
            SubjectAlternativeName(
                {
                    "value": [
                        "dns:%s" % self.hostname,
                        "dns:%s" % hostname2,
                    ]
                }
            ),
        )
        self.assertEqual(self.acme_cert.cert.expires, timezone.now() + ca_settings.ACME_DEFAULT_CERT_VALIDITY)
        self.assertIn(self.acme_cert.cert.cn, [self.hostname, hostname2])

    @override_tmpcadir()
    def test_not_after(self) -> None:
        """Test certificate issuance with not_after attr."""
        not_after = timezone.now() + timedelta(days=20)
        self.order.not_after = not_after
        self.order.save()

        with self.assertLogs() as logcm:
            tasks.acme_issue_certificate(self.acme_cert.pk)

        self.assertEqual(
            logcm.output, [f"INFO:django_ca.tasks:{self.order}: Issuing certificate for dns:{self.hostname}"]
        )
        self.acme_cert.refresh_from_db()
        self.order.refresh_from_db()
        self.assertEqual(self.order.status, AcmeOrder.STATUS_VALID)
        self.assertEqual(
            self.acme_cert.cert.subject_alternative_name,
            SubjectAlternativeName({"value": ["dns:%s" % self.hostname]}),
        )
        self.assertEqual(self.acme_cert.cert.expires, not_after)
        self.assertEqual(self.acme_cert.cert.cn, self.hostname)


@freeze_time(timestamps["everything_valid"])
class AcmeCleanupTestCase(TestCaseMixin, AcmeValuesMixin, TestCase):
    """Test :py:func:`~django_ca.tasks.acme_cleanup`."""

    load_cas = ("root",)

    def setUp(self) -> None:
        super().setUp()
        self.hostname = "challenge.example.com"
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
        self.cert = AcmeCertificate.objects.create(order=self.order, csr=certs["root-cert"]["csr"]["pem"])

    def test_basic(self) -> None:
        """Basic test."""
        tasks.acme_cleanup()  # does nothing if nothing is expired

        self.assertEqual(self.cert, AcmeCertificate.objects.get(pk=self.cert.pk))
        self.assertEqual(self.order, AcmeOrder.objects.get(pk=self.order.pk))
        self.assertEqual(self.auth, AcmeAuthorization.objects.get(pk=self.auth.pk))
        self.assertEqual(self.account, AcmeAccount.objects.get(pk=self.account.pk))

        with self.freeze_time(timezone.now() + timedelta(days=3)):
            tasks.acme_cleanup()

        self.assertEqual(AcmeOrder.objects.all().count(), 0)
        self.assertEqual(AcmeAuthorization.objects.all().count(), 0)
        self.assertEqual(AcmeChallenge.objects.all().count(), 0)
        self.assertEqual(AcmeCertificate.objects.all().count(), 0)

    def test_acme_disabled(self) -> None:
        """Test task when ACME is disabled."""

        with self.settings(CA_ENABLE_ACME=False), self.assertLogs() as logcm:
            with self.freeze_time(timezone.now() + timedelta(days=3)):
                tasks.acme_cleanup()
        self.assertEqual(logcm.output, ["INFO:django_ca.tasks:ACME is not enabled, not doing anything."])

        self.assertEqual(AcmeOrder.objects.all().count(), 1)
        self.assertEqual(AcmeAuthorization.objects.all().count(), 1)
        self.assertEqual(AcmeChallenge.objects.all().count(), 1)
        self.assertEqual(AcmeCertificate.objects.all().count(), 1)

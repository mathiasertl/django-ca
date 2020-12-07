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

"""Test ACME related views."""

import json
from contextlib import contextmanager
from datetime import timedelta
from http import HTTPStatus
from unittest import mock

import acme
import josepy as jose
import pyrfc3339
import pytz
from OpenSSL.crypto import X509Req
from requests.utils import parse_header_links

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from django.conf import settings
from django.test.utils import override_settings
from django.urls import reverse
from django.utils import timezone
from django.utils.crypto import get_random_string

from freezegun import freeze_time

from .. import ca_settings
from ..acme.messages import NewOrder
from ..acme.responses import AcmeResponseUnauthorized
from ..models import AcmeAccount
from ..models import AcmeAuthorization
from ..models import AcmeCertificate
from ..models import AcmeChallenge
from ..models import AcmeOrder
from ..models import Certificate
from ..models import CertificateAuthority
from ..models import acme_slug
from ..tasks import acme_issue_certificate
from ..tasks import acme_validate_challenge
from .base import DjangoCAWithCATestCase
from .base import DjangoCAWithCATransactionTestCase
from .base import certs
from .base import override_tmpcadir
from .base import timestamps


class DirectoryTestCase(DjangoCAWithCATestCase):
    """Test basic ACMEv2 directory view."""
    url = reverse('django_ca:acme-directory')

    @freeze_time(timestamps['everything_valid'])
    def test_default(self):
        """Test the default directory view."""
        ca = CertificateAuthority.objects.default()
        ca.acme_enabled = True
        ca.save()

        with mock.patch('secrets.token_bytes', return_value=b'foobar'):
            response = self.client.get(self.url)
        self.assertEqual(response.status_code, HTTPStatus.OK)
        req = response.wsgi_request
        self.assertEqual(response.json(), {
            'Zm9vYmFy': 'https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417',
            'keyChange': 'http://localhost:8000/django_ca/acme/todo/key-change',
            'revokeCert': 'http://localhost:8000/django_ca/acme/todo/revoke-cert',
            'newAccount': req.build_absolute_uri('/django_ca/acme/%s/new-account/' % ca.serial),
            'newNonce': req.build_absolute_uri('/django_ca/acme/%s/new-nonce/' % ca.serial),
            'newOrder': req.build_absolute_uri('/django_ca/acme/%s/new-order/' % ca.serial),
        })

    @freeze_time(timestamps['everything_valid'])
    def test_named_ca(self):
        """Test getting directory for named CA."""

        ca = CertificateAuthority.objects.default()
        ca.acme_enabled = True
        ca.save()

        url = reverse('django_ca:acme-directory', kwargs={'serial': ca.serial})
        with mock.patch('secrets.token_bytes', return_value=b'foobar'):
            response = self.client.get(url)
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(response['Content-Type'], 'application/json')
        req = response.wsgi_request
        self.assertEqual(response.json(), {
            'Zm9vYmFy': 'https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417',
            'keyChange': 'http://localhost:8000/django_ca/acme/todo/key-change',
            'revokeCert': 'http://localhost:8000/django_ca/acme/todo/revoke-cert',
            'newAccount': req.build_absolute_uri('/django_ca/acme/%s/new-account/' % ca.serial),
            'newNonce': req.build_absolute_uri('/django_ca/acme/%s/new-nonce/' % ca.serial),
            'newOrder': req.build_absolute_uri('/django_ca/acme/%s/new-order/' % ca.serial),
        })

    @freeze_time(timestamps['everything_valid'])
    def test_meta(self):
        """Test the meta property."""
        ca = CertificateAuthority.objects.default()
        ca.acme_enabled = True
        ca.website = 'http://ca.example.com'
        ca.acme_terms_of_service = 'http://ca.example.com/acme/tos'
        ca.caa_identity = 'ca.example.com'
        ca.save()

        url = reverse('django_ca:acme-directory', kwargs={'serial': ca.serial})
        with mock.patch('secrets.token_bytes', return_value=b'foobar'):
            response = self.client.get(url)
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(response['Content-Type'], 'application/json')
        req = response.wsgi_request
        self.assertEqual(response.json(), {
            'Zm9vYmFy': 'https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417',
            'keyChange': 'http://localhost:8000/django_ca/acme/todo/key-change',
            'revokeCert': 'http://localhost:8000/django_ca/acme/todo/revoke-cert',
            'newAccount': req.build_absolute_uri('/django_ca/acme/%s/new-account/' % ca.serial),
            'newNonce': req.build_absolute_uri('/django_ca/acme/%s/new-nonce/' % ca.serial),
            'newOrder': req.build_absolute_uri('/django_ca/acme/%s/new-order/' % ca.serial),
            'meta': {
                'termsOfService': ca.acme_terms_of_service,
                'caaIdentities': [
                    ca.caa_identity,
                ],
                'website': ca.website,
            },
        })

    @freeze_time(timestamps['everything_valid'])
    def test_acme_default_disabled(self):
        """Test that fetching the default CA with ACME disabled doesn't work."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, HTTPStatus.NOT_FOUND)
        self.assertEqual(response['Content-Type'], 'application/problem+json')
        self.assertEqual(response.json(), {
            'detail': 'No (usable) default CA configured.',
            'status': 404,
            'type': 'urn:ietf:params:acme:error:not-found',
        })

    @freeze_time(timestamps['everything_valid'])
    def test_acme_disabled(self):
        """Test that fetching the default CA with ACME disabled doesn't work."""
        ca = CertificateAuthority.objects.default()
        url = reverse('django_ca:acme-directory', kwargs={'serial': ca.serial})
        response = self.client.get(url)
        self.assertEqual(response.status_code, HTTPStatus.NOT_FOUND)
        self.assertEqual(response['Content-Type'], 'application/problem+json')
        self.assertEqual(response.json(), {
            'detail': '%s: CA not found.' % ca.serial,
            'status': 404,
            'type': 'urn:ietf:params:acme:error:not-found',
        })

    def test_no_ca(self):
        """Test using default CA when **no** CA exists."""
        CertificateAuthority.objects.all().delete()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, HTTPStatus.NOT_FOUND)
        self.assertEqual(response['Content-Type'], 'application/problem+json')
        self.assertEqual(response.json(), {
            'detail': 'No (usable) default CA configured.',
            'status': 404,
            'type': 'urn:ietf:params:acme:error:not-found',
        })

    @freeze_time(timestamps['everything_expired'])
    def test_expired_ca(self):
        """Test using default CA when all CAs are expired."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, HTTPStatus.NOT_FOUND)
        self.assertEqual(response['Content-Type'], 'application/problem+json')
        self.assertEqual(response.json(), {
            'detail': 'No (usable) default CA configured.',
            'status': 404,
            'type': 'urn:ietf:params:acme:error:not-found',
        })

    @override_settings(CA_ENABLE_ACME=False)
    def test_disabled(self):
        """Test that CA_ENABLE_ACME=False means HTTP 404."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, HTTPStatus.NOT_FOUND)
        self.assertEqual(response['Content-Type'], 'text/html')  # --> coming from Django

    def test_unknown_serial(self):
        """Test explicitly naming an unknown serial."""
        serial = 'ABCDEF'
        url = reverse('django_ca:acme-directory', kwargs={'serial': serial})
        response = self.client.get(url)

        self.assertEqual(response['Content-Type'], 'application/problem+json')
        self.assertEqual(response.json(), {
            'detail': 'ABCDEF: CA not found.',
            'status': 404,
            'type': 'urn:ietf:params:acme:error:not-found',
        })


class AcmeTestCaseMixin:
    """TestCase mixin with various common utility functions."""

    hostname = 'example.com'  # what we want a certificate for
    SERVER_NAME = 'example.com'
    PEM = '''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDF9BgQzTqQQnCLTcniyO++uDyb
RWtl+pCaG18whZOFa5ei+Sf0Qv9Z0cvOtZpxs3fE/IBVExKvZExtSf7JiBvh8Jv1
85svKEiZOhlkxB3sSem1xTdkPIr/kpgswK1BoWqX0pP5EQuVn483jXNNFWvaYM6H
KSAr5SU7IyM/9M95oQIDAQAB
-----END PUBLIC KEY-----'''

    def setUp(self):  # pylint: disable=invalid-name,missing-function-docstring
        super().setUp()
        self.ca = self.cas['root']
        self.cert = self.cas['child']  # actually a ca, but doesn't matter
        self.ca.acme_enabled = True
        self.ca.save()
        self.client.defaults['SERVER_NAME'] = self.SERVER_NAME

    def absolute_uri(self, name, **kwargs):
        """Override to set a default for `hostname`."""

        kwargs.setdefault('hostname', self.SERVER_NAME)
        return super().absolute_uri(name, **kwargs)

    def assertAcmeProblem(self, response, typ, status, message, ca=None):  # pylint: disable=invalid-name
        """Assert that a HTTP response confirms to an ACME problem report.

        .. seealso:: `RFC 8555, section 8 <https://tools.ietf.org/html/rfc8555#section-6.7>`_
        """
        self.assertEqual(response['Content-Type'], 'application/problem+json')
        self.assertLinkRelations(response, ca=ca)
        data = response.json()
        self.assertEqual(data['type'], 'urn:ietf:params:acme:error:%s' % typ)
        self.assertEqual(data['status'], status)
        self.assertEqual(data['detail'], message)
        self.assertIn('Replay-Nonce', response)

    def assertAcmeResponse(self, response, ca=None, link_relations=None):  # pylint: disable=invalid-name
        """Assert basic Acme Response properties (Content-Type & Link header)."""
        link_relations = link_relations or {}
        self.assertLinkRelations(response, ca=ca, **link_relations)
        self.assertEqual(response['Content-Type'], 'application/json')

    def assertLinkRelations(self, response, ca=None, **kwargs):  # pylint: disable=invalid-name
        """Assert Link relations for a given request."""
        if ca is None:
            ca = self.ca

        directory = reverse('django_ca:acme-directory', kwargs={'serial': ca.serial})
        kwargs['index'] = response.wsgi_request.build_absolute_uri(directory)

        expected = [{'rel': k, 'url': v} for k, v in kwargs.items()]
        actual = parse_header_links(response['Link'])
        self.assertEqual(expected, actual)

    def assertMalformed(self, resp, message='', typ='malformed'):  # pylint: disable=invalid-name
        """Assert an unauthorized response."""
        self.assertAcmeProblem(resp, typ=typ, status=HTTPStatus.BAD_REQUEST, message=message)

    def assertUnauthorized(self, resp,    # pylint: disable=invalid-name
                           message=AcmeResponseUnauthorized.message):
        """Assert an unauthorized response."""
        self.assertAcmeProblem(resp, 'unauthorized', status=HTTPStatus.UNAUTHORIZED, message=message)

    def get_nonce(self, ca=None):
        """Get a nonce with an actual request.

        Returns
        -------

        nonce : bytes
            The decoded bytes of the nonce.
        """
        if ca is None:
            ca = self.cas['root']

        url = reverse('django_ca:acme-new-nonce', kwargs={'serial': ca.serial})
        response = self.client.head(url)
        self.assertEqual(response.status_code, HTTPStatus.OK, response.content)
        return jose.decode_b64jose(response['replay-nonce'])

    @contextmanager
    def mock_slug(self):  # pylint: disable=no-self-use
        """Mock random slug generation, yields the static value."""

        slug = get_random_string(length=12)
        with mock.patch('django_ca.models.get_random_string', return_value=slug):
            yield slug

    def post(self, url, data, **kwargs):
        """Make a post request with some ACME specific default data."""
        kwargs.setdefault('content_type', 'application/jose+json')
        return self.client.post(url, json.dumps(data), **kwargs)


class AcmeNewNonceViewTestCase(DjangoCAWithCATestCase):
    """Test getting a new ACME nonce."""

    def setUp(self):
        super().setUp()
        self.url = reverse('django_ca:acme-new-nonce', kwargs={'serial': self.cas['root'].serial})

    @override_settings(CA_ENABLE_ACME=False)
    def test_disabled(self):
        """Test that CA_ENABLE_ACME=False means HTTP 404."""
        response = self.client.head(self.url)
        self.assertEqual(response.status_code, HTTPStatus.NOT_FOUND)
        self.assertEqual(response['Content-Type'], 'text/html')  # --> coming from Django

    def test_get_nonce(self):
        """Test that getting multiple nonces returns unique nonces."""

        nonces = []
        for _i in range(1, 5):
            response = self.client.head(self.url)
            self.assertEqual(response.status_code, HTTPStatus.OK)
            self.assertEqual(len(response['replay-nonce']), 43)
            self.assertEqual(response['cache-control'], 'no-store')
            nonces.append(response['replay-nonce'])

        self.assertEqual(len(nonces), len(set(nonces)))

    def test_get_request(self):
        """RFC 8555, section 7.2 also specifies a GET request."""

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)
        self.assertEqual(len(response['replay-nonce']), 43)
        self.assertEqual(response['cache-control'], 'no-store')


class AcmeBaseViewTestCaseMixin(AcmeTestCaseMixin):
    """Base class with test cases for all views."""

    post_as_get = False

    def setUp(self):
        super().setUp()
        self.account_slug = acme_slug()
        self.kid = 'http://%s%s' % (self.SERVER_NAME, self.absolute_uri(
            ':acme-account', serial=self.ca.serial, slug=self.account_slug
        ))

    def acme(self, uri, msg, cert=None, kid=None, nonce=None, payload_cb=None, post_kwargs=None):
        """Do a generic ACME request.

        The `payload_cb` parameter is an optional callback that will receive the message data before being
        serialized to JSON.
        """

        if nonce is None:
            nonce = self.get_nonce()
        if cert is None:
            cert = self.cert
        if post_kwargs is None:
            post_kwargs = {}

        comparable = jose.util.ComparableRSAKey(cert.key(password=None))
        key = jose.jwk.JWKRSA(key=comparable)

        if isinstance(msg, jose.json_util.JSONObjectWithFields):
            payload = msg.to_json()
            if payload_cb is not None:
                payload = payload_cb(payload)
            payload = json.dumps(payload).encode('utf-8')
        else:
            payload = msg

        jws = acme.jws.JWS.sign(payload, key, jose.jwa.RS256, nonce=nonce, url=self.absolute_uri(uri),
                                kid=kid)
        return self.post(uri, jws.to_json(), **post_kwargs)

    def get_message(self, **kwargs):
        """Return a  message that can be sent to the server successfully.

        This function is used by test cases that want to get a useful message and manipulate it in some way so
        that it violates the ACME spec.
        """
        if self.post_as_get:
            return b''

        return self.message_cls(**kwargs)

    def get_url(self, **kwargs):
        """Get a URL for this view with the given kwargs."""
        return reverse('django_ca:%s' % self.view_name, kwargs=kwargs)

    @property
    def message(self):
        """Property for sending the default message.

        """
        if self.post_as_get:
            return b''

        return self.get_message()

    @override_tmpcadir(CA_ENABLE_ACME=False)
    def test_disabled_acme(self):
        """Test that we get HTTP 404 if ACME is disabled."""
        resp = self.acme(self.url, self.message, nonce=b'foo')
        self.assertEqual(resp.status_code, HTTPStatus.NOT_FOUND)

    @override_tmpcadir()
    def test_invalid_content_type(self):
        """Test that any request with an invalid Content-Type header is an error.

        .. seealso:: RFC 8555, 6.2
        """
        resp = self.acme(self.url, self.message, post_kwargs={'CONTENT_TYPE': 'FOO'})
        self.assertAcmeProblem(resp, 'malformed', status=HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                               message='Requests must use the application/jose+json content type.')

    @override_tmpcadir()
    def test_jwk_and_kid(self):
        """Test sending both a jwk and a kid, which are supposed to be mutually exclusive."""

        sign = acme.jws.Signature.sign

        def sign_mock(*args, **kwargs):
            """Mock function to set include_jwk to true."""
            kwargs['include_jwk'] = True
            return sign(*args, **kwargs)

        with mock.patch('acme.jws.Signature.sign', side_effect=sign_mock):
            resp = self.acme(self.url, self.message, kid='foo')
        self.assertMalformed(resp, 'jwk and kid are mutually exclusive.')

    def test_invalid_json(self):
        """Test sending invalid JSON to the server."""

        resp = self.client.post(self.url, '{', content_type='application/jose+json')
        self.assertMalformed(resp, 'Could not parse JWS token.')


class AcmeWithAccountViewTestCaseMixin(AcmeBaseViewTestCaseMixin):  # pylint: disable=too-few-public-methods
    """Mixin that also adds an account to the database."""
    def setUp(self):  # pylint: disable=invalid-name,missing-function-docstring
        super().setUp()
        self.account = AcmeAccount.objects.create(
            ca=self.ca, terms_of_service_agreed=True, slug=self.account_slug, acme_kid=self.kid, pem=self.PEM
        )


@freeze_time(timestamps['everything_valid'])
class AcmeNewAccountViewTestCase(AcmeBaseViewTestCaseMixin, DjangoCAWithCATestCase):
    """Test creating a new account."""

    contact = 'mailto:user@example.com'
    url = reverse('django_ca:acme-new-account', kwargs={'serial': certs['root']['serial']})
    message = acme.messages.Registration(contact=(contact, ), terms_of_service_agreed=True)
    message_cls = acme.messages.Registration
    view_name = 'acme-new-account'

    @override_tmpcadir()
    def test_basic(self):
        """Basic test for creating an account via ACME."""

        self.assertEqual(AcmeAccount.objects.count(), 0)
        with self.mock_slug() as slug:
            resp = self.acme(self.url, self.message)
        self.assertEqual(resp.status_code, HTTPStatus.CREATED, resp.content)
        self.assertAcmeResponse(resp)

        # Get first AcmeAccount - which must be the one we just created
        acc = AcmeAccount.objects.get(slug=slug)
        self.assertEqual(acc.status, AcmeAccount.STATUS_VALID)
        self.assertEqual(acc.ca, self.ca)
        self.assertEqual(acc.contact, self.contact)
        self.assertTrue(acc.terms_of_service_agreed)
        self.assertEqual(acc.pem, self.PEM)

        # Test the response body
        self.assertEqual(resp['location'], self.absolute_uri(':acme-account', serial=self.ca.serial,
                                                             slug=acc.slug))
        self.assertEqual(resp.json(), {
            'contact': [self.contact],
            'orders': self.absolute_uri(':acme-account-orders', serial=self.ca.serial, slug=acc.slug),
            'status': 'valid',
        })

        # Test making a request where we already have a key
        resp = self.acme(self.url, self.get_message(
            contact=('mailto:other@example.net', ),  # make sure that we do not update the user
            terms_of_service_agreed=True,
        ))
        self.assertEqual(resp.status_code, HTTPStatus.OK)
        self.assertAcmeResponse(resp)
        self.assertEqual(resp['location'], self.absolute_uri(':acme-account', serial=self.ca.serial,
                                                             slug=acc.slug))
        self.assertEqual(resp.json(), {
            'contact': [self.contact],
            'orders': self.absolute_uri(':acme-account-orders', serial=self.ca.serial, slug=acc.slug),
            'status': 'valid',
        })
        self.assertEqual(AcmeAccount.objects.count(), 1)

        # test only_return existing:
        resp = self.acme(self.url, self.get_message(
            contact=('mailto:other@example.net', ),  # make sure that we do not update the user
            only_return_existing=True,
        ))
        self.assertEqual(resp.status_code, HTTPStatus.OK)
        self.assertAcmeResponse(resp)
        self.assertEqual(resp['location'], self.absolute_uri(':acme-account', serial=self.ca.serial,
                                                             slug=acc.slug))
        self.assertEqual(resp.json(), {
            'contact': [self.contact],
            'orders': self.absolute_uri(':acme-account-orders', serial=self.ca.serial, slug=acc.slug),
            'status': 'valid',
        })
        self.assertEqual(AcmeAccount.objects.count(), 1)

        # Test object properties one last time
        acc = AcmeAccount.objects.get(slug=slug)
        self.assertEqual(acc.status, AcmeAccount.STATUS_VALID)
        self.assertEqual(acc.ca, self.ca)
        self.assertEqual(acc.contact, self.contact)
        self.assertTrue(acc.terms_of_service_agreed)

    @override_tmpcadir()
    def test_no_contact(self):
        """Basic test for creating an account via ACME."""

        self.ca.acme_requires_contact = False
        self.ca.save()

        self.assertEqual(AcmeAccount.objects.count(), 0)
        with self.mock_slug() as slug:
            resp = self.acme(self.url, self.get_message(terms_of_service_agreed=True))
        self.assertEqual(resp.status_code, HTTPStatus.CREATED)
        self.assertAcmeResponse(resp)

        # Get first AcmeAccount - which must be the one we just created
        acc = AcmeAccount.objects.get(slug=slug)
        self.assertEqual(acc.status, AcmeAccount.STATUS_VALID)
        self.assertEqual(acc.ca, self.ca)
        self.assertEqual(acc.contact, '')
        self.assertTrue(acc.terms_of_service_agreed)

        # Test the response body
        self.assertEqual(resp['location'], self.absolute_uri(':acme-account', serial=self.ca.serial,
                                                             slug=acc.slug))
        self.assertEqual(resp.json(), {
            'contact': [],
            'orders': self.absolute_uri(':acme-account-orders', serial=self.ca.serial, slug=acc.slug),
            'status': 'valid',
        })

    @override_tmpcadir()
    def test_multiple_contacts(self):
        """Test for creating an account with multiple email addresses."""

        contact_2 = 'mailto:user@example.net'
        with self.mock_slug() as slug:
            resp = self.acme(self.url, self.get_message(contact=(self.contact, contact_2),
                                                        terms_of_service_agreed=True))
        self.assertEqual(resp.status_code, HTTPStatus.CREATED)
        self.assertAcmeResponse(resp)

        # Get first AcmeAccount - which must be the one we just created
        acc = AcmeAccount.objects.get(slug=slug)
        self.assertEqual(acc.status, AcmeAccount.STATUS_VALID)
        self.assertEqual(acc.ca, self.ca)
        self.assertCountEqual(acc.contact.split('\n'), [self.contact, contact_2])
        self.assertTrue(acc.terms_of_service_agreed)

        # Test the response body
        self.assertEqual(resp['location'], self.absolute_uri(':acme-account', serial=self.ca.serial,
                                                             slug=acc.slug))
        self.assertEqual(resp.json(), {
            'contact': [self.contact, contact_2],
            'orders': self.absolute_uri(':acme-account-orders', serial=self.ca.serial, slug=acc.slug),
            'status': 'valid',
        })

    @override_tmpcadir()
    def test_contacts_required(self):
        """Test failing to create an account if contact is required."""
        self.ca.acme_requires_contact = True
        self.ca.save()

        resp = self.acme(self.url, acme.messages.Registration(
            terms_of_service_agreed=True,
        ))
        self.assertEqual(resp.status_code, HTTPStatus.UNAUTHORIZED)
        self.assertUnauthorized(resp, 'Must provide at least one contact address.')
        self.assertEqual(AcmeAccount.objects.count(), 0)

    @override_tmpcadir()
    def test_unsupported_contact(self):
        """Test that creating an account with a phone number fails."""

        resp = self.acme(self.url, acme.messages.Registration(
            contact=('tel:1234567', self.contact),
            terms_of_service_agreed=True,
        ))
        self.assertEqual(resp.status_code, HTTPStatus.BAD_REQUEST)
        self.assertAcmeProblem(resp, 'unsupportedContact', status=HTTPStatus.BAD_REQUEST,
                               message='tel:1234567: Unsupported address scheme.')
        self.assertEqual(AcmeAccount.objects.count(), 0)

    @override_tmpcadir()
    def test_invalid_email(self):
        """Test that creating an account with a phone number fails."""

        resp = self.acme(self.url, acme.messages.Registration(
            contact=('mailto:"with spaces"@example.com', ),
            terms_of_service_agreed=True,
        ))
        self.assertEqual(resp.status_code, HTTPStatus.BAD_REQUEST)
        self.assertAcmeProblem(resp, 'invalidContact', status=HTTPStatus.BAD_REQUEST,
                               message='Quoted local part in email is not allowed.')
        self.assertEqual(AcmeAccount.objects.count(), 0)

        resp = self.acme(self.url, acme.messages.Registration(
            contact=('mailto:user@example.com,user@example.net', ),
            terms_of_service_agreed=True,
        ))
        self.assertEqual(resp.status_code, HTTPStatus.BAD_REQUEST)
        self.assertAcmeProblem(resp, 'invalidContact', status=HTTPStatus.BAD_REQUEST,
                               message='More than one addr-spec is not allowed.')
        self.assertEqual(AcmeAccount.objects.count(), 0)

        resp = self.acme(self.url, acme.messages.Registration(
            contact=('mailto:user@example.com?who-uses=this', ),
            terms_of_service_agreed=True,
        ))
        self.assertEqual(resp.status_code, HTTPStatus.BAD_REQUEST)
        self.assertAcmeProblem(resp, 'invalidContact', status=HTTPStatus.BAD_REQUEST,
                               message='example.com?who-uses=this: hfields are not allowed.')
        self.assertEqual(AcmeAccount.objects.count(), 0)

        resp = self.acme(self.url, acme.messages.Registration(
            contact=('mailto:user@example..com', ),
            terms_of_service_agreed=True,
        ))
        self.assertEqual(resp.status_code, HTTPStatus.BAD_REQUEST)
        self.assertAcmeProblem(resp, 'invalidContact', status=HTTPStatus.BAD_REQUEST,
                               message='example..com: Not a valid email address.')
        self.assertEqual(AcmeAccount.objects.count(), 0)

    @override_tmpcadir()
    def test_only_existing_does_not_exist(self):
        """Test making an only_existing request for an account that does not exist."""

        # test only_return existing:
        resp = self.acme(self.url, acme.messages.Registration(
            only_return_existing=True,
        ))
        self.assertAcmeProblem(resp, 'accountDoesNotExist', status=HTTPStatus.BAD_REQUEST,
                               message='Account does not exist.')
        self.assertEqual(AcmeAccount.objects.count(), 0)

    @override_tmpcadir()
    def test_validation_error(self):
        """Test triggering a model validation error.

        Note that at present it's probably inpossible to have such an error in real life as no fields have any
        validation of user-generated input that would not be captured before model validation.
        """
        with mock.patch('josepy.jwk.JWKRSA.thumbprint', return_value=b'abc' * 64):
            resp = self.acme(self.url, acme.messages.Registration(
                contact=(self.contact, ),
                terms_of_service_agreed=True,
            ))
            self.assertMalformed(resp, 'Account cannot be stored.')


@freeze_time(timestamps['everything_valid'])
class AcmeNewOrderViewTestCase(AcmeWithAccountViewTestCaseMixin, DjangoCAWithCATestCase):
    """Test creating a new order."""

    url = reverse('django_ca:acme-new-order', kwargs={'serial': certs['root']['serial']})
    message_cls = NewOrder

    def get_message(self, **kwargs):
        kwargs.setdefault('identifiers', [{'type': 'dns', 'value': self.SERVER_NAME}])
        return super().get_message(**kwargs)

    @override_tmpcadir()
    def test_basic(self, accept_naive=True):
        """Basic test for creating an account via ACME."""

        with self.mock_slug() as slug:
            resp = self.acme(self.url, self.message, kid=self.kid)
        self.assertEqual(resp.status_code, HTTPStatus.CREATED, resp.content)

        expires = timezone.now() + ca_settings.ACME_ORDER_VALIDITY
        self.assertEqual(resp.json(), {
            'authorizations': [
                self.absolute_uri(':acme-authz', serial=self.ca.serial, slug=slug),
            ],
            'expires': pyrfc3339.generate(expires, accept_naive=accept_naive),
            'finalize': self.absolute_uri(':acme-order-finalize', serial=self.ca.serial, slug=slug),
            'identifiers': [{'type': 'dns', 'value': self.SERVER_NAME}],
            'status': 'pending'
        })

        order = AcmeOrder.objects.get(account=self.account)
        self.assertEqual(order.account, self.account)
        self.assertEqual(order.slug, slug)
        self.assertEqual(order.status, 'pending')
        self.assertEqual(order.expires, expires)
        self.assertIsNone(order.not_before)
        self.assertIsNone(order.not_after)

        # Test the autogenerated AcmeAuthorization object
        authz = order.authorizations.all()
        self.assertEqual(len(authz), 1)
        self.assertEqual(authz[0].order, order)
        self.assertEqual(authz[0].type, 'dns')
        self.assertEqual(authz[0].value, self.SERVER_NAME)
        self.assertEqual(authz[0].status, AcmeAuthorization.STATUS_PENDING)
        self.assertFalse(authz[0].wildcard)

    @override_settings(USE_TZ=True)
    def test_basic_with_tz(self):
        """Basic test with timezone support enabled."""
        self.test_basic(accept_naive=False)

    @override_tmpcadir()
    def test_not_before_not_after(self, accept_naive=True):
        """Test the notBefore/notAfter properties."""
        not_before = timezone.now() + timedelta(seconds=10)
        not_after = timezone.now() + timedelta(days=3)

        if timezone.is_naive(not_before):
            not_before = timezone.make_aware(not_before, timezone=pytz.utc)
        if timezone.is_naive(not_after):
            not_after = timezone.make_aware(not_after, timezone=pytz.utc)

        msg = self.get_message(not_before=not_before, not_after=not_after)

        with self.mock_slug() as slug:
            resp = self.acme(self.url, msg, kid=self.kid)
        self.assertEqual(resp.status_code, HTTPStatus.CREATED, resp.content)

        expires = timezone.now() + ca_settings.ACME_ORDER_VALIDITY
        self.assertEqual(resp.json(), {
            'authorizations': [
                self.absolute_uri(':acme-authz', serial=self.ca.serial, slug=slug),
            ],
            'expires': pyrfc3339.generate(expires, accept_naive=accept_naive),
            'finalize': self.absolute_uri(':acme-order-finalize', serial=self.ca.serial, slug=slug),
            'identifiers': [{'type': 'dns', 'value': self.SERVER_NAME}],
            'status': 'pending',
            'notBefore': pyrfc3339.generate(not_before, accept_naive=accept_naive),
            'notAfter': pyrfc3339.generate(not_after, accept_naive=accept_naive),
        })

        order = AcmeOrder.objects.get(account=self.account)
        self.assertEqual(order.account, self.account)
        self.assertEqual(order.slug, slug)
        self.assertEqual(order.status, 'pending')
        self.assertEqual(order.expires, expires)

        if settings.USE_TZ:
            self.assertEqual(order.not_before, not_before)
            self.assertEqual(order.not_after, not_after)
        else:
            self.assertEqual(order.not_before, timezone.make_naive(not_before))
            self.assertEqual(order.not_after, timezone.make_naive(not_after))

        # Test the autogenerated AcmeAuthorization object
        authz = order.authorizations.all()
        self.assertEqual(len(authz), 1)
        self.assertEqual(authz[0].order, order)
        self.assertEqual(authz[0].type, 'dns')
        self.assertEqual(authz[0].value, self.SERVER_NAME)
        self.assertEqual(authz[0].status, AcmeAuthorization.STATUS_PENDING)
        self.assertFalse(authz[0].wildcard)

    @override_settings(USE_TZ=True)
    def test_not_before_not_after_with_tz(self):
        """Test the notBefore/notAfter properties, but with timezone support."""
        self.test_not_before_not_after(accept_naive=False)

    @override_tmpcadir()
    def test_no_identifiers(self):
        """Test sending no identifiers."""

        resp = self.acme(self.url, acme.messages.NewOrder(), kid=self.kid)
        self.assertMalformed(resp, 'Malformed payload.')

        # try empty tuple too
        resp = self.acme(self.url, acme.messages.NewOrder(identifiers=tuple()), kid=self.kid,
                         payload_cb=lambda d: dict(d, identifiers=()))
        self.assertMalformed(resp, 'Malformed payload.')

        self.assertEqual(AcmeOrder.objects.all().count(), 0)

    @override_tmpcadir(USE_TZ=True)
    def test_invalid_not_before_after(self):
        """Test invalid not_before/not_after dates."""

        past = timezone.now() - timedelta(days=1)
        resp = self.acme(self.url, self.get_message(not_before=past), kid=self.kid)
        self.assertMalformed(resp, 'Certificate cannot be valid before now.')

        far_future = timezone.now() + timedelta(days=3650)
        resp = self.acme(self.url, self.get_message(not_after=far_future), kid=self.kid)
        self.assertMalformed(resp, 'Certificate cannot be valid that long.')

        not_before = timezone.now() + timedelta(days=10)
        not_after = timezone.now() + timedelta(days=1)

        resp = self.acme(self.url, self.get_message(
            not_before=not_before, not_after=not_after), kid=self.kid)
        self.assertMalformed(resp, 'notBefore must be before notAfter.')


@freeze_time(timestamps['everything_valid'])
class AcmeAuthorizationViewTestCase(AcmeWithAccountViewTestCaseMixin, DjangoCAWithCATestCase):
    """Test creating a new order."""

    post_as_get = True
    view_name = 'acme-authz'

    def setUp(self):
        super().setUp()
        self.order = AcmeOrder.objects.create(account=self.account)
        self.order.add_authorizations([
            acme.messages.Identifier(typ=acme.messages.IDENTIFIER_FQDN, value='example.com')
        ])
        self.authz = AcmeAuthorization.objects.get(order=self.order, value='example.com')

    @property
    def url(self):
        """Get URL for the standard auth object."""
        return self.get_url(serial=self.ca.serial, slug=self.authz.slug)

    @override_tmpcadir()
    def test_basic(self, accept_naive=True):
        """Basic test for creating an account via ACME."""

        resp = self.acme(self.url, self.message, kid=self.kid)
        self.assertEqual(resp.status_code, HTTPStatus.OK, resp.content)
        self.assertAcmeResponse(resp)

        challenges = self.authz.challenges.all()
        self.assertEqual(len(challenges), 2)

        resp_data = resp.json()
        resp_challenges = resp_data.pop('challenges')
        self.assertCountEqual(resp_challenges, [
            {
                'type': challenges[0].type,
                'status': 'pending',
                'token': jose.encode_b64jose(challenges[0].token.encode('utf-8')),
                'url': 'http://%s/django_ca/acme/%s/chall/%s/' % (
                    self.SERVER_NAME, self.ca.serial, challenges[0].slug),
            },
            {
                'type': challenges[1].type,
                'status': 'pending',
                'token': jose.encode_b64jose(challenges[1].token.encode('utf-8')),
                'url': 'http://%s/django_ca/acme/%s/chall/%s/' % (
                    self.SERVER_NAME, self.ca.serial, challenges[1].slug),
            }
        ])

        expires = timezone.now() + ca_settings.ACME_ORDER_VALIDITY
        self.assertEqual(resp_data, {
            'expires': pyrfc3339.generate(expires, accept_naive=accept_naive),
            'identifier': {
                'type': 'dns',
                'value': 'example.com',
            },
            'status': 'pending',
        })

    @override_settings(USE_TZ=True)
    def test_basic_with_tz(self):
        """Basic test but with timezone support."""
        self.test_basic(accept_naive=False)

    @override_tmpcadir(USE_TZ=True)
    def test_valid_auth(self):
        """Test fetching a valid auth object."""

        self.authz.get_challenges()  # creates challenges in the first place
        self.authz.status = AcmeAuthorization.STATUS_VALID
        self.authz.save()
        self.authz.challenges.filter(type=AcmeChallenge.TYPE_HTTP_01).update(
            status=AcmeChallenge.STATUS_VALID, validated=timezone.now())

        resp = self.acme(self.url, self.message, kid=self.kid)
        self.assertEqual(resp.status_code, HTTPStatus.OK, resp.content)
        self.assertAcmeResponse(resp)

        challenges = self.authz.challenges.filter(status=AcmeChallenge.STATUS_VALID)
        self.assertEqual(len(challenges), 1)

        resp_data = resp.json()
        resp_challenges = resp_data.pop('challenges')
        self.assertCountEqual(resp_challenges, [
            {
                'type': challenges[0].type,
                'status': 'valid',
                'validated': pyrfc3339.generate(timezone.now()),  # time is frozen anyway
                'token': jose.encode_b64jose(challenges[0].token.encode('utf-8')),
                'url': 'http://%s/django_ca/acme/%s/chall/%s/' % (
                    self.SERVER_NAME, self.ca.serial, challenges[0].slug),
            },
        ])

        expires = timezone.now() + ca_settings.ACME_ORDER_VALIDITY
        self.assertEqual(resp_data, {
            'expires': pyrfc3339.generate(expires),
            'identifier': {
                'type': 'dns',
                'value': 'example.com',
            },
            'status': 'valid',
        })

    @override_tmpcadir(USE_TZ=True)
    def test_no_challenges(self):
        """Test viewing Auth with **no* challenges.

        This test case is useful because the ACME message class does not tolerate empty lists.
        """

        self.authz.get_challenges()  # creates challenges in the first place
        self.authz.status = AcmeAuthorization.STATUS_VALID
        self.authz.save()

        resp = self.acme(self.url, self.message, kid=self.kid)
        self.assertEqual(resp.status_code, HTTPStatus.OK, resp.content)
        self.assertAcmeResponse(resp)

        challenges = self.authz.challenges.filter(status=AcmeChallenge.STATUS_VALID)
        self.assertEqual(len(challenges), 0)

        expires = timezone.now() + ca_settings.ACME_ORDER_VALIDITY
        self.assertEqual(resp.json(), {
            'expires': pyrfc3339.generate(expires),
            'identifier': {
                'type': 'dns',
                'value': 'example.com',
            },
            'status': 'valid',
        })

    @override_tmpcadir()
    def test_unknown_auth(self):
        """Test fetching unknown auth object."""
        resp = self.acme(self.get_url(serial=self.ca.serial, slug='abc'), self.message, kid=self.kid)
        self.assertUnauthorized(resp, 'You are not authorized to perform this request.')


@freeze_time(timestamps['everything_valid'])
class AcmeChallengeViewTestCase(AcmeWithAccountViewTestCaseMixin, DjangoCAWithCATransactionTestCase):
    """Test retrieving a challenge."""

    post_as_get = True
    view_name = 'acme-challenge'

    def setUp(self):
        super().setUp()
        self.order = AcmeOrder.objects.create(account=self.account)
        self.order.add_authorizations([
            acme.messages.Identifier(typ=acme.messages.IDENTIFIER_FQDN, value='example.com')
        ])
        self.authz = AcmeAuthorization.objects.get(order=self.order, value='example.com')
        self.challenge = self.authz.get_challenges()[0]
        self.challenge.token = 'foobar'
        self.challenge.save()

    @property
    def url(self):
        """Get default generic url"""
        return self.get_url(serial=self.challenge.serial, slug=self.challenge.slug)

    @override_tmpcadir()
    def test_basic(self):
        """Basic test for creating an account via ACME."""

        with self.patch('django_ca.views.run_task') as mockcm:
            resp = self.acme(self.url, self.message, kid=self.kid)

        self.assertEqual(mockcm.call_args_list, [mock.call(acme_validate_challenge, self.challenge.pk)])

        self.assertEqual(resp.status_code, HTTPStatus.OK, resp.content)
        self.assertAcmeResponse(resp, link_relations={
            'up': 'http://%s%s' % (self.SERVER_NAME, self.authz.acme_url),
        })

        self.assertEqual(resp.json(), {
            'status': 'processing',
            'type': self.challenge.type,
            'token': jose.encode_b64jose(self.challenge.token.encode()),
            'url': 'http://%s%s' % (self.SERVER_NAME, self.challenge.acme_url),
        })

    @override_tmpcadir()
    def test_no_state_change(self):
        """Test challenge endpoint when no state change is triggered (e.g. already valid)."""

        self.challenge.status = AcmeChallenge.STATUS_VALID
        self.challenge.save()
        self.authz.status = AcmeAuthorization.STATUS_VALID
        self.authz.save()
        self.order.status = AcmeOrder.STATUS_VALID
        self.order.save()

        with self.patch('django_ca.views.run_task') as mockcm:
            resp = self.acme(self.url, self.message, kid=self.kid)

        mockcm.assert_not_called()  # no validation task was triggerd

        # ... but response is still ok
        self.assertEqual(resp.status_code, HTTPStatus.OK, resp.content)
        self.assertAcmeResponse(resp, link_relations={
            'up': 'http://%s%s' % (self.SERVER_NAME, self.authz.acme_url),
        })

        self.assertEqual(resp.json(), {
            'status': 'valid',
            'type': self.challenge.type,
            'token': jose.encode_b64jose(self.challenge.token.encode()),
            'url': 'http://%s%s' % (self.SERVER_NAME, self.challenge.acme_url),
        })

    @override_tmpcadir()
    def test_not_found(self):
        """Basic test for creating an account via ACME."""

        url = self.get_url(serial=self.challenge.serial, slug='abc')
        with self.patch('django_ca.views.run_task') as mockcm:
            resp = self.acme(url, self.message, kid=self.kid)
        mockcm.assert_not_called()
        self.assertUnauthorized(resp, 'You are not authorized to perform this request.')


@freeze_time(timestamps['everything_valid'])
class AcmeOrderFinalizeViewTestCase(AcmeWithAccountViewTestCaseMixin, DjangoCAWithCATransactionTestCase):
    """Test retrieving a challenge."""

    slug = '92MPyl7jm0zw'
    url = reverse('django_ca:acme-order-finalize', kwargs={'serial': certs['root']['serial'], 'slug': slug})

    def setUp(self):
        super().setUp()

        # Create a CSR based on root-cert
        # NOTE: certbot CSRs have an empty subject
        self.csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(self.hostname)]), critical=False
        ).sign(certs['root-cert']['key']['parsed'], hashes.SHA256())

        self.order = AcmeOrder.objects.create(account=self.account, status=AcmeOrder.STATUS_READY,
                                              slug=self.slug)
        self.order.add_authorizations([
            acme.messages.Identifier(typ=acme.messages.IDENTIFIER_FQDN, value=self.hostname)
        ])
        self.authz = AcmeAuthorization.objects.get(order=self.order, value=self.hostname)
        self.authz.status = AcmeAuthorization.STATUS_VALID
        self.authz.save()

    def assertBadCSR(self, resp, message):  # pylint: disable=invalid-name
        """Assert a badCSR error."""
        self.assertAcmeProblem(resp, 'badCSR', status=HTTPStatus.BAD_REQUEST, message=message)

    def get_message(self, csr):  # pylint: disable=no-self-use,arguments-differ
        """Get a message for the given cryptography CSR object."""
        req = X509Req.from_cryptography(csr)
        return acme.messages.CertificateRequest(
            csr=jose.util.ComparableX509(req)
        )

    @property
    def message(self):
        return self.get_message(self.csr)

    @override_tmpcadir()
    def test_basic(self, accept_naive=True):
        """Basic test for creating an account via ACME."""

        with self.patch('django_ca.views.run_task') as mockcm:
            resp = self.acme(self.url, self.message, kid=self.kid)
        self.assertEqual(resp.status_code, HTTPStatus.OK, resp.content)
        self.assertAcmeResponse(resp)

        order = AcmeOrder.objects.get(pk=self.order.pk)
        cert = order.acmecertificate
        self.assertEqual(mockcm.call_args_list,
                         [mock.call(acme_issue_certificate, acme_certificate_pk=cert.pk)])
        self.assertEqual(resp.json(), {
            'authorizations': [
                'http://%s%s' % (self.SERVER_NAME, self.authz.acme_url)
            ],
            'expires': pyrfc3339.generate(order.expires, accept_naive=accept_naive),
            'identifiers': [{'type': 'dns', 'value': self.hostname}],
            'status': 'processing',
        })

    @override_settings(USE_TZ=True)
    def test_basic_with_tz(self):
        """Basic test with USE_TZ=True."""
        self.test_basic(False)

    @override_tmpcadir()
    def test_not_found(self):
        """Test an order that does not exist."""
        url = reverse('django_ca:acme-order-finalize', kwargs={'serial': self.ca.serial, 'slug': 'foo'})
        with self.patch('django_ca.views.run_task') as mockcm:
            resp = self.acme(url, self.message, kid=self.kid)
        mockcm.assert_not_called()
        self.assertUnauthorized(resp, 'You are not authorized to perform this request.')

    @override_tmpcadir()
    def test_wrong_account(self):
        """Test an order for a different account."""

        account = AcmeAccount.objects.create(
            ca=self.ca, terms_of_service_agreed=True, slug='def', acme_kid='kid', pem='bar',
            thumbprint='foo'
        )
        self.order.account = account
        self.order.save()

        with self.patch('django_ca.views.run_task') as mockcm:
            resp = self.acme(self.url, self.message, kid=self.kid)
        mockcm.assert_not_called()
        self.assertUnauthorized(resp, 'You are not authorized to perform this request.')

    @override_tmpcadir()
    def test_not_ready(self):
        """Test an order that is not yet ready."""

        self.order.status = AcmeOrder.STATUS_INVALID
        self.order.save()

        with self.patch('django_ca.views.run_task') as mockcm:
            resp = self.acme(self.url, self.message, kid=self.kid)
        mockcm.assert_not_called()
        self.assertAcmeProblem(resp, 'orderNotReady', status=HTTPStatus.FORBIDDEN,
                               message='This order is not yet ready.')

    @override_tmpcadir()
    def test_invalid_auth(self):
        """Test an order where one of the authentications is not valid."""

        self.authz.status = AcmeAuthorization.STATUS_INVALID
        self.authz.save()

        with self.patch('django_ca.views.run_task') as mockcm:
            resp = self.acme(self.url, self.message, kid=self.kid)
        mockcm.assert_not_called()
        self.assertAcmeProblem(resp, 'orderNotReady', status=HTTPStatus.FORBIDDEN,
                               message='This order is not yet ready.')

    @override_tmpcadir()
    def test_csr_invalid_signature(self):
        """Test posting a CSR with an invalid signature"""

        # create property mock for CSR object.
        # We mock parse_acme_csr below because the actual class returned depends on the backend in use
        csr_mock = mock.MagicMock()
        # attach to type: https://docs.python.org/3/library/unittest.mock.html#unittest.mock.PropertyMock
        type(csr_mock).is_signature_valid = mock.PropertyMock(return_value=False)

        with self.patch('django_ca.views.run_task') as mockcm, self.patch(
                'django_ca.views.parse_acme_csr', return_value=csr_mock):
            resp = self.acme(self.url, self.message, kid=self.kid)
        mockcm.assert_not_called()
        self.assertBadCSR(resp, 'CSR signature is not valid.')

    @override_tmpcadir()
    def test_csr_bad_algorithm(self):
        """Test posting a CSR with a bad algorithm."""

        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(self.hostname)]), critical=False
        ).sign(certs['root-cert']['key']['parsed'], hashes.MD5())

        with self.patch('django_ca.views.run_task') as mockcm:
            resp = self.acme(self.url, self.get_message(csr), kid=self.kid)
        mockcm.assert_not_called()
        self.assertBadCSR(resp, 'md5: Insecure hash algorithm.')

    @override_tmpcadir()
    def test_csr_valid_subject(self):
        """Test posting a CSR where the CommonName was in the order."""

        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.hostname),
        ])).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(self.hostname)]), critical=False
        ).sign(certs['root-cert']['key']['parsed'], hashes.SHA256())

        with self.patch('django_ca.views.run_task') as mockcm:
            resp = self.acme(self.url, self.get_message(csr), kid=self.kid)
        self.assertEqual(resp.status_code, HTTPStatus.OK, resp.content)
        self.assertAcmeResponse(resp)

        order = AcmeOrder.objects.get(pk=self.order.pk)
        cert = order.acmecertificate
        self.assertEqual(mockcm.call_args_list,
                         [mock.call(acme_issue_certificate, acme_certificate_pk=cert.pk)])
        self.assertEqual(resp.json(), {
            'authorizations': [
                'http://%s%s' % (self.SERVER_NAME, self.authz.acme_url)
            ],
            'expires': pyrfc3339.generate(order.expires, accept_naive=True),
            'identifiers': [{'type': 'dns', 'value': self.hostname}],
            'status': 'processing',
        })

    @override_tmpcadir()
    def test_csr_subject_no_domain(self):
        """Test posting a CSR where the CommonName is not a domain name."""

        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "user@example.com"),
        ])).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(self.hostname)]), critical=False
        ).sign(certs['root-cert']['key']['parsed'], hashes.SHA256())

        with self.patch('django_ca.views.run_task') as mockcm:
            resp = self.acme(self.url, self.get_message(csr), kid=self.kid)
        mockcm.assert_not_called()
        self.assertBadCSR(resp, 'CommonName was not in order.')

    @override_tmpcadir()
    def test_csr_subject_not_in_order(self):
        """Test posting a CSR where the CommonName was not in the order."""

        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "example.net"),
        ])).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(self.hostname)]), critical=False
        ).sign(certs['root-cert']['key']['parsed'], hashes.SHA256())

        with self.patch('django_ca.views.run_task') as mockcm:
            resp = self.acme(self.url, self.get_message(csr), kid=self.kid)
        mockcm.assert_not_called()
        self.assertBadCSR(resp, 'CommonName was not in order.')

    @override_tmpcadir()
    def test_csr_no_san(self):
        """Test posting a CSR with no SubjectAlternativeName extension."""

        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).sign(
            certs['root-cert']['key']['parsed'], hashes.SHA256())

        with self.patch('django_ca.views.run_task') as mockcm:
            resp = self.acme(self.url, self.get_message(csr), kid=self.kid)
        mockcm.assert_not_called()
        self.assertBadCSR(resp, 'No subject alternative names found in CSR.')

    @override_tmpcadir()
    def test_csr_different_names(self):
        """Test posting a CSR with different names in the SubjectAlternativeName extesion."""

        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(self.hostname),
                x509.DNSName('example.net')
            ]), critical=False
        ).sign(certs['root-cert']['key']['parsed'], hashes.SHA256())

        with self.patch('django_ca.views.run_task') as mockcm:
            resp = self.acme(self.url, self.get_message(csr), kid=self.kid)
        mockcm.assert_not_called()
        self.assertBadCSR(resp, "Names in CSR do not match.")


@freeze_time(timestamps['everything_valid'])
class AcmeOrderViewTestCase(AcmeWithAccountViewTestCaseMixin, DjangoCAWithCATestCase):
    """Test retrieving an order."""

    post_as_get = True
    view_name = 'acme-order'

    def setUp(self):
        super().setUp()
        self.order = AcmeOrder.objects.create(account=self.account)
        self.authz = AcmeAuthorization.objects.create(order=self.order, value=self.hostname)

    @property
    def url(self):
        """Get URL for the standard auth object."""
        return self.get_url(serial=self.ca.serial, slug=self.order.slug)

    @override_tmpcadir()
    def test_basic(self, accept_naive=True):
        """Basic test for creating an account via ACME."""

        resp = self.acme(self.url, self.message, kid=self.kid)
        self.assertEqual(resp.status_code, HTTPStatus.OK, resp.content)
        self.assertAcmeResponse(resp)
        expires = timezone.now() + ca_settings.ACME_ORDER_VALIDITY
        self.assertEqual(resp.json(), {
            'authorizations': [
                'http://%s%s' % (self.SERVER_NAME, self.authz.acme_url)
            ],
            'expires': pyrfc3339.generate(expires, accept_naive=accept_naive),
            'identifiers': [{'type': 'dns', 'value': self.hostname}],
            'status': 'pending',
        })

    @override_settings(USE_TZ=True)
    def test_basic_with_tz(self):
        """Basic test with USE_TZ=True."""
        self.test_basic(False)

    @override_tmpcadir()
    def test_valid_cert(self):
        """Test viewing a an order with a valid certificate"""

        cert = Certificate(ca=self.ca)
        cert.x509 = certs['root-cert']['pub']['parsed']
        cert.save()

        self.order.status = AcmeOrder.STATUS_VALID
        self.order.save()
        self.authz.status = AcmeAuthorization.STATUS_VALID
        self.authz.save()
        acmecert = AcmeCertificate.objects.create(order=self.order, cert=cert)

        resp = self.acme(self.url, self.message, kid=self.kid)
        self.assertEqual(resp.status_code, HTTPStatus.OK, resp.content)
        self.assertAcmeResponse(resp)
        expires = timezone.now() + ca_settings.ACME_ORDER_VALIDITY
        self.assertEqual(resp.json(), {
            'authorizations': [
                'http://%s%s' % (self.SERVER_NAME, self.authz.acme_url)
            ],
            'certificate': 'http://%s%s' % (self.SERVER_NAME, acmecert.acme_url),
            'expires': pyrfc3339.generate(expires, accept_naive=True),
            'identifiers': [{'type': 'dns', 'value': self.hostname}],
            'status': 'valid',
        })

    @override_tmpcadir()
    def test_cert_not_yet_issued(self):
        """Test viewing a an order where the certificate has not yet been issued.

        NOTE: test_cert_not_yet_issued and test_cert_not_yet_valid test two different conditionas that
        *should* always be true at the same time.
        """

        self.order.status = AcmeOrder.STATUS_VALID
        self.order.save()
        self.authz.status = AcmeAuthorization.STATUS_VALID
        self.authz.save()
        AcmeCertificate.objects.create(order=self.order)

        resp = self.acme(self.url, self.message, kid=self.kid)
        self.assertEqual(resp.status_code, HTTPStatus.OK, resp.content)
        self.assertAcmeResponse(resp)
        expires = timezone.now() + ca_settings.ACME_ORDER_VALIDITY
        self.assertEqual(resp.json(), {
            'authorizations': [
                'http://%s%s' % (self.SERVER_NAME, self.authz.acme_url)
            ],
            'expires': pyrfc3339.generate(expires, accept_naive=True),
            'identifiers': [{'type': 'dns', 'value': self.hostname}],
            'status': 'valid',
        })

    @override_tmpcadir()
    def test_cert_not_yet_valid(self):
        """Test viewing a an order where the certificate has not yet valid.

        NOTE: test_cert_not_yet_issued and test_cert_not_yet_valid test two different conditionas that
        *should* always be true at the same time.
        """

        cert = Certificate(ca=self.ca)
        cert.x509 = certs['root-cert']['pub']['parsed']
        cert.save()

        self.order.status = AcmeOrder.STATUS_PROCESSING
        self.order.save()
        self.authz.status = AcmeAuthorization.STATUS_VALID
        self.authz.save()
        AcmeCertificate.objects.create(order=self.order, cert=cert)

        resp = self.acme(self.url, self.message, kid=self.kid)
        self.assertEqual(resp.status_code, HTTPStatus.OK, resp.content)
        self.assertAcmeResponse(resp)
        expires = timezone.now() + ca_settings.ACME_ORDER_VALIDITY
        self.assertEqual(resp.json(), {
            'authorizations': [
                'http://%s%s' % (self.SERVER_NAME, self.authz.acme_url)
            ],
            'expires': pyrfc3339.generate(expires, accept_naive=True),
            'identifiers': [{'type': 'dns', 'value': self.hostname}],
            'status': 'processing',
        })

    @override_tmpcadir()
    def test_wrong_account(self):
        """Test viewing for the wrong account"""

        account = AcmeAccount.objects.create(
            ca=self.ca, terms_of_service_agreed=True, slug='def', acme_kid='kid', pem='bar',
            thumbprint='foo'
        )
        self.order.account = account
        self.order.save()

        resp = self.acme(self.url, self.message, kid=self.kid)
        self.assertUnauthorized(resp)

    @override_tmpcadir()
    def test_not_found(self):
        """Test viewing an order that simply does not exist."""

        account = AcmeAccount.objects.create(
            ca=self.ca, terms_of_service_agreed=True, slug='def', acme_kid='kid', pem='bar',
            thumbprint='foo'
        )
        self.order.account = account
        self.order.save()

        url = self.get_url(serial=self.ca.serial, slug=self.order.slug)
        resp = self.acme(url, self.message, kid=self.kid)
        self.assertUnauthorized(resp)


@freeze_time(timestamps['everything_valid'])
class AcmeCertificateViewTestCase(AcmeWithAccountViewTestCaseMixin, DjangoCAWithCATestCase):
    """Test retrieving a certificate."""

    post_as_get = True
    view_name = 'acme-cert'

    def setUp(self):
        super().setUp()
        self.order = AcmeOrder.objects.create(account=self.account, status=AcmeOrder.STATUS_VALID)

        cert = Certificate(ca=self.ca)
        cert.x509 = certs['root-cert']['pub']['parsed']
        cert.save()
        self.acmecert = AcmeCertificate.objects.create(order=self.order, cert=cert)

    @property
    def url(self):
        """Get URL for the standard cert object."""
        return self.get_url(serial=self.ca.serial, slug=self.acmecert.slug)

    @override_tmpcadir()
    def test_basic(self):
        """Basic test case."""
        resp = self.acme(self.url, self.message, kid=self.kid)
        self.assertEqual(resp.status_code, HTTPStatus.OK, resp.content)

    @override_tmpcadir()
    def test_not_found(self):
        """Test fetching a cert that simply does not exist."""
        resp = self.acme(self.get_url(serial=self.ca.serial, slug='abc'), self.message, kid=self.kid)
        self.assertUnauthorized(resp)

    @override_tmpcadir()
    def test_wrong_account(self):
        """Test fetching a certificate for a different account."""
        account = AcmeAccount.objects.create(
            ca=self.ca, terms_of_service_agreed=True, slug='def', acme_kid='kid', pem='bar',
            thumbprint='foo'
        )
        self.order.account = account
        self.order.save()

        resp = self.acme(self.url, self.message, kid=self.kid)
        self.assertUnauthorized(resp)

    @override_tmpcadir()
    def test_no_cert_issued(self):
        """Test when no cert is issued.

        NOTE: should not really happen, as the order is marked as valid, the certificate is also set in one
        transaction.
        """

        self.acmecert.cert = None
        self.acmecert.save()
        resp = self.acme(self.url, self.message, kid=self.kid)
        self.assertUnauthorized(resp)

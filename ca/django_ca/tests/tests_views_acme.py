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
from josepy.jws import Signature
from requests.utils import parse_header_links

from django.conf import settings
from django.test.utils import override_settings
from django.urls import reverse
from django.utils import timezone
from django.utils.crypto import get_random_string

from freezegun import freeze_time

from .. import ca_settings
from ..acme import NewOrder
from ..models import AcmeAccount
from ..models import AcmeAccountAuthorization
from ..models import AcmeOrder
from ..models import CertificateAuthority
from .base import DjangoCAWithCATestCase
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

    def assertAcmeResponse(self, response, ca=None):  # pylint: disable=invalid-name
        """Assert basic Acme Response properties (Content-Type & Link header)."""
        self.assertLinkRelations(response, ca=ca)
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

        payload = msg.to_json()
        if payload_cb is not None:
            payload = payload_cb(payload)

        jws = acme.jws.JWS.sign(json.dumps(payload).encode('utf-8'), key, jose.jwa.RS256,
                                nonce=nonce, url=self.absolute_uri(uri), kid=kid)
        return self.post(uri, jws.to_json(), **post_kwargs)

    def get_basic_message(self):
        """Return a basic message that can be sent to the server successfully.

        This function is used by test cases that want to get a useful message and manipulate it in some way so
        that it violates the ACME spec.
        """
        raise NotImplementedError

    @override_tmpcadir()
    def test_invalid_content_type(self):
        """Test that any request with an invalid Content-Type header is an error.

        .. seealso:: RFC 8555, 6.2
        """
        resp = self.acme(self.generic_url, self.get_basic_message(), post_kwargs={'CONTENT_TYPE': 'FOO'})
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
            resp = self.acme(self.generic_url, self.get_basic_message(), kid='foo')
        self.assertAcmeProblem(resp, 'malformed', status=HTTPStatus.BAD_REQUEST,
                               message='jwk and kid are mutually exclusive.')

    def test_invalid_json(self):
        """Test sending invalid JSON to the server."""

        resp = self.client.post(self.generic_url, '{', content_type='application/jose+json')
        self.assertAcmeProblem(resp, 'malformed', status=HTTPStatus.BAD_REQUEST,
                               message='Could not parse JWS token.')


@freeze_time(timestamps['everything_valid'])
class AcmeNewAccountViewTestCase(AcmeBaseViewTestCaseMixin, DjangoCAWithCATestCase):
    """Test creating a new account."""

    contact = 'mailto:user@example.com'
    generic_url = reverse('django_ca:acme-new-account', kwargs={'serial': certs['root']['serial']})

    def get_basic_message(self):
        return acme.messages.Registration(
            contact=(self.contact, ),
            terms_of_service_agreed=True,
        )

    @override_tmpcadir()
    def test_basic(self):
        """Basic test for creating an account via ACME."""

        self.assertEqual(AcmeAccount.objects.count(), 0)
        resp = self.acme(self.generic_url, self.get_basic_message())
        self.assertEqual(resp.status_code, HTTPStatus.CREATED, resp.content)
        self.assertAcmeResponse(resp)

        # Get first AcmeAccount - which must be the one we just created
        acc = AcmeAccount.objects.get(thumbprint='ERBwTPWxRgjzsjPaG8F1NTVQuA3a9QYWSL41Dcjxhe4')
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
        resp = self.acme(self.generic_url, acme.messages.Registration(
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
        resp = self.acme(self.generic_url, acme.messages.Registration(
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
        acc = AcmeAccount.objects.get(thumbprint='ERBwTPWxRgjzsjPaG8F1NTVQuA3a9QYWSL41Dcjxhe4')
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
        resp = self.acme(self.generic_url, acme.messages.Registration(
            terms_of_service_agreed=True,
        ))
        self.assertEqual(resp.status_code, HTTPStatus.CREATED)
        self.assertAcmeResponse(resp)

        # Get first AcmeAccount - which must be the one we just created
        acc = AcmeAccount.objects.get(thumbprint='ERBwTPWxRgjzsjPaG8F1NTVQuA3a9QYWSL41Dcjxhe4')
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
        resp = self.acme(self.generic_url, acme.messages.Registration(
            contact=(self.contact, contact_2),
            terms_of_service_agreed=True,
        ))
        self.assertEqual(resp.status_code, HTTPStatus.CREATED)
        self.assertAcmeResponse(resp)

        # Get first AcmeAccount - which must be the one we just created
        acc = AcmeAccount.objects.get(thumbprint='ERBwTPWxRgjzsjPaG8F1NTVQuA3a9QYWSL41Dcjxhe4')
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

        resp = self.acme(self.generic_url, acme.messages.Registration(
            terms_of_service_agreed=True,
        ))
        self.assertEqual(resp.status_code, HTTPStatus.UNAUTHORIZED)
        self.assertAcmeProblem(resp, 'unauthorized', status=HTTPStatus.UNAUTHORIZED,
                               message='Must provide at least one contact address.')
        self.assertEqual(AcmeAccount.objects.count(), 0)

    @override_tmpcadir()
    def test_unsupported_contact(self):
        """Test that creating an account with a phone number fails."""

        resp = self.acme(self.generic_url, acme.messages.Registration(
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

        resp = self.acme(self.generic_url, acme.messages.Registration(
            contact=('mailto:"with spaces"@example.com', ),
            terms_of_service_agreed=True,
        ))
        self.assertEqual(resp.status_code, HTTPStatus.BAD_REQUEST)
        self.assertAcmeProblem(resp, 'invalidContact', status=HTTPStatus.BAD_REQUEST,
                               message='Quoted local part in email is not allowed.')
        self.assertEqual(AcmeAccount.objects.count(), 0)

        resp = self.acme(self.generic_url, acme.messages.Registration(
            contact=('mailto:user@example.com,user@example.net', ),
            terms_of_service_agreed=True,
        ))
        self.assertEqual(resp.status_code, HTTPStatus.BAD_REQUEST)
        self.assertAcmeProblem(resp, 'invalidContact', status=HTTPStatus.BAD_REQUEST,
                               message='More than one addr-spec is not allowed.')
        self.assertEqual(AcmeAccount.objects.count(), 0)

        resp = self.acme(self.generic_url, acme.messages.Registration(
            contact=('mailto:user@example.com?who-uses=this', ),
            terms_of_service_agreed=True,
        ))
        self.assertEqual(resp.status_code, HTTPStatus.BAD_REQUEST)
        self.assertAcmeProblem(resp, 'invalidContact', status=HTTPStatus.BAD_REQUEST,
                               message='example.com?who-uses=this: hfields are not allowed.')
        self.assertEqual(AcmeAccount.objects.count(), 0)

        resp = self.acme(self.generic_url, acme.messages.Registration(
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
        resp = self.acme(self.generic_url, acme.messages.Registration(
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
            resp = self.acme(self.generic_url, acme.messages.Registration(
                contact=(self.contact, ),
                terms_of_service_agreed=True,
            ))
            self.assertAcmeProblem(resp, 'malformed', status=HTTPStatus.BAD_REQUEST,
                                   message='Account cannot be stored.')


@freeze_time(timestamps['everything_valid'])
class AcmeNewOrderViewTestCase(AcmeBaseViewTestCaseMixin, DjangoCAWithCATestCase):
    """Test creating a new order."""

    generic_url = reverse('django_ca:acme-new-order', kwargs={'serial': certs['root']['serial']})

    def setUp(self):
        super().setUp()
        self.account_slug = 'abc'
        self.account_kid = 'http://%s%s' % (self.SERVER_NAME, self.absolute_uri(
            ':acme-account', serial=self.ca.serial, slug=self.account_slug
        ))
        self.account = AcmeAccount.objects.create(
            ca=self.ca, terms_of_service_agreed=True, slug='abc', acme_kid=self.account_kid, pem=self.PEM
        )

    def get_basic_message(self, **kwargs):
        return NewOrder(
            identifiers=[{'type': 'dns', 'value': self.SERVER_NAME}], **kwargs
        )

    @override_tmpcadir()
    def test_basic(self, accept_naive=True):
        """Basic test for creating an account via ACME."""

        with self.mock_slug() as slug:
            resp = self.acme(self.generic_url, self.get_basic_message(), kid=self.account_kid)
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

        # Test the autogenerated AcmeAccountAuthorization object
        authz = order.authorizations.all()
        self.assertEqual(len(authz), 1)
        self.assertEqual(authz[0].order, order)
        self.assertEqual(authz[0].type, 'dns')
        self.assertEqual(authz[0].value, self.SERVER_NAME)
        self.assertEqual(authz[0].status, AcmeAccountAuthorization.STATUS_PENDING)
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

        msg = self.get_basic_message(not_before=not_before, not_after=not_after)

        with self.mock_slug() as slug:
            resp = self.acme(self.generic_url, msg, kid=self.account_kid)
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

        # Test the autogenerated AcmeAccountAuthorization object
        authz = order.authorizations.all()
        self.assertEqual(len(authz), 1)
        self.assertEqual(authz[0].order, order)
        self.assertEqual(authz[0].type, 'dns')
        self.assertEqual(authz[0].value, self.SERVER_NAME)
        self.assertEqual(authz[0].status, AcmeAccountAuthorization.STATUS_PENDING)
        self.assertFalse(authz[0].wildcard)

    @override_settings(USE_TZ=True)
    def test_not_before_not_after_with_tz(self):
        """Test the notBefore/notAfter properties, but with timezone support."""
        self.test_not_before_not_after(accept_naive=False)

    @override_tmpcadir()
    def test_no_identifiers(self):
        """Test sending no identifiers."""

        resp = self.acme(self.generic_url, acme.messages.NewOrder(), kid=self.account_kid)
        self.assertAcmeProblem(resp, 'malformed', status=HTTPStatus.BAD_REQUEST,
                               message='Malformed payload.')

        # try empty tuple too
        resp = self.acme(self.generic_url, acme.messages.NewOrder(identifiers=tuple()), kid=self.account_kid,
                         payload_cb=lambda d: dict(d, identifiers=()))
        self.assertAcmeProblem(resp, 'malformed', status=HTTPStatus.BAD_REQUEST,
                               message='Malformed payload.')

        self.assertEqual(AcmeOrder.objects.all().count(), 0)

    @override_tmpcadir(USE_TZ=True)
    def test_invalid_not_before_after(self):
        """Test invalid not_before/not_after dates."""

        past = timezone.now() - timedelta(days=1)
        resp = self.acme(self.generic_url, self.get_basic_message(not_before=past), kid=self.account_kid)
        self.assertAcmeProblem(resp, 'malformed', status=HTTPStatus.BAD_REQUEST,
                               message='Certificate cannot be valid before now.')

        far_future = timezone.now() + timedelta(days=3650)
        resp = self.acme(self.generic_url, self.get_basic_message(not_after=far_future), kid=self.account_kid)
        self.assertAcmeProblem(resp, 'malformed', status=HTTPStatus.BAD_REQUEST,
                               message='Certificate cannot be valid that long.')

        not_before = timezone.now() + timedelta(days=10)
        not_after = timezone.now() + timedelta(days=1)

        resp = self.acme(self.generic_url, self.get_basic_message(
            not_before=not_before, not_after=not_after), kid=self.account_kid)
        self.assertAcmeProblem(resp, 'malformed', status=HTTPStatus.BAD_REQUEST,
                               message='notBefore must be before notAfter.')


@freeze_time(timestamps['everything_valid'])
class AcmeAuthorizationViewTestCase(AcmeBaseViewTestCaseMixin, DjangoCAWithCATestCase):
    """Test creating a new order."""

    generic_url = reverse('django_ca:acme-authz', kwargs={'serial': certs['root']['serial'], 'slug': 'foo'})


@freeze_time(timestamps['everything_valid'])
class AcmeChallengeViewTestCase(AcmeBaseViewTestCaseMixin, DjangoCAWithCATestCase):
    """Test retrieving a challenge."""

    generic_url = reverse('django_ca:acme-challenge',
                          kwargs={'serial': certs['root']['serial'], 'slug': 'foo'})


@freeze_time(timestamps['everything_valid'])
class AcmeOrderFinalizeViewTestCase(AcmeBaseViewTestCaseMixin, DjangoCAWithCATestCase):
    """Test retrieving a challenge."""

    generic_url = reverse('django_ca:acme-order-finalize',
                          kwargs={'serial': certs['root']['serial'], 'slug': 'foo'})


@freeze_time(timestamps['everything_valid'])
class AcmeOrderViewTestCase(AcmeBaseViewTestCaseMixin, DjangoCAWithCATestCase):
    """Test retrieving a challenge."""

    generic_url = reverse('django_ca:acme-order', kwargs={'serial': certs['root']['serial'], 'slug': 'foo'})


@freeze_time(timestamps['everything_valid'])
class AcmeCertificateViewTestCase(AcmeBaseViewTestCaseMixin, DjangoCAWithCATestCase):
    """Test retrieving a challenge."""

    generic_url = reverse('django_ca:acme-cert', kwargs={'serial': certs['root']['serial'], 'slug': 'foo'})

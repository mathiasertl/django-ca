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
from http import HTTPStatus
from unittest import mock

import acme
import josepy as jose
from requests.utils import parse_header_links

from django.test.utils import override_settings
from django.urls import reverse

from freezegun import freeze_time

from ..models import AcmeAccount
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

    def setUp(self):  # pylint: disable=invalid-name
        super().setUp()
        self.ca = self.cas['root']
        self.cert = self.cas['child']  # actually a ca, but doesn't matter
        self.ca.acme_enabled = True
        self.ca.save()

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
        self.assertEqual(response.status_code, HTTPStatus.OK)
        return jose.decode_b64jose(response['replay-nonce'])

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

    def test_invalid_json(self):
        """Test sending invalid JSON to the server."""

        resp = self.client.post(self.generic_url, '{', content_type='application/jose+json')
        self.assertAcmeProblem(resp, 'malformed', status=HTTPStatus.BAD_REQUEST,
                               message='Could not parse JWS token.')


@freeze_time(timestamps['everything_valid'])
class AcmeNewAccountViewTestCase(AcmeBaseViewTestCaseMixin, DjangoCAWithCATestCase):
    """Test creating a new account."""

    generic_url = reverse('django_ca:acme-new-account', kwargs={'serial': certs['root']['serial']})

    def acme(self, uri, msg, cert=None, nonce=None):
        if nonce is None:
            nonce = self.get_nonce()
        if cert is None:
            cert = self.cert

        comparable = jose.util.ComparableRSAKey(cert.key(password=None))
        key = jose.jwk.JWKRSA(key=comparable)
        jws = acme.jws.JWS.sign(msg.json_dumps().encode('utf-8'), key, jose.jwa.RS256,
                                nonce=nonce, url=self.absolute_uri(uri))
        return self.post(uri, jws.to_json())

    @override_tmpcadir()
    def test_basic(self):
        """Basic test for creating an account via ACME."""

        self.assertEqual(AcmeAccount.objects.count(), 0)
        contact = 'mailto:user@example.com'
        resp = self.acme(self.generic_url, acme.messages.Registration(
            contact=(contact, ),
            terms_of_service_agreed=True,
        ))
        self.assertEqual(resp.status_code, HTTPStatus.CREATED)
        self.assertAcmeResponse(resp)

        # Get first AcmeAccount - which must be the one we just created
        acc = AcmeAccount.objects.get(thumbprint='ERBwTPWxRgjzsjPaG8F1NTVQuA3a9QYWSL41Dcjxhe4')
        self.assertEqual(acc.status, AcmeAccount.STATUS_VALID)
        self.assertEqual(acc.ca, self.ca)
        self.assertEqual(acc.contact, contact)
        self.assertTrue(acc.terms_of_service_agreed)

        # Test the response body
        self.assertEqual(resp['location'], self.absolute_uri(':acme-account', serial=self.ca.serial,
                                                             pk=acc.pk))
        self.assertEqual(resp.json(), {
            'contact': [contact],
            'orders': self.absolute_uri(':acme-account-orders', serial=self.ca.serial, pk=acc.pk),
            'status': 'valid',
        })


@freeze_time(timestamps['everything_valid'])
class AcmeNewOrderViewTestCase(AcmeBaseViewTestCaseMixin, DjangoCAWithCATestCase):
    """Test creating a new order."""

    generic_url = reverse('django_ca:acme-new-order', kwargs={'serial': certs['root']['serial']})


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

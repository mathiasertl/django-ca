# -*- coding: utf-8 -*-
#
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

import base64
import logging
import os
from datetime import timedelta

import asn1crypto
from oscrypto import asymmetric

from django.conf import settings
from django.conf.urls import url
from django.test import Client
from django.utils.encoding import force_text

from ..models import Certificate
from ..utils import int_to_hex
from ..views import OCSPView
from .base import DjangoCAWithCertTestCase
from .base import certs
from .base import ocsp_pubkey
from .base import override_settings

try:
    from django.urls import reverse
except ImportError:  # Django 1.8 import
    from django.core.urlresolvers import reverse


# openssl ocsp -issuer django_ca/tests/fixtures/root.pem -serial <serial> \
#         -reqout django_ca/tests/fixtures/ocsp/unknown-serial -resp_text
#
# WHERE serial is an int: (int('0x<hex>'.replace(':', '').lower(), 0)
def _load_req(req):
    path = os.path.join(settings.FIXTURES_DIR, 'ocsp', req)
    with open(path, 'rb') as stream:
        return stream.read()


req1 = _load_req('req1')
req1_nonce = b'5ul\xc4\xb6\xccP\xe8\xd8\xbd\x16xA \r9'
no_nonce_req = _load_req('req-no-nonce')
unknown_req = _load_req('unknown-serial')
multiple_req = _load_req('multiple-serial')

urlpatterns = [
    url(r'^ocsp/$', OCSPView.as_view(
        ca=certs['root']['serial'],
        responder_key=settings.OCSP_KEY_PATH,
        responder_cert=settings.OCSP_PEM_PATH,
        expires=1200,
    ), name='post'),

    url(r'^ocsp/cert/(?P<data>[a-zA-Z0-9=+/]+)$', OCSPView.as_view(
        ca=certs['root']['serial'],
        responder_key=settings.OCSP_KEY_PATH,
        responder_cert=settings.OCSP_PEM_PATH,
    ), name='get'),

    url(r'^ocsp/ca/(?P<data>[a-zA-Z0-9=+/]+)$', OCSPView.as_view(
        ca=certs['root']['serial'],
        responder_key=settings.OCSP_KEY_PATH,
        responder_cert=settings.OCSP_PEM_PATH,
        ca_ocsp=True,
    ), name='get-ca'),

    url(r'^ocsp-unknown/(?P<data>[a-zA-Z0-9=+/]+)$', OCSPView.as_view(
        ca='unknown',
        responder_key=settings.OCSP_KEY_PATH,
        responder_cert=settings.OCSP_PEM_PATH,
    ), name='unknown'),

    url(r'^ocsp/false-key/(?P<data>[a-zA-Z0-9=+/]+)$', OCSPView.as_view(
        ca=certs['root']['serial'],
        responder_key='/false/foobar',
        responder_cert=settings.OCSP_PEM_PATH,
        expires=1200,
    ), name='false-key'),

    url(r'^ocsp/false-pem/(?P<data>[a-zA-Z0-9=+/]+)$', OCSPView.as_view(
        ca=certs['root']['serial'],
        responder_key=settings.OCSP_KEY_PATH,
        responder_cert='/false/foobar/',
        expires=1200,
    ), name='false-pem'),
]


class OCSPViewTestMixin(object):
    _subject_mapping = {
        'country_name': 'C',
        'state_or_province_name': 'ST',
        'locality_name': 'L',
        'organization_name': 'O',
        'organizational_unit_name': 'OU',
        'common_name': 'CN',
        'email_address': 'emailAddress',
    }

    def assertAlmostEqualDate(self, got, expected):
        # Sometimes next_update timestamps are of by a second or so, so we test
        # if they are just close
        delta = timedelta(seconds=3)
        self.assertTrue(got < expected + delta and got > expected - delta)

    def sign_func(self, tbs_request, algo):
        if algo['algorithm'].native == 'sha256_rsa':
            algo = 'sha256'
        else:
            # OCSPResponseBuilder (used server-side) statically uses sha256, so this should never
            # happen for now.
            raise ValueError('Unknown algorithm: %s' % algo.native)

        # from ocspbuilder.OCSPResponseBuilder.build:
        if self.ocsp_private_key.algorithm == 'rsa':
            sign_func = asymmetric.rsa_pkcs1v15_sign
        elif self.ocsp_private_key.algorithm == 'dsa':
            sign_func = asymmetric.dsa_sign
        elif self.ocsp_private_key.algorithm == 'ec':
            sign_func = asymmetric.ecdsa_sign

        return sign_func(self.ocsp_private_key, tbs_request.dump(), algo)

    @classmethod
    def setUpClass(cls):
        super(OCSPViewTestMixin, cls).setUpClass()

        logging.disable(logging.CRITICAL)
        cls.client = Client()
        cls.ocsp_cert = cls.load_cert(ca=cls.ca, x509=ocsp_pubkey)

        # used for verifying signatures
        cls.ocsp_private_key = asymmetric.load_private_key(force_text(settings.OCSP_KEY_PATH))

    def assertOCSPSubject(self, got, expected):
        translated = {}
        for frm, to in self._subject_mapping.items():
            if frm in got:
                translated[to] = got.pop(frm)

        self.assertEqual(got, {})
        self.assertEqual(translated, expected)

    def assertOCSP(self, http_response, requested, status='successful', nonce=None,
                   expires=600):
        self.assertEqual(http_response['Content-Type'], 'application/ocsp-response')

        ocsp_response = asn1crypto.ocsp.OCSPResponse.load(http_response.content)
        self.assertEqual(ocsp_response['response_status'].native, status)

        response_bytes = ocsp_response['response_bytes']
        self.assertEqual(response_bytes['response_type'].native, 'basic_ocsp_response')

        response = response_bytes['response'].parsed

        # assert signature algorithm
        signature = response['signature']
        signature_algo = response['signature_algorithm']
        self.assertEqual(signature_algo['algorithm'].native, 'sha256_rsa')
        self.assertIsNone(signature_algo['parameters'].native)

        # verify the responder cert
        certs = response['certs']
        self.assertEqual(len(certs), 1)
        serials = [int_to_hex(c['tbs_certificate']['serial_number'].native) for c in certs]
        self.assertEqual(serials, [settings.OCSP_SERIAL])

        # verify subjects of certificates
        self.assertOCSPSubject(certs[0]['tbs_certificate']['subject'].native,
                               self.ocsp_cert.subject)
        self.assertOCSPSubject(certs[0]['tbs_certificate']['issuer'].native,
                               self.ocsp_cert.ca.subject)

        tbs_response_data = response['tbs_response_data']
        self.assertEqual(tbs_response_data['version'].native, 'v1')

        # Test extensions
        response_extensions = {r['extn_id'].native: r for r
                               in tbs_response_data['response_extensions']}
        if nonce is not None:
            nonce_ext = response_extensions.pop('nonce')
            self.assertFalse(nonce_ext['critical'].native)
            self.assertEqual(nonce_ext['extn_value'].native, nonce)
        self.assertEqual(response_extensions, {})  # no extensions are left

        # Verify responder id
        responder_id = tbs_response_data['responder_id']
        self.assertEqual(responder_id.name, 'by_key')
        # TODO: Validate responder id

        produced_at = tbs_response_data['produced_at'].native

        # Verify responses
        responses = tbs_response_data['responses']
        self.assertEqual(len(responses), len(requested))
        responses = {int_to_hex(r['cert_id']['serial_number'].native): r for r in responses}
        for serial, response in responses.items():
            cert = Certificate.objects.get(serial=serial)

            # test cert_status
            cert_status = response['cert_status'].native
            if cert.revoked is False:
                self.assertIsNone(cert_status)
            else:
                revocation_time = cert_status['revocation_time'].replace(tzinfo=None)
                revocation_reason = cert_status['revocation_reason']

                if cert.revoked_reason is None:
                    self.assertEqual(revocation_reason, 'unspecified')
                else:
                    self.assertEqual(revocation_reason, cert.ocsp_status)
                self.assertEqual(revocation_time, cert.revoked_date.replace(microsecond=0))

            # test next_update
            this_update = response['this_update'].native
            self.assertEqual(produced_at, this_update)
            next_update = response['next_update'].native
            self.assertAlmostEqualDate(this_update + timedelta(seconds=expires), next_update)

            single_extensions = {e['extn_id'].native: e for e in response['single_extensions']}

            # test certificate_issuer single extension
            issuer_subject = single_extensions.pop('certificate_issuer')
            self.assertFalse(issuer_subject['critical'].native)

            self.assertEqual(len(issuer_subject['extn_value'].native), 1)
            self.assertOCSPSubject(issuer_subject['extn_value'].native[0], cert.ca.subject)
            self.assertEqual(single_extensions, {})  # None are left

            # TODO: verify issuer_name_hash and issuer_key_hash
            # cert_id = response['cert_id']

        # TODO: Verify signature
        expected_signature = self.sign_func(tbs_response_data, signature_algo)
        self.assertEqual(signature.native, expected_signature)


@override_settings(CA_OCSP_URLS={
    'root': {
        'ca': certs['root']['serial'],
        'responder_key': os.path.join(settings.FIXTURES_DIR, 'ocsp.key'),
        'responder_cert': os.path.join(settings.FIXTURES_DIR, 'ocsp.pem'),
    },
})
class OCSPTestGenericView(OCSPViewTestMixin, DjangoCAWithCertTestCase):
    def test_get(self):
        data = base64.b64encode(req1).decode('utf-8')
        url = reverse('django_ca:ocsp-get-root', kwargs={'data': data})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertOCSP(response, requested=[self.cert], nonce=req1_nonce)

    @override_settings(USE_TZ=True)
    def test_get_with_use_tz(self):
        self.test_get()

    def test_post(self):
        response = self.client.post(reverse('django_ca:ocsp-post-root'), req1,
                                    content_type='application/ocsp-request')
        self.assertEqual(response.status_code, 200)
        self.assertOCSP(response, requested=[self.cert], nonce=req1_nonce)

    @override_settings(USE_TZ=True)
    def test_post_with_use_tz(self):
        self.test_post()


@override_settings(ROOT_URLCONF=__name__)
class OCSPTestView(OCSPViewTestMixin, DjangoCAWithCertTestCase):
    def test_get(self):
        data = base64.b64encode(req1).decode('utf-8')
        response = self.client.get(reverse('get', kwargs={'data': data}))
        self.assertEqual(response.status_code, 200)
        self.assertOCSP(response, requested=[self.cert], nonce=req1_nonce)

    @override_settings(USE_TZ=True)
    def test_get_with_use_tz(self):
        self.test_get()

    def test_post(self):
        response = self.client.post(reverse('post'), req1, content_type='application/ocsp-request')
        self.assertEqual(response.status_code, 200)
        self.assertOCSP(response, requested=[self.cert], nonce=req1_nonce, expires=1200)

    @override_settings(USE_TZ=True)
    def test_post_with_use_tz(self):
        self.test_post()

    def test_no_nonce(self):
        data = base64.b64encode(req1).decode('utf-8')
        response = self.client.get(reverse('get', kwargs={'data': data}))
        self.assertEqual(response.status_code, 200)

        # TODO: this should fail
        self.assertOCSP(response, requested=[self.cert], nonce=req1_nonce)

    def test_revoked(self):
        cert = Certificate.objects.get(pk=self.cert.pk)
        cert.revoke()

        response = self.client.post(reverse('post'), req1, content_type='application/ocsp-request')
        self.assertEqual(response.status_code, 200)
        self.assertOCSP(response, requested=[self.cert], nonce=req1_nonce, expires=1200)

        cert.revoke('affiliation_changed')
        response = self.client.post(reverse('post'), req1, content_type='application/ocsp-request')
        self.assertEqual(response.status_code, 200)
        self.assertOCSP(response, requested=[self.cert], nonce=req1_nonce, expires=1200)

    def test_ca_ocsp(self):
        data = base64.b64encode(req1).decode('utf-8')
        response = self.client.get(reverse('get-ca', kwargs={'data': data}))
        self.assertEqual(response.status_code, 200)
        ocsp_response = asn1crypto.ocsp.OCSPResponse.load(response.content)
        print(ocsp_response['response_status'].native)
        #self.assertOCSP(response, requested=[self.cert], nonce=req1_nonce, expires=1200)

    def test_bad_ca(self):
        data = base64.b64encode(req1).decode('utf-8')
        response = self.client.get(reverse('unknown', kwargs={'data': data}))
        self.assertEqual(response.status_code, 200)
        ocsp_response = asn1crypto.ocsp.OCSPResponse.load(response.content)
        self.assertEqual(ocsp_response['response_status'].native, 'internal_error')

    def test_unknown(self):
        data = base64.b64encode(unknown_req).decode('utf-8')
        response = self.client.get(reverse('get', kwargs={'data': data}))
        self.assertEqual(response.status_code, 200)
        ocsp_response = asn1crypto.ocsp.OCSPResponse.load(response.content)
        self.assertEqual(ocsp_response['response_status'].native, 'internal_error')

    def test_bad_responder_cert(self):
        data = base64.b64encode(unknown_req).decode('utf-8')
        response = self.client.get(reverse('get', kwargs={'data': data}))
        self.assertEqual(response.status_code, 200)
        ocsp_response = asn1crypto.ocsp.OCSPResponse.load(response.content)
        self.assertEqual(ocsp_response['response_status'].native, 'internal_error')

    def test_bad_request(self):
        data = base64.b64encode(b'foobar').decode('utf-8')
        response = self.client.get(reverse('get', kwargs={'data': data}))
        self.assertEqual(response.status_code, 200)
        ocsp_response = asn1crypto.ocsp.OCSPResponse.load(response.content)
        self.assertEqual(ocsp_response['response_status'].native, 'malformed_request')

    def test_multiple(self):
        data = base64.b64encode(multiple_req).decode('utf-8')
        response = self.client.get(reverse('get', kwargs={'data': data}))
        self.assertEqual(response.status_code, 200)
        ocsp_response = asn1crypto.ocsp.OCSPResponse.load(response.content)
        self.assertEqual(ocsp_response['response_status'].native, 'malformed_request')

    def test_bad_ca_cert(self):
        self.ca.pub = 'foobar'
        self.ca.save()

        data = base64.b64encode(req1).decode('utf-8')
        response = self.client.get(reverse('get', kwargs={'data': data}))
        self.assertEqual(response.status_code, 200)
        ocsp_response = asn1crypto.ocsp.OCSPResponse.load(response.content)
        self.assertEqual(ocsp_response['response_status'].native, 'internal_error')

    def test_bad_responder_key(self):
        data = base64.b64encode(req1).decode('utf-8')

        response = self.client.get(reverse('false-key', kwargs={'data': data}))
        self.assertEqual(response.status_code, 200)
        ocsp_response = asn1crypto.ocsp.OCSPResponse.load(response.content)
        self.assertEqual(ocsp_response['response_status'].native, 'internal_error')

    def test_bad_responder_pem(self):
        data = base64.b64encode(req1).decode('utf-8')

        response = self.client.get(reverse('false-pem', kwargs={'data': data}))
        self.assertEqual(response.status_code, 200)
        ocsp_response = asn1crypto.ocsp.OCSPResponse.load(response.content)
        self.assertEqual(ocsp_response['response_status'].native, 'internal_error')

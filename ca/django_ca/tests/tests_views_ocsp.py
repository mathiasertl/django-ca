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

from django.conf.urls import url
from django.core.exceptions import ImproperlyConfigured
from django.core.urlresolvers import reverse
from django.test import Client

from ..models import Certificate
from ..models import CertificateAuthority
from ..utils import serial_from_int
from ..views import OCSPView
from .base import DjangoCAWithCertTestCase
from .base import fixtures_dir
from .base import ocsp_pem
from .base import ocsp_pubkey
from .base import ocsp_serial
from .base import override_settings
from .base import root_serial


#openssl ocsp -issuer django_ca/tests/fixtures/root.pem -serial 123  \
#        -reqout django_ca/tests/fixtures/ocsp/unknown-serial -resp_text
def _load_req(req):
    path = os.path.join(fixtures_dir, 'ocsp', req)
    with open(path, 'rb') as stream:
        return stream.read()

req1 = _load_req('req1')
req1_nonce = b'\xedf\x00S\xbef\x16Y\xcc\xe9\xe9\xa3\x08\xf7\xc2\xda'
no_nonce_req = _load_req('req-no-nonce')
unknown_req = _load_req('unknown-serial')
multiple_req = _load_req('multiple-serial')

ocsp_key_path = os.path.join(fixtures_dir, 'ocsp.key')
urlpatterns = [
    url(r'^ocsp/$', OCSPView.as_view(
        ca=root_serial,
        responder_key=ocsp_key_path,
        responder_cert=ocsp_serial,
        expires=1200,
    ), name='post'),

    url(r'^ocsp/(?P<data>[a-zA-Z0-9=+/]+)$', OCSPView.as_view(
        ca=root_serial,
        responder_key=ocsp_key_path,
        responder_cert=ocsp_serial,
    ), name='get'),

    url(r'^ocsp-unknown/(?P<data>[a-zA-Z0-9=+/]+)$', OCSPView.as_view(
        ca='unknown',
        responder_key=ocsp_key_path,
        responder_cert=ocsp_serial,
    ), name='unknown'),
]

@override_settings(ROOT_URLCONF=__name__)
class OCSPTestView(DjangoCAWithCertTestCase):
    _subject_mapping = {
        'country_name': 'C',
        'state_or_province_name': 'ST',
        'locality_name': 'L',
        'organization_name': 'O',
        'organizational_unit_name': 'OU',
        'common_name': 'CN',
        'email_address': 'emailAddress',
    }

    @classmethod
    def setUpClass(cls):
        super(OCSPTestView, cls).setUpClass()

        logging.disable(logging.CRITICAL)
        cls.client = Client()
        cls.ocsp_cert = cls.load_cert(ca=cls.ca, x509=ocsp_pubkey)

        # used for verifying signatures
        cls.ocsp_private_key = asymmetric.load_private_key(ocsp_key_path)

    def assertAlmostEqualDate(self, got, expected):
        # Sometimes next_update timestamps are of by a second or so, so we test
        # if they are just close
        delta = timedelta(seconds=3)
        self.assertTrue(got < expected + delta and got > expected - delta)

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
        serials = [serial_from_int(c['tbs_certificate']['serial_number'].native) for c in certs]
        self.assertEqual(serials, [ocsp_serial])

        # verify subjects of certificates
        self.assertOCSPSubject(certs[0]['tbs_certificate']['subject'].native, self.ocsp_cert.subject)
        self.assertOCSPSubject(certs[0]['tbs_certificate']['issuer'].native, self.ocsp_cert.ca.subject)

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
        #TODO: Validate responder id

        produced_at = tbs_response_data['produced_at'].native

        # Verify responses
        responses = tbs_response_data['responses']
        self.assertEqual(len(responses), len(requested))
        responses = {serial_from_int(r['cert_id']['serial_number'].native): r for r in responses}
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
            #cert_id = response['cert_id']

        # TODO: Verify signature
        expected_signature = self.sign_func(tbs_response_data, signature_algo)
        self.assertEqual(signature.native, expected_signature)

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

    def test_get(self):
        data = base64.b64encode(req1).decode('utf-8')
        response = self.client.get(reverse('get', kwargs={'data': data}))
        self.assertEqual(response.status_code, 200)
        self.assertOCSP(response, requested=[self.cert], nonce=req1_nonce)

    def test_post(self):
        response = self.client.post(reverse('post'), req1, content_type='application/ocsp-request')
        self.assertEqual(response.status_code, 200)
        self.assertOCSP(response, requested=[self.cert], nonce=req1_nonce, expires=1200)

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

        cert.revoke('affiliationChanged')
        response = self.client.post(reverse('post'), req1, content_type='application/ocsp-request')
        self.assertEqual(response.status_code, 200)
        self.assertOCSP(response, requested=[self.cert], nonce=req1_nonce, expires=1200)

    def test_kwargs(self):
        # test kwargs to the view function
        view = OCSPView.as_view(ca=root_serial, responder_key=ocsp_key_path,
                                responder_cert=ocsp_serial)
        kwargs = view.view_initkwargs
        CertificateAuthority.objects.get(serial=kwargs['ca'])
        self.assertEqual(kwargs['responder_cert'], ocsp_pem)

    def test_bad_kwarg(self):
        with self.assertRaises(ImproperlyConfigured) as e:
            OCSPView.as_view(ca=root_serial, responder_key='/gone', responder_cert=ocsp_serial)
        self.assertEqual(e.exception.args, ('/gone: Could not read private key.', ))

        with self.assertRaises(ImproperlyConfigured) as e:
            OCSPView.as_view(ca=root_serial, responder_key=ocsp_key_path, responder_cert='gone')
        self.assertEqual(e.exception.args, ('gone: Could not read public key.', ))

    def test_bad_ca(self):
        data = base64.b64encode(req1).decode('utf-8')
        response = self.client.get(reverse('unknown', kwargs={'data': data}))
        self.assertEqual(response.status_code, 500)
        ocsp_response = asn1crypto.ocsp.OCSPResponse.load(response.content)
        self.assertEqual(ocsp_response['response_status'].native, 'internal_error')

    def test_unknown(self):
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

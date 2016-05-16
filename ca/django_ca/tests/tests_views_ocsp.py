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
import os

import asn1crypto
from oscrypto import asymmetric

from django.conf.urls import url
from django.core.urlresolvers import reverse
from django.test import Client

from ..models import Certificate
from ..utils import serial_from_int
from ..views import OCSPView
from .base import DjangoCAWithCertTestCase
from .base import fixtures_dir
from .base import ocsp_pubkey
from .base import ocsp_serial
from .base import override_settings
from .base import root_serial


#openssl ocsp -CAfile files/ca.pem -issuer files/ca.pem -serial 123  -reqout file -resp_text
def _load_req(req):
    path = os.path.join(fixtures_dir, 'ocsp', req)
    with open(path, 'rb') as stream:
        return stream.read()

req1 = _load_req('req1')
req1_nonce = b'\xedf\x00S\xbef\x16Y\xcc\xe9\xe9\xa3\x08\xf7\xc2\xda'

ocsp_key_path = os.path.join(fixtures_dir, 'ocsp.key')
urlpatterns = [
    url(r'^ocsp/(?P<data>[a-zA-Z0-9=+/]+)$', OCSPView.as_view(
        ca_serial=root_serial,
        responder_key=ocsp_key_path,
        responder_cert=ocsp_serial,
    ), name='get'),
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
        cls.client = Client()
        cls.ocsp_cert = cls.load_cert(ca=cls.ca, x509=ocsp_pubkey)

        # used for verifying signatures
        cls.ocsp_private_key = asymmetric.load_private_key(ocsp_key_path)

    def assertOCSPSubject(self, got, expected):
        translated = {}
        for frm, to in self._subject_mapping.items():
            if frm in got:
                translated[to] = got.pop(frm)

        self.assertEqual(got, {})
        self.assertEqual(translated, expected)

    def assertOCSP(self, http_response, requested, status='successful', nonce=None):
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

        # Verify responses
        responses = tbs_response_data['responses']
        self.assertEqual(len(responses), len(requested))
        responses = {serial_from_int(r['cert_id']['serial_number'].native): r for r in responses}
        for serial, response in responses.items():
            cert = Certificate.objects.get(serial=serial)

            # test cert_status
            if cert.revoked is False:
                self.assertIsNone(response['cert_status'].native)
            else:
                # TODO: not yet implemented
                self.assertIsNone(response['cert_status'].native)

            single_extensions = {e['extn_id'].native: e for e in response['single_extensions']}

            # test certificate_issuer single extension
            issuer_subject = single_extensions.pop('certificate_issuer')
            self.assertFalse(issuer_subject['critical'].native)

            self.assertEqual(len(issuer_subject['extn_value'].native), 1)
            self.assertOCSPSubject(issuer_subject['extn_value'].native[0], cert.ca.subject)
            self.assertEqual(single_extensions, {})  # None are left

            cert_id = response['cert_id']
            # TODO: verify issuer_name_hash and issuer_key_hash

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

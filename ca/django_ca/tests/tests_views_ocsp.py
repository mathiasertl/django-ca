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
import unittest
from datetime import timedelta

from freezegun import freeze_time

import asn1crypto
import asn1crypto.x509
import ocspbuilder
import oscrypto
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from oscrypto import asymmetric

from django.conf import settings
from django.conf.urls import url
from django.test import Client
from django.urls import reverse
from django.utils.encoding import force_text

from .. import ca_settings
from ..constants import ReasonFlags
from ..models import Certificate
from ..subject import Subject
from ..utils import hex_to_bytes
from ..utils import int_to_hex
from ..views import OCSPView
from .base import DjangoCAWithCertTestCase
from .base import certs
from .base import ocsp_data
from .base import override_settings
from .base import override_tmpcadir

try:
    import unittest.mock as mock
except ImportError:
    import mock


# openssl ocsp -issuer django_ca/tests/fixtures/root.pem -serial <serial> \
#         -reqout django_ca/tests/fixtures/ocsp/unknown-serial -resp_text
#
# WHERE serial is an int: (int('0x<hex>'.replace(':', '').lower(), 0)
def _load_req(req):
    path = os.path.join(settings.FIXTURES_DIR, 'ocsp', req)
    with open(path, 'rb') as stream:
        return stream.read()


ocsp_profile = certs['profile-ocsp']
ocsp_key_path = os.path.join(settings.FIXTURES_DIR, ocsp_profile['key_filename'])
ocsp_pem_path = os.path.join(settings.FIXTURES_DIR, ocsp_profile['pub_filename'])
ocsp_pem = ocsp_profile['pub']['pem']
req1 = _load_req(ocsp_data['nonce']['filename'])
req1_nonce = hex_to_bytes(ocsp_data['nonce']['nonce'])
req1_asn1_nonce = hex_to_bytes(ocsp_data['nonce']['asn1crypto_nonce'])
req_no_nonce = _load_req(ocsp_data['no-nonce']['filename'])
unknown_req = _load_req('unknown-serial')
multiple_req = _load_req('multiple-serial')

urlpatterns = [
    url(r'^ocsp/$', OCSPView.as_view(
        ca=certs['child']['serial'],
        responder_key=ocsp_profile['key_filename'],
        responder_cert=ocsp_profile['pub_filename'],
        expires=1200,
    ), name='post'),
    url(r'^ocsp/serial/$', OCSPView.as_view(
        ca=certs['child']['serial'],
        responder_key=ocsp_profile['key_filename'],
        responder_cert=certs['profile-ocsp']['serial'],
        expires=1300,
    ), name='post-serial'),
    url(r'^ocsp/full-pem/$', OCSPView.as_view(
        ca=certs['child']['serial'],
        responder_key=ocsp_profile['key_filename'],
        responder_cert=ocsp_pem,
        expires=1400,
    ), name='post-full-pem'),
    url(r'^ocsp/loaded-oscrypto/$', OCSPView.as_view(
        ca=certs['child']['serial'],
        responder_key=ocsp_profile['key_filename'],
        responder_cert=oscrypto.asymmetric.load_certificate(ocsp_pem.encode('utf-8')),
        expires=1500,
    ), name='post-loaded-oscrypto'),
    url(r'^ocsp/loaded-cryptography/$', OCSPView.as_view(
        ca=certs['child']['serial'],
        responder_key=ocsp_profile['key_filename'],
        responder_cert=certs['profile-ocsp']['pub']['parsed'],
        expires=1500,
    ), name='post-loaded-cryptography'),

    # Use absolute paths to trigger log warnings
    url(r'^ocsp/abs-path/$', OCSPView.as_view(
        ca=certs['child']['serial'],
        responder_key=ocsp_key_path,
        responder_cert=ocsp_pem_path,
        expires=1500,
    ), name='post-abs-path'),

    url(r'^ocsp/cert/(?P<data>[a-zA-Z0-9=+/]+)$', OCSPView.as_view(
        ca=certs['child']['serial'],
        responder_key=ocsp_profile['key_filename'],
        responder_cert=ocsp_profile['pub_filename'],
    ), name='get'),

    url(r'^ocsp/ca/(?P<data>[a-zA-Z0-9=+/]+)$', OCSPView.as_view(
        ca=certs['root']['serial'],
        responder_key=ocsp_profile['key_filename'],
        responder_cert=ocsp_profile['pub_filename'],
        ca_ocsp=True,
    ), name='get-ca'),

    url(r'^ocsp-unknown/(?P<data>[a-zA-Z0-9=+/]+)$', OCSPView.as_view(
        ca='unknown',
        responder_key=ocsp_profile['key_filename'],
        responder_cert=ocsp_profile['pub_filename'],
    ), name='unknown'),

    url(r'^ocsp/false-key/(?P<data>[a-zA-Z0-9=+/]+)$', OCSPView.as_view(
        ca=certs['root']['serial'],
        responder_key='/false/foobar',
        responder_cert=ocsp_profile['pub_filename'],
        expires=1200,
    ), name='false-key'),

    # set invalid responder_certs
    url(r'^ocsp/false-pem/(?P<data>[a-zA-Z0-9=+/]+)$', OCSPView.as_view(
        ca=certs['child']['serial'],
        responder_key=ocsp_profile['key_filename'],
        responder_cert='/false/foobar/',
    ), name='false-pem'),
    url(r'^ocsp/false-pem-serial/(?P<data>[a-zA-Z0-9=+/]+)$', OCSPView.as_view(
        ca=certs['child']['serial'],
        responder_key=ocsp_profile['key_filename'],
        responder_cert='AA:BB:CC',
    ), name='false-pem-serial'),
    url(r'^ocsp/false-pem-full/(?P<data>[a-zA-Z0-9=+/]+)$', OCSPView.as_view(
        ca=certs['child']['serial'],
        responder_key=ocsp_profile['key_filename'],
        responder_cert='-----BEGIN CERTIFICATE-----\nvery-mean!',
    ), name='false-pem-full'),
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

    def setUp(self):
        super(OCSPViewTestMixin, self).setUp()

        self.client = Client()

        # used for verifying signatures
        ocsp_key_path = os.path.join(settings.FIXTURES_DIR, ocsp_profile['key_filename'])
        self.ocsp_private_key = asymmetric.load_private_key(force_text(ocsp_key_path))

    def assertAlmostEqualDate(self, got, expected):
        # Sometimes next_update timestamps are off by a second or so, so we test
        delta = timedelta(seconds=3)
        self.assertTrue(got < expected + delta and got > expected - delta, (got, expected))

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

    def assertOCSPSubject(self, got, expected):
        translated = {}
        for frm, to in self._subject_mapping.items():
            if frm in got:
                translated[to] = got.pop(frm)

        self.assertEqual(got, {})
        self.assertEqual(Subject(translated), expected)

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
        resp_certs = response['certs']
        self.assertEqual(len(resp_certs), 1)
        serials = [int_to_hex(c['tbs_certificate']['serial_number'].native) for c in resp_certs]
        self.assertEqual(serials, [certs['profile-ocsp']['serial']])

        # verify subjects of certificates
        self.assertOCSPSubject(resp_certs[0]['tbs_certificate']['subject'].native,
                               self.certs['profile-ocsp'].subject)
        self.assertOCSPSubject(resp_certs[0]['tbs_certificate']['issuer'].native,
                               self.certs['profile-ocsp'].ca.subject)

        tbs_response_data = response['tbs_response_data']
        self.assertEqual(tbs_response_data['version'].native, 'v1')

        # Test extensions
        response_extensions = {r['extn_id'].native: r for r
                               in tbs_response_data['response_extensions']}
        if nonce is not None:
            nonce_ext = response_extensions.pop('nonce')
            self.assertFalse(nonce_ext['critical'].native)
            self.assertEqual(nonce_ext['extn_value'].native, req1_asn1_nonce)
        self.assertEqual(response_extensions, {})  # no extensions are left

        # Verify responder id
        responder_id = tbs_response_data['responder_id']
        self.assertEqual(responder_id.name, 'by_key')
        # TODO: Validate responder id

        # cryptography does not support setting "produced_at", instead it's set during signing.
        # but that does happen within OpenSSL, so we can't use freezegun to properly test this.
        #produced_at = tbs_response_data['produced_at'].native

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

                self.assertEqual(revocation_reason, cert.revoked_reason)
                self.assertEqual(revocation_time, cert.revoked_date.replace(microsecond=0))

            # test next_update
            this_update = response['this_update'].native
            # self.assertEqual(produced_at, this_update)
            next_update = response['next_update'].native
            self.assertAlmostEqualDate(this_update + timedelta(seconds=expires), next_update)

            # TODO: cryptography does not support single response extensions
            #single_extensions = {e['extn_id'].native: e for e in response['single_extensions']}
            # test certificate_issuer single extension
            #issuer_subject = single_extensions.pop('certificate_issuer')
            #self.assertFalse(issuer_subject['critical'].native)

            #self.assertEqual(len(issuer_subject['extn_value'].native), 1)
            #self.assertOCSPSubject(issuer_subject['extn_value'].native[0], cert.ca.subject)
            #self.assertEqual(single_extensions, {})  # None are left

            # TODO: verify issuer_name_hash and issuer_key_hash
            # cert_id = response['cert_id']

        # TODO: Verify signature
        expected_signature = self.sign_func(tbs_response_data, signature_algo)
        self.assertEqual(signature.native, expected_signature)


class OCSPTestGenericView(OCSPViewTestMixin, DjangoCAWithCertTestCase):
    @override_tmpcadir()
    def test_get(self):
        cert = self.certs['child-cert']
        data = base64.b64encode(req1).decode('utf-8')
        url = reverse('django_ca:ocsp-get-child', kwargs={'data': data})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertOCSP(response, requested=[cert], nonce=req1_nonce)

    @override_tmpcadir()
    def test_post(self):
        cert = self.certs['child-cert']
        response = self.client.post(reverse('django_ca:ocsp-post-child'), req1,
                                    content_type='application/ocsp-request')
        self.assertEqual(response.status_code, 200)
        self.assertOCSP(response, requested=[cert], nonce=req1_nonce)


@override_settings(USE_TZ=True)
class OCSPTestGenericViewWithTZ(OCSPTestGenericView):
    pass


@override_settings(ROOT_URLCONF=__name__)
@freeze_time("2019-02-03 15:43:12")
class OCSPTestView(OCSPViewTestMixin, DjangoCAWithCertTestCase):
    @override_tmpcadir()
    def test_get(self):
        cert = self.certs['child-cert']
        data = base64.b64encode(req1).decode('utf-8')
        response = self.client.get(reverse('get', kwargs={'data': data}))
        self.assertEqual(response.status_code, 200)
        self.assertOCSP(response, requested=[cert], nonce=req1_nonce)

    def test_bad_query(self):
        response = self.client.get(reverse('get', kwargs={'data': 'XXX'}))
        self.assertEqual(response.status_code, 200)
        ocsp_response = asn1crypto.ocsp.OCSPResponse.load(response.content)
        self.assertEqual(ocsp_response['response_status'].native, 'malformed_request')

    def test_raises_exception(self):
        def effect(data):
            raise Exception('oh no!')

        with mock.patch('django_ca.views.OCSPView.process_ocsp_request', side_effect=effect):
            data = base64.b64encode(req1).decode('utf-8')
            response = self.client.get(reverse('get', kwargs={'data': data}))
            self.assertEqual(response.status_code, 200)
            ocsp_response = asn1crypto.ocsp.OCSPResponse.load(response.content)
            self.assertEqual(ocsp_response['response_status'].native, 'internal_error')

            # also do a post request
            response = self.client.post(reverse('post'), req1, content_type='application/ocsp-request')
            self.assertEqual(response.status_code, 200)
            ocsp_response = asn1crypto.ocsp.OCSPResponse.load(response.content)
            self.assertEqual(ocsp_response['response_status'].native, 'internal_error')

    @override_tmpcadir()
    def test_post(self):
        cert = self.certs['child-cert']
        response = self.client.post(reverse('post'), req1, content_type='application/ocsp-request')
        self.assertEqual(response.status_code, 200)
        self.assertOCSP(response, requested=[cert], nonce=req1_nonce, expires=1200)

        response = self.client.post(reverse('post-serial'), req1, content_type='application/ocsp-request')
        self.assertEqual(response.status_code, 200)
        self.assertOCSP(response, requested=[cert], nonce=req1_nonce, expires=1300)

        response = self.client.post(reverse('post-full-pem'), req1, content_type='application/ocsp-request')
        self.assertEqual(response.status_code, 200)
        self.assertOCSP(response, requested=[cert], nonce=req1_nonce, expires=1400)

        response = self.client.post(reverse('post-abs-path'), req1, content_type='application/ocsp-request')
        self.assertEqual(response.status_code, 200)
        self.assertOCSP(response, requested=[cert], nonce=req1_nonce, expires=1500)

    @unittest.skipUnless(ca_settings.CRYPTOGRAPHY_OCSP, 'Skip cryptography test for cryptography<2.4')
    @override_tmpcadir()
    def test_loaded_cryptography_cert(self):
        cert = self.certs['child-cert']
        response = self.client.post(reverse('post-loaded-cryptography'), req1,
                                    content_type='application/ocsp-request')
        self.assertEqual(response.status_code, 200)
        self.assertOCSP(response, requested=[cert], nonce=req1_nonce, expires=1500)

    @unittest.skipIf(ca_settings.CRYPTOGRAPHY_OCSP, 'Skip cryptography test for cryptography>=2.4')
    @override_tmpcadir()
    def test_loaded_oscrypto_cert(self):
        response = self.client.post(reverse('post-loaded-oscrypto'), req1,
                                    content_type='application/ocsp-request')
        self.assertEqual(response.status_code, 200)
        self.assertOCSP(response, requested=[self.certs['child-cert']], nonce=req1_nonce, expires=1500)

    @unittest.skipUnless(ca_settings.CRYPTOGRAPHY_OCSP, 'Skip cryptography test for cryptography<2.4')
    @override_tmpcadir()
    def test_no_nonce(self):
        from cryptography.x509 import ocsp
        cert = self.certs['child-cert']
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(cert.x509, cert.ca.x509, hashes.SHA1())
        data = base64.b64encode(builder.build().public_bytes(serialization.Encoding.DER))

        response = self.client.get(reverse('get', kwargs={'data': data.decode('utf-8')}))
        self.assertOCSP(response, requested=[cert], nonce=None)

    @override_tmpcadir()
    def test_no_nonce_asn1crypto(self):
        cert = self.certs['child-cert']
        builder = ocspbuilder.OCSPRequestBuilder(
            certificate=asn1crypto.x509.Certificate.load(cert.x509.public_bytes(Encoding.DER)),
            issuer=asn1crypto.x509.Certificate.load(cert.ca.x509.public_bytes(Encoding.DER))
        )
        builder.nonce = False
        data = base64.b64encode(builder.build().dump()).decode('utf-8')

        response = self.client.get(reverse('get', kwargs={'data': data}))
        self.assertEqual(response.status_code, 200)
        self.assertOCSP(response, requested=[cert], nonce=None)

    @override_tmpcadir()
    def test_revoked(self):
        cert = self.certs['child-cert']
        cert.revoke()

        response = self.client.post(reverse('post'), req1, content_type='application/ocsp-request')
        self.assertEqual(response.status_code, 200)
        self.assertOCSP(response, requested=[cert], nonce=req1_nonce, expires=1200)

        cert.revoke(ReasonFlags.affiliation_changed)
        response = self.client.post(reverse('post'), req1, content_type='application/ocsp-request')
        self.assertEqual(response.status_code, 200)
        self.assertOCSP(response, requested=[cert], nonce=req1_nonce, expires=1200)

    def test_ca_ocsp(self):
        data = base64.b64encode(req1).decode('utf-8')
        response = self.client.get(reverse('get-ca', kwargs={'data': data}))
        self.assertEqual(response.status_code, 200)
        asn1crypto.ocsp.OCSPResponse.load(response.content)
        #self.assertOCSP(response, requested=[self.cert], nonce=req1_nonce, expires=1200)

    def test_bad_ca(self):
        data = base64.b64encode(req1).decode('utf-8')
        with self.assertLogs() as cm:
            response = self.client.get(reverse('unknown', kwargs={'data': data}))
        self.assertEqual(cm.output, [
            'ERROR:django_ca.views:unknown: Certificate Authority could not be found.',
        ])

        self.assertEqual(response.status_code, 200)
        ocsp_response = asn1crypto.ocsp.OCSPResponse.load(response.content)
        self.assertEqual(ocsp_response['response_status'].native, 'internal_error')

    def test_unknown(self):
        data = base64.b64encode(unknown_req).decode('utf-8')
        with self.assertLogs() as cm:
            response = self.client.get(reverse('get', kwargs={'data': data}))
        self.assertEqual(cm.output, [
            'WARNING:django_ca.views:OCSP request for unknown cert received.',
        ])
        self.assertEqual(response.status_code, 200)
        ocsp_response = asn1crypto.ocsp.OCSPResponse.load(response.content)
        self.assertEqual(ocsp_response['response_status'].native, 'internal_error')

    def _test_bad_responder_cert(self):
        # TODO: can't make sense of what this is supposed to test
        data = base64.b64encode(req1).decode('utf-8')

        with self.assertLogs() as cm:
            response = self.client.get(reverse('get', kwargs={'data': data}))
        self.assertEqual(response.status_code, 200)
        ocsp_response = asn1crypto.ocsp.OCSPResponse.load(response.content)
        self.assertEqual(ocsp_response['response_status'].native, 'internal_error')
        self.assertEqual(cm.output, [
            'ERROR:django_ca.views:Could not read responder key/cert.'
        ])

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

    @override_tmpcadir()
    def test_bad_ca_cert(self):
        ca = self.cas['child']
        ca.pub = 'foobar'
        ca.save()

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

    @override_tmpcadir()
    def test_bad_responder_pem(self):
        data = base64.b64encode(req1).decode('utf-8')
        msg = 'ERROR:django_ca.views:Could not read responder key/cert.'
        prefix = 'WARNING:django_ca.views'

        pem_msg = '%s:%%s: OCSP responder uses absolute path to certificate. Please see %s.' % (
            prefix, ca_settings.CA_FILE_STORAGE_URL)

        with self.assertLogs() as cm:
            response = self.client.get(reverse('false-pem', kwargs={'data': data}))
        self.assertEqual(cm.output, [
            pem_msg % '/false/foobar/',
            msg,
        ])
        self.assertEqual(response.status_code, 200)
        ocsp_response = asn1crypto.ocsp.OCSPResponse.load(response.content)
        self.assertEqual(ocsp_response['response_status'].native, 'internal_error')

        with self.assertLogs() as cm:
            response = self.client.get(reverse('false-pem-serial', kwargs={'data': data}))
        self.assertEqual(cm.output, [
            msg,
        ])
        self.assertEqual(response.status_code, 200)
        ocsp_response = asn1crypto.ocsp.OCSPResponse.load(response.content)

        self.assertEqual(ocsp_response['response_status'].native, 'internal_error')
        with self.assertLogs() as cm:
            response = self.client.get(reverse('false-pem-full', kwargs={'data': data}))
        self.assertEqual(cm.output, [
            msg,
        ])
        self.assertEqual(response.status_code, 200)
        ocsp_response = asn1crypto.ocsp.OCSPResponse.load(response.content)
        self.assertEqual(ocsp_response['response_status'].native, 'internal_error')


@override_settings(USE_TZ=True)
class OCSPWithTZTestView(OCSPTestView):
    pass

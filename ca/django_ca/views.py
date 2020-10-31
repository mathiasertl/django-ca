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

"""Views for the django-ca app.

.. seealso::

   * https://docs.djangoproject.com/en/dev/topics/class-based-views/
   * https://django-ca.readthedocs.io/en/latest/python/views.html
"""

import base64
import binascii
import logging
import os
import secrets
from datetime import datetime
from datetime import timedelta
from urllib.parse import urlparse

import acme.jws
import josepy as jose
import pytz
from acme import messages

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ExtensionNotFound
from cryptography.x509 import OCSPNonce
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509 import ocsp

from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.db import transaction
from django.http import Http404
from django.http import HttpResponse
from django.http import HttpResponseServerError
from django.http import JsonResponse
from django.urls import resolve
from django.urls import reverse
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import View
from django.views.generic.detail import SingleObjectMixin

from . import ca_settings
from .acme import AcmeException
from .acme import AcmeMalformed
from .acme import AcmeObjectResponse
from .acme import AcmeResponseAccountCreated
from .acme import AcmeResponseAuthorization
from .acme import AcmeResponseBadNonce
from .acme import AcmeResponseError
from .acme import AcmeResponseMalformed
from .acme import AcmeResponseNotFound
from .acme import AcmeResponseOrder
from .acme import AcmeResponseOrderCreated
from .acme import AcmeResponseUnauthorized
from .acme import AcmeResponseUnsupportedMediaType
from .models import AcmeAccount
from .models import AcmeAccountAuthorization
from .models import AcmeCertificate
from .models import AcmeChallenge
from .models import AcmeOrder
from .models import Certificate
from .models import CertificateAuthority
from .tasks import acme_issue_certificate
from .tasks import acme_validate_challenge
from .utils import SERIAL_RE
from .utils import get_crl_cache_key
from .utils import int_to_hex
from .utils import parse_encoding
from .utils import read_file
from .utils import sanitize_serial

log = logging.getLogger(__name__)


class CertificateRevocationListView(View, SingleObjectMixin):
    """Generic view that provides Certificate Revocation Lists (CRLs)."""

    slug_field = 'serial'
    slug_url_kwarg = 'serial'
    queryset = CertificateAuthority.objects.all().prefetch_related('certificate_set')

    password = None
    """Password used to load the private key of the certificate authority. If not set, the private key is
    assumed to be unencrypted."""

    # parameters for the CRL itself
    type = Encoding.DER
    """Filetype for CRL."""

    scope = 'user'
    """Set to ``"user"`` to limit CRL to certificates or ``"ca"`` to certificate authorities or ``None`` to
    include both."""

    expires = 600
    """CRL expires in this many seconds."""

    digest = hashes.SHA512()
    """Digest used for generating the CRL."""

    # header used in the request
    content_type = None
    """Value of the Content-Type header used in the response. For CRLs in PEM format, use ``text/plain``."""

    def get(self, request, serial):
        # pylint: disable=missing-function-docstring; standard Django view function
        encoding = parse_encoding(request.GET.get('encoding', self.type))
        cache_key = get_crl_cache_key(serial, algorithm=self.digest, encoding=encoding, scope=self.scope)

        crl = cache.get(cache_key)
        if crl is None:
            ca = self.get_object()
            encoding = parse_encoding(self.type)
            crl = ca.get_crl(expires=self.expires, algorithm=self.digest, password=self.password,
                             scope=self.scope)
            crl = crl.public_bytes(encoding)
            cache.set(cache_key, crl, self.expires)

        content_type = self.content_type
        if content_type is None:
            if self.type == Encoding.DER:
                content_type = 'application/pkix-crl'
            elif self.type == Encoding.PEM:
                content_type = 'text/plain'
            else:  # pragma: no cover
                # DER/PEM are all known encoding types, so this shouldn't happen
                return HttpResponseServerError()

        return HttpResponse(crl, content_type=content_type)


@method_decorator(csrf_exempt, name='dispatch')
class OCSPBaseView(View):
    """View to provide an OCSP responder.

    django-ca currently provides two OCSP implementations, one using cryptography>=2.4 and one using oscrypto
    for older versions of cryptography that do not support OCSP. This is a base view that provides some
    generic settings and common functions to both implementations.

    Note that providing the responder key or certificate using an absolute path is deprecated for the Django
    file storage API. Please see :ref:`update-file-storage` for more information.
    """

    ca = None
    """The name or serial of your Certificate Authority."""

    responder_key = None
    """Private key used for signing OCSP responses. Either a relative path used by :ref:`CA_FILE_STORAGE
    <settings-ca-file-storage>` or (**deprecated**) an absolute path on the local filesystem."""

    responder_cert = None
    """Public key of the responder.

    This may either be:

    * A relative path used by :ref:`CA_FILE_STORAGE <settings-ca-file-storage>`
    * **Deprecated:** An absolute path on the local filesystem
    * A serial of a certificate as stored in the database
    * The PEM of the certificate as string
    * A loaded :py:class:`~cg:cryptography.x509.Certificate`
    """

    expires = 600
    """Time in seconds that the responses remain valid. The default is 600 seconds or ten minutes."""

    ca_ocsp = False
    """If set to ``True``, validate child CAs instead."""

    def get(self, request, data):
        # pylint: disable=missing-function-docstring; standard Django view function
        try:
            data = base64.b64decode(data)
        except binascii.Error:
            return self.malformed_request()

        try:
            return self.process_ocsp_request(data)
        except Exception as e:  # pylint: disable=broad-except; we really need to catch everything here
            log.exception(e)
            return self.fail()

    def post(self, request):
        # pylint: disable=missing-function-docstring; standard Django view function
        try:
            return self.process_ocsp_request(request.body)
        except Exception as e:  # pylint: disable=broad-except; we really need to catch everything here
            log.exception(e)
            return self.fail()

    def get_responder_key_data(self):
        if os.path.isabs(self.responder_key):
            log.warning('%s: OCSP responder uses absolute path to private key. Please see %s.',
                        self.responder_key, ca_settings.CA_FILE_STORAGE_URL)

        return read_file(self.responder_key)

    def get_responder_cert_data(self):
        if self.responder_cert.startswith('-----BEGIN CERTIFICATE-----\n'):
            return self.responder_cert.encode('utf-8')

        if SERIAL_RE.match(self.responder_cert):
            serial = self.responder_cert.replace(':', '')
            return Certificate.objects.get(serial=serial).pub.encode('utf-8')

        if os.path.isabs(self.responder_cert):
            log.warning('%s: OCSP responder uses absolute path to certificate. Please see %s.',
                        self.responder_cert, ca_settings.CA_FILE_STORAGE_URL)

        return read_file(self.responder_cert)

    def get_ca(self):
        return CertificateAuthority.objects.get_by_serial_or_cn(self.ca)

    def get_cert(self, ca, serial):
        if self.ca_ocsp is True:
            return CertificateAuthority.objects.filter(parent=ca).get(serial=serial)
        else:
            return Certificate.objects.filter(ca=ca).get(serial=serial)

    def http_response(self, data, status=200):
        return HttpResponse(data, status=status, content_type='application/ocsp-response')


class OCSPView(OCSPBaseView):
    """View providing OCSP functionality.

    Depending on the cryptography version used, this view might use either cryptography or oscrypto."""

    def fail(self, status=ocsp.OCSPResponseStatus.INTERNAL_ERROR):
        return self.http_response(
            ocsp.OCSPResponseBuilder.build_unsuccessful(status).public_bytes(Encoding.DER)
        )

    def malformed_request(self):
        return self.fail(ocsp.OCSPResponseStatus.MALFORMED_REQUEST)

    def get_responder_key(self):
        key = self.get_responder_key_data()
        return serialization.load_pem_private_key(key, None, default_backend())

    def get_responder_cert(self):
        # User configured a loaded certificate
        if isinstance(self.responder_cert, x509.Certificate):
            return self.responder_cert

        responder_cert = self.get_responder_cert_data()
        return load_pem_x509_certificate(responder_cert, default_backend())

    def process_ocsp_request(self, data):
        try:
            ocsp_req = ocsp.load_der_ocsp_request(data)  # NOQA
        except Exception as e:  # pylint: disable=broad-except; we really need to catch everything here
            log.exception(e)
            return self.malformed_request()

        # Fail if there are any critical extensions that we do not understand
        for ext in ocsp_req.extensions:
            if ext.critical and not isinstance(ext.value, OCSPNonce):  # pragma: no cover
                # It seems impossible to get cryptography to create such a request, so it's not tested
                return self.malformed_request()

        # Get CA and certificate
        try:
            ca = self.get_ca()
        except CertificateAuthority.DoesNotExist:
            log.error('%s: Certificate Authority could not be found.', self.ca)
            return self.fail()

        try:
            cert = self.get_cert(ca, int_to_hex(ocsp_req.serial_number))
        except Certificate.DoesNotExist:
            log.warning('OCSP request for unknown cert received.')
            return self.fail()
        except CertificateAuthority.DoesNotExist:
            log.warning('OCSP request for unknown CA received.')
            return self.fail()

        # get key/cert for OCSP responder
        try:
            responder_key = self.get_responder_key()
            responder_cert = self.get_responder_cert()
        except Exception:  # pylint: disable=broad-except; we really need to catch everything here
            log.error('Could not read responder key/cert.')
            return self.fail()

        # get the certificate status
        if cert.revoked:
            status = ocsp.OCSPCertStatus.REVOKED
        else:
            status = ocsp.OCSPCertStatus.GOOD

        now = datetime.utcnow()
        builder = ocsp.OCSPResponseBuilder()
        expires = datetime.utcnow() + timedelta(seconds=self.expires)
        builder = builder.add_response(
            cert=cert.x509, issuer=ca.x509, algorithm=hashes.SHA1(),
            cert_status=status,
            this_update=now,
            next_update=expires,
            revocation_time=cert.get_revocation_time(),
            revocation_reason=cert.get_revocation_reason()
        ).responder_id(
            ocsp.OCSPResponderEncoding.HASH, responder_cert
        )

        # Add the responder cert to the response, necessary because we (so far) always use delegate
        # certificates
        builder = builder.certificates([responder_cert])

        # Add OCSP nonce if present
        try:
            nonce = ocsp_req.extensions.get_extension_for_class(OCSPNonce)
            builder = builder.add_extension(nonce.value, critical=nonce.critical)
        except ExtensionNotFound:
            pass

        response = builder.sign(responder_key, hashes.SHA256())
        return self.http_response(response.public_bytes(Encoding.DER))


@method_decorator(csrf_exempt, name='dispatch')
class GenericOCSPView(OCSPView):
    def dispatch(self, request, serial, **kwargs):
        # pylint: disable=missing-function-docstring; standard Django view function
        if request.method == 'GET' and 'data' not in kwargs:
            return self.http_method_not_allowed(request, serial, **kwargs)
        if request.method == 'POST' and 'data' in kwargs:
            return self.http_method_not_allowed(request, serial, **kwargs)
        self.ca = CertificateAuthority.objects.get(serial=serial)
        return super().dispatch(request, **kwargs)

    def get_ca(self):
        return self.ca

    def get_responder_key_data(self):
        return read_file('ocsp/%s.key' % self.ca.serial.replace(':', ''))

    def get_responder_cert_data(self):
        return read_file('ocsp/%s.pem' % self.ca.serial.replace(':', ''))


class GenericCAIssuersView(View):
    """Generic view that returns a CA public key in DER format.

    This view serves the URL named in the ``issuers`` key in the
    :py:class:`~django_ca.extensions.AuthorityInformationAccess` extension.
    """

    def get(self, request, serial):
        # pylint: disable=missing-function-docstring; standard Django view function
        ca = CertificateAuthority.objects.get(serial=serial)
        data = ca.x509.public_bytes(encoding=Encoding.DER)
        return HttpResponse(data, content_type='application/pkix-cert')


class AcmeDirectory(View):
    """
    `Equivalent LE URL <https://acme-v02.api.letsencrypt.org/directory>`__
    """

    def _url(self, request, name, ca):  # pylint: disable=no-self-use
        return request.build_absolute_uri(reverse('django_ca:%s' % name, kwargs={'serial': ca.serial}))

    def get(self, request, serial=None):
        # pylint: disable=missing-function-docstring; standard Django view function
        if not ca_settings.CA_ENABLE_ACME:
            raise Http404('Page not found.')

        if serial is None:
            try:
                ca = CertificateAuthority.objects.default()
            except ImproperlyConfigured:
                return AcmeResponseNotFound('No (usable) default CA configured.')
        else:
            try:
                ca = CertificateAuthority.objects.usable().get(serial=sanitize_serial(serial))
            except ValueError:  # pragma: no cover; any invalid serial already caught by URL converter
                return AcmeResponseMalformed('%s: Serial not valid.' % serial)
            except CertificateAuthority.DoesNotExist:
                return AcmeResponseNotFound('%s: CA not found.' % serial)

        # Get some random data into the directory view, as explained in the Let's Encrypt directory:
        #   https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417
        rnd = jose.encode_b64jose(secrets.token_bytes(16))

        return JsonResponse({
            rnd: "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417",
            "keyChange": "http://localhost:8000/django_ca/acme/todo/key-change",
            "meta": {
                #"caaIdentities": [
                #    "letsencrypt.org"
                #],
                "termsOfService": "https://localhost:8000/django_ca/example.pdf",
                "website": "https://localhost:8000"
            },
            "newAccount": self._url(request, 'acme-new-account', ca),
            "newNonce": self._url(request, 'acme-new-nonce', ca),
            "newOrder": self._url(request, 'acme-new-order', ca),
            "revokeCert": "http://localhost:8000/django_ca/acme/todo/revoke-cert"  # TODO
        })


@method_decorator(csrf_exempt, name='dispatch')
class AcmeBaseView(View):
    """Base class for all ACME views."""

    ignore_body = False  # True if we want to ignore the message body
    post_as_get = False  # True if this is a POST-as-GET request (see RFC 8555, 6.3).
    requires_key = False  # True if we require a full key (-> new accounts)
    message_cls = None  # Set to class parsing the request body if post_as_get=False.
    nonce_length = 32

    def acme_request(self, **kwargs):
        """Function to handle the given ACME request. Views are expected to implement this function.

        Parameters
        ----------

        **kwargs : dict
            The arguments as passed by the resolver. If ``post_as_get`` is True, an instance of the class
            specified in ``message_cls`` is passed as the ``message`` keyword argument.
        """
        raise NotImplementedError  # pragma: no cover

    def get_message_cls(self, request, **kwargs):
        """Get the message class used for parsing the request body."""
        # pylint: disable=unused-argument; kwargs is not usually used
        return self.message_cls

    def get_nonce(self):
        """Get a random Nonce and add it to the cache."""

        data = secrets.token_bytes(self.nonce_length)
        nonce = jose.encode_b64jose(data)
        cache_key = 'acme-nonce-%s-%s' % (self.kwargs['serial'], nonce)
        cache.set(cache_key, 0)
        return nonce

    def validate_nonce(self, nonce):
        """Validate that the given nonce was issued and was not used before."""
        cache_key = 'acme-nonce-%s-%s' % (self.kwargs['serial'], nonce)
        try:
            count = cache.incr(cache_key)
        except ValueError:
            return False

        if count > 1:  # nonce was already used
            # NOTE: "incr" returns the *new* value, so "1" is the expected value.
            return False

        return True

    def validate_message(self, message):
        """Let subclasses do individual validation of the received message."""

    def set_link_relations(self, response, **kwargs):
        """Set Link releations headers according to RFC8288.

        `RFC8555, section 7.1 <https://tools.ietf.org/html/rfc8555#section-7.1>`_ states:

            The "index" link relation is present on all resources other than the directory and indicates the
            URL of the directory.

        .. seealso:: https://tools.ietf.org/html/rfc8288
        """

        kwargs['index'] = reverse('django_ca:acme-directory', kwargs={'serial': self.kwargs['serial']})
        response['Link'] = ', '.join('<%s>;rel="%s"' % (self.request.build_absolute_uri(v), k)
                                     for k, v in kwargs.items())

    def dispatch(self, request, *args, **kwargs):
        if not ca_settings.CA_ENABLE_ACME:
            raise Http404('Page not found.')

        try:
            response = super().dispatch(request, *args, **kwargs)
            self.set_link_relations(response)
        except Exception as ex:  # pylint: disable=broad-except
            log.exception(ex)
            response = AcmeResponseError(message='Internal server error')

        # RFC 8555, section 6.7:
        # An ACME server provides nonces to clients using the HTTP Replay-Nonce header field, as specified in
        # Section 6.5.1.  The server MUST include a Replay-Nonce header field in every successful response to
        # a POST request and SHOULD provide it in error responses as well.
        response['replay-nonce'] = self.get_nonce()
        return response

    def post(self, request, serial, **kwargs):
        # pylint: disable=missing-function-docstring; standard Django view function
        # pylint: disable=attribute-defined-outside-init
        # pylint: disable=too-many-return-statements,too-many-branches; b/c of the many checks

        if request.content_type != 'application/jose+json':
            # RFC 8555, 6.2:
            # "Because client requests in ACME carry JWS objects in the Flattened JSON Serialization, they
            # must have the Content-Type header field set to "application/jose+json".  If a request does not
            # meet this requirement, then the server MUST return a response with status code 415 (Unsupported
            # Media Type).
            return AcmeResponseUnsupportedMediaType()

        try:
            self.jws = acme.jws.JWS.json_loads(request.body)
        except Exception as ex:  # pylint: disable=broad-except; we really should catch everything here
            log.exception(ex)
            return AcmeResponseMalformed('Could not parse JWS token.')

        combined = self.jws.signature.combined
        if combined.jwk and combined.kid:
            # 'The "jwk" and "kid" fields are mutually exclusive.  Servers MUST reject requests that contain
            # both.'
            return AcmeResponseMalformed('JWS contained mutually exclusive fields "jwk" and "kid".')

        if combined.jwk:
            if not self.requires_key:
                return AcmeResponseMalformed('Request requires a JWK key ID.')

            # verify request
            if not self.jws.verify():
                return AcmeResponseMalformed('JWS signature invalid.')

            self.jwk = combined.jwk
        elif combined.kid:
            if self.requires_key:
                return AcmeResponseMalformed('Request requires a full JWK key.')

            # combined.kid is a full URL pointing to the account.
            parsed_url = urlparse(combined.kid)
            match = resolve(parsed_url.path)
            if match.app_name != 'django_ca' or match.namespace != 'django_ca' \
                    or match.url_name != 'acme-account':
                return AcmeResponseMalformed('%s: Not an account URL.' % combined.kid)
            if request.build_absolute_uri(parsed_url.path) != combined.kid:
                # If the two URLs are not identical, it means the request contained e.g. a different hostname
                # or similar.
                return AcmeResponseMalformed('%s: Not a valid account URL.' % combined.kid)

            try:
                account = AcmeAccount.objects.get(pk=match.kwargs['pk'])
            except AcmeAccount.DoesNotExist:
                return AcmeResponseMalformed('Account not found.')  # TODO: status code etc
            if account.usable is False:
                return AcmeResponseUnauthorized()

            # load and verify JWK
            self.jwk = jose.JWK.load(account.pem.encode('utf-8'))
            if not self.jws.verify(self.jwk):
                return AcmeResponseMalformed('JWS signature invalid.')

            self.account = account
        else:
            # ... 'Either "jwk" (JSON Web Key) or "kid" (Key ID)'
            return AcmeResponseMalformed('JWS contained mutually exclusive fields "jwk" and "kid".')

        if len(self.jws.signatures) != 1:
            # RFC 8555, 6.2: "The JWS MUST NOT have multiple signatures"
            return AcmeResponseMalformed('Multiple JWS signatures encountered.')

        # "The JWS Protected Header MUST include the following fields:...
        if not combined.alg or combined.alg == 'none':
            # ... "alg"
            return AcmeResponseMalformed('No algorithm specified.')

        # Get certificate authority for this request
        self.ca = CertificateAuthority.objects.usable().get(serial=serial)

        if not self.validate_nonce(jose.encode_b64jose(combined.nonce)):
            # ... "nonce"
            resp = AcmeResponseBadNonce()

            return resp

        if combined.url != request.build_absolute_uri():
            # ... "url"
            # RFC 8555 is not really clear on the required response code, but merely says "If the two do not
            # match, then the server MUST reject the request as unauthorized."
            return AcmeResponseUnauthorized()

        if self.post_as_get is True:
            if self.jws.payload != b'':
                return AcmeResponseMalformed('Non-empty payload in get-as-post request.')

            try:
                response = self.acme_request(**kwargs)
            except AcmeException as e:
                response = e.get_response()
        elif self.ignore_body is True:
            try:
                response = self.acme_request(**kwargs)
            except AcmeException as e:
                response = e.get_response()
        else:
            message_cls = self.get_message_cls(request, **kwargs)
            message = message_cls.json_loads(self.jws.payload)

            try:
                self.validate_message(message)
                response = self.acme_request(message=message, **kwargs)
            except AcmeException as e:
                response = e.get_response()

        return response


class AcmeNewNonce(AcmeBaseView):  # pylint: disable=abstract-method; no need to override acme_request()
    """
    `Equivalent LE URL <https://acme-v02.api.letsencrypt.org/acme/new-nonce>`__
    """
    def head(self, request, serial):
        # pylint: disable=method-hidden; seems like a false positive
        # pylint: disable=missing-function-docstring; standard Django method
        resp = HttpResponse()
        resp['replay-nonce'] = self.get_nonce()
        return resp


class AcmeNewAccount(AcmeBaseView):
    """Implements endpoint for creating a new account, that is ``/acme/new-account``.

    .. seealso:: `RFC 8555, 7.3 <https://tools.ietf.org/html/rfc8555#section-7.3>`_
    """
    message_cls = messages.Registration
    requires_key = True

    def acme_request(self, message):  # pylint: disable=arguments-differ; more concrete here
        pem = self.jwk['key'].public_bytes(
            encoding=Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        account = AcmeAccount.objects.create(
            ca=self.ca,
            contact=message.emails[0],
            status=AcmeAccount.STATUS_VALID,
            terms_of_service_agreed=message.terms_of_service_agreed,
            thumbprint=jose.encode_b64jose(self.jwk.thumbprint()),
            pem=pem
        )

        return AcmeResponseAccountCreated(self.request, account)


class AcmeAccountView(AcmeBaseView):
    pass


class AcmeAccountOrdersView(AcmeBaseView):
    pass


class AcmeNewOrderView(AcmeBaseView):
    """Implements endpoint for applying for a new certificate, that is ``/acme/new-order``.

    If the client receives a successful response, it will next fetch the authorizations listed in it, which
    are served by :py:class:`~django_ca.views.AcmeAuthorizationView`.

    ``certbot`` sends the :py:class:`~acme:acme.messages.NewOrder` message via
    :py:meth:`~acme:acme.client.ClientV2.new_order`.

    .. seealso:: `RFC 8555, 7.4 <https://tools.ietf.org/html/rfc8555#section-7.4>`_
    """
    message_cls = messages.NewOrder

    def validate_message(self, message):
        """Test that fields not allowed for this endpoint are not present.

        RFC 8555, 7.4 specifies that "body ... is a subset of the order object", so we test that other
        possible fields for the NewOrder class are not set.
        """
        for field in ['status', 'expires', 'error', 'authorizations', 'finalize', 'certificate']:
            if getattr(message, field) is not None:
                raise AcmeMalformed('%s is not allowed here.' % field)

        # TODO: test potential notBefore/notAfter in message, but this is not in the certbot message
        # TODO: test if identifiers are acceptable

    @transaction.atomic
    def acme_request(self, message):  # pylint: disable=arguments-differ; more concrete here
        order = AcmeOrder.objects.create(account=self.account)

        authorizations = []
        for ident in message.identifiers:
            authz = order.add_authorization(ident)
            authorizations.append(self.request.build_absolute_uri(authz.acme_url))

        expires = order.expires
        if timezone.is_naive(expires):  # acme.messages.Order requires a timezone-aware object
            expires = timezone.make_aware(expires, timezone=pytz.utc)

        response = AcmeResponseOrderCreated(
            status=order.status,
            expires=expires,
            identifiers=message.identifiers,
            authorizations=authorizations,
            finalize=self.request.build_absolute_uri(order.acme_finalize_url),
        )
        response['Location'] = self.request.build_absolute_uri(order.acme_url)
        return response


class AcmeOrderView(AcmeBaseView):
    post_as_get = True

    def acme_request(self, slug):  # pylint: disable=arguments-differ; more concrete here
        order = AcmeOrder.objects.get(slug=slug)

        expires = order.expires
        if timezone.is_naive(expires):  # acme.messages.Order requires a timezone-aware object
            expires = timezone.make_aware(expires, timezone=pytz.utc)

        # TODO: should only be pending auths, and only if state of order is pending
        authorizations = order.authorizations.all()

        cert = AcmeCertificate.objects.get(order=order)
        cert_url = self.request.build_absolute_uri(cert.acme_url)

        response = AcmeResponseOrder(
            status=order.status,
            expires=expires,
            identifiers=[{'type': a.type, 'value': a.value} for a in authorizations],
            authorizations=[self.request.build_absolute_uri(a) for a in authorizations],
            certificate=cert_url
        )
        response['Location'] = self.request.build_absolute_uri(order.acme_url)
        return response


class AcmeOrderFinalizeView(AcmeBaseView):
    """Implements endpoint for applying for certificate issuance, that is ``/acme/order/<slug>/finalize``.

    The client is supposed to call this URL to submit its CSR, once "it believes it has fulfilled the server's
    requirements".

    .. seealso:: `RFC 8555, 7.4 <https://tools.ietf.org/html/rfc8555#section-7.4>`_
    """
    message_cls = messages.CertificateRequest

    def acme_request(self, message, slug):  # pylint: disable=arguments-differ; more concrete here
        order = AcmeOrder.objects.get(slug=slug)

        # Note: Jose wraps the CSR in a josepy.util.ComparableX509, that has *no* public member methods.
        # The only public attribute or function is the wrapped object. We encode it back to get the regular
        # PEM.
        # Note that the CSR received here is not an actual PEM, see AcmeCertificate.parse_csr()
        csr = message.encode('csr')

        expires = order.expires
        if timezone.is_naive(expires):  # acme.messages.Order requires a timezone-aware object
            expires = timezone.make_aware(expires, timezone=pytz.utc)

        cert = AcmeCertificate.objects.get_or_create(order=order, defaults={'csr': csr})[0]
        # TODO: should only be pending auths, and only if state of order is pending
        authorizations = order.authorizations.all()
        cert_url = self.request.build_absolute_uri(cert.acme_url)

        if order.status == AcmeOrder.STATUS_READY:
            order.status == AcmeOrder.STATUS_PROCESSING
            order.save()

            acme_issue_certificate.delay(acme_certificate_pk=cert.pk)

        response = AcmeResponseOrder(
            status=order.status,
            expires=expires,
            identifiers=[{'type': a.type, 'value': a.value} for a in authorizations],
            authorizations=[self.request.build_absolute_uri(a) for a in authorizations],
            certificate=cert_url
        )
        response['Location'] = self.request.build_absolute_uri(order.acme_url)
        return response


class AcmeCertificateView(AcmeBaseView):
    """Implements endpoint to download a certificate, that is ``/acme/cert/<slug>/``.

    .. seealso:: `RFC8555, 8555, 7.4.2 <https://tools.ietf.org/html/rfc8555#section-7.4.2>`_
    """
    post_as_get = True

    def acme_request(self, slug):  # pylint: disable=arguments-differ; more concrete here
        acme_cert = AcmeCertificate.objects.get(slug=slug)
        bundle = '\n'.join([cert.pub.strip() for cert in acme_cert.cert.bundle])
        return HttpResponse(bundle, content_type='application/pem-certificate-chain')


class AcmeAuthorizationView(AcmeBaseView):
    """Implements endpoint for identifier authorization, that is ``/acme/authz/<slug>/``.

    .. seealso:: `RFC 8555, 7.5 <https://tools.ietf.org/html/rfc8555#section-7.5>`_
    """

    post_as_get = True

    def acme_request(self, slug):  # pylint: disable=arguments-differ; more concrete here
        # TODO: filter for AcmeOrder status
        auth = AcmeAccountAuthorization.objects.select_related('order').get(slug=slug)
        challenges = auth.get_challenges()

        expires = auth.expires
        if not settings.USE_TZ:  # acme.Order requires a timezone-aware object
            expires = timezone.make_aware(expires, timezone=pytz.utc)

        # RFC8555, section 7.5.1:
        #
        #   "When finalizing an authorization, the server MAY remove challenges other than the one that was
        #   completed".
        #
        # The example response at the end of section 7.5.1 also only shows the valid challenge.
        if auth.status == AcmeAccountAuthorization.STATUS_VALID:
            challenges = [c for c in challenges if c.status == AcmeChallenge.STATUS_VALID]

        resp = AcmeResponseAuthorization(
            identifier=auth.identifier,
            challenges=[c.get_challenge(self.request) for c in challenges],
            status=auth.status,
            expires=expires,
        )
        return resp


class AcmeChallengeView(AcmeBaseView):
    """Implements ``/acme/chall/<slug>``, indicating to the server that the challenge can now be validated.

    .. seealso:: https://tools.ietf.org/html/rfc8555#section-7.1.5
    """

    ignore_body = True

    def set_link_relations(self, response, **kwargs):
        """SEt the "up" link header to the matching authorization.

        `RFC8555, section 7.1 <https://tools.ietf.org/html/rfc8555#section-7.1>`_ states:

            The "up" link relation is used with challenge resources to indicate the authorization resource to
            which a challenge belongs.
        """
        return super().set_link_relations(response, up=self.challenge.acme_url, **kwargs)

    def get_message_cls(self, request, slug):
        self.challenge = AcmeChallenge.objects.get(slug=slug)
        return self.challenge.get_challenge(request)

    def acme_request(self, slug):  # pylint: disable=arguments-differ; more concrete here
        self.challenge = AcmeChallenge.objects.get(slug=slug)

        # Set the status to "processing", to quote RFC8555, Section 7.1.6:
        # "They transition to the "processing" state when the client responds to the challenge"
        self.challenge.status = AcmeChallenge.STATUS_PROCESSING
        self.challenge.save()

        # Actually perform challenge validation asynchronously
        acme_validate_challenge.delay(self.challenge.pk)

        return AcmeObjectResponse(self.challenge.get_challenge(self.request))

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

import abc
import logging
import secrets
import typing
from datetime import datetime
from datetime import timezone as tz
from http import HTTPStatus
from typing import Dict, Generic, Iterable, List, Optional, Set, Type, TypeVar, Union, cast

import acme.jws
import josepy as jose
from acme import messages

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.db import transaction
from django.http import Http404, HttpRequest, HttpResponse, JsonResponse
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import View

from .. import ca_settings
from ..constants import REASON_CODES
from ..models import (
    AcmeAccount,
    AcmeAuthorization,
    AcmeCertificate,
    AcmeChallenge,
    AcmeOrder,
    Certificate,
    CertificateAuthority,
)
from ..tasks import acme_issue_certificate, acme_validate_challenge, run_task
from ..utils import check_name, int_to_hex, make_naive, validate_email
from .errors import AcmeBadCSR, AcmeException, AcmeForbidden, AcmeMalformed, AcmeUnauthorized
from .messages import CertificateRequest, NewOrder
from .responses import (
    AcmeResponse,
    AcmeResponseAccount,
    AcmeResponseAccountCreated,
    AcmeResponseAuthorization,
    AcmeResponseBadNonce,
    AcmeResponseChallenge,
    AcmeResponseError,
    AcmeResponseMalformed,
    AcmeResponseMalformedPayload,
    AcmeResponseNotFound,
    AcmeResponseOrder,
    AcmeResponseOrderCreated,
    AcmeResponseUnauthorized,
    AcmeResponseUnsupportedMediaType,
)
from .utils import parse_acme_csr

log = logging.getLogger(__name__)
MessageTypeVar = TypeVar("MessageTypeVar", bound=jose.json_util.JSONObjectWithFields)
DirectoryMetaAlias = Dict[str, Union[str, List[str]]]


if typing.TYPE_CHECKING:
    from django.http.response import HttpResponseBase


class ContactValidationMixin:
    """Mixin for validating contact information."""

    def validate_contacts(self, message: messages.Registration) -> None:
        """Validate the contact information for this message."""

        for contact in message.contact:
            if contact.startswith(messages.Registration.email_prefix):
                addr = contact[len(messages.Registration.email_prefix) :]

                # RFC 8555, section 7.3
                #
                #   Clients MUST NOT provide a "mailto" URL in the "contact" field that contains "hfields"
                #   [RFC6068] or more than one "addr-spec" in the "to" component.

                # We rule out quoted local address fields, otherwise it's extremely hard to validate
                # email addresses.
                if addr.startswith('"'):
                    raise AcmeMalformed("invalidContact", "Quoted local part in email is not allowed.")

                # Since the local part is not quoted, it cannot contain a ',' either, so a ',' means there
                # is more than one "addr-spec" in the "to" component. (see RFC 8555 quote above)
                if "," in addr:
                    raise AcmeMalformed("invalidContact", "More than one addr-spec is not allowed.")

                # Validate that there are no hfields in the address.
                # NOTE: ',' appears to be valid in the local part according to RFC 5322
                _local, domain = addr.split("@", 1)
                if "?" in domain:
                    raise AcmeMalformed("invalidContact", f"{domain}: hfields are not allowed.")

                # Finally, verify that we're getting at least a valid domain.
                try:
                    validate_email(addr)
                except ValueError as ex:
                    raise AcmeMalformed("invalidContact", f"{domain}: Not a valid email address.") from ex
            else:
                # RFC 8555, section 7.3
                #
                #   If the server rejects a contact URL for using an unsupported scheme, it MUST raise an
                #   error of type "unsupportedContact", ...
                raise AcmeMalformed("unsupportedContact", f"{contact}: Unsupported address scheme.")


class AcmeDirectory(View):
    """
    `Equivalent LE URL <https://acme-v02.api.letsencrypt.org/directory>`__

    .. seealso:: `RFC 8555, section 7.1.1 <https://tools.ietf.org/html/rfc8555#section-7.1.1>`_
    """

    def _url(self, request: HttpRequest, name: str, ca: CertificateAuthority) -> str:
        return request.build_absolute_uri(reverse(f"django_ca:{name}", kwargs={"serial": ca.serial}))

    def get(self, request: HttpRequest, serial: Optional[str] = None) -> HttpResponse:
        # pylint: disable=missing-function-docstring; standard Django view function
        if not ca_settings.CA_ENABLE_ACME:
            raise Http404("Page not found.")

        if serial is None:
            try:
                # NOTE: default() already calls usable()
                ca = CertificateAuthority.objects.acme().default()
            except ImproperlyConfigured:
                return AcmeResponseNotFound(message="No (usable) default CA configured.")
        else:
            try:
                # NOTE: Serial is already sanitized by URL converter
                ca = CertificateAuthority.objects.acme().usable().get(serial=serial)
            except CertificateAuthority.DoesNotExist:
                return AcmeResponseNotFound(message=f"{serial}: CA not found.")

        # Get some random data into the directory view, as explained in the Let's Encrypt directory:
        #   https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417
        rnd = jose.json_util.encode_b64jose(secrets.token_bytes(16))

        directory: Dict[str, Union[str, DirectoryMetaAlias]] = {
            rnd: "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417",
            "keyChange": "http://localhost:8000/django_ca/acme/todo/key-change",
            "newAccount": self._url(request, "acme-new-account", ca),
            "newNonce": self._url(request, "acme-new-nonce", ca),
            "newOrder": self._url(request, "acme-new-order", ca),
            "revokeCert": self._url(request, "acme-revoke", ca),
        }

        # Construct a "meta" object if and add it if any fields are defined. Note that the meta object is
        # optional (RFC 8555, section 7.1.1: "The object MAY additionally contain a "meta" field.").
        meta: DirectoryMetaAlias = {}
        if ca.website:
            meta["website"] = ca.website
        if ca.terms_of_service:
            meta["termsOfService"] = ca.terms_of_service
        if ca.caa_identity:
            meta["caaIdentities"] = [ca.caa_identity]  # array of string
        if meta:
            directory["meta"] = meta

        return JsonResponse(directory)


class AcmeGetNonceViewMixin:
    """View mixin that provides methods to get and validate a Nonce.

    Note that thix mixin depends on the presence of a ``serial`` argument to the URL resolver.
    """

    kwargs: Dict[str, str]
    nonce_length = 32
    """Length of generated Nonces."""

    def get_cache_key(self, nonce: str) -> str:
        """Get the cache key for the given request and nonce."""
        return f"acme-nonce-{self.kwargs['serial']}-{nonce}"

    def get_nonce(self) -> str:
        """Get a random Nonce and add it to the cache."""

        data = secrets.token_bytes(self.nonce_length)
        nonce = jose.json_util.encode_b64jose(data)
        cache.set(self.get_cache_key(nonce), 0)
        return nonce

    def validate_nonce(self, nonce: str) -> bool:
        """Validate that the given nonce was issued and was not used before."""
        try:
            count = cache.incr(self.get_cache_key(nonce))
        except ValueError:
            # raised if cache_key is not set
            return False

        if count > 1:  # nonce was already used
            # NOTE: "incr" returns the *new* value, so "1" is the expected value.
            return False

        return True


@method_decorator(csrf_exempt, name="dispatch")
class AcmeBaseView(AcmeGetNonceViewMixin, View, metaclass=abc.ABCMeta):
    """Base class for all ACME views."""

    requires_key = False  # True if we require a full key (-> new accounts)
    accepts_kid_or_jwk = False  # Set to true to accept both KID or JWK
    jwk: jose.jwk.JWK
    jws: acme.jws.JWS

    @abc.abstractmethod
    def process_acme_request(self, slug: Optional[str]) -> AcmeResponse:
        """Abstract method expected to implement processing a message.

        The `slug` argument is the URL slug that identifies an ACME object and is None for requests that
        either create an object or do not process any object.
        """

    def is_account_usable(self, account: AcmeAccount) -> bool:
        """Method determining if an account is usable.

        Implementing views may override this function if what makes an account "usable" is different. Notably,
        the AccountView considers accounts usable even if the terms of service where not agreed, as the user
        can then agree to the terms of service.
        """
        # Check for various conditions that make an account unusable and raise an appropriate exception
        if account.status == AcmeAccount.STATUS_DEACTIVATED:
            # NOTE: Account may have other status that makes it unusable, these cases are covered by
            # account.usable below.
            raise AcmeUnauthorized(message="Account has been deactivated.")
        if account.ca.terms_of_service and not account.terms_of_service_agreed:
            raise AcmeUnauthorized(message="Account did not agree to the terms of service.")

        # COVERAGE NOTE: The check for the CA is already done when selecting the CA, so account.ca.usable
        # should always be true at this point. Check is left here as an additional precaution.
        if not account.ca.usable:  # pragma: no cover
            raise AcmeUnauthorized(message="Certificate Authority is not usable.")

        # This should return True unless the account was revoked by the server, in which case we let the main
        # function return a generic error message instead.
        return account.usable

    def set_link_relations(self, response: "HttpResponseBase", **kwargs: str) -> None:
        """Set Link releations headers according to RFC8288.

        `RFC8555, section 7.1 <https://tools.ietf.org/html/rfc8555#section-7.1>`_ states:

            The "index" link relation is present on all resources other than the directory and indicates the
            URL of the directory.

        .. seealso:: https://tools.ietf.org/html/rfc8288
        """

        kwargs["index"] = reverse("django_ca:acme-directory", kwargs={"serial": self.kwargs["serial"]})
        response["Link"] = ", ".join(
            f'<{self.request.build_absolute_uri(v)}>;rel="{k}"' for k, v in kwargs.items()
        )

    # def log_request(self):
    #    """Function for logging prepared requests."""
    #    if getattr(settings, 'LOG_ACME_REQUESTS', None):
    #        prepared_key = self.__class__.__name__
    #        prepared_path = os.path.join(settings.FIXTURES_DIR, 'prepared-acme-requests.json')
    #        prepared_data = {}
    #        if os.path.exists(prepared_path):
    #            with open(prepared_path) as stream:
    #                prepared_data = json.load(stream)
    #        if prepared_key not in prepared_data:
    #            prepared_data[prepared_key] = []
    #        prepared_data[prepared_key].append(self.prepared)
    #        with open(prepared_path, 'w') as stream:
    #            json.dump(prepared_data, stream, indent=4)

    def dispatch(  # type: ignore[override]
        self, request: HttpRequest, serial: str, slug: Optional[str] = None
    ) -> "HttpResponseBase":
        if not ca_settings.CA_ENABLE_ACME:
            raise Http404("Page not found.")

        try:
            response = super().dispatch(request, serial=serial, slug=slug)
        except AcmeException as ex:
            response = ex.get_response()
        except Exception as ex:  # pylint: disable=broad-except
            log.exception(ex)
            response = AcmeResponseError(message="Internal server error")

        self.set_link_relations(response)

        # self.log_request()

        # RFC 8555, section 6.7:
        # An ACME server provides nonces to clients using the HTTP Replay-Nonce header field, as specified in
        # Section 6.5.1.  The server MUST include a Replay-Nonce header field in every successful response to
        # a POST request and SHOULD provide it in error responses as well.
        response["replay-nonce"] = self.get_nonce()
        return response

    def post(self, request: HttpRequest, serial: str, slug: Optional[str] = None) -> AcmeResponse:
        # pylint: disable=missing-function-docstring; standard Django view function
        # pylint: disable=attribute-defined-outside-init
        # pylint: disable=too-many-return-statements; b/c of the many checks

        # TODO: RFC 8555, 6.2 has a nice list of things to check here that we don't yet fully cover
        if request.content_type != "application/jose+json":
            # RFC 8555, 6.2:
            # "Because client requests in ACME carry JWS objects in the Flattened JSON Serialization, they
            # must have the Content-Type header field set to "application/jose+json".  If a request does not
            # meet this requirement, then the server MUST return a response with status code 415 (Unsupported
            # Media Type).
            return AcmeResponseUnsupportedMediaType()

        # self.prepared['body'] = json.loads(request.body.decode('utf-8'))

        try:
            self.jws = acme.jws.JWS.json_loads(request.body)
        except (jose.errors.DeserializationError, TypeError):
            return AcmeResponseMalformed(message="Could not parse JWS token.")

        combined = self.jws.signature.combined
        if combined.jwk and combined.kid:
            # 'The "jwk" and "kid" fields are mutually exclusive.  Servers MUST reject requests that contain
            # both.'
            return AcmeResponseMalformed(message="jwk and kid are mutually exclusive.")

        # Get certificate authority for this request
        try:
            self.ca = CertificateAuthority.objects.acme().usable().get(serial=serial)
        except CertificateAuthority.DoesNotExist:
            return AcmeResponseNotFound(message="The requested CA cannot be found.")

        if combined.jwk:
            if not self.requires_key and not self.accepts_kid_or_jwk:
                return AcmeResponseMalformed(message="Request requires a JWK key ID.")

            self.jwk = combined.jwk  # set JWK from request
        elif combined.kid:
            if self.requires_key and not self.accepts_kid_or_jwk:
                return AcmeResponseMalformed(message="Request requires a full JWK key.")

            # combined.kid is a full URL pointing to the account.
            try:
                account = AcmeAccount.objects.viewable().get(ca=self.ca, kid=combined.kid)
            except AcmeAccount.DoesNotExist:
                return AcmeResponseUnauthorized(message="Account not found.")

            if self.is_account_usable(account) is False:
                # RFC 855, 7.3.6:
                #
                #   If a server receives a POST or POST-as-GET from a deactivated account, it MUST return an
                #   error response with status code 401 (Unauthorized) and type
                #   "urn:ietf:params:acme:error:unauthorized".
                return AcmeResponseUnauthorized(message="Account not usable.")
            # self.prepared['thumbprint'] = account.thumbprint
            # self.prepared['pem'] = account.pem
            # self.prepared['account_pk'] = account.pk

            self.jwk = jose.jwk.JWK.load(account.pem.encode("utf-8"))  # load JWK from database
            self.account = account
        else:
            # ... 'Either "jwk" (JSON Web Key) or "kid" (Key ID)'
            return AcmeResponseMalformed(message="JWS contained neither key nor key ID.")

        if len(self.jws.signatures) != 1:  # pragma: no cover
            # RFC 8555, 6.2: "The JWS MUST NOT have multiple signatures"
            return AcmeResponseMalformed(message="Multiple JWS signatures encountered.")

        # "The JWS Protected Header MUST include the following fields:...
        if not combined.alg:  # pragma: no cover
            # ... "alg"
            return AcmeResponseMalformed(message="No algorithm specified.")

        # Verify JWS signature
        try:
            if not self.jws.verify(self.jwk):
                return AcmeResponseMalformed(message="JWS signature invalid.")
        except Exception:  # pylint: disable=broad-except
            return AcmeResponseMalformed(message="JWS signature invalid.")

        # self.prepared['nonce'] = jose.encode_b64jose(combined.nonce)
        if combined.nonce is None or not self.validate_nonce(jose.json_util.encode_b64jose(combined.nonce)):
            # ... "nonce"
            return AcmeResponseBadNonce()

        if combined.url != request.build_absolute_uri():
            # ... "url"
            # RFC 8555 is not really clear on the required response code, but merely says "If the two do not
            # match, then the server MUST reject the request as unauthorized."
            return AcmeResponseUnauthorized(message="URL does not match.")

        return self.process_acme_request(slug=slug)


class AcmePostAsGetView(AcmeBaseView, metaclass=abc.ABCMeta):
    """Base class for ACME post-as-get requests."""

    ignore_body = False  # True if we want to ignore the message body

    @abc.abstractmethod
    def acme_request(self, slug: str) -> AcmeResponse:
        """Abstract method to process an ACME post-as-get request.

        Actual view subclasses are expected to implement this function.

        Note that the `slug` argument is never ``None`` for post-as-get requests, as the request would then
        contain no information.
        """

    def process_acme_request(self, slug: Optional[str]) -> AcmeResponse:
        if self.ignore_body is False and self.jws.payload != b"":
            return AcmeResponseMalformed(message="Non-empty payload in get-as-post request.")
        if slug is None:  # pragma: no cover; just a safety measure
            return AcmeResponseError(message="PostAsGet view called with slug.")

        return self.acme_request(slug=slug)


class AcmeMessageBaseView(AcmeBaseView, Generic[MessageTypeVar], metaclass=abc.ABCMeta):
    """Base class for ACME requests with a message payload."""

    message_cls: Type[MessageTypeVar]

    @abc.abstractmethod
    def acme_request(self, message: MessageTypeVar, slug: Optional[str]) -> AcmeResponse:
        """Process ACME request.

        Actual view subclasses are expected to implement this function.
        """

    def process_acme_request(self, slug: Optional[str]) -> AcmeResponse:
        try:
            message = self.message_cls.json_loads(self.jws.payload)
            log.debug("ACME message: %s", message)
        except jose.errors.DeserializationError as e:
            return AcmeResponseMalformedPayload(message=", ".join(e.args))

        return self.acme_request(message, slug)


class AcmeNewNonceView(AcmeGetNonceViewMixin, View):
    """View to retrieve a new nonce for replay protection.

    Equivalent LE URL: https://acme-v02.api.letsencrypt.org/acme/new-nonce

    .. seealso::

       * `RFC 8555, section 6.5 <https://tools.ietf.org/html/rfc8555#section-6.5>`_
       * `RFC 8555, section 7.2 <https://tools.ietf.org/html/rfc8555#section-7.2>`_
    """

    def dispatch(self, request: HttpRequest, serial: str) -> "HttpResponseBase":  # type: ignore[override]
        if not ca_settings.CA_ENABLE_ACME:
            raise Http404("Page not found.")

        response = super().dispatch(request, serial)
        response["replay-nonce"] = self.get_nonce()

        # RFC 8555, section 7.2:
        #
        #   The server MUST include a Cache-Control header field with the "no-store" directive in responses
        response["cache-control"] = "no-store"
        return response

    def head(self, request: HttpRequest, serial: str) -> HttpResponse:
        """Get a new Nonce with a HEAD request."""
        # pylint: disable=method-hidden; false positive - View.setup() sets head as property if not defined
        # pylint: disable=unused-argument; false positive - really used by AcmeGetNonceViewMixin
        return HttpResponse()

    def get(self, request: HttpRequest, serial: str) -> HttpResponse:
        """Get a new Nonce with a GET request.

        Note that certbot always does a HEAD request, but RFC 8555, section 7.2 mandates support for GET
        requests.
        """
        # pylint: disable=unused-argument; false positive - really used by AcmeGetNonceViewMixin
        return HttpResponse(status=HTTPStatus.NO_CONTENT)  # 204, unlike HEAD, which has 200


class AcmeNewAccountView(ContactValidationMixin, AcmeMessageBaseView[messages.Registration]):
    """Implements endpoint for creating a new account, that is ``/acme/new-account``.

    This view is called when the ACME client tries to register a new account.

    .. seealso:: `RFC 8555, 7.3 <https://tools.ietf.org/html/rfc8555#section-7.3>`_
    """

    message_cls = messages.Registration
    requires_key = True

    def acme_request(self, message: messages.Registration, slug: Optional[str]) -> AcmeResponseAccount:
        """Process ACME request."""
        pem = (
            self.jwk.key.public_bytes(
                encoding=Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode("utf-8")
            .strip()
        )
        thumbprint = jose.json_util.encode_b64jose(self.jwk.thumbprint())

        # RFC 8555, section 7.3:
        #
        #   If this field is present with the value "true", then the server MUST NOT create a new account if
        #   one does not already exist.  This allows a client to look up an account URL based on an account
        #   key (see Section 7.3.1).
        if message.only_return_existing:
            try:
                account = AcmeAccount.objects.get(thumbprint=thumbprint, pem=pem)
                return AcmeResponseAccount(self.request, account)
            except AcmeAccount.DoesNotExist as ex:
                # RFC 8555, section 7.3:
                #
                #   ... account does not exist, then the server MUST return an error response with status code
                #   400 (Bad Request) and type "urn:ietf:params:acme:error:accountDoesNotExist".
                raise AcmeMalformed(typ="accountDoesNotExist", message="Account does not exist.") from ex

        # RFC 8555, section 7.3.1
        #
        #   If the server receives a newAccount request signed with a key for which it already has an account
        #   registered with the provided account key, then it MUST return a response with status code 200 (OK)
        #   and provide the URL of that account in the Location header field.
        try:
            # NOTE: Filter for thumbprint too b/c index for the field should speed up lookups.
            account = AcmeAccount.objects.get(thumbprint=thumbprint, pem=pem)
            return AcmeResponseAccount(self.request, account)
        except AcmeAccount.DoesNotExist:
            pass

        if self.ca.acme_requires_contact and not message.emails:
            # NOTE: RFC 8555 does not specify an error code in this case
            raise AcmeUnauthorized(message="Must provide at least one contact address.")

        # Make sure that contact addresses are valid
        self.validate_contacts(message)

        # certbot/acme 1.31.0 does not send this value at all the CA does not have any terms of service.
        # This issue was not present in 1.29.0 and is no longer present in 2.0.0, but any other client may of
        # course not send this value.
        if message.terms_of_service_agreed is None:
            terms_of_service_agreed = False
        else:
            terms_of_service_agreed = message.terms_of_service_agreed

        account = AcmeAccount(
            ca=self.ca,
            contact="\n".join(message.contact),
            status=AcmeAccount.STATUS_VALID,
            terms_of_service_agreed=terms_of_service_agreed,
            thumbprint=thumbprint,
            pem=pem,
        )
        account.set_kid(self.request)

        # Call full_clean() so that model validation can do its magic
        try:
            account.full_clean()
            account.save()
        except ValidationError as ex:
            # Add a pretty list of validation errors to the detail field in the response
            subproblems = ", ".join(
                sorted([f"{k}: {v1.rstrip('.')}" for k, v in ex.message_dict.items() for v1 in v])
            )
            raise AcmeMalformed(message=f"Invalid account: {subproblems}.") from ex

        # self.prepared['thumbprint'] = account.thumbprint
        # self.prepared['pem'] = account.pem
        # self.prepared['account_pk'] = account.pem

        # RFC 8555, section 7.3
        #
        #   The server returns this account object in a 201 (Created) response, with the account URL in a
        #   Location header field.
        #
        # AcmeResponseAccountCreated adds the Location field currently.
        return AcmeResponseAccountCreated(self.request, account)


class AcmeAccountView(ContactValidationMixin, AcmeMessageBaseView[messages.Registration]):
    """View allowing the update of accounts or receiving current account details."""

    message_cls = messages.Registration

    def is_account_usable(self, account: AcmeAccount) -> bool:
        """Overridden to make accounts usable that have not agreed to the terms of service.

        A client may agree to the terms of service after account creation, then making the account usable for
        other operations.
        """
        if account.status == AcmeAccount.STATUS_DEACTIVATED:
            # NOTE: Account may have other status that makes it unusable, these cases are covered by
            # the check if the status is valid below
            raise AcmeUnauthorized(message="Account has been deactivated.")

        # COVERAGE NOTE: The check for the CA is already done when selecting the CA, so account.ca.usable
        # should always be true at this point. Check is left here as an additional precaution.
        if not account.ca.usable:  # pragma: no cover
            raise AcmeUnauthorized(message="Certificate Authority is not usable.")

        return account.status == AcmeAccount.STATUS_VALID

    @transaction.atomic
    def acme_request(self, message: messages.Registration, slug: Optional[str] = None) -> AcmeResponseAccount:
        account = AcmeAccount.objects.get(slug=slug)

        if message.status == AcmeAccount.STATUS_DEACTIVATED:
            # RFC 8555, section 7.3.6 - Account Deactivation
            log.info("Deactivating account %s", account.slug)
            account.status = AcmeAccount.STATUS_DEACTIVATED
            account.save()

            # Cancel all pending operations
            account.orders.filter(status=AcmeOrder.STATUS_PENDING).update(status=AcmeOrder.STATUS_INVALID)
            AcmeAuthorization.objects.filter(
                order__account=account, status=AcmeAuthorization.STATUS_PENDING
            ).update(status=AcmeAuthorization.STATUS_DEACTIVATED)
        elif message.contact:
            self.validate_contacts(message)
            account.contact = "\n".join(message.contact)
            account.save()
        elif message.terms_of_service_agreed is not None:
            account.terms_of_service_agreed = message.terms_of_service_agreed
            account.save()
        else:
            raise AcmeMalformed(message="Only contact information can be updated.")

        return AcmeResponseAccount(self.request, account)


class AcmeAccountOrdersView(AcmeBaseView):
    """View showing orders for an account (not yet implemented)"""

    # TODO: implement this view
    def process_acme_request(self, slug: Optional[str]) -> AcmeResponse:  # pragma: no cover
        raise AcmeException(message="Not Implemented.")


class AcmeNewOrderView(AcmeMessageBaseView[NewOrder]):
    """Implements endpoint for applying for a new certificate, that is ``/acme/new-order``.

    This is the first request of an ACME client when requesting a new certificate.

    If the client receives a successful response, it will next fetch the authorizations listed in it, which
    are served by :py:class:`~django_ca.views.AcmeAuthorizationView`.

    ``certbot`` sends the :py:class:`~acme:acme.messages.NewOrder` message via
    :py:meth:`~acme:acme.client.ClientV2.new_order`.

    .. seealso:: `RFC 8555, 7.4 <https://tools.ietf.org/html/rfc8555#section-7.4>`_
    """

    message_cls = NewOrder

    @transaction.atomic
    def acme_request(self, message: NewOrder, slug: Optional[str] = None) -> AcmeResponseOrderCreated:
        """Process ACME request."""
        now = datetime.now(tz.utc)

        # josepy message classes define field names as class variables, but instance attributes are of the
        # same type (similar to Django). So we cast fields detected as RFC3339Field to datetime.
        not_before = cast(Optional[datetime], message.not_before)
        not_after = cast(Optional[datetime], message.not_after)

        if not_before and not_before < now:
            raise AcmeMalformed(message="Certificate cannot be valid before now.")
        if not_after and not_after > now + ca_settings.ACME_MAX_CERT_VALIDITY:
            raise AcmeMalformed(message="Certificate cannot be valid that long.")
        if not_before and not_after and not_before > not_after:
            raise AcmeMalformed(message="notBefore must be before notAfter.")
        if not message.identifiers:
            # NOTE: Catches sending an empty tuple, which is not caught in message deserialization
            raise AcmeMalformed(message="The following fields are required: identifiers")

        if settings.USE_TZ is False:
            if not_before is not None:
                not_before = make_naive(not_before)
            if not_after is not None:
                not_after = make_naive(not_after)

        # TODO: test if identifiers are acceptable
        order = AcmeOrder.objects.create(account=self.account, not_before=not_before, not_after=not_after)

        authorizations = [
            self.request.build_absolute_uri(authz.acme_url)
            for authz in order.add_authorizations(message.identifiers)
        ]

        expires = order.expires
        if expires.tzinfo is None:  # acme.messages.Order requires a timezone-aware object
            expires = expires.replace(tzinfo=tz.utc)

        response = AcmeResponseOrderCreated(
            authorizations=authorizations,
            expires=expires,
            finalize=self.request.build_absolute_uri(order.acme_finalize_url),
            identifiers=message.identifiers,
            not_after=message.not_after,
            not_before=message.not_before,
            status=order.status,
        )
        response["Location"] = self.request.build_absolute_uri(order.acme_url)
        return response


class AcmeOrderView(AcmePostAsGetView):
    """Implements endpoint for viewing an order, that is ``/acme/order/<slug>/``.

    A client calls this view after calling :py:class:`~django_ca.views.AcmeOrderFinalizeView`, presumably
    to retrieve final information about this certificate. This view itself is sparsely documented in RFC 8555.

    This view does seem to be a little redundant too, as the response is almost identical to the response the
    client received in the previous request. Nevertheless, certbot still calls this view and fails without it.

    .. seealso:: `RFC 8555, 7.4 <https://tools.ietf.org/html/rfc8555#section-7.4>`_
    """

    def acme_request(self, slug: str) -> AcmeResponseOrder:
        try:
            order = AcmeOrder.objects.viewable().account(self.account).get(slug=slug)
        except AcmeOrder.DoesNotExist as ex:
            # RFC 8555, section 10.5: Avoid leaking info that this slug does not exist by
            # return a normal unauthorized message.
            raise AcmeUnauthorized() from ex
        # self.prepared['order'] = order.slug

        expires = order.expires
        if expires.tzinfo is None:  # acme.messages.Order requires a timezone-aware object
            expires = expires.replace(tzinfo=tz.utc)

        authorizations = order.authorizations.all()
        if order.status in [AcmeOrder.STATUS_VALID, AcmeOrder.STATUS_INVALID]:
            # RFC 8555, section 7.1.3:
            #
            #   For final orders (in the "valid" or "invalid" state), the authorizations that were completed.
            authorizations = authorizations.filter(status=AcmeAuthorization.STATUS_VALID)

        cert_url = None
        try:
            cert = AcmeCertificate.objects.get(order=order)
            if cert.cert and order.status == AcmeOrder.STATUS_VALID:
                # WARNING: certbot (at least version 0.31.0) will try to fetch the certificate immediately if
                # we return the URL. That view will fail if the certificate is not yet issued, and certbot
                # fails with an error.
                # This behavior is independent of the status of the order, despite the fact this is the field
                # that should be used for this according to RFC 8555.
                cert_url = self.request.build_absolute_uri(cert.acme_url)
        except AcmeCertificate.DoesNotExist:
            pass

        response = AcmeResponseOrder(
            status=order.status,
            expires=expires,
            identifiers=tuple({"type": a.type, "value": a.value} for a in authorizations),
            authorizations=tuple(self.request.build_absolute_uri(a.acme_url) for a in authorizations),
            certificate=cert_url,
        )
        response["Location"] = self.request.build_absolute_uri(order.acme_url)
        return response


class AcmeOrderFinalizeView(AcmeMessageBaseView[CertificateRequest]):
    """Implements endpoint for applying for certificate issuance, that is ``/acme/order/<slug>/finalize``.

    The client is supposed to call this URL to submit its CSR, once "it believes it has fulfilled the server's
    requirements".

    Note that in practice, the client can call this endpoint only once while the order is "ready". The
    endpoint returns an error if the order is not ready, and the call updates the state to "processing".

    .. seealso:: `RFC 8555, 7.4 <https://tools.ietf.org/html/rfc8555#section-7.4>`_
    """

    message_cls = CertificateRequest

    def validate_csr(self, message: CertificateRequest, authorizations: Iterable[AcmeAuthorization]) -> str:
        """Parse and validate the CSR, returns the PEM as str."""

        # Note: Jose wraps the CSR in a josepy.util.ComparableX509, that has *no* public member methods.
        # The only public attribute or function is the wrapped object. We encode it back to get the regular
        # PEM.
        # Note that the CSR received here is not an actual PEM, see AcmeCertificate.parse_csr()
        try:
            csr = parse_acme_csr(message.encode("csr"))
        except x509.InvalidVersion as ex:
            raise AcmeBadCSR(message="Invalid CSR version.") from ex
        except Exception as ex:
            log.exception("Error parsing CSR.")
            raise AcmeBadCSR(message="Unable to parse CSR.") from ex

        if csr.is_signature_valid is False:
            raise AcmeBadCSR(message="CSR signature is not valid.")

        # Do not accept MD5 or SHA1 signatures
        hash_algorithm = csr.signature_hash_algorithm
        if hasattr(hashes, "MD5") and isinstance(
            hash_algorithm, hashes.MD5
        ):  # pragma: only cryptography<39.0
            raise AcmeBadCSR(message=f"{hash_algorithm.name}: Insecure hash algorithm.")
        if hasattr(hashes, "SHA1") and isinstance(  # pragma: only cryptography<39.0
            hash_algorithm, hashes.SHA1
        ):
            raise AcmeBadCSR(message=f"{hash_algorithm.name}: Insecure hash algorithm.")

        # Get list of general names from the authorizations
        names_from_order = set(auth.general_name for auth in authorizations)

        # Perform sanity checks on the CSRs subject.
        # NOTE: certbot does *not* set any subject at all
        if csr.subject:
            check_name(csr.subject)

            # We allow a client setting a CommonName, but it *must* be part of the order.
            common_name = next((attr for attr in csr.subject if attr.oid == NameOID.COMMON_NAME), None)
            if common_name is not None:
                if isinstance(common_name.value, bytes):  # pragma: no cover
                    raise AcmeBadCSR(message="CommonName was not in order.")
                if x509.DNSName(common_name.value) not in names_from_order:
                    raise AcmeBadCSR(message="CommonName was not in order.")

        try:
            san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            names_from_csr: Set[x509.GeneralName] = set(san_ext.value)
        except x509.ExtensionNotFound as ex:
            raise AcmeBadCSR(message="No subject alternative names found in CSR.") from ex

        if names_from_order != names_from_csr:
            raise AcmeBadCSR(message="Names in CSR do not match.")

        return csr.public_bytes(Encoding.PEM).decode("utf-8")

    def acme_request(self, message: CertificateRequest, slug: Optional[str]) -> AcmeResponseOrder:
        """Process ACME request."""
        try:
            order = AcmeOrder.objects.viewable().account(account=self.account).get(slug=slug)
        except AcmeOrder.DoesNotExist as ex:
            # RFC 8555, section 10.5: Avoid leaking info that this slug does not exist by
            # return a normal unauthorized message.
            raise AcmeUnauthorized() from ex
        # self.prepared['order'] = order.slug

        # RFC 8555, section 7.4:
        #
        #   A request to finalize an order will result in error if the order is not in the "ready" state.  In
        #   such cases, the server MUST return a 403 (Forbidden) error with a problem document of type
        #   "orderNotReady".  The client should then send a POST-as-GET request to the order resource to
        #   obtain its current state.  The status of the order will indicate what action the client should
        #   take (see below).
        if order.status != AcmeOrder.STATUS_READY:
            # NOTE: The provision quoted above means that you will *always* get "orderNotReady", even if you
            # fetch this URL and the certificate has already been issued. We might consider returning the
            # order instead in this case.
            # The spec also says you should send a POST-as-GET after a certain time, if the order is in the
            # processing state, but it's not entirely clear if that request should go here or the normal order
            # resource.
            # Further investigation is on what LE and certbot do is needed here.
            raise AcmeForbidden(typ="orderNotReady", message="This order is not yet ready.")

        expires = order.expires
        if expires.tzinfo is None:  # acme.messages.Order requires a timezone-aware object
            expires = expires.replace(tzinfo=tz.utc)

        authorizations = order.authorizations.all()
        for auth in authorizations:
            if auth.status != AcmeAuthorization.STATUS_VALID:
                # This is a state that should never happen in practice, because the order is only marked as
                # ready once all authorizations are valid.
                raise AcmeForbidden(typ="orderNotReady", message="This order is not yet ready.")

        # TODO: Do we validate that the account holds ALL necessary authorizations?

        # Parse and validate the CSR
        csr = self.validate_csr(message, authorizations)

        # Create AcmeCertificate object (at this point without cert, as it hasn't been issued yet)
        cert = AcmeCertificate.objects.create(order=order, csr=csr)

        # Update the status of the order to "processing"
        order.status = AcmeOrder.STATUS_PROCESSING
        order.save()

        # start task only after commit, see:
        # https://docs.djangoproject.com/en/dev/topics/db/transactions/#django.db.transaction.on_commit
        transaction.on_commit(lambda: run_task(acme_issue_certificate, acme_certificate_pk=cert.pk))

        response = AcmeResponseOrder(
            status=order.status,
            expires=expires,
            identifiers=tuple({"type": a.type, "value": a.value} for a in authorizations),
            authorizations=tuple(self.request.build_absolute_uri(a.acme_url) for a in authorizations),
        )
        response["Location"] = self.request.build_absolute_uri(order.acme_url)
        return response


class AcmeCertificateView(AcmePostAsGetView):
    """Implements endpoint to download a certificate, that is ``/acme/cert/<slug>/``.

    This is the final view called in the certificate validation process and downloads the issued certificate.

    .. seealso:: `RFC8555, 8555, 7.4.2 <https://tools.ietf.org/html/rfc8555#section-7.4.2>`_
    """

    # This is the only view that does not return JSON, thus acme_request() returns the superclass
    # HttpResponse, and not an AcmeResponse (which is always JSON).
    def acme_request(self, slug: str) -> HttpResponse:  # type: ignore[override]
        try:
            cert = AcmeCertificate.objects.viewable().account(self.account).get(slug=slug)
        except AcmeCertificate.DoesNotExist as ex:
            raise AcmeUnauthorized() from ex

        # self.prepared['cert'] = slug
        # self.prepared['csr'] = cert.csr
        # self.prepared['order'] = cert.order.slug
        return HttpResponse(cert.cert.bundle_as_pem, content_type="application/pem-certificate-chain")


class AcmeAuthorizationView(AcmePostAsGetView):
    """Implements endpoint for identifier authorization, that is ``/acme/authz/<slug>/``.

    This is the second request when a client requests a new certificate and represents an authorization
    request for one of the identifiers in the order. The URL for this view is returned by the
    :py:class:`~django_ca.views.AcmeNewOrderView`.

    This view returns URLs to the challenges served by ::py:class:`~django_ca.views.AcmeChallengeView`. The
    client will then post to one of these challenges to start the validation process.

    The client periodically polls this view after initiating a challenge to know when the server has
    successfully validated the challenge.

    Note that this resource accepts both a post-as-get request but also a response body: RFC 8555, section
    7.5.2 describes deactivating an account authorization.

    .. seealso:: `RFC 8555, 7.5 <https://tools.ietf.org/html/rfc8555#section-7.5>`_
    """

    def acme_request(self, slug: str) -> AcmeResponseAuthorization:
        # TODO: implement deactivating an authorization (section 7.5.2)

        try:
            auth = AcmeAuthorization.objects.viewable().account(account=self.account).url().get(slug=slug)
        except AcmeAuthorization.DoesNotExist as ex:
            # RFC 8555, section 10.5: Avoid leaking info that this slug does not exist by
            # return a normal unauthorized message.
            raise AcmeUnauthorized() from ex

        # self.prepared['order'] = auth.order.slug
        # self.prepared['auth'] = auth.slug
        challenges = auth.get_challenges()

        expires = auth.expires
        if expires.tzinfo is None:  # acme.Order requires a timezone-aware object
            expires = expires.replace(tzinfo=tz.utc)

        # RFC8555, section 7.5.1:
        #
        #   "When finalizing an authorization, the server MAY remove challenges other than the one that was
        #   completed".
        #
        # The example response at the end of section 7.5.1 also only shows the valid challenge.
        if auth.status == AcmeAuthorization.STATUS_VALID:
            challenges = [c for c in challenges if c.status == AcmeChallenge.STATUS_VALID]

        resp = AcmeResponseAuthorization(
            identifier=auth.identifier,
            challenges=tuple(c.get_challenge(self.request) for c in challenges),
            status=auth.status,
            expires=expires,
        )
        return resp


class AcmeChallengeView(AcmePostAsGetView):
    """Implements ``/acme/chall/<slug>``, indicating to the server that the challenge can now be validated.

    The client calls this view to tell the server to start validation of the resource of this challenges
    resource using the challenge method (http-01, dns-01, ...) for this challenge.

    After this view is called, the client will poll :py:class:`~django_ca.views.AcmeAuthorizationView` to know
    when the server has validated the challenge. After successful validation the client calls
    :py:class:`~django_ca.views.AcmeOrderFinalizeView` to request issuing of the certificate.

    .. seealso::

        * `RFC 8555, section 7.1.5 <https://tools.ietf.org/html/rfc8555#section-7.1.5>`_
        * `RFC 8555, section 7.5.1 <https://tools.ietf.org/html/rfc8555#section-7.5.1>`_
    """

    ignore_body = True

    def set_link_relations(self, response: "HttpResponseBase", **kwargs: str) -> None:
        """Set the "up" link header to the matching authorization.

        `RFC8555, section 7.1 <https://tools.ietf.org/html/rfc8555#section-7.1>`_ states:

            The "up" link relation is used with challenge resources to indicate the authorization resource to
            which a challenge belongs.
        """
        if response.status_code < HTTPStatus.BAD_REQUEST:
            # Only return an up relation if no error is thrown
            kwargs["up"] = self.auth.acme_url
        super().set_link_relations(response, **kwargs)

    def acme_request(self, slug: str) -> AcmeResponseChallenge:
        try:
            challenge = AcmeChallenge.objects.viewable().account(self.account).url().get(slug=slug)
        except AcmeChallenge.DoesNotExist:
            # RFC 8555, section 10.5: Avoid leaking info that this slug does not exist by
            # return a normal unauthorized message.
            raise AcmeUnauthorized()  # pylint: disable=raise-missing-from

        # Set self.auth attribute, we need it in set_link_relations()
        self.auth = challenge.auth  # pylint: disable=attribute-defined-outside-init

        # self.prepared['order'] = challenge.auth.order.slug
        # self.prepared['auth'] = challenge.auth.slug
        # self.prepared['challenge'] = slug

        if challenge.usable is True:  # if not -> no state change
            # RFC8555, Section 7.1.6:
            #
            #   They transition to the "processing" state when the client responds to the challenge
            challenge.status = AcmeChallenge.STATUS_PROCESSING
            challenge.save()

            # Actually perform challenge validation asynchronously
            # start task only after commit, see:
            # https://docs.djangoproject.com/en/2.2/topics/db/transactions/#django.db.transaction.on_commit
            transaction.on_commit(lambda: run_task(acme_validate_challenge, challenge.pk))

        return AcmeResponseChallenge(
            chall=challenge.acme_challenge,
            _url=self.request.build_absolute_uri(challenge.acme_url),
            status=challenge.status,
            validated=challenge.validated,
        )


class AcmeCertificateRevocationView(AcmeMessageBaseView[messages.Revocation]):
    """View providing ACMEv2 certificate revocation.

    .. seealso::

        `RFC 8555, section 7.6 <https://tools.ietf.org/html/rfc8555#section-7.6>`_
    """

    accepts_kid_or_jwk = True
    message_cls = messages.Revocation

    def get_certificate(self, serial: str) -> Certificate:
        """Get the certificate that is to be revoked by this request.

        This function handles the special authorization requirements for this request (they can be signed by
        either the account key pair or the certificate key pair).
        """

        certs = Certificate.objects.filter(ca=self.ca).currently_valid()

        # If the request is signed with the certificate key (and not the account), a JWK is set for this
        # request and we verify it was signed by the certificate on record.
        if self.jws.signature.combined.jwk:
            # NOTE: RFC 8555, section 7.6 states:
            #
            #   The server MUST also consider a revocation request valid if it is signed with the private key
            #   corresponding to the public key in the certificate.
            #
            # This implies that the account used to request the certificate may even be revoked or invalid, as
            # long as the private key is used to sign the request. So we don't look at the ACME account at all
            # here.
            cert = certs.get(serial=serial)

            jwk = cert.jwk

            # The JWS signature was already verified using the JWK from the request in the base class. But we
            # still need to verify that it was signed by the certificate that is to be revoked (and not just
            # any certificate).
            #
            # Theoretically, cert.jwk != self.jwk would be a sufficient check, but we do not trust the
            # __eq__ implementation given the linked GitHub issues, so we also verify the signature a second
            # time based on the database key.
            #   https://josepy.readthedocs.io/en/latest/api/util/
            if jwk != self.jwk or not self.jws.verify(jwk):
                raise AcmeUnauthorized(message="Request signed by the wrong certificate.")
        else:
            # Get the certificate by serial if it *has* an ACME account.
            # NOTE: The base class already makes sure that the account is currently valid.
            cert = certs.filter(acmecertificate__order__account__isnull=False).get(serial=serial)

            # If the request is from the account that issued the certificate, the certificate can be revoked.
            # NOTE: self.account is **only** set if the request has no JWK.
            if cert.acmecertificate.order.account == self.account:
                return cert

            # If the account holds authorizations for all of the identifiers in the certificate, it can also
            # be revoked, so get a list of all currently valid authorizations that the account holds
            authz = set(AcmeAuthorization.objects.dns().valid().account(account=self.account).names())

            # Get names from the certificate, first from the CommonName...
            # NOTE: returns empty list if subject does not have a CommonName.
            names = [cn.value for cn in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]

            # ... then from the SubjectAlternativeName extension
            try:
                san = cert.pub.loaded.extensions.get_extension_for_class(x509.SubjectAlternativeName)

                # If ANY subjectAlternativeName is NOT a DNS name, we cannot revoke this cert.
                if list(filter(lambda v: not isinstance(v, x509.DNSName), san.value)):
                    raise AcmeUnauthorized(message="Certificate contains non-DNS subjectAlternativeNames.")
                names += [name.value for name in san.value]
            except x509.ExtensionNotFound:
                pass

            # Finally test if the account holds all authorizations required for revoking this certificate.
            if not set(names) <= authz:
                raise AcmeUnauthorized(message="Account does not hold necessary authorizations.")

        return cert

    def acme_request(self, message: messages.Revocation, slug: Optional[str]) -> AcmeResponse:
        reason_code = message.reason
        if reason_code is None:
            reason_code = 0

        try:
            reason = REASON_CODES[reason_code]
        except KeyError as ex:
            raise AcmeMalformed(
                typ="badRevocationReason", message=f"{message.reason}: Unsupported revocation reason."
            ) from ex

        # Get cryptography certificate from ACME message
        cg_cert = message.certificate.wrapped.to_cryptography()
        if not isinstance(cg_cert, x509.Certificate):  # pragma: no cover
            # COVERAGE NOTE: message deserialization already raises an error when no certificate is passed,
            # so this check here is just for more safety (and to make mypy happy).
            raise AcmeMalformed(message="Request did not contain a certificate.")

        try:
            cert = self.get_certificate(int_to_hex(cg_cert.serial_number))
        except Certificate.DoesNotExist as ex:
            raise AcmeUnauthorized(message="Certificate not found.") from ex

        # Check that the certificate in the payload matches with the one on record
        if cert.pub.loaded != cg_cert:
            raise AcmeUnauthorized(message="Certificate does not match records.")

        # RFC 8555, section 7.6
        #
        #   if the certificate has already been revoked, the server returns an error response with status code
        #   400 (Bad Request) and type "urn:ietf:params:acme:error:alreadyRevoked".
        if cert.revoked:
            raise AcmeMalformed(typ="alreadyRevoked", message="Certificate was already revoked.")

        # Finally actually revoke the certificate
        cert.revoke(reason)
        return AcmeResponse({})  # No response specified in RFC 8555!

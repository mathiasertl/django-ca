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

"""Collection of Django HTTP response subclasses representing ACME responses."""

from http import HTTPStatus
from typing import Any, Optional, Type

from acme import messages

from django.http import HttpRequest, JsonResponse
from django.urls import reverse

from ..models import AcmeAccount
from .messages import Order


class AcmeResponse(JsonResponse):
    """Base class for all ACME responses."""


class AcmeSimpleResponse(AcmeResponse):
    """Base class for all responses returning an ACME recourses (accounts, etc.)."""

    message_cls: Type[messages.ResourceBody]

    def __init__(self, **kwargs: Any):
        super().__init__(self.message_cls(**kwargs).to_json())


class AcmeResponseAccount(AcmeResponse):
    """Response containing an ACME account."""

    def __init__(self, request: HttpRequest, account: AcmeAccount) -> None:
        contact = []
        if account.contact:
            contact = account.contact.split("\n")

        data = {
            "status": account.status,
            "contact": contact,
            "orders": request.build_absolute_uri(
                reverse(
                    "django_ca:acme-account-orders",
                    kwargs={"slug": account.slug, "serial": account.ca.serial},
                )
            ),
        }

        super().__init__(data)
        self["Location"] = account.kid


class AcmeResponseAccountCreated(AcmeResponseAccount):
    """Response when an ACME account is created."""

    status_code = HTTPStatus.CREATED  # 201


class AcmeResponseOrder(AcmeSimpleResponse):
    """A HTTP response returning an Order object."""

    message_cls = Order


class AcmeResponseOrderCreated(AcmeResponseOrder):
    """An Order response but with HTTP status code CREATED (201)."""

    status_code = HTTPStatus.CREATED  # 201


class AcmeResponseAuthorization(AcmeSimpleResponse):
    """A HTTP response for an ACME authorization."""

    message_cls = messages.Authorization


class AcmeResponseChallenge(AcmeSimpleResponse):
    """A HTTP response for an ACME challenge."""

    message_cls = messages.ChallengeBody


class AcmeResponseError(AcmeResponse):
    """Base class for all ACME error responses."""

    message = "Internal server error"
    status_code = HTTPStatus.INTERNAL_SERVER_ERROR  # 500
    type = "serverInternal"

    def __init__(self, typ: Optional[str] = None, message: str = "") -> None:
        super().__init__(
            {
                "type": f"urn:ietf:params:acme:error:{typ or self.type}",
                "status": self.status_code,
                "detail": message or self.message,
            },
            content_type="application/problem+json",
        )


class AcmeResponseMalformed(AcmeResponseError):
    """ACME response with type malformed."""

    message = "Malformed request"
    status_code = HTTPStatus.BAD_REQUEST  # 400
    type = "malformed"


class AcmeResponseBadCSR(AcmeResponseMalformed):
    """ACME response for an invalid CSR."""

    type = "badCSR"
    message = "CSR is not acceptable."


class AcmeResponseMalformedPayload(AcmeResponseMalformed):
    """A subclass of a malformed response for unparseable payloads.

    This class is reserved for cases where the payload cannot even be processed, e.g. it's missing a required
    key, or a value is invalid.
    """

    message = "Malformed payload."


class AcmeResponseUnauthorized(AcmeResponseError):
    """ACME response with type unauthorized."""

    status_code = HTTPStatus.UNAUTHORIZED  # 401
    type = "unauthorized"
    message = "You are not authorized to perform this request."


class AcmeResponseForbidden(AcmeResponseError):
    """ACME response with HTTP status code 403 (Forbidden)."""

    status_code = HTTPStatus.FORBIDDEN  # 403
    type = "forbidden"
    message = "You are forbidden from accessing this resource."


class AcmeResponseNotFound(AcmeResponseError):
    """ACME response when a requested entity cannot be found."""

    status_code = HTTPStatus.NOT_FOUND  # 404
    type = "not-found"
    message = "The requested entity could not be found."


class AcmeResponseBadNonce(AcmeResponseError):
    """

    .. seealso:: RFC 8555, section 6.5:

       "When a server rejects a request because its nonce value was unacceptable (or not present), it MUST
       provide HTTP status code 400 (Bad Request), and indicate the ACME error type
       "urn:ietf:params:acme:error:badNonce".  An error response with the "badNonce" error type MUST include a
       Replay-Nonce header field with a fresh nonce that the server will accept in a retry of the original
       query (and possibly in other requests, according to the server's nonce scoping policy)."
    """

    status_code = HTTPStatus.BAD_REQUEST  # 400
    type = "badNonce"
    message = "Bad or invalid nonce."


class AcmeResponseUnsupportedMediaType(AcmeResponseMalformed):
    """Acme response for unsupported media type."""

    status_code = HTTPStatus.UNSUPPORTED_MEDIA_TYPE
    message = "Requests must use the application/jose+json content type."

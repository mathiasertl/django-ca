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

"""Endpoint implementation for the API."""

from http import HTTPStatus

from ninja import NinjaAPI, Query
from ninja.errors import HttpError

from django.core.exceptions import ValidationError
from django.core.handlers.wsgi import WSGIRequest
from django.db import transaction
from django.http import Http404, HttpResponse

from django_ca import __version__
from django_ca.api.auth import BasicAuth
from django_ca.api.errors import Forbidden
from django_ca.api.schemas import (
    CertificateAuthorityFilterSchema,
    CertificateAuthoritySchema,
    CertificateAuthorityUpdateSchema,
    CertificateFilterSchema,
    CertificateOrderSchema,
    CertificateSchema,
    RevokeCertificateSchema,
)
from django_ca.api.utils import get_certificate_authority
from django_ca.models import Certificate, CertificateAuthority, CertificateOrder
from django_ca.pydantic.messages import SignCertificateMessage
from django_ca.querysets import CertificateAuthorityQuerySet, CertificateQuerySet
from django_ca.tasks import run_task, sign_certificate as sign_certificate_task

api = NinjaAPI(title="django-ca API", version=__version__, urls_namespace="django_ca:api")


@api.exception_handler(Forbidden)
def forbidden(request: WSGIRequest, exc: Exception) -> HttpResponse:  # pylint: disable=unused-argument
    """Add the exception handler for the Forbidden exception."""
    return api.create_response(request, {"detail": "Forbidden"}, status=HTTPStatus.FORBIDDEN)


@api.get(
    "/ca/",
    response=list[CertificateAuthoritySchema],
    auth=BasicAuth("django_ca.view_certificateauthority"),
    summary="List available certificate authorities",
    tags=["Certificate authorities"],
)
def list_certificate_authorities(
    request: WSGIRequest,
    filters: CertificateAuthorityFilterSchema = Query(...),  # type: ignore[type-arg]  # noqa: B008
) -> CertificateAuthorityQuerySet:
    """Retrieve a list of currently usable certificate authorities."""
    qs = CertificateAuthority.objects.enabled().exclude(api_enabled=False)
    if filters.expired is False:
        qs = qs.valid()
    return qs


@api.get(
    "/ca/{serial:serial}/",
    response=CertificateAuthoritySchema,
    auth=BasicAuth("django_ca.view_certificateauthority"),
    summary="View certificate authority",
    tags=["Certificate authorities"],
)
def view_certificate_authority(request: WSGIRequest, serial: str) -> CertificateAuthority:
    """Retrieve details of the certificate authority with the given serial."""
    return get_certificate_authority(serial, expired=True)  # You can *view* expired CAs


@api.put(
    "/ca/{serial:serial}/",
    response=CertificateAuthoritySchema,
    auth=BasicAuth("django_ca.change_certificateauthority"),
    summary="Update certificate authority",
    tags=["Certificate authorities"],
)
def update_certificate_authority(
    request: WSGIRequest, serial: str, data: CertificateAuthorityUpdateSchema
) -> CertificateAuthority:
    """Update a certificate authority.

    All request body fields are optional, so you can also update only individual fields.
    """
    ca = get_certificate_authority(serial, expired=True)

    # sign_certificate_policies is a django_ca.pydantic.extensions.ExtensionModel, so we can generate the
    # cryptography instance directly
    for field in [f for f in data.model_fields_set if f.startswith("sign_")]:
        if value := getattr(data, field):
            setattr(ca, field, value)
        else:
            setattr(ca, field, None)

    for attr, value in data.model_dump(exclude_unset=True).items():
        if attr.startswith("sign_"):  # exclude sign extensions
            continue
        setattr(ca, attr, value)

    try:
        ca.full_clean()
    except ValidationError as ex:
        raise HttpError(HTTPStatus.BAD_REQUEST, str(ex)) from ex

    ca.save()
    return ca


@api.post(
    "/ca/{serial:serial}/sign/",
    response=CertificateOrderSchema,
    auth=BasicAuth("django_ca.sign_certificate"),
    summary="Sign a certificate",
    tags=["Certificates"],
)
def sign_certificate(request: WSGIRequest, serial: str, data: SignCertificateMessage) -> CertificateOrder:
    """Sign a certificate.

    The `extensions` value is optional and allows you to add additional extensions to the certificate. Usually
    extensions are defined either by the CA or by the named profile.
    """
    ca = get_certificate_authority(serial)

    # TYPEHINT NOTE: django-ninja sets the user as `request.auth` and mypy does not know about it
    order = CertificateOrder.objects.create(
        certificate_authority=ca,
        user=request.auth,  # type: ignore[attr-defined]
    )

    parameters = data.model_dump(mode="json", exclude_unset=True)

    # start task only after commit, see:
    #   https://docs.djangoproject.com/en/dev/topics/db/transactions/#django.db.transaction.on_commit
    transaction.on_commit(lambda: run_task(sign_certificate_task, order_pk=order.pk, **parameters))

    return order


@api.get(
    "/ca/{serial:serial}/orders/{acme:slug}/",
    response=CertificateOrderSchema,
    auth=BasicAuth("django_ca.sign_certificate"),
    summary="Retrieve certificate order",
    tags=["Certificates"],
)
def get_certificate_order(request: WSGIRequest, serial: str, slug: str) -> CertificateOrder:
    """Retrieve information about the certificate order identified by `slug`."""
    return CertificateOrder.objects.get(
        certificate_authority__serial=serial, certificate_authority__api_enabled=True, slug=slug
    )


@api.get(
    "/ca/{serial:serial}/certs/",
    response=list[CertificateSchema],
    auth=BasicAuth("django_ca.view_certificate"),
    summary="List certificates",
    tags=["Certificates"],
)
def list_certificates(
    request: WSGIRequest,
    serial: str,
    filters: CertificateFilterSchema = Query(...),  # type: ignore[type-arg]  # noqa: B008
) -> CertificateQuerySet:
    """Retrieve certificates signed by the certificate authority named by `serial`."""
    ca = get_certificate_authority(serial, expired=True)  # You can list certificates of expired CAs
    qs = Certificate.objects.filter(ca=ca)

    if filters.expired is False:
        qs = qs.currently_valid()
    if filters.autogenerated is False:
        qs = qs.exclude(autogenerated=True)
    if filters.revoked is False:
        qs = qs.exclude(revoked=True)
    if filters.profile is not None:
        qs = qs.filter(profile=filters.profile)

    return qs


@api.get(
    "/ca/{serial:serial}/certs/{serial:certificate_serial}/",
    response=CertificateSchema,
    auth=BasicAuth("django_ca.view_certificate"),
    summary="View certificate",
    tags=["Certificates"],
)
def view_certificate(request: WSGIRequest, serial: str, certificate_serial: str) -> Certificate:
    """Retrieve details of the certificate with the given certificate serial."""
    ca = get_certificate_authority(serial, expired=True)  # You can view certificates of expired CAs
    return Certificate.objects.get(ca=ca, serial=certificate_serial)


@api.post(
    "/ca/{serial:serial}/revoke/{serial:certificate_serial}/",
    response=CertificateSchema,
    auth=BasicAuth("django_ca.revoke_certificate"),
    summary="Revoke certificate",
    tags=["Certificates"],
)
def revoke_certificate(
    request: WSGIRequest, serial: str, certificate_serial: str, revocation: RevokeCertificateSchema
) -> Certificate:
    """Revoke a certificate with the given serial.

    Both `reason` and `compromised` fields are optional.
    """
    ca = get_certificate_authority(serial)
    try:
        cert = Certificate.objects.currently_valid().get(ca=ca, serial=certificate_serial)
    except Certificate.DoesNotExist as ex:
        raise Http404(f"{certificate_serial}: Certificate not found.") from ex

    if cert.revoked is True:
        raise HttpError(HTTPStatus.BAD_REQUEST, "The certificate is already revoked.")

    cert.revoke(revocation.reason, revocation.compromised)
    return cert

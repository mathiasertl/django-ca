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
from typing import List

from ninja import NinjaAPI, Query
from ninja.errors import HttpError

from cryptography import x509

from django.core.exceptions import ValidationError
from django.core.handlers.wsgi import WSGIRequest
from django.http import Http404, HttpResponse

from django_ca import __version__, constants
from django_ca.api.auth import BasicAuth
from django_ca.api.errors import Forbidden
from django_ca.api.schemas import (
    CertificateAuthorityFilterSchema,
    CertificateAuthoritySchema,
    CertificateAuthorityUpdateSchema,
    CertificateFilterSchema,
    CertificateSchema,
    RevokeCertificateSchema,
    SignCertificateSchema,
)
from django_ca.api.utils import get_certificate_authority
from django_ca.extensions import parse_extension
from django_ca.models import Certificate, CertificateAuthority
from django_ca.querysets import CertificateAuthorityQuerySet, CertificateQuerySet

api = NinjaAPI(title="django-ca API", version=__version__, urls_namespace="django_ca:api")


@api.exception_handler(Forbidden)
def forbidden(request: WSGIRequest, exc: Exception) -> HttpResponse:  # pylint: disable=unused-argument
    """Add the exception handler for the Forbidden exception."""
    return api.create_response(request, {"detail": "Forbidden"}, status=HTTPStatus.FORBIDDEN)


@api.get(
    "/ca/",
    response=List[CertificateAuthoritySchema],
    auth=BasicAuth("django_ca.view_certificateauthority"),
    summary="List available certificate authorities",
    tags=["Certificate authorities"],
)
def list_certificate_authorities(
    request: WSGIRequest, filters: CertificateAuthorityFilterSchema = Query(...)
) -> CertificateAuthorityQuerySet:
    """Retrieve a list of currently usable certificate authorities."""
    qs = CertificateAuthority.objects.enabled()
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
    for attr, value in data.dict(exclude_unset=True).items():
        setattr(ca, attr, value)

    try:
        ca.full_clean()
    except ValidationError as ex:
        raise HttpError(HTTPStatus.BAD_REQUEST, ex.message_dict) from ex  # type: ignore[arg-type]

    ca.save()
    return ca


@api.post(
    "/ca/{serial:serial}/sign/",
    response=CertificateSchema,
    auth=BasicAuth("django_ca.sign_certificate"),
    summary="Sign a certificate",
    tags=["Certificates"],
)
def sign_certificate(request: WSGIRequest, serial: str, data: SignCertificateSchema) -> Certificate:
    """Sign a certificate.

    The `extensions` value is completely optional and allows you to add additional extensions to the
    certificate. Usually extensions are defined either by the CA or by the named profile.
    """
    csr = x509.load_pem_x509_csr(data.csr.encode())
    ca = get_certificate_authority(serial)
    subject = x509.Name(
        [x509.NameAttribute(oid=x509.ObjectIdentifier(attr.oid), value=attr.value) for attr in data.subject]
    )
    algorithm = expires = None
    extensions: List[x509.Extension[x509.ExtensionType]] = []

    if ca.key_exists is False:
        raise HttpError(
            HTTPStatus.BAD_REQUEST,
            "This certificate authority can not be used to sign certificates via the API.",
        )

    if data.algorithm is not None:
        algorithm = constants.HASH_ALGORITHM_TYPES[data.algorithm]()
    if data.expires is not None:
        expires = data.expires

    for extension_key, extension_data in data.extensions.dict(exclude_unset=True).items():
        extensions.append(parse_extension(extension_key, extension_data))

    extension_oids = [ext.oid for ext in extensions]
    for oid, extension in ca.extensions_for_certificate.items():
        if oid not in extension_oids:
            extensions.append(extension)

    # Create the signed certificate object
    certificate = ca.sign(
        csr, subject=subject, algorithm=algorithm, expires=expires, extensions=extensions, cn_in_san=False
    )

    # Store certificate in database
    certificate_obj = Certificate(ca=ca, profile=data.profile, autogenerated=data.autogenerated)
    certificate_obj.update_certificate(certificate)
    certificate_obj.save()

    return certificate_obj


@api.get(
    "/ca/{serial:serial}/certs/",
    response=List[CertificateSchema],
    auth=BasicAuth("django_ca.view_certificate"),
    summary="List certificates",
    tags=["Certificates"],
)
def list_certificates(
    request: WSGIRequest, serial: str, filters: CertificateFilterSchema = Query(...)
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

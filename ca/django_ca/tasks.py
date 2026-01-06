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

"""Asynchronous Celery tasks for django-ca.

.. seealso:: https://docs.celeryproject.org/en/stable/index.html
"""

import logging
import typing
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from http import HTTPStatus

import requests

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from django.db import transaction
from django.utils import timezone

from django_ca.acme.validation import validate_dns_01
from django_ca.celery import DjangoCaTask, run_task, shared_task
from django_ca.celery.messages import CacheCrlCeleryMessage, CacheCrlsCeleryMessage
from django_ca.conf import model_settings
from django_ca.constants import EXTENSION_DEFAULT_CRITICAL
from django_ca.models import (
    AcmeAuthorization,
    AcmeCertificate,
    AcmeChallenge,
    AcmeOrder,
    Certificate,
    CertificateAuthority,
    CertificateOrder,
)
from django_ca.profiles import profiles
from django_ca.pydantic.messages import GenerateOCSPKeyMessage, SignCertificateMessage
from django_ca.typehints import (
    JSON,
    SerializedPydanticExtension,
    SerializedPydanticName,
    SignatureHashAlgorithmName,
)
from django_ca.utils import parse_general_name

log = logging.getLogger(__name__)


@shared_task(base=DjangoCaTask)
def cache_crl(data: CacheCrlCeleryMessage) -> None:
    """Task to cache the CRL for a given CA."""
    assert isinstance(data, CacheCrlCeleryMessage)
    ca = CertificateAuthority.objects.get(serial=data.serial)
    key_backend_options_model = ca.key_backend.use_model.model_validate(
        data.key_backend_options, context={"ca": ca, "backend": ca.key_backend}, strict=True
    )
    ca.cache_crls(key_backend_options_model)


@shared_task(base=DjangoCaTask)
def cache_crls(data: CacheCrlsCeleryMessage | None = None) -> None:
    """Task to cache the CRLs for all CAs."""
    if data is None:
        data = CacheCrlsCeleryMessage()
    assert isinstance(data, CacheCrlsCeleryMessage)

    serials = data.serials
    key_backend_options = data.key_backend_options

    if not serials:
        serials = tuple(CertificateAuthority.objects.usable().values_list("serial", flat=True))

    for serial in serials:
        try:
            options = key_backend_options.get(serial, {})
            run_task(cache_crl, CacheCrlCeleryMessage(serial=serial, key_backend_options=options))
        except Exception:  # pylint: disable=broad-exception-caught
            # NOTE: When using Celery, an exception will only be raised here if task.delay() itself raises an
            # exception, e.g. if the connection to the broker fails. Without celery, exceptions in cache_crl()
            # are raised here directly.
            log.exception("Error caching CRL for %s", serial)


@shared_task
def generate_ocsp_key(
    serial: str, key_backend_options: dict[str, JSON] | None = None, force: bool = False
) -> int | None:
    """Task to generate an OCSP key for the CA named by `serial`.

    The `serial` names the certificate authority for which to regenerate the OCSP responder certificate. All
    other arguments are passed on to :py:func:`~django_ca.models.CertificateAuthority.generate_ocsp_key`.

    The task returns the primary key of the generated certificate if it was generated, or ``None`` otherwise.
    """
    if key_backend_options is None:
        key_backend_options = {}

    parameters = GenerateOCSPKeyMessage(serial=serial, force=force)
    ca: CertificateAuthority = CertificateAuthority.objects.get(serial=parameters.serial)
    key_backend_options_model = ca.key_backend.use_model.model_validate(
        key_backend_options, context={"ca": ca, "backend": ca.key_backend}, strict=True
    )

    cert = ca.generate_ocsp_key(key_backend_options=key_backend_options_model, force=parameters.force)
    if cert is not None:
        return cert.pk
    return None


@shared_task
def generate_ocsp_keys(
    serials: Iterable[str] | None = None, key_backend_options: dict[str, dict[str, JSON]] | None = None
) -> None:
    """Task to generate an OCSP keys for all usable CAs."""
    if serials is None:
        serials = []
    if key_backend_options is None:
        key_backend_options = {}

    if not serials:
        serials = typing.cast(
            Iterable[str], CertificateAuthority.objects.usable().values_list("serial", flat=True)
        )

    for serial in serials:
        try:
            run_task(generate_ocsp_key, serial, key_backend_options=key_backend_options.get(serial, {}))
        except Exception:  # pylint: disable=broad-exception-caught
            # NOTE: When using Celery, an exception will only be raised here if task.delay() itself raises an
            # exception, e.g. if the connection to the broker fails. Without celery, exceptions in
            # generate_ocsp_key() are raised here directly.
            log.exception("Error creating OCSP responder key for %s", serial)


@shared_task
@transaction.atomic
def api_sign_certificate(
    order_pk: int,
    csr: str,
    subject: SerializedPydanticName,
    algorithm: SignatureHashAlgorithmName | None = None,
    not_after: str | None = None,
    extensions: list[SerializedPydanticExtension] | None = None,
    profile: str = model_settings.CA_DEFAULT_PROFILE,
    autogenerated: bool = False,
    key_backend_options: dict[str, JSON] | None = None,
) -> int | None:
    """Sign a certificate from the given order with the given parameters."""
    if key_backend_options is None:
        key_backend_options = {}

    order = CertificateOrder.objects.select_related("certificate_authority").get(pk=order_pk)
    ca: CertificateAuthority = order.certificate_authority

    message = SignCertificateMessage(
        key_backend_options=key_backend_options,
        algorithm=algorithm,
        autogenerated=autogenerated,
        csr=csr,
        not_after=not_after,
        extensions=extensions,
        profile=profile,
        subject=subject,
    )

    key_backend_options_model = ca.key_backend.get_use_private_key_options(ca, key_backend_options)

    parsed_extensions = message.get_extensions()

    extension_oids = [ext.oid for ext in parsed_extensions]
    for oid, extension in ca.extensions_for_certificate.items():
        if oid not in extension_oids:
            parsed_extensions.append(extension)

    parsed_csr = message.get_csr()

    # Create a signed certificate
    try:
        certificate = ca.sign(
            key_backend_options_model,
            parsed_csr,
            subject=message.subject.cryptography,  # pylint: disable=no-member  # false positive
            algorithm=message.get_algorithm(),
            not_after=message.not_after,
            extensions=parsed_extensions,
        )
    except Exception:  # pylint: disable=broad-exception-caught  # really want to catch everything
        log.exception("Could not sign certificate")
        order.status = CertificateOrder.STATUS_FAILED
        order.error_code = 1
        order.error = "Could not sign certificate."
        order.save()
        return None

    # Store certificate in database
    certificate_obj = Certificate(
        ca=ca, csr=parsed_csr, profile=message.profile, autogenerated=message.autogenerated
    )
    certificate_obj.update_certificate(certificate)
    certificate_obj.save()

    # Update certificate order
    order.status = CertificateOrder.STATUS_ISSUED
    order.certificate = certificate_obj
    order.save()

    return certificate_obj.pk


@shared_task
@transaction.atomic
def acme_validate_challenge(challenge_pk: int) -> None:
    """Validate an ACME challenge."""
    if not model_settings.CA_ENABLE_ACME:
        log.error("ACME is not enabled.")
        return

    try:
        challenge = AcmeChallenge.objects.url().get(pk=challenge_pk)
    except AcmeChallenge.DoesNotExist:
        log.error("Challenge with id=%s not found", challenge_pk)
        return

    # Whoever is invoking this task is responsible for setting the status to "processing" first.
    if challenge.status != AcmeChallenge.STATUS_PROCESSING:
        log.error(
            "%s: %s: Invalid state (must be %s)", challenge, challenge.status, AcmeChallenge.STATUS_PROCESSING
        )
        return

    # If the auth cannot be used for validation, neither can this challenge. We check auth.usable instead of
    # challenge.usable b/c a challenge in the "processing" state is not "usable" (= it is already being used).
    if challenge.auth.usable is False:
        log.error("%s: Authentication is not usable", challenge)
        return

    # General data for challenge validation
    value = challenge.auth.value

    # Challenge is marked as invalid by default
    challenge_valid = False

    # Validate HTTP challenge (only thing supported so far)
    if challenge.type == AcmeChallenge.TYPE_HTTP_01:
        decoded_token = challenge.encoded_token.decode("utf-8")
        expected = challenge.expected

        if requests is None:  # pragma: no cover
            log.error("requests is not installed, cannot do http-01 challenge validation.")
            return

        url = f"http://{value}/.well-known/acme-challenge/{decoded_token}"

        try:
            with requests.get(url, timeout=1, stream=True) as response:
                # Only fetch the response body if the status code is HTTP 200 (OK)
                if response.status_code == HTTPStatus.OK:
                    # Only fetch the expected number of bytes to prevent a large file ending up in memory
                    # But fetch one extra byte (if available) to make sure that response has no extra bytes
                    received = response.raw.read(len(expected) + 1, decode_content=True)
                    challenge_valid = received == expected
        except Exception as ex:  # pylint: disable=broad-except
            log.exception(ex)
    elif challenge.type == AcmeChallenge.TYPE_DNS_01:
        challenge_valid = validate_dns_01(challenge)
    else:  # pragma: no cover
        log.error("%s: Challenge type is not supported.", challenge)

    # Transition state of the challenge depending on if the challenge is valid or not. RFC8555, Section 7.1.6:
    #
    #   "If validation is successful, the challenge moves to the "valid" state; if there is an error, the
    #   challenge moves to the "invalid" state."
    #
    # We also transition the matching authorization object:
    #
    #   "If one of the challenges listed in the authorization transitions to the "valid" state, then the
    #   authorization also changes to the "valid" state.  If the client attempts to fulfill a challenge and
    #   fails, or if there is an error while the authorization is still pending, then the authorization
    #   transitions to the "invalid" state.
    #
    # We also transition the matching order object (section 7.4):
    #
    #   "* ready: The server agrees that the requirements have been fulfilled, and is awaiting finalization.
    #   Submit a finalization request."
    if challenge_valid:
        challenge.status = AcmeChallenge.STATUS_VALID
        challenge.validated = timezone.now()
        challenge.auth.status = AcmeAuthorization.STATUS_VALID

        # Set the order status to READY if all challenges are valid
        auths = AcmeAuthorization.objects.filter(order=challenge.auth.order)
        auths = auths.exclude(status=AcmeAuthorization.STATUS_VALID)
        if not auths.exclude(pk=challenge.auth.pk).exists():
            log.info("Order is now valid")
            challenge.auth.order.status = AcmeOrder.STATUS_READY
    else:
        challenge.status = AcmeChallenge.STATUS_INVALID

        # RFC 8555, section 7.1.6:
        #
        # If the client attempts to fulfill a challenge and fails, or if there is an error while the
        # authorization is still pending, then the authorization transitions to the "invalid" state.
        challenge.auth.status = AcmeAuthorization.STATUS_INVALID

        # RFC 8555, section 7.1.6:
        #
        #   If an error occurs at any of these stages, the order moves to the "invalid" state.
        challenge.auth.order.status = AcmeOrder.STATUS_INVALID

    log.info("%s is %s", challenge, challenge.status)
    challenge.save()
    challenge.auth.save()
    challenge.auth.order.save()


@shared_task
@transaction.atomic
def acme_issue_certificate(acme_certificate_pk: int) -> None:
    """Actually issue an ACME certificate."""
    if not model_settings.CA_ENABLE_ACME:
        log.error("ACME is not enabled.")
        return

    try:
        acme_cert = AcmeCertificate.objects.select_related("order__account__ca").get(pk=acme_certificate_pk)
    except AcmeCertificate.DoesNotExist:
        log.error("Certificate with id=%s not found", acme_certificate_pk)
        return

    if acme_cert.usable is False:
        log.error("%s: Cannot issue certificate for this order", acme_cert.order)
        return

    names = [a.subject_alternative_name for a in acme_cert.order.authorizations.all()]
    log.info("%s: Issuing certificate for %s", acme_cert.order, ",".join(names))
    subject_alternative_names = x509.SubjectAlternativeName([parse_general_name(name) for name in names])

    extensions = [
        x509.Extension(
            oid=ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
            critical=EXTENSION_DEFAULT_CRITICAL[ExtensionOID.SUBJECT_ALTERNATIVE_NAME],
            value=subject_alternative_names,
        )
    ]

    ca = acme_cert.order.account.ca
    profile = profiles[ca.acme_profile]

    # Honor not_after from the order if set
    if acme_cert.order.not_after:
        not_after = acme_cert.order.not_after

        # Make sure not_after is tz-aware, even if USE_TZ=False.
        if timezone.is_naive(not_after):
            not_after = timezone.make_aware(not_after)
    else:
        not_after = datetime.now(tz=UTC) + model_settings.CA_ACME_DEFAULT_CERT_VALIDITY

    csr = acme_cert.parse_csr()

    # Initialize key backend options
    key_backend_options = ca.key_backend.get_use_private_key_options(ca, {})

    # Finally, actually create a certificate
    cert = Certificate.objects.create_cert(
        ca, key_backend_options, csr=csr, profile=profile, not_after=not_after, extensions=extensions
    )

    acme_cert.cert = cert
    acme_cert.order.status = AcmeOrder.STATUS_VALID
    acme_cert.order.save()
    acme_cert.save()


@shared_task
@transaction.atomic
def acme_cleanup() -> None:
    """Cleanup expired ACME orders."""
    if not model_settings.CA_ENABLE_ACME:
        # NOTE: Since this task does only cleanup, log message is only info.
        log.info("ACME is not enabled, not doing anything.")
        return

    # Delete orders that expired more than a day ago.
    threshold = timezone.now() - timedelta(days=1)
    AcmeOrder.objects.filter(expires__lt=threshold).delete()

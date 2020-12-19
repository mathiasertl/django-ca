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
# see <http://www.gnu.org/licenses/>.

"""Asynchronous Celery tasks for django-ca.

.. seealso:: https://docs.celeryproject.org/en/stable/index.html
"""

import logging
from datetime import timedelta
from http import HTTPStatus

from django.db import transaction
from django.utils import timezone

from . import ca_settings
from .extensions import SubjectAlternativeName
from .models import AcmeAuthorization
from .models import AcmeCertificate
from .models import AcmeChallenge
from .models import AcmeOrder
from .models import Certificate
from .models import CertificateAuthority
from .profiles import profiles

log = logging.getLogger(__name__)

try:
    from celery import shared_task
except ImportError:
    def shared_task(func):
        """Dummy decorator so that we can use the decorator whether celery is installed or not."""

        # We do not yet need this, but might come in handy in the future:
        #func.delay = lambda *a, **kw: func(*a, **kw)
        #func.apply_async = lambda *a, **kw: func(*a, **kw)
        return func

# requests and josepy are optional dependencies for acme tasks
try:
    import josepy as jose
    import requests
except ImportError:  # pragma: no cover
    jose = requests = None


def run_task(task, *args, **kwargs):
    """Function that passes `task` to celery or invokes it directly, depending on if Celery is installed."""
    eager = kwargs.pop('eager', False)

    if ca_settings.CA_USE_CELERY is True and eager is False:
        return task.delay(*args, **kwargs)

    return task(*args, **kwargs)


@shared_task
def cache_crl(serial, **kwargs):
    """Task to cache the CRL for a given CA."""
    ca = CertificateAuthority.objects.get(serial=serial)
    ca.cache_crls(**kwargs)


@shared_task
def cache_crls(serials=None):
    """Task to cache the CRLs for all CAs."""
    if not serials:
        serials = CertificateAuthority.objects.usable().values_list('serial', flat=True)

    for serial in serials:
        run_task(cache_crl, serial)


@shared_task
def generate_ocsp_key(serial, **kwargs):
    """Task to generate an OCSP key for the CA named by `serial`."""
    ca = CertificateAuthority.objects.get(serial=serial)
    private_path, cert_path, cert = ca.generate_ocsp_key(**kwargs)
    return private_path, cert_path, cert.pk


@shared_task
def generate_ocsp_keys(**kwargs):
    """Task to generate an OCSP keys for all usable CAs."""
    keys = []
    for serial in CertificateAuthority.objects.usable().values_list('serial', flat=True):
        keys.append(generate_ocsp_key(serial, **kwargs))
    return keys


@shared_task
@transaction.atomic
def acme_validate_challenge(challenge_pk):
    """Validate an ACME challenge."""
    if not ca_settings.CA_ENABLE_ACME:
        log.error('ACME is not enabled.')
        return

    if jose is None:  # pragma: no cover
        log.error('josepy is not installed, cannot do challenge validation.')
        return

    try:
        challenge = AcmeChallenge.objects.url().get(pk=challenge_pk)
    except AcmeChallenge.DoesNotExist:
        log.error('Challenge with id=%s not found', challenge_pk)
        return

    # Whoever is invoking this task is responsible for setting the status to "processing" first.
    if challenge.status != AcmeChallenge.STATUS_PROCESSING:
        log.error('%s: %s: Invalid state (must be %s)', challenge, challenge.status,
                  AcmeChallenge.STATUS_PROCESSING)
        return

    # If the auth cannot be used for validation, neither can this challenge. We check auth.usable instead of
    # challenge.usable b/c a challenge in the "processing" state is not "usable" (= it is already being used).
    if challenge.auth.usable is False:
        log.error('%s: Authentication is not usable', challenge)
        return

    # General data for challenge validation
    token = challenge.token
    value = challenge.auth.value
    encoded = jose.encode_b64jose(token.encode('utf-8'))
    thumbprint = challenge.auth.order.account.thumbprint
    expected = f'{encoded}.{thumbprint}'

    if challenge.type == AcmeChallenge.TYPE_HTTP_01:
        if requests is None:  # pragma: no cover
            log.error('requests is not installed, cannot do http-01 challenge validation.')
            return

        url = f'http://{value}/.well-known/acme-challenge/{encoded}'

        # Validate HTTP challenge (only thing supported so far)
        try:
            response = requests.get(url, timeout=1)

            if response.status_code == HTTPStatus.OK:
                received = response.text
            else:
                received = False
        except Exception as ex:  # pylint: disable=broad-except
            log.exception(ex)
            received = False
    else:
        log.error("%s: Only HTTP-01 challenges supported so far", challenge)
        received = False

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
    if received == expected:
        challenge.status = AcmeChallenge.STATUS_VALID
        challenge.validated = timezone.now()
        challenge.auth.status = AcmeAuthorization.STATUS_VALID

        # Set the order status to READY if all challenges are valid
        auths = AcmeAuthorization.objects.filter(order=challenge.auth.order)
        auths = auths.exclude(status=AcmeAuthorization.STATUS_VALID)
        if not auths.exclude(pk=challenge.auth.pk).exists():
            log.info('Order is now valid')
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

    log.info('Challenge %s is %s', challenge.pk, challenge.status)
    challenge.save()
    challenge.auth.save()
    challenge.auth.order.save()


@shared_task
@transaction.atomic
def acme_issue_certificate(acme_certificate_pk):
    """Actually issue an ACME certificate."""
    if not ca_settings.CA_ENABLE_ACME:
        log.error('ACME is not enabled.')
        return

    try:
        acme_cert = AcmeCertificate.objects.select_related('order__account__ca').get(pk=acme_certificate_pk)
    except AcmeCertificate.DoesNotExist:
        log.error('Certificate with id=%s not found', acme_certificate_pk)
        return

    if acme_cert.usable is False:
        log.error('%s: Cannot issue certificate for this order', acme_cert.order)
        return

    subject_alternative_names = [a.subject_alternative_name for a in acme_cert.order.authorizations.all()]
    log.info('%s: Issuing certificate for %s', acme_cert.order, ',' .join(subject_alternative_names))

    extensions = {
        SubjectAlternativeName.key: SubjectAlternativeName({'value': subject_alternative_names})
    }

    profile = profiles['server']

    # Honor not_after from the order if set
    if acme_cert.order.not_after:
        expires = acme_cert.order.not_after
    else:
        expires = timezone.now() + ca_settings.ACME_DEFAULT_CERT_VALIDITY

    csr = acme_cert.parse_csr()

    # Finally, actually create a certificate
    cert = Certificate.objects.create_cert(
        acme_cert.order.account.ca, csr=csr, profile=profile, expires=expires, extensions=extensions)

    acme_cert.cert = cert
    acme_cert.order.status = AcmeOrder.STATUS_VALID
    acme_cert.order.save()
    acme_cert.save()


@shared_task
@transaction.atomic
def acme_cleanup():
    """Cleanup expired ACME orders."""

    if not ca_settings.CA_ENABLE_ACME:
        # NOTE: Since this task does only cleanup, log message is only info.
        log.info('ACME is not enabled, not doing anything.')
        return

    # Delete orders that expired more then a day ago.
    threshold = timezone.now() - timedelta(days=1)
    AcmeOrder.objects.filter(expires__lt=threshold).delete()

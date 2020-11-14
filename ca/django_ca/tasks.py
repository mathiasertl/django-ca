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

import logging
from datetime import timedelta

import josepy as jose
import requests

from django.db import transaction
from django.utils import timezone

from . import ca_settings
from .extensions import SubjectAlternativeName
from .models import AcmeAccountAuthorization
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
        # Dummy decorator so that we can use the decorator wether celery is installed or not

        # We do not yet need this, but might come in handy in the future:
        #func.delay = lambda *a, **kw: func(*a, **kw)
        #func.apply_async = lambda *a, **kw: func(*a, **kw)
        return func


def run_task(task, *args, **kwargs):
    eager = kwargs.pop('eager', False)

    if ca_settings.CA_USE_CELERY is True and eager is False:
        return task.delay(*args, **kwargs)
    else:
        return task(*args, **kwargs)


@shared_task
def cache_crl(serial, **kwargs):
    ca = CertificateAuthority.objects.get(serial=serial)
    ca.cache_crls(**kwargs)


@shared_task
def cache_crls(serials=None):
    if not serials:
        serials = CertificateAuthority.objects.usable().values_list('serial', flat=True)

    for serial in serials:
        run_task(cache_crl, serial)


@shared_task
def generate_ocsp_key(serial, **kwargs):
    ca = CertificateAuthority.objects.get(serial=serial)
    private_path, cert_path, cert = ca.generate_ocsp_key(**kwargs)
    return private_path, cert_path, cert.pk


@shared_task
def generate_ocsp_keys(**kwargs):
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

    challenge = AcmeChallenge.objects.get(pk=challenge_pk)

    # Set the status to "processing", to quote RFC8555, Section 7.1.6:
    # "They transition to the "processing" state when the client responds to the challenge"
    challenge.status = AcmeChallenge.STATUS_PROCESSING
    challenge.save()

    token = challenge.token
    value = challenge.auth.value
    encoded = jose.encode_b64jose(token.encode('utf-8'))
    thumbprint = challenge.auth.order.account.thumbprint
    url = f'http://{value}/.well-known/acme-challenge/{encoded}'
    expected = f'{encoded}.{thumbprint}'

    # Validate HTTP challenge (only thing supported so far)
    response = requests.get(url)

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
    if response.text == expected:
        challenge.status = AcmeChallenge.STATUS_VALID
        challenge.validated = timezone.now()
        challenge.auth.status = AcmeAccountAuthorization.STATUS_VALID

        # Set the order status to READY if all challenges are valid
        auths = AcmeAccountAuthorization.objects.filter(order=challenge.auth.order)
        auths = auths.exclude(status=AcmeAccountAuthorization.STATUS_VALID)
        if not auths.exclude(pk=challenge.auth.pk).exists():
            log.info('Order is now valid.')
            challenge.auth.order.status = AcmeOrder.STATUS_READY
    else:
        challenge.status = AcmeChallenge.STATUS_INVALID
        challenge.auth.status = AcmeAccountAuthorization.STATUS_INVALID
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

    log.info('#1 %s', AcmeCertificate.objects.get(pk=acme_certificate_pk))
    log.info('#2 %s', AcmeCertificate.objects.get(pk=acme_certificate_pk).order.status)

    qs = AcmeCertificate.objects.filter(order__status=AcmeOrder.STATUS_PROCESSING).select_related('order')
    acme_cert = qs.get(pk=acme_certificate_pk)
    log.info('Issuing acme_cert: %s', acme_cert)
    subject_alternative_names = [a.subject_alternative_name for a in acme_cert.order.authorizations.all()]
    log.info('SAN: %s', subject_alternative_names)

    extensions = {
        SubjectAlternativeName.key: SubjectAlternativeName({'value': subject_alternative_names})
    }

    ca = CertificateAuthority.objects.first()  # TODO: properly select CA

    profile = profiles['server']
    expires = timezone.now() + timedelta(days=90)
    csr = acme_cert.parse_csr()

    cert = Certificate.objects.create_cert(ca, csr=csr, profile=profile, expires=expires,
                                           extensions=extensions)
    acme_cert.cert = cert
    acme_cert.order.status = AcmeOrder.STATUS_VALID
    acme_cert.save()

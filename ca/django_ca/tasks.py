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

from . import ca_settings
from .models import CertificateAuthority

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

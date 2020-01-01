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
        func.delay = lambda *a, **kw: func(*a, **kw)
        func.apply_async = lambda *a, **kw: func(*a, **kw)
        return func


def run_task(name, *args, **kwargs):
    eager = kwargs.pop('eager', False)
    func = globals()[name]

    if ca_settings.CA_USE_CELERY is True and eager is False:
        return func.delay(*args, **kwargs)
    else:
        return func(*args, **kwargs)


@shared_task
def cache_crl(serial):
    ca = CertificateAuthority.objects.get(serial=serial)
    ca.cache_crls()


@shared_task
def cache_crls():
    for serial in CertificateAuthority.objects.usable().values_list('serial', flat=True):
        cache_crl.delay(serial)


@shared_task
def generate_ocsp_key(serial, **kwargs):
    ca = CertificateAuthority.objects.get(serial=serial)
    ca.generate_ocsp_key(**kwargs)


@shared_task
def generate_ocsp_keys(**kwargs):
    for serial in CertificateAuthority.objects.usable().values_list('serial', flat=True):
        generate_ocsp_key.delay(serial, **kwargs)

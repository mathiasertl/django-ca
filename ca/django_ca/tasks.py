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


def run_task(name, *args, **kwargs):
    eager = kwargs.pop('eager', False)
    func = globals()[name]

    if ca_settings.CA_USE_CELERY is True and eager is False:
        return func.delay(*args, **kwargs)
    else:
        return func(*args, **kwargs)


def cache_crl(serial):
    ca = CertificateAuthority.objects.get(serial=serial)
    ca.cache_crls()


def cache_crls():
    for serial in CertificateAuthority.objects.usable().values_list('serial', flat=True):
        run_task('cache_crl', serial)


try:
    from celery import shared_task
except ImportError:
    pass
else:
    cache_crl = shared_task(cache_crl)
    cache_crls = shared_task(cache_crls)

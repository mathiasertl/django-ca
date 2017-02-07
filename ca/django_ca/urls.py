# -*- coding: utf-8 -*-
#
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

from django.conf import settings
from django.conf.urls import url

from . import ca_settings
from . import views

app_name = 'django_ca'
urlpatterns = []


CA_OCSP_URLS = getattr(settings, 'CA_OCSP_URLS', {})

if ca_settings.CA_PROVIDE_GENERIC_CRL is True:  # pragma: no branch
    urlpatterns.append(
        url(r'^crl/(?P<serial>[0-9A-F:]+)/$', views.CertificateRevocationListView.as_view(),
            name='crl'))

for name, kwargs in CA_OCSP_URLS.items():
    urlpatterns += [
        url(r'ocsp/%s/$' % name, views.OCSPView.as_view(**kwargs),
            name='ocsp-post-%s' % name),
        url(r'ocsp/%s/(?P<data>[a-zA-Z0-9=+/]+)$' % name, views.OCSPView.as_view(**kwargs),
            name='ocsp-get-%s' % name)
    ]

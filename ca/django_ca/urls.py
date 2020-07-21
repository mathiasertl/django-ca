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
from django.urls import path
from django.urls import register_converter

from . import converters
from . import views

app_name = 'django_ca'

register_converter(converters.HexConverter, 'hex')
register_converter(converters.Base64Converter, 'base64')

urlpatterns = [
    path('issuer/<hex:serial>.der', views.GenericCAIssuersView.as_view(), name='issuer'),
    path('ocsp/<hex:serial>/cert/', views.GenericOCSPView.as_view(expires=3600), name='ocsp-cert-post'),
    path('ocsp/<hex:serial>/cert/<base64:data>', views.GenericOCSPView.as_view(expires=3600),
         name='ocsp-cert-get'),
    path('ocsp/<hex:serial>/ca/', views.GenericOCSPView.as_view(ca_ocsp=True, expires=86400),
         name='ocsp-ca-post'),
    path('ocsp/<hex:serial>/ca/<base64:data>', views.GenericOCSPView.as_view(ca_ocsp=True, expires=86400),
         name='ocsp-ca-get'),
    path('crl/<hex:serial>/', views.CertificateRevocationListView.as_view(), name='crl'),
    path('crl/ca/<hex:serial>/', views.CertificateRevocationListView.as_view(scope='ca'), name='ca-crl'),
]


for name, kwargs in getattr(settings, 'CA_OCSP_URLS', {}).items():
    kwargs.setdefault('ca', name)
    urlpatterns += [
        path('ocsp/%s/' % name, views.OCSPView.as_view(**kwargs), name='ocsp-post-%s' % name),
        path('ocsp/%s/<base64:data>' % name, views.OCSPView.as_view(**kwargs), name='ocsp-get-%s' % name)
    ]

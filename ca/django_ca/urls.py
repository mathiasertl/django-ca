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

"""URL configuration for this project."""

from django.conf import settings
from django.urls import path
from django.urls import register_converter

from . import ca_settings
from . import converters
from . import views

app_name = 'django_ca'

register_converter(converters.HexConverter, 'hex')
register_converter(converters.Base64Converter, 'base64')
register_converter(converters.AcmeSlugConverter, 'acme')

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


if ca_settings.CA_ENABLE_ACME:
    urlpatterns += [
        path('acme/directory/', views.AcmeDirectory.as_view(), name='acme-directory'),
        path('acme/directory/<hex:serial>/', views.AcmeDirectory.as_view(), name='acme-directory'),
        path('acme/<hex:serial>/new-nonce/', views.AcmeNewNonce.as_view(), name='acme-new-nonce'),
        path('acme/<hex:serial>/new-account/', views.AcmeNewAccount.as_view(), name='acme-new-account'),
        path('acme/<hex:serial>/new-order/', views.AcmeNewOrderView.as_view(), name='acme-new-order'),
        path('acme/<hex:serial>/acct/<int:pk>/', views.AcmeAccountView.as_view(), name='acme-account'),
        path('acme/<hex:serial>/acct/<int:pk>/orders/', views.AcmeAccountOrdersView.as_view(),
             name='acme-account-orders'),
        path('acme/<hex:serial>/order/<acme:slug>/', views.AcmeOrderView.as_view(), name='acme-order'),
        path('acme/<hex:serial>/order/<acme:slug>/finalize/', views.AcmeOrderFinalizeView.as_view(),
             name='acme-order-finalize'),
        path('acme/<hex:serial>/authz/<acme:slug>/', views.AcmeAuthorizationView.as_view(),
             name='acme-authz'),
        path('acme/<hex:serial>/chall/<acme:slug>/', views.AcmeChallengeView.as_view(),
             name='acme-challenge'),
        path('acme/<hex:serial>/cert/<acme:slug>/', views.AcmeCertificateView.as_view(),
             name='acme-cert'),
    ]


for name, kwargs in getattr(settings, 'CA_OCSP_URLS', {}).items():
    kwargs.setdefault('ca', name)
    urlpatterns += [
        path('ocsp/%s/' % name, views.OCSPView.as_view(**kwargs), name='ocsp-post-%s' % name),
        path('ocsp/%s/<base64:data>' % name, views.OCSPView.as_view(**kwargs), name='ocsp-get-%s' % name)
    ]

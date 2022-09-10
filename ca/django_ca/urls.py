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
from django.urls import path, register_converter

from . import ca_settings, converters, views

app_name = "django_ca"

register_converter(converters.AcmeSlugConverter, "acme")
register_converter(converters.Base64Converter, "base64")
register_converter(converters.HexConverter, "hex")
register_converter(converters.SerialConverter, "serial")

urlpatterns = [
    path("issuer/<hex:serial>.der", views.GenericCAIssuersView.as_view(), name="issuer"),
    path("ocsp/<hex:serial>/cert/", views.GenericOCSPView.as_view(expires=3600), name="ocsp-cert-post"),
    path(
        "ocsp/<hex:serial>/cert/<base64:data>",
        views.GenericOCSPView.as_view(expires=3600),
        name="ocsp-cert-get",
    ),
    path(
        "ocsp/<hex:serial>/ca/",
        views.GenericOCSPView.as_view(ca_ocsp=True, expires=86400),
        name="ocsp-ca-post",
    ),
    path(
        "ocsp/<hex:serial>/ca/<base64:data>",
        views.GenericOCSPView.as_view(ca_ocsp=True, expires=86400),
        name="ocsp-ca-get",
    ),
    path("crl/<hex:serial>/", views.CertificateRevocationListView.as_view(), name="crl"),
    path("crl/ca/<hex:serial>/", views.CertificateRevocationListView.as_view(scope="ca"), name="ca-crl"),
]


if ca_settings.CA_ENABLE_ACME:
    from .acme import views as acme_views

    # NOTE: Some functions depend on the fact that ALL ACME urls have a "serial" kwarg
    urlpatterns += [
        path("acme/directory/", acme_views.AcmeDirectory.as_view(), name="acme-directory"),
        path("acme/directory/<serial:serial>/", acme_views.AcmeDirectory.as_view(), name="acme-directory"),
        path("acme/<serial:serial>/new-nonce/", acme_views.AcmeNewNonceView.as_view(), name="acme-new-nonce"),
        path(
            "acme/<serial:serial>/new-account/",
            acme_views.AcmeNewAccountView.as_view(),
            name="acme-new-account",
        ),
        path("acme/<serial:serial>/new-order/", acme_views.AcmeNewOrderView.as_view(), name="acme-new-order"),
        path(
            "acme/<serial:serial>/acct/<acme:slug>/",
            acme_views.AcmeAccountView.as_view(),
            name="acme-account",
        ),
        path(
            "acme/<serial:serial>/acct/<acme:slug>/orders/",
            acme_views.AcmeAccountOrdersView.as_view(),
            name="acme-account-orders",
        ),
        path(
            "acme/<serial:serial>/order/<acme:slug>/", acme_views.AcmeOrderView.as_view(), name="acme-order"
        ),
        path(
            "acme/<serial:serial>/order/<acme:slug>/finalize/",
            acme_views.AcmeOrderFinalizeView.as_view(),
            name="acme-order-finalize",
        ),
        path(
            "acme/<serial:serial>/authz/<acme:slug>/",
            acme_views.AcmeAuthorizationView.as_view(),
            name="acme-authz",
        ),
        path(
            "acme/<serial:serial>/chall/<acme:slug>/",
            acme_views.AcmeChallengeView.as_view(),
            name="acme-challenge",
        ),
        path(
            "acme/<serial:serial>/cert/<acme:slug>/",
            acme_views.AcmeCertificateView.as_view(),
            name="acme-cert",
        ),
        path(
            "acme/<serial:serial>/revoke/",
            acme_views.AcmeCertificateRevocationView.as_view(),
            name="acme-revoke",
        ),
    ]


for name, kwargs in getattr(settings, "CA_OCSP_URLS", {}).items():
    kwargs.setdefault("ca", name)
    urlpatterns += [
        path(f"ocsp/{name}/", views.OCSPView.as_view(**kwargs), name=f"ocsp-post-{name}"),
        path(f"ocsp/{name}/<base64:data>", views.OCSPView.as_view(**kwargs), name=f"ocsp-get-{name}"),
    ]

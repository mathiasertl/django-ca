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

"""URL configuration for this project."""

from django.conf import settings
from django.urls import URLPattern, URLResolver, path, register_converter

from django_ca import converters, views
from django_ca.conf import model_settings

app_name = "django_ca"

register_converter(converters.AcmeSlugConverter, "django-ca-acme-slug")
register_converter(converters.Base64Converter, "django-ca-base64")
register_converter(converters.HexConverter, "django-ca-hex")
register_converter(converters.SerialConverter, "django-ca-serial")

urlpatterns: list[URLResolver | URLPattern] = [
    path("issuer/<django-ca-hex:serial>.der", views.GenericCAIssuersView.as_view(), name="issuer"),
    path("ocsp/<django-ca-hex:serial>/cert/", views.GenericOCSPView.as_view(), name="ocsp-cert-post"),
    path(
        "ocsp/<django-ca-hex:serial>/cert/<django-ca-base64:data>",
        views.GenericOCSPView.as_view(),
        name="ocsp-cert-get",
    ),
    path("ocsp/<django-ca-hex:serial>/ca/", views.GenericOCSPView.as_view(ca_ocsp=True), name="ocsp-ca-post"),
    path(
        "ocsp/<django-ca-hex:serial>/ca/<django-ca-base64:data>",
        views.GenericOCSPView.as_view(ca_ocsp=True),
        name="ocsp-ca-get",
    ),
    path(
        "crl/<django-ca-hex:serial>/",
        views.CertificateRevocationListView.as_view(only_contains_user_certs=True),
        name="crl",
    ),
    path(
        "crl/ca/<django-ca-hex:serial>/",
        views.CertificateRevocationListView.as_view(only_contains_ca_certs=True),
        name="ca-crl",
    ),
]

if model_settings.CA_ENABLE_REST_API is True:  # pragma: no branch
    from django_ca.api.endpoints import api

    urlpatterns.append(path("api/", api.urls))


if model_settings.CA_ENABLE_ACME:  # pragma: no branch
    from django_ca.acme import views as acme_views

    # NOTE: Some functions depend on the fact that ALL ACME urls have a "serial" kwarg
    urlpatterns += [
        path("acme/directory/", acme_views.AcmeDirectory.as_view(), name="acme-directory"),
        path(
            "acme/directory/<django-ca-serial:serial>/",
            acme_views.AcmeDirectory.as_view(),
            name="acme-directory",
        ),
        path(
            "acme/<django-ca-serial:serial>/new-nonce/",
            acme_views.AcmeNewNonceView.as_view(),
            name="acme-new-nonce",
        ),
        path(
            "acme/<django-ca-serial:serial>/new-account/",
            acme_views.AcmeNewAccountView.as_view(),
            name="acme-new-account",
        ),
        path(
            "acme/<django-ca-serial:serial>/new-order/",
            acme_views.AcmeNewOrderView.as_view(),
            name="acme-new-order",
        ),
        path(
            "acme/<django-ca-serial:serial>/acct/<django-ca-acme-slug:slug>/",
            acme_views.AcmeAccountView.as_view(),
            name="acme-account",
        ),
        path(
            "acme/<django-ca-serial:serial>/acct/<django-ca-acme-slug:slug>/orders/",
            acme_views.AcmeAccountOrdersView.as_view(),
            name="acme-account-orders",
        ),
        path(
            "acme/<django-ca-serial:serial>/order/<django-ca-acme-slug:slug>/",
            acme_views.AcmeOrderView.as_view(),
            name="acme-order",
        ),
        path(
            "acme/<django-ca-serial:serial>/order/<django-ca-acme-slug:slug>/finalize/",
            acme_views.AcmeOrderFinalizeView.as_view(),
            name="acme-order-finalize",
        ),
        path(
            "acme/<django-ca-serial:serial>/authz/<django-ca-acme-slug:slug>/",
            acme_views.AcmeAuthorizationView.as_view(),
            name="acme-authz",
        ),
        path(
            "acme/<django-ca-serial:serial>/chall/<django-ca-acme-slug:slug>/",
            acme_views.AcmeChallengeView.as_view(),
            name="acme-challenge",
        ),
        path(
            "acme/<django-ca-serial:serial>/cert/<django-ca-acme-slug:slug>/",
            acme_views.AcmeCertificateView.as_view(),
            name="acme-cert",
        ),
        path(
            "acme/<django-ca-serial:serial>/revoke/",
            acme_views.AcmeCertificateRevocationView.as_view(),
            name="acme-revoke",
        ),
    ]


for name, kwargs in getattr(settings, "CA_OCSP_URLS", {}).items():
    kwargs.setdefault("ca", name)
    urlpatterns += [
        path(f"ocsp/{name}/", views.OCSPView.as_view(**kwargs), name=f"ocsp-post-{name}"),
        path(
            f"ocsp/{name}/<django-ca-base64:data>", views.OCSPView.as_view(**kwargs), name=f"ocsp-get-{name}"
        ),
    ]

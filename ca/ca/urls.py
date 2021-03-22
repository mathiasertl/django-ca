from django.contrib import admin
from django.urls import include
from django.urls import path

admin.autodiscover()

urlpatterns = [
    # Examples:
    # url(r'^$', 'ca.views.home', name='home'),
    path("django_ca/", include("django_ca.urls")),
    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),
    # Uncomment the next line to enable the admin:
    path("admin/", admin.site.urls),
]

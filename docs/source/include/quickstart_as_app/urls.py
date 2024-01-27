from django.urls import include, path

urlpatterns = [
    path("ca/", include("django_ca.urls")),
    # other URLs...
]

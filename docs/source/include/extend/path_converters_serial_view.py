from django.http import HttpRequest, HttpResponse
from django.views.generic.base import View

from django_ca.models import CertificateAuthority


class MyView(View):
    def get(self, request: HttpRequest, serial: str) -> HttpResponse:
        ca = CertificateAuthority.objects.get(serial=serial)
        return HttpResponse(ca.name)

from django.contrib.auth.models import User
from django.db import models

from OpenSSL import crypto

from certificate.managers import CertificateManager


class Certificate(models.Model):
    _x509 = None

    objects = CertificateManager()

    watchers = models.ManyToManyField(User)

    created = models.DateTimeField(auto_now=True)
    expires = models.DateTimeField(null=False, blank=False)

    csr = models.TextField(null=False, blank=False)
    pub = models.TextField(null=False, blank=False)

    cn = models.CharField(max_length=64, null=False, blank=False)

    @property
    def x509(self):
        if self._x509 is None:
            self._x509 = crypto.load_certificate(crypto.FILETYPE_PEM, self.pub)
        return self._x509

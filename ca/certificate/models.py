from django.db import models

from certificate.managers import CertificateManager

class Certificate(models.Model):
    objects = CertificateManager()

    created = models.DateTimeField(auto_now=True)
    expires = models.DateTimeField(null=False, blank=False)

    csr = models.TextField(null=False, blank=False)
    pub = models.TextField(null=False, blank=False)

    cn = models.CharField(max_length=64, null=False, blank=False)

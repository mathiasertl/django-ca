# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations

from OpenSSL import crypto

def compute_serial(apps, schema_editor):
    Certificate = apps.get_model('certificate', 'Certificate')
    for cert in Certificate.objects.filter(serial='missing'):
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert.pub)
        cert.serial = hex(x509.get_serial_number())[2:-1].upper()
        cert.save()


class Migration(migrations.Migration):

    dependencies = [
        ('certificate', '0002_auto_20150207_1459'),
    ]

    operations = [
        migrations.RunPython(compute_serial),
    ]

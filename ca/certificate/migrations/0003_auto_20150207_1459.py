# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations


def compute_serial(apps, schema_editor):
    Certificate = apps.get_model('certificate', 'Certificate')
    for cert in Certificate.objects.filter(serial='missing'):
        cert.serial = hex(cert.x509.get_serial_number())
        cert.save()


class Migration(migrations.Migration):

    dependencies = [
        ('certificate', '0002_auto_20150207_1459'),
    ]

    operations = [
        migrations.RunPython(compute_serial),
    ]

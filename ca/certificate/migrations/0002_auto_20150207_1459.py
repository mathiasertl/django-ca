# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('certificate', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='certificate',
            name='revoked',
            field=models.BooleanField(default=False),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='certificate',
            name='serial',
            field=models.CharField(default='missing', max_length=35),
            preserve_default=False,
        ),
    ]

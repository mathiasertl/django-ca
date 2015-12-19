# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('certificate', '0003_auto_20150207_1459'),
    ]

    operations = [
        migrations.AddField(
            model_name='certificate',
            name='revoked_reason',
            field=models.CharField(default='unspecified', max_length=32),
            preserve_default=True,
        ),
    ]

# Generated by Django 5.0.1 on 2024-01-20 10:26

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('django_ca', '0040_auto_20240120_0931'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='certificateauthority',
            name='crl_url',
        ),
        migrations.RemoveField(
            model_name='certificateauthority',
            name='issuer_alt_name',
        ),
        migrations.RemoveField(
            model_name='certificateauthority',
            name='issuer_url',
        ),
        migrations.RemoveField(
            model_name='certificateauthority',
            name='ocsp_url',
        ),
    ]

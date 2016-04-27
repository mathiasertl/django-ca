# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import django_ca.utils


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Certificate',
            fields=[
                ('id', models.AutoField(serialize=False, primary_key=True, auto_created=True, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now=True)),
                ('expires', models.DateTimeField()),
                ('pub', models.TextField(verbose_name='Public key')),
                ('cn', models.CharField(max_length=64, verbose_name='CommonName')),
                ('serial', models.CharField(unique=True, max_length=48)),
                ('csr', models.TextField(verbose_name='CSR')),
                ('revoked', models.BooleanField(default=False)),
                ('revoked_date', models.DateTimeField(null=True, blank=True, verbose_name='Revoked on')),
                ('revoked_reason', models.CharField(null=True, choices=[('', 'No reason'), ('unspecified', 'Unspecified'), ('keyCompromise', 'Key compromised'), ('CACompromise', 'CA compromised'), ('affiliationChanged', 'Affiliation changed'), ('superseded', 'Superseded'), ('cessationOfOperation', 'Cessation of operation'), ('certificateHold', 'On Hold')], blank=True, max_length=32, verbose_name='Reason for revokation')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='CertificateAuthority',
            fields=[
                ('id', models.AutoField(serialize=False, primary_key=True, auto_created=True, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now=True)),
                ('expires', models.DateTimeField()),
                ('pub', models.TextField(verbose_name='Public key')),
                ('cn', models.CharField(max_length=64, verbose_name='CommonName')),
                ('serial', models.CharField(unique=True, max_length=48)),
                ('name', models.CharField(unique=True, help_text='A human-readable name', max_length=32)),
                ('enabled', models.BooleanField(default=True)),
                ('private_key_path', models.CharField(help_text='Path to the private key.', max_length=256)),
                ('crl_url', models.TextField(null=True, help_text='URLs, one per line, where you can retrieve the CRL.', blank=True, validators=[django_ca.utils.multiline_url_validator], verbose_name='CRL URLs')),
                ('issuer_url', models.URLField(null=True, help_text='URL to the certificate of this CA (in DER format).', blank=True, verbose_name='Issuer URL')),
                ('ocsp_url', models.URLField(null=True, help_text='URL of a OCSP responser for the CA.', blank=True, verbose_name='OCSP responder URL')),
                ('issuer_alt_name', models.URLField(null=True, help_text='URL for your CA.', blank=True, verbose_name='issuerAltName')),
                ('parent', models.ForeignKey(related_name='children', to='django_ca.CertificateAuthority', blank=True, null=True)),
            ],
            options={
                'verbose_name_plural': 'Certificate Authorities',
                'verbose_name': 'Certificate Authority',
            },
        ),
        migrations.CreateModel(
            name='Watcher',
            fields=[
                ('id', models.AutoField(serialize=False, primary_key=True, auto_created=True, verbose_name='ID')),
                ('name', models.CharField(null=True, blank=True, max_length=64, verbose_name='CommonName')),
                ('mail', models.EmailField(unique=True, max_length=254, verbose_name='E-Mail')),
            ],
        ),
        migrations.AddField(
            model_name='certificate',
            name='ca',
            field=models.ForeignKey(to='django_ca.CertificateAuthority', verbose_name='Certificate Authority'),
        ),
        migrations.AddField(
            model_name='certificate',
            name='watchers',
            field=models.ManyToManyField(related_name='certificates', to='django_ca.Watcher', blank=True),
        ),
    ]

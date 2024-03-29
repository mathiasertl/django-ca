# Generated by Django 3.1.4 on 2020-12-13 20:14

import django.core.validators
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import django_ca.models


class Migration(migrations.Migration):

    dependencies = [
        ('django_ca', '0019_certificate_autogenerated'),
    ]

    operations = [
        migrations.CreateModel(
            name='AcmeAccount',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('pem', models.TextField(unique=True, validators=[django_ca.models.pem_validator], verbose_name='Public key')),
                ('thumbprint', models.CharField(max_length=64)),
                ('slug', models.SlugField(default=django_ca.models.acme_slug, unique=True)),
                ('kid', models.URLField(unique=True, validators=[django.core.validators.URLValidator(schemes=('http', 'https'))], verbose_name='Key ID')),
                ('status', models.CharField(choices=[('valid', 'Valid'), ('deactivated', 'Deactivated'), ('revoked', 'Revoked')], default='valid', max_length=12)),
                ('contact', models.TextField(blank=True, help_text='Contact addresses for this account, one per line.')),
                ('terms_of_service_agreed', models.BooleanField(default=False)),
            ],
            options={
                'verbose_name': 'ACME Account',
                'verbose_name_plural': 'ACME Accounts',
            },
            bases=(django_ca.models.DjangoCAModel, ),
        ),
        migrations.AddField(
            model_name='certificateauthority',
            name='acme_enabled',
            field=models.BooleanField(default=False, help_text='Whether it is possible to use ACME for this CA.', verbose_name='Enable ACME'),
        ),
        migrations.AddField(
            model_name='certificateauthority',
            name='acme_requires_contact',
            field=models.BooleanField(default=True, help_text='If this CA requires a contact address during account registration.', verbose_name='Requires contact'),
        ),
        migrations.AddField(
            model_name='certificateauthority',
            name='caa_identity',
            field=models.CharField(blank=True, help_text='CAA identity for this CA (NOTE: Not currently used!).', max_length=32, verbose_name='CAA identity'),
        ),
        migrations.AddField(
            model_name='certificateauthority',
            name='terms_of_service',
            field=models.URLField(blank=True, help_text='URL to Terms of Service for this CA', verbose_name='Terms of Service'),
        ),
        migrations.AddField(
            model_name='certificateauthority',
            name='website',
            field=models.URLField(blank=True, help_text='Website for your CA.'),
        ),
        migrations.CreateModel(
            name='AcmeOrder',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('slug', models.SlugField(default=django_ca.models.acme_slug, unique=True)),
                ('status', models.CharField(choices=[('invalid', 'Invalid'), ('pending', 'Pending'), ('processing', 'Processing'), ('ready', 'Ready'), ('valid', 'Valid')], default='pending', max_length=10)),
                ('expires', models.DateTimeField(default=django_ca.models.acme_order_expires)),
                ('not_before', models.DateTimeField(null=True)),
                ('not_after', models.DateTimeField(null=True)),
                ('account', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='orders', to='django_ca.acmeaccount')),
            ],
            options={
                'verbose_name': 'ACME Order',
                'verbose_name_plural': 'ACME Orders',
            },
            bases=(django_ca.models.DjangoCAModel, ),
        ),
        migrations.CreateModel(
            name='AcmeCertificate',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('slug', models.SlugField(default=django_ca.models.acme_slug, unique=True)),
                ('csr', models.TextField(verbose_name='CSR')),
                ('cert', models.OneToOneField(null=True, on_delete=django.db.models.deletion.CASCADE, to='django_ca.certificate')),
                ('order', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to='django_ca.acmeorder')),
            ],
            options={
                'verbose_name': 'ACME Certificate',
                'verbose_name_plural': 'ACME Certificate',
            },
        ),
        migrations.CreateModel(
            name='AcmeAuthorization',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('slug', models.SlugField(default=django_ca.models.acme_slug, unique=True)),
                ('type', models.CharField(choices=[('dns', 'DNS')], default='dns', max_length=8)),
                ('value', models.CharField(max_length=255)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('valid', 'Valid'), ('invalid', 'Invalid'), ('deactivated', 'Deactivated'), ('expired', 'Expired'), ('revoked', 'Revoked')], default='pending', max_length=12)),
                ('wildcard', models.BooleanField(default=False)),
                ('order', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='authorizations', to='django_ca.acmeorder')),
            ],
            options={
                'verbose_name': 'ACME Authorization',
                'verbose_name_plural': 'ACME Authorizations',
                'unique_together': {('order', 'type', 'value')},
            },
        ),
        migrations.AddField(
            model_name='acmeaccount',
            name='ca',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='django_ca.certificateauthority', verbose_name='Certificate Authority'),
        ),
        migrations.CreateModel(
            name='AcmeChallenge',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('slug', models.SlugField(default=django_ca.models.acme_slug, unique=True)),
                ('type', models.CharField(choices=[('http-01', 'HTTP Challenge'), ('dns-01', 'DNS Challenge'), ('tls-alpn-01', 'TLS ALPN Challenge')], max_length=12)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('processing', 'Processing'), ('valid', 'Valid'), ('invalid', 'Name')], default='pending', max_length=12)),
                ('validated', models.DateTimeField(blank=True, null=True)),
                ('error', models.CharField(blank=True, max_length=64)),
                ('token', models.CharField(blank=True, default=django_ca.models.acme_token, max_length=64)),
                ('auth', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='challenges', to='django_ca.acmeauthorization')),
            ],
            options={
                'verbose_name': 'ACME Challenge',
                'verbose_name_plural': 'ACME Challenges',
                'unique_together': {('auth', 'type')},
            },
        ),
        migrations.AlterUniqueTogether(
            name='acmeaccount',
            unique_together={('ca', 'thumbprint')},
        ),
    ]

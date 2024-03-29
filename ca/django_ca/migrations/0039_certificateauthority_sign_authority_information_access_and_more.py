# Generated by Django 5.0.1 on 2024-01-13 07:50

import django_ca.modelfields
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('django_ca', '0038_auto_20231228_1932'),
    ]

    operations = [
        migrations.AddField(
            model_name='certificateauthority',
            name='sign_authority_information_access',
            field=django_ca.modelfields.AuthorityInformationAccessField(blank=True, default=None, help_text='Add a Authority  Information Access extension when signing certificates.', null=True, verbose_name='Authority Information Access'),
        ),
        migrations.AddField(
            model_name='certificateauthority',
            name='sign_crl_distribution_points',
            field=django_ca.modelfields.CRLDistributionPointsField(blank=True, default=None, help_text='Add a CRL Distribution Points extension when signing certificates.', null=True, verbose_name='CRL Distribution Points'),
        ),
        migrations.AddField(
            model_name='certificateauthority',
            name='sign_issuer_alternative_name',
            field=django_ca.modelfields.IssuerAlternativeNameField(blank=True, default=None, help_text='Add an Issuer Alternative Name extension when signing certificates.', null=True, verbose_name='Issuer Alternative Name'),
        ),
    ]

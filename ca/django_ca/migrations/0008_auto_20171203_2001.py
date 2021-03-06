# Generated by Django 2.0 on 2017-12-03 20:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('django_ca', '0007_auto_20171119_1100'),
    ]

    operations = [
        migrations.AddField(
            model_name='certificateauthority',
            name='revoked',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='certificateauthority',
            name='revoked_date',
            field=models.DateTimeField(blank=True, null=True, verbose_name='Revoked on'),
        ),
        migrations.AddField(
            model_name='certificateauthority',
            name='revoked_reason',
            field=models.CharField(blank=True, choices=[('', 'No reason'), ('aa_compromise', 'Attribute Authority compromised'), ('affiliation_changed', 'Affiliation changed'), ('ca_compromise', 'CA compromised'), ('certificate_hold', 'On Hold'), ('cessation_of_operation', 'Cessation of operation'), ('key_compromise', 'Key compromised'), ('privilege_withdrawn', 'Privilege withdrawn'), ('remove_from_crl', 'Removed from CRL'), ('superseded', 'Superseded'), ('unspecified', 'Unspecified')], max_length=32, null=True, verbose_name='Reason for revokation'),
        ),
    ]

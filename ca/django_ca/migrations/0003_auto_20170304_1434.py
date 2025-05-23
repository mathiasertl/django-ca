# Generated by Django 1.10.5 on 2017-03-04 14:34

from django.db import migrations


def migrate_revocation_reasons(apps, schema_editor):  # pragma: no cover
    Certificate = apps.get_model("django_ca", "Certificate")
    certs = Certificate.objects.exclude(revoked_reason__isnull=True)

    for cert in certs.exclude(revoked_reason__in=["", "unspecified", "superseded"]):
        if cert.revoked_reason == "keyCompromise":
            cert.revoked_reason = "key_compromise"
        elif cert.revoked_reason == "caCompromise":
            cert.revoked_reason = "ca_compromise"
        elif cert.revoked_reason == "affiliationChanged":
            cert.revoked_reason = "affiliation_changed"
        elif cert.revoked_reason == "cessationOfOperation":
            cert.revoked_reason = "cessation_of_operation"
        elif cert.revoked_reason == "certificateHold":
            cert.revoked_reason = "certificate_hold"
        else:
            raise RuntimeError("Unknown revocation reason encountered: %s" % cert.revoked_reason)

        cert.save()


class Migration(migrations.Migration):
    dependencies = [
        ("django_ca", "0002_auto_20170304_1434"),
    ]

    operations = [
        migrations.RunPython(migrate_revocation_reasons, elidable=True),
    ]

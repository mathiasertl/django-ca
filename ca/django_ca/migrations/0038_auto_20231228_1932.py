# Generated by Django 5.0 on 2023-12-28 18:32

from django.db import migrations


def update_sign_certificates_schema(apps, schema_editor) -> None:  # pragma: no cover
    """Migrate stored data to new Pydantic-based serialization."""
    CertificateAuthority = apps.get_model("django_ca", "CertificateAuthority")
    for ca in CertificateAuthority.objects.exclude(sign_certificate_policies=None):
        ca.save()


class Migration(migrations.Migration):
    dependencies = [
        ("django_ca", "0037_alter_certificateauthority_name_and_more"),
    ]

    operations = [
        migrations.RunPython(
            update_sign_certificates_schema, reverse_code=migrations.RunPython.noop, elidable=True
        )
    ]

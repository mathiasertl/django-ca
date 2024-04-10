from django_ca.pydantic import MSCertificateTemplateModel, MSCertificateTemplateValueModel

MSCertificateTemplateModel(
    critical=True,
    value=MSCertificateTemplateValueModel(
        template_id="1.2.3", major_version=1, minor_version=2
    ),
)

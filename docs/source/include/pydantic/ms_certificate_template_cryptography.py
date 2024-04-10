from cryptography import x509
from cryptography.x509.oid import ExtensionOID

x509.Extension(
    critical=True,
    oid=ExtensionOID.MS_CERTIFICATE_TEMPLATE,
    value=x509.MSCertificateTemplate(
        template_id=x509.ObjectIdentifier("1.2.3"), major_version=1, minor_version=2
    ),
)

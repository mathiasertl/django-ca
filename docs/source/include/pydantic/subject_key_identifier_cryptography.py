from cryptography import x509
from cryptography.x509.oid import ExtensionOID

x509.Extension(
    critical=False,
    oid=ExtensionOID.SUBJECT_KEY_IDENTIFIER,
    value=x509.SubjectKeyIdentifier(b"\x90"),
)

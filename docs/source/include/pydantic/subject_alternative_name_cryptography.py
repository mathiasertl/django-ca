from cryptography import x509
from cryptography.x509.oid import ExtensionOID

value = x509.SubjectAlternativeName(
    [x509.DNSName("example.com"), x509.DNSName("example.net")]
)
x509.Extension(critical=False, oid=ExtensionOID.SUBJECT_ALTERNATIVE_NAME, value=value)

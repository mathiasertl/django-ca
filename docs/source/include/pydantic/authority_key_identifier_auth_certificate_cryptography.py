from cryptography import x509
from cryptography.x509.oid import ExtensionOID

x509.Extension(
    critical=False,
    oid=ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
    value=x509.AuthorityKeyIdentifier(
        key_identifier=None,
        authority_cert_issuer=[x509.UniformResourceIdentifier("http://example.com")],
        authority_cert_serial_number=123,
    ),
)

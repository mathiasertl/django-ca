from cryptography import x509
from cryptography.x509.oid import ExtensionOID

x509.Extension(
    critical=True,
    oid=ExtensionOID.NAME_CONSTRAINTS,
    value=x509.NameConstraints(
        permitted_subtrees=[x509.DNSName(".com")],
        excluded_subtrees=[
            x509.DNSName("one.example.com"),
            x509.DNSName("two.example.com"),
        ],
    ),
)

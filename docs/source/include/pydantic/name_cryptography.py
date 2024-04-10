from cryptography import x509
from cryptography.x509.oid import NameOID

x509.Name(
    [
        x509.NameAttribute(oid=NameOID.COUNTRY_NAME, value="AT"),
        x509.NameAttribute(oid=NameOID.COMMON_NAME, value="example.com"),
    ]
)

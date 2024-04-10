from cryptography import x509
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import NameOID

x509.NameAttribute(
    oid=NameOID.X500_UNIQUE_IDENTIFIER, value=b"example.com", _type=_ASN1Type.BitString
)

from asn1crypto.core import OctetString
from cryptography import x509

value = OctetString(b"\x61\x62\x63").dump()  # equals b"\x61\x62\x63"
x509.OtherName(type_id=x509.ObjectIdentifier("1.2.3"), value=value)

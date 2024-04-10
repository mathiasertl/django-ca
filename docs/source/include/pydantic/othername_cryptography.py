from asn1crypto.core import UTF8String
from cryptography import x509

value = UTF8String("some_string").dump()  # equals b"\x0c\x0bsome_string"
x509.OtherName(type_id=x509.ObjectIdentifier("1.2.3"), value=value)

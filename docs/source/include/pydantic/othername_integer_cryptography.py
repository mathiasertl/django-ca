from asn1crypto.core import Integer
from cryptography import x509

value = Integer(12).dump()
x509.OtherName(type_id=x509.ObjectIdentifier("1.2.3"), value=value)

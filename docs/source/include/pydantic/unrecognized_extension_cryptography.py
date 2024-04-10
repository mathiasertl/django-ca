from cryptography import x509

oid = x509.ObjectIdentifier("1.2.3")
value = x509.UnrecognizedExtension(oid=oid, value=b"123")
x509.Extension(critical=True, oid=oid, value=value)

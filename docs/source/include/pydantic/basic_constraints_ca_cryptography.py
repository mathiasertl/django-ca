from cryptography import x509
from cryptography.x509.oid import ExtensionOID

value = x509.BasicConstraints(ca=True, path_length=0)
x509.Extension(critical=True, oid=ExtensionOID.BASIC_CONSTRAINTS, value=value)

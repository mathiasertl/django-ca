from cryptography import x509
from cryptography.x509.oid import ExtensionOID

value = x509.BasicConstraints(ca=False, path_length=None)
x509.Extension(critical=True, oid=ExtensionOID.BASIC_CONSTRAINTS, value=value)

from cryptography import x509
from cryptography.x509.oid import NameOID

name = x509.Name([x509.NameAttribute(oid=NameOID.COMMON_NAME, value="example.com")])
x509.DirectoryName(name)

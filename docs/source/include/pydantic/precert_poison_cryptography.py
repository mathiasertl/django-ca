from cryptography import x509
from cryptography.x509.oid import ExtensionOID

x509.Extension(critical=True, oid=ExtensionOID.PRECERT_POISON, value=x509.PrecertPoison())

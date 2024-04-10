from cryptography import x509
from cryptography.x509.oid import ExtensionOID

x509.Extension(critical=False, oid=ExtensionOID.OCSP_NO_CHECK, value=x509.OCSPNoCheck())

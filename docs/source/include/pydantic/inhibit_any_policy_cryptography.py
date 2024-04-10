from cryptography import x509
from cryptography.x509.oid import ExtensionOID

x509.Extension(
    critical=True, oid=ExtensionOID.INHIBIT_ANY_POLICY, value=x509.InhibitAnyPolicy(1)
)
